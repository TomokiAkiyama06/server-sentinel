"""Durable compressed-video ring and autonomous Main-loss protection.

The segmenter supplies video-only compressed bytes under explicit per-source
bitrate/cadence bounds. This module does not decode media or open camera devices.
"""

from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
import os
import sqlite3
import threading
from uuid import UUID, uuid4

from .ring_ledger import Ledger
from .ring_models import (DenyControls, POST, PRE, RETENTION, SECOND, RingConfig,
                          RingRefused, SegmentProfile, integer, intervals_and_gaps, round_up)
from .storage import StorageRefused


class DiskRing:
    def __init__(self, settings, store, *, ledger_maximum_bytes, authority=None, ledger_space=os.fstatvfs):
        self.settings, self.store = settings, store
        self.authority = authority or DenyControls()
        self.lock = threading.RLock()
        self.ledger = Ledger(settings, maximum_bytes=ledger_maximum_bytes, space=ledger_space)
        self.db = self.ledger.connection
        self.config, self.profiles = None, {}
        self.connected = False
        self.state, self.reason = "degraded", "not_configured"
        try:
            self.ledger_headroom = (self.ledger.headroom if os.stat(settings.media_root, follow_symlinks=False).st_dev
                                    == os.fstat(self.ledger.fd).st_dev else 0)
            row = self.db.execute("SELECT value FROM settings WHERE key='configuration'").fetchone()
            if row:
                value = json.loads(row[0])
                self.config = RingConfig(**value["config"])
                self.profiles = {UUID(item["source_id"]): SegmentProfile(
                    **{**item, "source_id": UUID(item["source_id"])}
                ) for item in value["profiles"]}
                self._ledger_capacity(self.config, self.profiles)
            self._recover()
        except BaseException:
            self.close()
            raise

    def close(self):
        self.ledger.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @contextmanager
    def _operation(self):
        with self.lock:
            try:
                self.ledger.check()
                yield
            except (sqlite3.Error, OSError) as exc:
                self.state, self.reason = "STORAGE_HARD_STOP", "ledger_unavailable"
                raise RingRefused("ledger_unavailable") from exc
            except RingRefused as exc:
                if str(exc).startswith("ledger_"):
                    self.state, self.reason = "STORAGE_HARD_STOP", str(exc)
                raise
            except StorageRefused as exc:
                self.state, self.reason = "STORAGE_HARD_STOP", str(exc)
                raise RingRefused("media_storage_unavailable") from exc

    def _clock(self, now, trusted, *, record=True):
        row = self.db.execute("SELECT value FROM settings WHERE key='latest_clock'").fetchone()
        previous = int(row[0]) if row else 0
        if now < previous:
            trusted = False
        elif trusted and record:
            with self.ledger.transaction():
                self.db.execute("INSERT OR REPLACE INTO settings VALUES ('latest_clock', ?)", (str(now),))
        return trusted

    def _recover(self):
        physical = self.store.list_segments()
        allocated = self.store.segment_allocations()
        with self.ledger.transaction():
            for row in self.db.execute("SELECT * FROM segments").fetchall():
                identifier = UUID(row["id"])
                if row["state"] == "deleting":
                    continue
                state = "missing"
                if identifier in physical:
                    valid = self.store.verify_segment(identifier, row["length"], row["checksum"])
                    state = "stored" if valid and allocated.get(identifier, 0) >= 512 else "uncertain"
                self.db.execute("UPDATE segments SET state=?, allocated=? WHERE id=?",
                                (state, allocated.get(identifier, 0), row["id"]))
                if state != "stored":
                    self.state, self.reason = "degraded", "segment_integrity_gap"
        # Deletion intent was durable before unlink. Resume only those owned IDs.
        for row in self.db.execute("SELECT id FROM segments WHERE state='deleting'").fetchall():
            self._remove_segment(row["id"])
        for row in self.db.execute("SELECT id FROM incidents WHERE state='deleting'").fetchall():
            self._delete_incident(row["id"])

    def _rows(self):
        return self.db.execute("SELECT * FROM segments ORDER BY end, id").fetchall()

    def _reconcile_presence(self):
        physical = self.store.list_segments()
        allocations = self.store.segment_allocations()
        changes = []
        for row in self._rows():
            identifier = UUID(row["id"])
            if row["state"] == "stored" and (physical.get(identifier) != row["length"]
                                               or allocations.get(identifier, 0) < 512):
                state = "missing" if identifier not in physical else "uncertain"
                changes.append((state, allocations.get(identifier, 0), row["id"]))
        if changes:
            with self.ledger.transaction():
                self.db.executemany("UPDATE segments SET state=?, allocated=? WHERE id=?", changes)

    def _protected(self, segment_id, *, excluding=None):
        query = ("SELECT 1 FROM protection p JOIN incidents i ON i.id=p.incident "
                 "WHERE p.segment=? AND i.state!='deleted'")
        values = [segment_id]
        if excluding is not None:
            query += " AND i.id!=?"
            values.append(excluding)
        return self.db.execute(query + " LIMIT 1", values).fetchone() is not None

    def _reclaimable(self, now):
        return [row for row in self._rows()
                if row["end"] <= now - PRE and row["state"] != "writing"
                and not self._protected(row["id"])]

    def _selected_reclaimable(self, now, config):
        rows = self._reclaimable(now)
        if config.mode == "duration":
            return [row for row in rows if row["end"] <= now - config.value * SECOND]
        return rows

    def _configuration_reclaimable(self, now, proposed):
        candidates = self._selected_reclaimable(now, proposed)
        if self.config is None:
            return candidates
        # A failed proposal leaves the current configuration authoritative.
        # Only media already eligible for its FIFO may be removed pre-commit.
        current = self._selected_reclaimable(now, self.config)
        if self.config.mode == "capacity":
            allocations = self.store.segment_allocations()
            excess = sum(allocations.get(UUID(row["id"]), 0) for row in self._rows()
                         if not self._protected(row["id"])) - self.config.value
            eligible = []
            for row in current:
                if excess <= 0:
                    break
                eligible.append(row)
                excess -= allocations.get(UUID(row["id"]), 0)
            current = eligible
        allowed = {row["id"] for row in current}
        return [row for row in candidates if row["id"] in allowed]

    def _estimate(self, profiles, duration, *, expected=False):
        result = sum(profile.bytes_for(duration, self.store.allocation_unit, expected=expected)
                     for profile in profiles.values())
        return integer(result)

    @staticmethod
    def _segment_count(profiles, duration):
        return sum((duration + item.segment_duration_us - 1) // item.segment_duration_us + 2
                   for item in profiles.values())

    @staticmethod
    def _trusted_profile_row(row, profiles):
        profile = profiles.get(UUID(row["source"]))
        return (row["clock_trusted"] and profile is not None
                and row["end"] - row["start"] == profile.segment_duration_us)

    def _ledger_capacity(self, config, profiles, *, proposal=None, additional_segments=0, additional_protections=0,
                         reactivating=()):
        rows = self._rows()
        protected = sum(self._protected(row["id"]) for row in rows)
        carryover = 0
        for row in rows:
            if self._protected(row["id"]):
                continue
            if (row["state"] != "stored" or row["allocated"] < 512
                    or not self._trusted_profile_row(row, profiles)):
                carryover += 1
        selected = (self._segment_count(profiles, config.value * SECOND) if config.mode == "duration"
                    else config.value // 512 + 1)
        segments = protected + carryover + max(len(rows) - protected - carryover, selected) + additional_segments
        incidents = self.db.execute("SELECT count(*) FROM incidents").fetchone()[0]
        protections = self.db.execute("SELECT count(*) FROM protection").fetchone()[0] + additional_protections
        active = self.db.execute("SELECT * FROM incidents WHERE state='active'").fetchall()
        for incident in active + list(reactivating):
            linked = self.db.execute("SELECT segments.* FROM segments JOIN protection ON segment=segments.id "
                                     "WHERE incident=?", (incident["id"],)).fetchall()
            present = sum(self._trusted_profile_row(row, profiles) for row in linked)
            future = max(0, self._segment_count(profiles, incident["end"] - incident["start"]) - present)
            segments += future
            protections += future
        if proposal is not None:
            start, end = proposal
            matching = [row for row in rows if row["end"] > start and row["start"] < end
                        and UUID(row["source"]) in profiles]
            present = sum(self._trusted_profile_row(row, profiles) for row in matching)
            future = max(0, self._segment_count(profiles, end - start) - present)
            # Ordinary carryover already occupies a separate row reservation.
            # Only compatible ordinary rows newly leaving the projected ring
            # need an additional reservation when they become protected.
            projected = sum(not self._protected(row["id"]) and row["state"] == "stored"
                            and row["allocated"] >= 512 and self._trusted_profile_row(row, profiles)
                            for row in matching)
            segments += future + projected
            protections += len(matching) + future
            incidents += 1
        return self.ledger.require_rows(segments=segments, incidents=incidents, protections=protections)

    def _budget(self, profiles, now):
        self._reconcile_presence()
        free = self.store.check(require_reserve=False)
        allocations = self.store.segment_allocations()
        source_ids = {str(source) for source in profiles}
        pre = sum(allocations.get(UUID(row["id"]), 0) for row in self._rows()
                  if row["state"] == "stored" and row["clock_trusted"] and row["source"] in source_ids
                  and row["end"] > now - PRE and row["start"] < now)
        reclaimable = sum(allocations.get(UUID(row["id"]), 0)
                          for row in self._reclaimable(now))
        post = self._estimate(profiles, POST)
        additional = max(post, self._estimate(profiles, PRE + POST) - pre) + self.ledger_headroom
        return {
            "filesystem_free": free, "required_additional": additional,
            "required_pre_allocated": pre, "reclaimable_allocated": reclaimable,
            "safety_reserve": self.settings.safety_reserve_bytes, "ledger_headroom": self.ledger_headroom,
        }

    def configure(self, config, profiles, *, now_us, clock_trusted):
        self.authority.require_owner("configure_ring")
        integer(now_us)
        if type(clock_trusted) is not bool:
            raise RingRefused("clock_trust_required")
        if not isinstance(config, RingConfig) or not isinstance(profiles, tuple):
            raise RingRefused("invalid_configuration")
        if not 1 <= len(profiles) <= 4 or any(not isinstance(item, SegmentProfile) for item in profiles):
            raise RingRefused("invalid_profile_collection")
        mapping = {item.source_id: item for item in profiles}
        if len(mapping) != len(profiles):
            raise RingRefused("duplicate_source_identity")
        if any(item.segment_bytes() > self.settings.max_segment_bytes for item in profiles):
            raise RingRefused("profile_exceeds_segment_write_limit")
        with self._operation():
            # Configuration must respect a previously observed clock, but it is
            # not itself a capture-time observation. Recording it here would
            # make already buffered pre-roll look like a rollback.
            clock_trusted = self._clock(now_us, clock_trusted, record=False)
            if self.db.execute("SELECT 1 FROM incidents WHERE state='active' LIMIT 1").fetchone():
                raise RingRefused("protection_configuration_busy")
            pre = self._estimate(mapping, PRE)
            if config.mode == "capacity" and config.value < pre:
                raise RingRefused("insufficient_pre_loss_capacity")
            if config.mode == "duration":
                integer(config.value * SECOND)
                self._estimate(mapping, config.value * SECOND)
            budget = self._budget(mapping, now_us)
            reclaimable = self._configuration_reclaimable(now_us, config) if clock_trusted else ()
            allocations = self.store.segment_allocations()
            credit = sum(allocations.get(UUID(row["id"]), 0) for row in reclaimable)
            if (budget["filesystem_free"] + credit
                    < budget["required_additional"] + budget["safety_reserve"]):
                raise RingRefused("insufficient_simultaneous_pre_post_budget")
            self._selected_target_fits(config, mapping)
            self._capacity_transition_fits(config, mapping, now_us, clock_trusted)
            self._ledger_capacity(config, mapping, proposal=(now_us - PRE, now_us + POST))
            # Credit only blocks that were actually returned by deletion. A
            # hardlink/open reader can keep blocks allocated after unlink.
            for row in reclaimable:
                if self.store.check(require_reserve=False) >= budget["required_additional"] + budget["safety_reserve"]:
                    break
                self._remove_segment(row["id"])
            self.store.check(budget["required_additional"])
            self._selected_target_fits(config, mapping)
            value = {"config": asdict(config), "profiles": [
                {**asdict(item), "source_id": str(item.source_id)} for item in profiles
            ]}
            with self.ledger.transaction():
                self.db.execute("INSERT OR REPLACE INTO settings VALUES ('configuration', ?)",
                                (json.dumps(value, separators=(",", ":")),))
            self.config, self.profiles = config, mapping
            self._trim(now_us, trusted=clock_trusted)
            return self._status(now_us, clock_trusted=clock_trusted)

    def _selected_target_fits(self, config, profiles):
        selected = (self._estimate(profiles, config.value * SECOND)
                    if config.mode == "duration" else config.value)
        allocations = self.store.segment_allocations()
        ordinary = sum(allocations.get(UUID(row["id"]), 0) for row in self._rows()
                       if not self._protected(row["id"]))
        # Existing ordinary allocations already occupy part of this selected
        # target. They are not credited as immediately reclaimable pre-data.
        if self.store.check(require_reserve=False) + ordinary < selected + self.settings.safety_reserve_bytes + self.ledger_headroom:
            raise RingRefused("selected_target_exceeds_safe_filesystem")

    def _capacity_transition_fits(self, config, profiles, now, trusted):
        if config.mode != "capacity":
            return
        allocations = self.store.segment_allocations()
        retained = carryover = 0
        for row in self._rows():
            if self._protected(row["id"]) or (trusted and row["end"] <= now - PRE):
                continue
            allocated = allocations.get(UUID(row["id"]), 0)
            retained += allocated
            profile = profiles.get(UUID(row["source"]))
            if (not trusted or not row["clock_trusted"] or row["state"] != "stored" or profile is None
                    or row["end"] - row["start"] != profile.segment_duration_us
                    or allocated > round_up(profile.segment_bytes(), self.store.allocation_unit)):
                carryover += allocated
        # Compatible legacy intervals fit within the new bounded PRE envelope.
        # Incompatible media remains additional carryover throughout rollover;
        # checking only one next segment misses failures several batches later.
        transition = self._estimate(profiles, PRE) + carryover
        next_batch = sum(round_up(profile.segment_bytes(), self.store.allocation_unit)
                         for profile in profiles.values())
        if max(transition, retained + next_batch) > config.value:
            raise RingRefused("capacity_transition_exceeds_limit")

    def _remove_segment(self, identifier):
        if self._protected(identifier):
            raise RingRefused("protected_segment_deletion_refused")
        with self.ledger.transaction():
            self.db.execute("UPDATE segments SET state='deleting' WHERE id=?", (identifier,))
        self.store.delete_segment(UUID(identifier))
        with self.ledger.transaction():
            self.db.execute("DELETE FROM protection WHERE segment=?", (identifier,))
            self.db.execute("DELETE FROM segments WHERE id=?", (identifier,))

    def _trim(self, now, *, trusted=True):
        if not trusted or self.config is None:
            return
        allocations = self.store.segment_allocations()
        ordinary = sum(allocations.get(UUID(row["id"]), 0) for row in self._rows()
                       if not self._protected(row["id"]))
        for row in self._selected_reclaimable(now, self.config):
            outside = row["end"] <= now - self.config.value * SECOND
            if self.config.mode == "duration" and not outside:
                continue
            if self.config.mode == "capacity" and ordinary <= self.config.value:
                break
            self._remove_segment(row["id"])
            ordinary -= allocations.get(UUID(row["id"]), 0)

    def _free_for_write(self, length, now, *, trusted):
        for row in self._selected_reclaimable(now, self.config) if trusted else ():
            try:
                self.store.check(length + self.ledger_headroom)
                return
            except StorageRefused as exc:
                if str(exc) != "STORAGE_HARD_STOP":
                    raise
            self._remove_segment(row["id"])
        self.store.check(length + self.ledger_headroom)

    def append(self, source_id, start_us, end_us, data, *, now_us, clock_trusted):
        integer(start_us)
        integer(end_us)
        integer(now_us)
        if type(clock_trusted) is not bool:
            raise RingRefused("clock_trust_required")
        with self._operation():
            clock_trusted = self._clock(now_us, clock_trusted)
            profile = self.profiles.get(source_id)
            if profile is None or self.config is None:
                raise RingRefused("source_not_configured")
            if (end_us - start_us != profile.segment_duration_us or end_us > now_us
                    or not isinstance(data, bytes) or not data or len(data) > profile.segment_bytes()):
                self.state, self.reason = "degraded", "profile_bound_violation"
                raise RingRefused("profile_bound_violation")
            query = "SELECT max(end) FROM segments WHERE source=?"
            if clock_trusted:
                query += " AND clock_trusted=1"
            previous = self.db.execute(query, (str(source_id),)).fetchone()[0]
            if not clock_trusted and (previous is None or start_us != previous):
                self._tick(now_us, False)
                self.state, self.reason = "degraded", "clock_uncertain"
                raise RingRefused("clock_uncertain")
            if previous is not None and start_us < previous:
                self.state, self.reason = "degraded", "non_monotonic_segment"
                raise RingRefused("non_monotonic_segment")
            identifier = str(uuid4())
            incidents = self.db.execute(
                "SELECT * FROM incidents WHERE state IN ('active','complete','partial') "
                "AND start<? AND end>? AND (expires IS NULL OR expires>?)", (end_us, start_us, now_us)
            ).fetchall()
            incidents = [row for row in incidents if str(source_id) in json.loads(row["sources"])]
            # Untrusted chronology may later overlap corrected trusted capture;
            # it cannot spend that capture's reserved post-window metadata.
            self._ledger_capacity(self.config, self.profiles, additional_segments=int(not clock_trusted),
                                  additional_protections=len(incidents) if not clock_trusted else 0,
                                  reactivating=tuple(row for row in incidents if row["state"] != "active"))
            self._trim(now_us, trusted=clock_trusted)
            # Ordinary capacity remains a physical allocation limit, separate
            # from protected bytes. Never evict required pre-loss coverage.
            if self.config.mode == "capacity" and not incidents:
                allocations = self.store.segment_allocations()
                ordinary = sum(allocations.get(UUID(row["id"]), 0) for row in self._rows()
                               if not self._protected(row["id"]))
                needed = ((len(data) + self.store.allocation_unit - 1)
                          // self.store.allocation_unit) * self.store.allocation_unit
                for row in self._reclaimable(now_us) if clock_trusted else ():
                    if ordinary + needed <= self.config.value:
                        break
                    self._remove_segment(row["id"])
                    ordinary -= allocations.get(UUID(row["id"]), 0)
                if ordinary + needed > self.config.value:
                    self.state, self.reason = "STORAGE_PRESSURE", "ordinary_capacity_exhausted"
                    raise RingRefused("ordinary_capacity_exhausted")
            with self.ledger.transaction():
                self.db.execute("INSERT INTO segments VALUES (?,?,?,?,?,?,?, 'writing', ?)",
                                (identifier, str(source_id), start_us, end_us, len(data), 0,
                                 hashlib.sha256(data).hexdigest(), int(clock_trusted)))
                for incident in incidents:
                    self.db.execute("INSERT INTO protection VALUES (?,?)", (incident["id"], identifier))
                    if not clock_trusted:
                        self.db.execute("UPDATE incidents SET clock_uncertain=1 WHERE id=?", (incident["id"],))
                    if incident["completed"] is not None:
                        self.db.execute("UPDATE incidents SET state='active', completed=NULL, expires=NULL WHERE id=?",
                                        (incident["id"],))
            try:
                self._free_for_write(len(data), now_us, trusted=clock_trusted)
                self.store.write_segment(UUID(identifier), data)
                allocated = self.store.segment_allocations()[UUID(identifier)]
                # st_blocks uses 512-byte units; f_frsize is not a guaranteed
                # minimum allocation on every filesystem. Zero-allocation
                # media cannot uphold the finite capacity-mode row bound.
                if allocated < 512:
                    self.store.delete_segment(UUID(identifier))
                    raise StorageRefused("unsupported_segment_allocation")
                if self.config.mode == "capacity" and not incidents:
                    allocations = self.store.segment_allocations()
                    total = sum(allocations.get(UUID(row["id"]), 0) for row in self._rows()
                                if not self._protected(row["id"]))
                    if total > self.config.value:
                        # This provisional write never becomes an admitted ring
                        # segment when actual allocation exceeds its bound.
                        self.store.delete_segment(UUID(identifier))
                        raise StorageRefused("actual_allocation_exceeded_capacity")
            except StorageRefused as exc:
                with self.ledger.transaction():
                    self.db.execute("UPDATE segments SET state='missing' WHERE id=?", (identifier,))
                self.state, self.reason = "STORAGE_HARD_STOP", str(exc)
                raise RingRefused("segment_storage_refused") from exc
            with self.ledger.transaction():
                self.db.execute("UPDATE segments SET state='stored', allocated=? WHERE id=?",
                                (allocated, identifier))
            self._tick(now_us, clock_trusted)
            self._trim(now_us, trusted=clock_trusted)
            self._status(now_us, clock_trusted=clock_trusted)
            return UUID(identifier)

    def observe_connection(self, *, authenticated, connected, unexpected, now_us, clock_trusted):
        integer(now_us)
        if any(type(value) is not bool for value in (authenticated, connected, unexpected, clock_trusted)):
            raise RingRefused("invalid_connection_observation")
        with self._operation():
            clock_trusted = self._clock(now_us, clock_trusted)
            incident = None
            if self.connected and not (authenticated and connected) and unexpected:
                incident = self._preserve("main_connection_lost", now_us - PRE,
                                          now_us + POST, now_us, clock_trusted)
            self.connected = authenticated and connected
            return incident

    def preserve(self, reason, start_us, end_us, *, now_us, clock_trusted):
        self.authority.require_preserve()
        if reason not in {"server_movement", "camera_tamper"}:
            raise RingRefused("invalid_preservation_reason")
        with self._operation():
            return self._preserve(reason, start_us, end_us, now_us, clock_trusted)

    def _preserve(self, reason, start, end, now, trusted):
        integer(start)
        integer(end)
        integer(now)
        integer(end + RETENTION)
        if start >= end or self.config is None or type(trusted) is not bool:
            raise RingRefused("invalid_preservation_window")
        self._ledger_capacity(self.config, self.profiles, proposal=(start, end))
        trusted = self._clock(now, trusted)
        identifier = str(uuid4())
        with self.ledger.transaction():
            self.db.execute("INSERT INTO incidents VALUES (?,?,?,?,NULL,NULL,'active',?,?)",
                            (identifier, reason, start, end, int(not trusted),
                             json.dumps([str(source) for source in self.profiles])))
            for row in self._rows():
                if row["end"] > start and row["start"] < end and UUID(row["source"]) in self.profiles:
                    self.db.execute("INSERT INTO protection VALUES (?,?)", (identifier, row["id"]))
        self._tick(now, trusted)
        return UUID(identifier)

    def tick(self, *, now_us, clock_trusted):
        integer(now_us)
        if type(clock_trusted) is not bool:
            raise RingRefused("clock_trust_required")
        with self._operation():
            clock_trusted = self._clock(now_us, clock_trusted)
            self._tick(now_us, clock_trusted)
            self._trim(now_us, trusted=clock_trusted)
            return self._status(now_us, clock_trusted=clock_trusted)

    def _tick(self, now, trusted):
        integer(now)
        for row in self.db.execute("SELECT id FROM incidents WHERE state='deleting'").fetchall():
            self._delete_incident(row["id"], now=now, trusted=trusted)
        if not trusted:
            with self.ledger.transaction():
                self.db.execute("UPDATE incidents SET clock_uncertain=1 WHERE state='active'")
            return
        for row in self.db.execute("SELECT * FROM incidents WHERE state='active' AND end<=?", (now,)).fetchall():
            details = self._incident(row, now)
            state = "partial" if details["has_gaps"] or row["clock_uncertain"] else "complete"
            with self.ledger.transaction():
                self.db.execute("UPDATE incidents SET state=?, completed=?, expires=? WHERE id=?",
                                (state, row["end"], row["end"] + RETENTION, row["id"]))
        for row in self.db.execute("SELECT id FROM incidents WHERE "
                                   "state IN ('complete','partial') AND expires<=?", (now,)).fetchall():
            self._delete_incident(row["id"], now=now, trusted=True)

    def delete_incident(self, identifier, *, now_us, clock_trusted):
        self.authority.require_owner("delete_incident")
        if not isinstance(identifier, UUID):
            raise RingRefused("invalid_incident_identity")
        integer(now_us)
        if type(clock_trusted) is not bool:
            raise RingRefused("clock_trust_required")
        with self._operation():
            trusted = self._clock(now_us, clock_trusted)
            self._delete_incident(str(identifier), now=now_us, trusted=trusted)
            self._trim(now_us, trusted=trusted)

    def _ordinary_owned(self, row, now, trusted):
        # On recovery/uncertain time, retaining an ordinary reference is safer
        # than asserting a FIFO cutoff. The next trusted tick applies limits.
        if self.config is None:
            return False
        return (not trusted or self.config.mode == "capacity"
                or row["end"] > now - self.config.value * SECOND)

    def _delete_incident(self, identifier, *, now=None, trusted=False):
        incident = self.db.execute("SELECT * FROM incidents WHERE id=?", (identifier,)).fetchone()
        if incident is None or incident["state"] == "deleted":
            return
        with self.ledger.transaction():
            self.db.execute("UPDATE incidents SET state='deleting' WHERE id=?", (identifier,))
        segments = self.db.execute("SELECT s.* FROM segments s JOIN protection p ON p.segment=s.id "
                                   "WHERE p.incident=?", (identifier,)).fetchall()
        for row in segments:
            segment = row["id"]
            keep_ordinary = self._ordinary_owned(row, now, trusted)
            with self.ledger.transaction():
                self.db.execute("DELETE FROM protection WHERE incident=? AND segment=?", (identifier, segment))
                if not self._protected(segment) and not keep_ordinary:
                    self.db.execute("UPDATE segments SET state='deleting' WHERE id=?", (segment,))
            if not self._protected(segment) and not keep_ordinary:
                self._remove_segment(segment)
        with self.ledger.transaction():
            self.db.execute("UPDATE incidents SET state='deleted' WHERE id=?", (identifier,))

    def _incident(self, row, now):
        end = max(row["start"], min(now, row["end"])) if row["state"] == "active" else row["end"]
        rows = self.db.execute("SELECT s.* FROM segments s JOIN protection p ON s.id=p.segment "
                               "WHERE p.incident=?", (row["id"],)).fetchall()
        coverage = {}
        for source in json.loads(row["sources"]):
            intervals, gaps = intervals_and_gaps(
                [(segment["start"], segment["end"]) for segment in rows
                 if segment["state"] == "stored" and segment["clock_trusted"]
                 and segment["source"] == source], row["start"], end
            )
            coverage[source] = {"intervals_us": intervals, "gaps_us": gaps}
        has_gaps = any(value["gaps_us"] for value in coverage.values())
        state = row["state"]
        if state == "complete" and (has_gaps or row["clock_uncertain"]):
            state = "partial"
        return {
            "incident_id": row["id"], "trigger_reason": row["reason"],
            "started_at_us": row["start"], "target_end_us": row["end"],
            "completed_at_us": row["completed"], "expires_at_us": row["expires"],
            "state": state, "byte_length": sum(item["length"] for item in rows if item["state"] == "stored"),
            "allocated_bytes": sum(item["allocated"] for item in rows),
            "clock_uncertain": bool(row["clock_uncertain"]), "coverage": coverage,
            "has_gaps": has_gaps,
        }

    def incident(self, identifier, *, now_us):
        integer(now_us)
        if not isinstance(identifier, UUID):
            raise RingRefused("invalid_incident_identity")
        with self._operation():
            self._reconcile_presence()
            row = self.db.execute("SELECT * FROM incidents WHERE id=?", (str(identifier),)).fetchone()
            if row is None:
                raise RingRefused("incident_not_found")
            return self._incident(row, now_us)

    def status(self, *, now_us, clock_trusted):
        integer(now_us)
        if type(clock_trusted) is not bool:
            raise RingRefused("clock_trust_required")
        try:
            with self._operation():
                return self._status(now_us, clock_trusted=clock_trusted)
        except RingRefused as exc:
            reason = self.reason if self.state == "STORAGE_HARD_STOP" else str(exc)
            return {"state": "STORAGE_HARD_STOP", "reason": reason,
                    "filesystem_free": None, "safety_reserve": self.settings.safety_reserve_bytes,
                    "mode": self.config.mode if self.config else None,
                    "selected_value": self.config.value if self.config else None}

    def _status(self, now, *, clock_trusted):
        if self.config is None:
            return {"state": "degraded", "reason": "not_configured"}
        self.ledger.check_space()
        budget = self._budget(self.profiles, now)
        clock_trusted = self._clock(now, clock_trusted, record=False)
        ledger_pressure = False
        try:
            active = self.db.execute("SELECT 1 FROM incidents WHERE state='active' LIMIT 1").fetchone()
            self._ledger_capacity(self.config, self.profiles, proposal=None if active else (now - PRE, now + POST))
        except RingRefused as exc:
            if str(exc) != "insufficient_ledger_capacity":
                raise
            ledger_pressure = True
        allocated = self.store.segment_allocations()
        rows = self._rows()
        known_ids = {UUID(row["id"]) for row in rows}
        orphan_bytes = sum(size for identifier, size in allocated.items() if identifier not in known_ids)
        ordinary = sum(allocated.get(UUID(row["id"]), 0) for row in rows if not self._protected(row["id"]))
        protected = sum(allocated.get(UUID(row["id"]), 0) for row in rows if self._protected(row["id"]))
        coverage = {}
        for source in self.profiles:
            intervals, gaps = intervals_and_gaps([(row["start"], row["end"]) for row in rows
                                                  if row["source"] == str(source) and row["state"] == "stored"
                                                  and row["clock_trusted"]],
                                                 now - PRE, now)
            coverage[str(source)] = {"intervals_us": intervals, "gaps_us": gaps}
        if budget["filesystem_free"] < budget["safety_reserve"]:
            self.state, self.reason = "STORAGE_HARD_STOP", "safety_reserve_unavailable"
        elif self.config.mode == "capacity" and ordinary > self.config.value:
            self.state, self.reason = "STORAGE_PRESSURE", "ordinary_capacity_exhausted"
        elif ledger_pressure:
            self.state, self.reason = "STORAGE_PRESSURE", "insufficient_ledger_capacity"
        elif budget["filesystem_free"] + budget["reclaimable_allocated"] < budget["required_additional"] + budget["safety_reserve"]:
            self.state, self.reason = "STORAGE_PRESSURE", "post_loss_headroom_reduced"
        elif not clock_trusted:
            self.state, self.reason = "degraded", "clock_uncertain"
        elif any(row["state"] != "stored" and self._protected(row["id"]) for row in rows):
            self.state, self.reason = "degraded", "protected_evidence_integrity_gap"
        elif orphan_bytes:
            self.state, self.reason = "degraded", "orphan_media_present"
        elif any(item["gaps_us"] for item in coverage.values()):
            self.state, self.reason = "degraded", "pre_loss_coverage_gap"
        elif any(row["state"] != "stored" and not self._protected(row["id"])
                 and self._ordinary_owned(row, now, clock_trusted) for row in rows):
            self.state, self.reason = "degraded", "ordinary_ring_integrity_gap"
        else:
            self.state, self.reason = "healthy", "protection_ready"
        selected_duration = self.config.value * SECOND if self.config.mode == "duration" else PRE
        max_bytes = self._estimate(self.profiles, selected_duration)
        expected_bytes = self._estimate(self.profiles, selected_duration, expected=True)
        estimated_duration = None
        if self.config.mode == "capacity":
            # Binary search under the exact same aggregate block/overhead model.
            left, right = 0, self.config.value * SECOND
            while left < right:
                middle = (left + right + 1) // 2
                if self._estimate(self.profiles, middle) <= self.config.value:
                    left = middle
                else:
                    right = middle - 1
            estimated_duration = left
            max_bytes = self._estimate(self.profiles, left)
            expected_bytes = self._estimate(self.profiles, left, expected=True)
        return {**budget, "mode": self.config.mode, "selected_value": self.config.value,
                "selected_unit": "seconds" if self.config.mode == "duration" else "bytes",
                "projected_maximum_bytes": max_bytes, "projected_expected_bytes": expected_bytes,
                "estimated_duration_us": estimated_duration, "ordinary_allocated_bytes": ordinary,
                "protected_allocated_bytes": protected, "orphan_allocated_bytes": orphan_bytes,
                "state": self.state, "reason": self.reason,
                "pre_loss_coverage": coverage}
