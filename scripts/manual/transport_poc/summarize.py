"""Evaluate gates G1-G6 and the secondary metrics from measurement JSONL.

Input: one or more run directories (``<out>/<run_id>``) that contain one
directory per ``<scenario>-<candidate>`` with ``receiver.jsonl``,
``sender.jsonl``, ``proxy.jsonl`` and ``orchestrator-*.jsonl``. For a
two-host run, pass the Main-side and the capture-side run directories; files
of the same scenario directory name are merged.

Every comparison uses timestamps of one host only, or Agent capture-clock
values carried in the envelope (``*_capture_ns``) against the Agent's own
loss time. Results are ``pass``/``fail``/``unmeasured``/``not_applicable``.
Packet loss and jitter are always ``unmeasured`` (no root ``netem``).
"""
from collections import defaultdict
import json
from pathlib import Path

from . import matrix, records

SECOND = 1_000_000_000
PROTECTED_NS = 600 * SECOND
RECONNECT_P95_NS = 10 * SECOND
DETECTION_NS = 15 * SECOND
OUTQ_SLACK = 64 * 1024
GROWTH_BYTES = 16 * 1024 * 1024
DISCONNECT_SCENARIOS = {"outage_5s", "outage_120s", "rst", "slow_stop_10s", "slow_stop_60s",
                        "main_restart"}
COMM_LOSS_SCENARIOS = {"outage_1s", "outage_5s", "outage_120s", "rst", "slow_stop_10s",
                       "slow_stop_60s", "main_restart"}
NEGATIVE_SCENARIOS = {"auth_unpaired", "auth_other_ca", "auth_revoked"}
# Main-side outages (orchestrator sigstop / restart_receiver windows): the Agent
# must detect each one itself, on its own clock.
MAIN_OUTAGE_SCENARIOS = {"slow_stop_10s", "slow_stop_60s", "main_restart"}
# Main-side refusal reasons that are an authentication / admission decision
# (``connection_limit`` is a resource bound, not an authentication result).
AUTH_REFUSAL_REASONS = {
    "tls_handshake_failed", "tls_session_failed", "capture_node_not_admitted",
    "capture_node_certificate_invalid", "capture_node_certificate_missing",
    "tls_version_refused", "unauthorized"}
# A candidate verdict covers only the scenarios that ran: a gate whose required
# scenarios are not all present is ``unmeasured`` (unless one already failed).
REQUIRED_SCENARIOS = {
    "g1": NEGATIVE_SCENARIOS | {"auth_revoked_live", "route_probe"},
    "g2": {"normal", "capture_restart"} | COMM_LOSS_SCENARIOS,
    "g3": {"normal", "slow_drain", "bandwidth_cap", "outage_120s", "slow_stop_60s",
           "capacity_4"},
    "g4": set(DISCONNECT_SCENARIOS),
    "g5": set(COMM_LOSS_SCENARIOS),
    "g6": {"capacity_4", "fifth_refused"},
}
GATES = ("g1", "g2", "g3", "g4", "g5", "g6")
# Impairments after which the Agent must have dropped the connection (G4):
# always for reset / restart, and for a silent window only when it is longer
# than the Agent loss timeout by a full second (no borderline expectation).
LOSS_MARGIN_NS = SECOND


def load_runs(directories):
    runs = defaultdict(lambda: defaultdict(list))
    for directory in directories:
        for scenario_dir in sorted(Path(directory).iterdir()):
            if not scenario_dir.is_dir():
                continue
            for path in sorted(scenario_dir.glob("*.jsonl")):
                role = path.stem.split("-")[0]
                runs[scenario_dir.name][role].extend(records.read_jsonl(path))
    return runs


def _kind(items, kind):
    return [item for item in items if item.get("kind") == kind]


def _last(items, kind):
    found = _kind(items, kind)
    return found[-1] if found else None


def _sum_end(items, field):
    return sum(item.get(field) or 0 for item in _kind(items, "end") if field in item)


def _verdict(ok):
    return "pass" if ok else "fail"


def _bound(ok):
    """A bound check: None (the value could not be read) is ``unmeasured``."""
    return "unmeasured" if ok is None else _verdict(ok)


def _combine(verdicts):
    verdicts = [v for v in verdicts if v not in ("not_applicable",)]
    if not verdicts:
        return "unmeasured"
    if "fail" in verdicts:
        return "fail"
    if "unmeasured" in verdicts:
        return "unmeasured"
    return "pass"


class RunSummary:
    def __init__(self, name, roles):
        self.name = name
        self.receiver = roles.get("receiver", [])
        self.sender = roles.get("sender", [])
        self.proxy = roles.get("proxy", [])
        self.orchestrator = [item for role, items in roles.items()
                             if role == "orchestrator" for item in items]
        start = _last(self.orchestrator, "start") or {}
        self.scenario = start.get("scenario") or name.rsplit("-", 1)[0]
        self.candidate = start.get("candidate") or name.rsplit("-", 1)[-1]
        self.n_sources = start.get("n_sources")
        self.inputs = start.get("inputs", "synthetic")
        sides = {item.get("side") for item in _kind(self.orchestrator, "start")}
        # A ``--role main`` / ``--role agent`` record means two hosts (two clocks).
        self.two_host = bool(sides & {"main", "agent"})
        self.fast = start.get("fast")
        self.metrics = {}
        self.gates = {}

    def plan(self):
        """The deterministic schedule this run executed, or None if unknown."""
        if self.fast is None or self.scenario not in matrix.SCENARIOS:
            return None
        return matrix.timing(self.scenario, bool(self.fast))

    def stale_after_ns(self):
        ready = [r for r in _kind(self.receiver, "ready") if r.get("stale_after_ns")]
        return ready[0]["stale_after_ns"] if ready else None

    # -- G1 -----------------------------------------------------------------
    def g1(self, single_host=True):
        accepted = _sum_end(self.receiver, "accepted")
        sender_accepted = sum(item.get("accepted", 0) for item in _kind(self.sender, "end"))
        sessions = len(_kind(self.receiver, "session_open"))
        self.metrics.update(receiver_accepted=accepted, sender_accepted=sender_accepted,
                            sessions=sessions,
                            auth_refusals=len(_kind(self.receiver, "auth_refused")))
        if not self.receiver:
            return "unmeasured"
        if self.scenario in NEGATIVE_SCENARIOS:
            return self._g1_negative(accepted, sender_accepted, sessions)
        if self.scenario == "route_probe":
            probes = _kind(self.sender, "route_probe")
            return _verdict(bool(probes) and all(p["reason"] in ("not_found", "peer_closed")
                                                 for p in probes) and accepted == 0)
        if self.scenario == "auth_revoked_live":
            return self._g1_revoked_live(accepted, single_host)
        return _verdict(sessions > 0)

    def _g1_revoked_live(self, accepted, single_host):
        """Revocation of a connected node: detected, then nothing accepted.

        Evidence required: the Main-side orchestrator ``revoke`` action (else
        ``unmeasured``), the receiver ``revoked`` decision, at least one
        receiver sample after it whose accepted count equals the count at the
        decision (else ``unmeasured``: nothing was observed afterwards), and a
        refused re-admission after it (Main ``auth_refused``; on one host a
        sender ``connect`` also counts). Positive control: media before it.
        """
        action = [a for a in _kind(self.orchestrator, "action") if a.get("action") == "revoke"]
        revoked = _kind(self.receiver, "revoked")
        if not action:
            return "unmeasured"  # the revocation itself is not on record
        if not revoked:
            return "fail"
        detected = revoked[0]["t_ns"]
        delay = detected - action[0]["t_ns"]
        samples = _kind(self.receiver, "sample")
        baseline = revoked[0].get("accepted")
        if baseline is None:  # older record: last count observed before detection
            before = [s["accepted"] for s in samples
                      if s["t_ns"] < detected and s.get("accepted") is not None]
            baseline = before[-1] if before else None
        after = [s for s in samples if s["t_ns"] > detected]
        retried = any(r["t_ns"] > detected and r.get("reason") in AUTH_REFUSAL_REASONS
                      for r in _kind(self.receiver, "auth_refused"))
        if single_host:
            retried = retried or any(c["t_ns"] > detected for c in _kind(self.sender, "connect"))
        self.metrics.update(revocation_detect_ns=delay, revoked_samples_after=len(after),
                            revoked_retry_refused=retried)
        if baseline is None or not after:
            return "unmeasured"
        frozen = all(s.get("accepted") == baseline for s in after)
        # Detection within admission check interval + one sample, and no
        # media accepted afterwards; positive control: media before it.
        if not frozen or accepted <= 0 or baseline <= 0 or delay > 3 * SECOND:
            return "fail"
        if not retried:
            return "fail" if self.sender else "unmeasured"
        return "pass"

    def _g1_negative(self, accepted, sender_accepted, sessions):
        """Zero accepted media only counts with evidence that auth was exercised.

        Requires the Agent-side run (``start``), at least one connection attempt
        and a Main-side authentication refusal; a sender that never ran or never
        connected must not certify the negative test.
        """
        attempts = len(_kind(self.sender, "connect"))
        refusals = [r for r in _kind(self.receiver, "auth_refused")
                    if r.get("reason") in AUTH_REFUSAL_REASONS]
        self.metrics.update(connect_attempts=attempts, auth_refusal_evidence=len(refusals))
        if accepted or sender_accepted or sessions:
            return "fail"
        if not _kind(self.sender, "start"):
            return "unmeasured"  # Agent side missing: the test is incomplete
        return _verdict(attempts > 0 and bool(refusals))

    # -- G2 -----------------------------------------------------------------
    def g2(self):
        if not self.receiver:
            return "unmeasured"
        durable = {}
        for item in _kind(self.receiver, "durable"):
            durable[(item["source"], item["epoch"])] = item  # last instance wins (cumulative)
        gaps = _kind(self.receiver, "gap")
        exact = True
        actual_total = reported_total = duplicates = 0
        restart_starts = {(g["source"], g["epoch"], g["before_sequence"])
                          for g in gaps if g["reason"] == "capture_restart"}
        for (source, epoch), row in durable.items():
            # Every epoch starts at sequence 0, so units lost before the first
            # durable one are loss too (the tracker reports them as a leading
            # sequence_skip). After a capture restart the leading extent is
            # the unknown-extent capture_restart gap instead.
            origin = (row["min_sequence"] if (source, epoch, row["min_sequence"]) in restart_starts
                      else 0)
            actual = row["max_sequence"] - origin + 1 - row["units"]
            reported = 0
            for gap in gaps:
                if (gap["source"], gap["epoch"]) != (source, epoch):
                    continue
                if gap["reason"] == "coalesced" or (gap["reason"] in ("sequence_skip",
                                                                      "ingest_refused")
                                                    and gap["missing_units"] is None):
                    exact = False
                elif (gap["reason"] in ("sequence_skip", "ingest_refused")
                      and gap["before_sequence"] <= row["max_sequence"]):
                    reported += gap["missing_units"]
            duplicates += row["duplicates"]
            actual_total += actual
            reported_total += reported
            exact = exact and actual == reported
        # Sender evidence: an epoch the Agent got accepted units for but that
        # has no durable row lost them all, with no exact count on record.
        unrecorded = [(e["source"], e["epoch"]) for e in _kind(self.sender, "end")
                      if e.get("epoch") is not None and (e.get("accepted") or 0) > 0
                      and (e["source"], e["epoch"]) not in durable]
        if unrecorded:
            exact = False
        restarts_ok = True
        epochs_by_source = defaultdict(set)
        for source, epoch in durable:
            epochs_by_source[source].add(epoch)
        restart_gaps = [g for g in gaps if g["reason"] == "capture_restart"]
        for source, epochs in epochs_by_source.items():
            needed = len(epochs) - 1
            unknown = [g for g in restart_gaps if g["source"] == source]
            if len(unknown) < needed or any(g["missing_units"] is not None for g in unknown):
                restarts_ok = False
        if self.scenario == "capture_restart" and not any(len(e) > 1
                                                          for e in epochs_by_source.values()):
            restarts_ok = False
        self.metrics.update(actual_missing=actual_total, reported_missing=reported_total,
                            durable_duplicates=duplicates, capture_restart_gaps=len(restart_gaps),
                            epochs_without_durable=len(unrecorded),
                            lossless=actual_total == 0 and reported_total == 0)
        if not durable and self.scenario not in NEGATIVE_SCENARIOS | {"route_probe"}:
            return "fail"
        return _verdict(exact and restarts_ok and duplicates == 0)

    # -- G3 -----------------------------------------------------------------
    @staticmethod
    def _growth(samples, field="rss_bytes"):
        values = [s[field] for s in samples if s.get(field) is not None]
        if len(values) < 4:
            return None
        warm = values[len(values) // 4]
        return max(values[len(values) // 4:]) - warm, warm

    def _g3_side(self, samples, side, rss_limit, *, require_ss):
        """Bound checks of one side's samples; returns per-check verdicts.

        The kernel send queue is the queued byte count: ``TIOCOUTQ`` (always)
        and, when ``ss -tmi`` ran, skmem ``w`` (wmem_queued). skmem ``tb`` is
        the buffer *limit*, which Linux may expand before SO_SNDBUF is applied
        to a freshly connected socket; it is recorded but not gated. Without
        ``ss`` the skmem check is ``unmeasured`` for real-input runs (the
        runbook requires ``ss``) and skipped for synthetic loopback runs.
        """
        last = samples[-1]
        limit = 2 * last["sndbuf"] + OUTQ_SLACK
        max_outq = max(s["max_outq"] for s in samples)
        ss_measured = any(s.get("ss_sockets") is not None for s in samples)
        ss_w = max((s.get("ss_w") or 0) for s in samples)
        ss_tb = max((s.get("ss_tb") or 0) for s in samples)
        hwm_values = [s["hwm_bytes"] for s in samples if s.get("hwm_bytes") is not None]
        growth = self._growth(samples)
        self.metrics.update({
            f"{side}_max_outq": max_outq, f"{side}_hwm": max(hwm_values, default=None),
            f"{side}_ss_measured": ss_measured, f"{side}_ss_w": ss_w if ss_measured else None,
            f"{side}_ss_tb": ss_tb if ss_measured else None,
            f"{side}_rss_growth": None if growth is None else growth[0]})
        verdicts = [_verdict(max_outq <= limit),
                    _bound(None if not hwm_values else max(hwm_values) <= rss_limit),
                    _bound(None if growth is None
                           else growth[0] <= max(GROWTH_BYTES, growth[1] // 10))]
        if ss_measured:
            verdicts.append(_verdict(ss_w <= limit))
        elif require_ss:
            verdicts.append("unmeasured")
        return verdicts

    def g3(self, rss_limit):
        if self.scenario == "route_probe":
            return "not_applicable"  # one request, no media flow to bound
        rsamples = _kind(self.receiver, "sample")
        ssamples = _kind(self.sender, "sample")
        psamples = _kind(self.proxy, "sample")
        if psamples:
            # Structural, not gated: the proxy holds at most one recv() buffer.
            self.metrics.update(proxy_max_held=max(s["max_held"] for s in psamples))
        if not rsamples or not ssamples:
            return "unmeasured"  # both ends are required
        require_ss = self.inputs == "real"
        last = rsamples[-1]
        max_q = max(s["max_queued_messages"] for s in rsamples)
        max_b = max(s["max_queued_bytes"] for s in rsamples)
        self.metrics.update(receiver_max_queue=max_q, receiver_max_queue_bytes=max_b)
        verdicts = [_verdict(max_q <= last["limit_queued_messages"]
                             and max_b <= last["limit_queued_bytes"])]
        verdicts += self._g3_side(rsamples, "receiver", rss_limit, require_ss=require_ss)
        max_pending = max(s["max_pending"] for s in ssamples)
        self.metrics.update(sender_max_pending=max_pending)
        verdicts.append(_verdict(max_pending <= ssamples[-1]["pending_limit"]))
        verdicts += self._g3_side(ssamples, "sender", rss_limit, require_ss=require_ss)
        return _combine(verdicts)

    # -- G4 -----------------------------------------------------------------
    def _impairment_windows(self):
        """(start_ns, end_ns) per impairment, on the host that applied it."""
        windows = []
        starts = {}
        restart_at = None
        for item in self.proxy:
            if item["kind"] == "impairment_start":
                starts[item["impairment"]] = item["t_ns"]
            elif item["kind"] == "impairment_end" and item["impairment"] in starts:
                windows.append((starts.pop(item["impairment"]), item["t_ns"], "proxy"))
        stop_at = None
        for item in _kind(self.orchestrator, "action"):
            if item["action"] == "sigstop":
                stop_at = item["t_ns"]
            elif item["action"] == "sigcont" and stop_at is not None:
                windows.append((stop_at, item["t_ns"], "main"))
                stop_at = None
            elif item["action"] == "restart_receiver":
                restart_at = item["t_ns"]
            elif item["action"] == "ready" and restart_at is not None:
                windows.append((restart_at, item["t_ns"], "main"))
                restart_at = None
        return windows

    def _loss_timeout_ns(self):
        start = _last(self.sender, "start") or {}
        return start.get("loss_timeout_ns")

    def _required_disconnects(self):
        """Scheduled impairments that must each produce one reconnect (G4)."""
        plan = self.plan()
        loss_timeout = self._loss_timeout_ns()
        if plan is None or loss_timeout is None:
            return None
        required = 0
        for item in plan.get("proxy", []) + plan.get("actions", []):
            action, length = item[1], (item[2] if len(item) > 2 else 0)
            if action in ("reset", "restart_receiver"):
                required += 1
            elif (action in ("blackhole", "sigstop")
                  and length * SECOND >= loss_timeout + LOSS_MARGIN_NS):
                required += 1
        return required

    def g4(self, single_host):
        if self.scenario not in DISCONNECT_SCENARIOS:
            return "not_applicable"
        if not self.sender:
            return "unmeasured"
        windows = sorted(self._impairment_windows())
        closes = sorted(c["t_ns"] for c in _kind(self.sender, "closed")
                        if c["reason"] != "shutdown")
        accepts = sorted(a["t_ns"] for a in _kind(self.sender, "first_accept"))
        if any(origin == "main" for *_, origin in windows) and not single_host:
            # Main-side windows use the Main clock; measure on the Agent clock
            # from each unexpected disconnect to the next accepted unit.
            windows = [(t, t, "agent") for t in closes]
        # Each window takes its own disconnect and its own first accepted unit
        # after it: one close/accept episode never counts for two windows.
        used_closes, used_accepts = set(), set()
        times = []
        for start, end, _origin in windows:
            close = next((i for i, t in enumerate(closes)
                          if i not in used_closes and start <= t <= end + 30 * SECOND), None)
            if close is None:
                continue
            used_closes.add(close)
            accept = next((i for i, t in enumerate(accepts)
                           if i not in used_accepts and t >= max(end, closes[close])), None)
            if accept is None:
                self.metrics.update(reconnect_missing=True)
                return "fail"
            used_accepts.add(accept)
            times.append(accepts[accept] - end)
        self.reconnect_samples = times
        required = self._required_disconnects()
        self.metrics.update(reconnects=len(times), reconnects_required=required,
                            reconnect_p95_ns=records.percentiles(times)[95])
        if required is not None and len(times) < required:
            return "fail"  # a scheduled disconnect has no reconnect episode
        if not times and self.scenario in {"outage_5s", "outage_120s", "rst", "main_restart"}:
            return "fail"
        if times and records.percentiles(times)[95] > RECONNECT_P95_NS:
            return "fail"
        return "unmeasured" if required is None else "pass"

    # -- G5 -----------------------------------------------------------------
    def _main_outage_detection(self, losses, single_host):
        """Agent loss detection for each Main-side stop/restart, on the Agent clock.

        Each loss episode (one per Agent connection) carries ``idle_ns``: Agent
        clock time from the last bytes received from Main to the detection.
        That bounds the detection delay without comparing host clocks. On a
        single host the episode must also fall in its window.
        """
        if self.scenario not in MAIN_OUTAGE_SCENARIOS:
            return "not_applicable"
        windows = [(start, end) for start, end, origin in self._impairment_windows()
                   if origin == "main"]
        if not windows:
            return "unmeasured"  # Main-side orchestrator record missing
        episodes = {}
        for loss in losses:
            key = loss.get("connection", loss["t_ns"])
            if key not in episodes:
                episodes[key] = loss
        delays = [loss.get("idle_ns") for loss in episodes.values()]
        matched = 0
        if single_host:
            used = set()
            for start, end in windows:
                hit = next((key for key, loss in sorted(episodes.items(),
                                                        key=lambda kv: kv[1]["t_ns"])
                            if key not in used and start <= loss["t_ns"] <= end + DETECTION_NS),
                           None)
                if hit is not None:
                    used.add(hit)
                    matched += 1
                    delays.append(episodes[hit]["t_ns"] - start)
        else:
            matched = min(len(episodes), len(windows))
        self.metrics.update(main_outages=len(windows), agent_loss_episodes=len(episodes),
                            agent_main_outage_detect_max_ns=max(
                                (d for d in delays if d is not None), default=None))
        if matched < len(windows) or any(d is None or d > DETECTION_NS for d in delays):
            return "fail"
        return "pass"

    def _silent_outage_evidence(self, single_host):
        """Scheduled proxy blackholes ran, and Main flagged each long one.

        Every scheduled blackhole needs its ``impairment_start`` record (the
        Agent-side ``proxy.jsonl``; absent: ``unmeasured``, fewer: ``fail``).
        Each blackhole at least as long as the Main stale threshold must show
        Main's own detection: an ``interrupted`` record per source with
        ``since_last_rx_ns`` <= 15 s (on one host also inside the window + 15
        s; on two hosts one per window and source, without clock comparison).
        """
        plan = self.plan()
        if plan is None:
            return "unmeasured"
        scheduled = [item for item in plan.get("proxy", []) if item[1] == "blackhole"]
        if not scheduled:
            return "pass"
        if not self.proxy:
            return "unmeasured"
        starts = [item for item in self.proxy if item["kind"] == "impairment_start"
                  and item["impairment"] == "blackhole"]
        stale = self.stale_after_ns()
        self.metrics.update(blackholes_scheduled=len(scheduled), blackholes_recorded=len(starts))
        if len(starts) < len(scheduled):
            return "fail"
        if stale is None:
            return "unmeasured"  # Main-side threshold not on record
        windows = [(start, end) for start, end, origin in self._impairment_windows()
                   if origin == "proxy" and end - start >= stale]
        sources = sorted({d["source"] for d in _kind(self.receiver, "durable")
                          if d["source"] >= 0})
        interrupted = [i for i in _kind(self.receiver, "interrupted")
                       if i.get("since_last_rx_ns") is not None
                       and i["since_last_rx_ns"] <= DETECTION_NS]
        matched = 0
        for source in sources:
            mine = sorted((i["t_ns"] for i in interrupted if i.get("source") == source))
            if not single_host:
                matched += min(len(mine), len(windows))
                continue
            used = set()
            for start, end in windows:
                hit = next((k for k, t in enumerate(mine)
                            if k not in used and start <= t <= end + DETECTION_NS), None)
                if hit is not None:
                    used.add(hit)
                    matched += 1
        required = len(windows) * len(sources)
        self.metrics.update(main_detect_required=required, main_detect_matched=matched)
        if not sources and windows:
            return "fail"
        return _verdict(matched >= required)

    def g5(self, loss_timeout_ns, single_host=True):
        if self.scenario not in COMM_LOSS_SCENARIOS:
            gaps = _kind(self.receiver, "durable_gap")
            self.metrics.update(unprotected_gap_units=sum(g["missing_units"] or 0 for g in gaps))
            return "not_applicable"
        if not self.sender or not self.receiver:
            return "unmeasured"
        losses = _kind(self.sender, "loss_detected")
        proxy_evidence = self._silent_outage_evidence(single_host)
        ok = True
        detections = []
        for item in self.proxy:
            if (item["kind"] == "impairment_start" and item["impairment"] == "blackhole"
                    and item["duration_ns"] >= loss_timeout_ns):
                later = [loss["t_ns"] for loss in losses if loss["t_ns"] >= item["t_ns"]]
                if not later:
                    ok = False
                else:
                    detections.append(later[0] - item["t_ns"])
        # A stopped or restarting Main cannot detect anything: interrupted
        # records it writes inside (or just after) its own stop/restart window
        # measure that window, not detection. Both clocks are the Main host's.
        main_windows = [(start, end) for start, end, origin in self._impairment_windows()
                        if origin == "main"]
        main_detect = [i["since_last_rx_ns"] for i in _kind(self.receiver, "interrupted")
                       if i.get("since_last_rx_ns") is not None
                       and not any(start <= i["t_ns"] <= end + DETECTION_NS
                                   for start, end in main_windows)]
        if detections and any(value > DETECTION_NS for value in detections):
            ok = False
        main_outage = self._main_outage_detection(losses, single_host)
        if any(value > DETECTION_NS for value in main_detect):
            ok = False
        uncovered = 0
        loss_times = [loss["t_ns"] for loss in losses]
        for gap in _kind(self.receiver, "durable_gap"):
            if gap["missing_units"] is None:
                continue  # epoch change: capture restart, not a communication loss
            covered = any(t - PROTECTED_NS <= gap["from_capture_ns"]
                          and gap["to_capture_ns"] <= t + PROTECTED_NS for t in loss_times)
            if not covered:
                uncovered += 1
        self.metrics.update(agent_detect_max_ns=max(detections) if detections else None,
                            main_detect_max_ns=max(main_detect) if main_detect else None,
                            uncovered_durable_gaps=uncovered)
        # A failed check fails the gate even when other evidence is missing.
        return _combine([proxy_evidence, main_outage, _verdict(ok and uncovered == 0)])

    # -- G6 -----------------------------------------------------------------
    def g6(self):
        if self.scenario not in ("capacity_4", "fifth_refused"):
            return "not_applicable"
        if not self.receiver or not self.sender:
            return "unmeasured"
        durable_sources = {item["source"] for item in _kind(self.receiver, "durable")
                           if item["units"] > 0}
        metric = _last(self.sender, "metric") or {}
        backpressured = _sum_end(self.receiver, "backpressured")
        rate_limited = _sum_end(self.receiver, "rate_limited")
        drops = sum(item.get("drops", 0) for item in _kind(self.sender, "end"))
        end = _last(self.receiver, "end") or {}
        self.metrics.update(backpressured=backpressured, rate_limited=rate_limited,
                            sender_drops=drops,
                            cpu_capped=end.get("cpu_quota_us") is not None,
                            agent_cpu_capped=metric.get("cpu_quota_us") is not None)
        healthy = {0, 1, 2, 3} <= durable_sources and backpressured == 0 and rate_limited == 0
        ends = {item.get("source"): item for item in _kind(self.sender, "end")}
        if not ends or not end:
            return "unmeasured"  # no per-source totals: drops cannot be read as 0
        if self.scenario == "capacity_4":
            # "4 sources under a CPU limit": both sides must have run capped,
            # and every source's sender totals must be on record.
            capped = (end.get("cpu_quota_us") is not None
                      and metric.get("cpu_quota_us") is not None)
            all_ends = {0, 1, 2, 3} <= set(ends)
            return _verdict(healthy and all_ends and drops == 0 and capped)
        fifth = ends.get(4)
        if fifth is None:
            return "fail"
        if "rejected_source_capacity" not in fifth:
            return "unmeasured"  # the refusal reason is not on record
        refused = (fifth["accepted"] == 0 and fifth["rejected"] > 0
                   and fifth["rejected_source_capacity"] == fifth["rejected"])
        return _verdict({0, 1, 2, 3} <= durable_sources and 4 not in durable_sources and refused)

    # -- secondary ----------------------------------------------------------
    def secondary(self):
        result = {}
        windows = self._impairment_windows()
        closes = [c for c in _kind(self.sender, "closed") if c["reason"] != "shutdown"]
        unexpected = [c for c in closes
                      if not any(s - SECOND <= c["t_ns"] <= e + 30 * SECOND
                                 for s, e, _ in windows)]
        if self.scenario in ("normal", "soak", "capacity_4"):
            result["unexpected_disconnects"] = len(unexpected)
        proxy_end = _last(self.proxy, "end")
        sender_samples = _kind(self.sender, "sample")
        payload = sum(m.get("payload_bytes", 0) for m in _kind(self.sender, "metric"))
        if proxy_end and payload:
            result["overhead_ratio"] = round(proxy_end["bytes_up"] / payload - 1, 5)
        if sender_samples:
            last = sender_samples[-1]
            first = sender_samples[0]
            wall = (last["t_ns"] - first["t_ns"]) / SECOND
            if wall > 0 and self.n_sources:
                cpu = (last["cpu_seconds"] - first["cpu_seconds"]
                       + last.get("child_cpu_seconds", 0.0)
                       - first.get("child_cpu_seconds", 0.0)) / wall
                result["agent_cpu_per_source"] = round(cpu / self.n_sources, 4)
        for item in _kind(self.sender, "latency"):
            if item["metric"] == "capture":
                result["latency_p95_ns"] = item["p95_ns"]
        return result

    def evaluate(self, *, rss_limit, loss_timeout_ns, single_host):
        single_host = single_host and not self.two_host
        self.gates = {"g1": self.g1(single_host), "g2": self.g2(), "g3": self.g3(rss_limit),
                      "g4": self.g4(single_host), "g5": self.g5(loss_timeout_ns, single_host),
                      "g6": self.g6()}
        self.metrics.update(self.secondary())
        return self


def holder_cpu_rate(paths):
    """Mean CPU cores used by the camera holder (process + pipelines) over its run.

    Live-descendant sampling misses a pipeline that exited between samples, so
    this is a lower bound for restarted pipelines.
    """
    rates = []
    for path in paths:
        samples = _kind(records.read_jsonl(path), "sample")
        if len(samples) >= 2:
            first, last = samples[0], samples[-1]
            wall = (last["t_ns"] - first["t_ns"]) / SECOND
            cpu = (last["cpu_seconds"] - first["cpu_seconds"]
                   + last.get("child_cpu_seconds", 0.0) - first.get("child_cpu_seconds", 0.0))
            if wall > 0:
                rates.append(cpu / wall)
    return sum(rates) if rates else None


def holder_check(paths, summaries):
    """Holder forwarding health over the real-input runs it served.

    ``queue_drops`` (camera frames the holder could not take in time) must be
    0. ``forward_drops`` counts sender disconnects seen by the holder; each
    sender process exit (one per real-input run, plus each ``restart_sender``)
    accounts for at most one, anything beyond that is a forwarding failure.
    """
    if not paths:
        return None
    frames = queue_drops = forward_drops = 0
    for path in paths:
        samples = _kind(records.read_jsonl(path), "sample")
        if not samples:
            return {"holder_verdict": "unmeasured"}
        last = samples[-1]
        frames += last.get("frames") or 0
        queue_drops += last.get("queue_drops") or 0
        forward_drops += last.get("forward_drops") or 0
    real = [s for s in summaries if s.inputs == "real"]
    allowed = len(real) + sum(1 for s in real for a in _kind(s.orchestrator, "action")
                              if a.get("action") == "restart_sender")
    return {"holder_frames": frames, "holder_queue_drops": queue_drops,
            "holder_forward_drops": forward_drops, "holder_forward_drops_allowed": allowed,
            "holder_verdict": _verdict(frames > 0 and queue_drops == 0
                                       and forward_drops <= allowed)}


def _candidate_gate(items, gate):
    """Combine run verdicts; missing required scenarios make it ``unmeasured``."""
    verdict = _combine([s.gates[gate] for s in items])
    missing = REQUIRED_SCENARIOS[gate] - {s.scenario for s in items}
    if missing and verdict != "fail":
        verdict = "unmeasured"
    return verdict, len(missing)


def summarize(directories, *, rss_limit=512 * 1024 * 1024, single_host=True, holder_files=()):
    """Gate report. Runs recorded by ``--role main`` / ``--role agent`` are
    always evaluated as two-host (no cross-host clock comparison)."""
    runs = load_runs(directories)
    holder_rate = holder_cpu_rate(holder_files)
    summaries = []
    for name, roles in sorted(runs.items()):
        summary = RunSummary(name, roles)
        start = _last(summary.sender, "start") or {}
        loss_timeout = start.get("loss_timeout_ns") or 5 * SECOND
        summary.evaluate(rss_limit=rss_limit, loss_timeout_ns=loss_timeout,
                         single_host=single_host)
        if (summary.inputs == "real" and holder_rate is not None and summary.n_sources
                and "agent_cpu_per_source" in summary.metrics):
            summary.metrics["agent_cpu_per_source"] = round(
                summary.metrics["agent_cpu_per_source"] + holder_rate / summary.n_sources, 4)
            summary.metrics["holder_cpu_included"] = True
        summaries.append(summary)
    by_candidate = defaultdict(list)
    for summary in summaries:
        by_candidate[summary.candidate].append(summary)
    report = {"runs": [], "candidates": []}
    for summary in summaries:
        report["runs"].append({"scenario": summary.scenario, "candidate": summary.candidate,
                               "inputs": summary.inputs, **summary.gates, **summary.metrics})
    for candidate, items in sorted(by_candidate.items()):
        gates, missing = {}, {}
        for gate in GATES:
            gates[gate], missing[gate + "_missing_scenarios"] = _candidate_gate(items, gate)
        unprotected = [s.metrics["unprotected_gap_units"] for s in items
                       if "unprotected_gap_units" in s.metrics]
        reconnects = [t for s in items for t in getattr(s, "reconnect_samples", [])]
        soak = [s for s in items if s.scenario == "soak"]
        overhead = [s.metrics["overhead_ratio"] for s in items
                    if s.scenario in ("normal", "capacity_4") and "overhead_ratio" in s.metrics]
        latency = [s.metrics["latency_p95_ns"] for s in items
                   if s.scenario in ("normal", "capacity_4") and s.metrics.get("latency_p95_ns")]
        real = [s for s in items if s.inputs == "real" and s.metrics.get("holder_cpu_included")]
        secondary = {
            "soak": ("unmeasured" if not soak else _verdict(
                all(s.metrics.get("unexpected_disconnects", 1) == 0 for s in soak))),
            "overhead": ("unmeasured" if not overhead else _verdict(max(overhead) <= 0.10)),
            "agent_cpu": ("unmeasured" if any(s.inputs == "real" for s in items) and not real
                          else "not_applicable" if not real else _verdict(
                all(s.metrics["agent_cpu_per_source"] <= 0.5 for s in real))),
            "latency_reference": ("unmeasured" if not latency else _verdict(
                max(latency) <= SECOND)),
            "packet_loss": "unmeasured", "jitter": "unmeasured",
        }
        report["candidates"].append({
            "candidate": candidate, "runs": len(items), **gates, **missing,
            # Durable stand-in gaps in scenarios without a communication loss
            # (e.g. slow_drain backpressure): not protected by the Agent's
            # loss window, so they are listed rather than hidden.
            "unprotected_gap_units": sum(unprotected) if unprotected else None,
            "reconnect_p95_ns": records.percentiles(reconnects)[95],
            "overhead_max": max(overhead) if overhead else None,
            "latency_p95_max_ns": max(latency) if latency else None,
            **{"secondary_" + k: v for k, v in secondary.items()}})
    holder = holder_check(holder_files, summaries)
    if holder is not None:
        report["holder"] = holder
    for row in report["runs"] + report["candidates"] + ([holder] if holder else []):
        records.validate_record(row)
    return report


def _seconds(value):
    return "-" if value is None else f"{value / SECOND:.2f}"


def render(report):
    gates = ("g1", "g2", "g3", "g4", "g5", "g6")
    lines = ["candidate   G1   G2   G3   G4   G5   G6   reconnect_p95_s  overhead  soak"
             "        unprotected_gap_units"]
    for row in report["candidates"]:
        overhead = "-" if row["overhead_max"] is None else f"{row['overhead_max']:.4f}"
        lines.append(f"{row['candidate']:<11} " + " ".join(f"{row[g][:4]:<4}" for g in gates)
                     + f" {_seconds(row['reconnect_p95_ns']):>15}  {overhead:>8}"
                     + f"  {row['secondary_soak']:<11} {row['unprotected_gap_units']}")
        missing = [g for g in gates if row.get(g + "_missing_scenarios")]
        if missing:
            lines.append("  required scenarios missing for: " + ", ".join(missing))
    if "holder" in report:
        holder = report["holder"]
        lines.append(f"holder: {holder['holder_verdict']} (queue_drops "
                     f"{holder.get('holder_queue_drops')}, forward_drops "
                     f"{holder.get('holder_forward_drops')}/"
                     f"{holder.get('holder_forward_drops_allowed')})")
    lines.append("")
    lines.append("scenario            candidate   G1   G2   G3   G4   G5   G6  missing(rep/act)")
    for row in report["runs"]:
        lines.append(f"{row['scenario']:<19} {row['candidate']:<11} "
                     + " ".join(f"{row[g][:4]:<4}" for g in gates)
                     + f"  {row.get('reported_missing')}/{row.get('actual_missing')}")
    return "\n".join(lines)


def write(report, path):
    data = json.dumps(report, indent=1, sort_keys=True, allow_nan=False)
    Path(path).write_text(data + "\n", encoding="ascii")
