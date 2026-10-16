"""Issue #10 S7 (Owner decision D10, D5 defaults): the interim live frame pull.

Synthetic only: software authenticators, synthetic ``/proc/net`` rows, a
temporary SQLite database, the in-process ASGI driver of
``test_human_surface`` and synthetic JPEG-shaped bytes (an SOI marker, an
ASCII filler and an EOI marker; no image of anything). No camera, browser,
proxy or Tailscale is involved, so browser decoding of real camera MJPG
frames remains a manual check (``MANUAL_TEST.md``).
"""

import asyncio
from contextlib import closing
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

from app.auth.human_surface import (
    LIVE_SESSIONS_PATH, LIVE_SOURCES_PATH, SIGN_OUT_PATH, HumanAccessUnavailable, match_route,
)
from app.auth.live_access import BoundLiveAccess
from app.auth.model import Permission
from app.auth.rate_limit import SourceRateLimiter
from app.auth.reservation import DAILY_SECONDS
from app.auth.store import Requirement
from app.cameras.registry import CameraRegistry, SourceHealthState, SourceType
from app.cameras.registry.models import CaptureProfile
from app.media.live.frame_pull import LiveFrameLimits, LiveFrameService, LiveFrameUnavailable
from app.media.live.local_preview import LocalPreviewHub
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.test_human_admin_routes import AdminRouteFixture
from tests.test_human_surface import EXPOSED, call, header, payload, status


JPEG = b"\xff\xd8\xff\xe0" + b"synthetic-not-an-image" + b"\xff\xd9"
OTHER_JPEG = b"\xff\xd8\xff\xdb" + b"synthetic-second-frame" + b"\xff\xd9"


class Monotonic:
    """A monotonic clock that moves only when a test says so."""

    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value


def frame(data):
    return SimpleNamespace(data=data)


def health(source_id, value):
    return SimpleNamespace(source_id=source_id, state=SimpleNamespace(value=value))


class LiveRouteFixture(AdminRouteFixture):
    def setUp(self):
        super().setUp()
        registry = CameraRegistry(self.database, unaudited_writes=True)
        # Five enabled rows (three viewable, one YUYV, one not configured here)
        # exceed the default active limit of 4; this test registry allows them.
        registry.set_active_limit(8)
        mjpg = CaptureProfile(width=1280, height=720, fps=30, pixel_format="MJPG")
        self.sources = [registry.create_source(source_type=SourceType.LOCAL_UVC, name=f"Synthetic camera {name}",
                                               enabled=True, desired_capture_profile=mjpg).id
                        for name in ("A", "B", "C")]
        # Configured and enabled, but captured as YUYV: this interim transport
        # cannot serve it, so it is neither listed nor opened.
        self.yuyv = registry.create_source(
            source_type=SourceType.LOCAL_UVC, name="Synthetic raw camera", enabled=True,
            desired_capture_profile=CaptureProfile(width=640, height=480, fps=30, pixel_format="YUYV")).id
        for source_id in self.sources:
            registry.update_source_health(source_id, health_state=SourceHealthState.ONLINE)
        # Configured but disabled, and enabled but not configured: neither is listed.
        self.disabled = registry.create_source(source_type=SourceType.LOCAL_UVC, name="Synthetic disabled",
                                               enabled=False, desired_capture_profile=mjpg).id
        self.unconfigured = registry.create_source(source_type=SourceType.LOCAL_UVC,
                                                   name="Synthetic elsewhere", enabled=True,
                                                   desired_capture_profile=mjpg).id
        self.hub = LocalPreviewHub((*self.sources, self.disabled, self.yuyv))
        self.monotonic = Monotonic()
        self.live = LiveFrameService(self.hub, self.store, monotonic=self.monotonic,
                                     limits=LiveFrameLimits(sweep_interval_seconds=0.02))
        self.access.attach_live(self.live)
        self.access.live_limiter = SourceRateLimiter(per_source_capacity=1000, global_capacity=None,
                                                     monotonic=self.limit_clock)

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.addAsyncCleanup(self.wait_stopped)

    async def wait_stopped(self):
        await self.stop_serving()
        self.assertFalse(self.live.running)
        await self.until(lambda: self.hub.status.viewers == 0)

    # -- requests ------------------------------------------------------

    async def sources_of(self, cookie):
        return await call(self.surface, "GET", LIVE_SOURCES_PATH, cookie=cookie)

    async def open(self, cookie, csrf, source_id, *, raw=None):
        body = raw if raw is not None else json.dumps({"source_id": str(source_id)}).encode()
        return await call(self.surface, "POST", LIVE_SESSIONS_PATH, cookie=cookie, body=body,
                          headers=[(b"x-csrf-token", csrf.encode())])

    async def opened(self, cookie, csrf, source_id):
        result = await self.open(cookie, csrf, source_id)
        self.assertEqual(status(result), 200)
        return UUID(payload(result)["session_id"])

    async def frame(self, cookie, session_id, after=0, *, query=None, identity=None):
        options = {} if identity is None else {"identity": identity}
        return await call(self.surface, "GET", f"{LIVE_SESSIONS_PATH}/{session_id}/frame", cookie=cookie,
                          query=f"after={after}".encode() if query is None else query, **options)

    async def close(self, cookie, csrf, session_id):
        return await call(self.surface, "POST", f"{LIVE_SESSIONS_PATH}/{session_id}/close", cookie=cookie,
                          headers=[(b"x-csrf-token", csrf.encode())], content_type=None)

    async def viewer(self, permissions=(Permission.LIVE_VIEW,)):
        principal, key, _ = self.enroll(permissions)
        cookie = await self.sign_in(key)
        return principal, cookie, await self.csrf(cookie)

    def tick(self, seconds=1.0):
        self.monotonic.value += seconds

    def live_status(self):
        return self.live.status().result(timeout=10)


class LiveViewTests(LiveRouteFixture):
    def test_routes_are_mounted_with_their_requirements(self):
        session = str(uuid4())
        expected = {
            ("GET", LIVE_SOURCES_PATH): Requirement.LIVE,
            ("POST", LIVE_SESSIONS_PATH): Requirement.LIVE,
            ("GET", f"{LIVE_SESSIONS_PATH}/{session}/frame"): Requirement.LIVE,
            ("POST", f"{LIVE_SESSIONS_PATH}/{session}/close"): Requirement.SESSION,
        }
        for (method, path), requirement in expected.items():
            route = match_route({"method": method, "path": path, "raw_path": path.encode()})
            self.assertIsNotNone(route)
            self.assertIs(route.requirement, requirement)
            self.assertEqual(route.csrf, method == "POST")
        for path in (f"{LIVE_SESSIONS_PATH}/{session.upper()}/frame", f"{LIVE_SESSIONS_PATH}/{session}",
                     f"{LIVE_SESSIONS_PATH}/{session}/frame/", f"{LIVE_SESSIONS_PATH}/{session}/download",
                     f"{LIVE_SOURCES_PATH}/{session}", "/api/live/1"):
            self.assertIsNone(match_route({"method": "GET", "path": path, "raw_path": path.encode()}))

    async def test_live_view_lists_sources_opens_and_pulls_frames(self):
        _, cookie, csrf = await self.viewer()
        listed = await self.sources_of(cookie)
        self.assertEqual(status(listed), 200)
        self.assertEqual(sorted(payload(listed)["sources"], key=lambda item: item["id"]), sorted((
            {"id": str(source_id), "name": f"Synthetic camera {name}", "health": "online"}
            for source_id, name in zip(self.sources, "ABC")), key=lambda item: item["id"]))
        self.assertEqual(set(payload(listed)), {"sources"})
        # No demand yet: a frame offered now is dropped, never retained.
        self.hub.on_frame(self.sources[0], frame(JPEG))
        self.assertEqual(self.hub.status.retained_bytes, 0)
        opened = await self.open(cookie, csrf, self.sources[0])
        self.assertEqual(status(opened), 200)
        body = payload(opened)
        self.assertEqual(set(body), {"session_id", "source_id", "lease_seconds", "frame_interval_ms"})
        self.assertEqual((body["source_id"], body["lease_seconds"], body["frame_interval_ms"]),
                         (str(self.sources[0]), 15.0, 200))
        session_id = UUID(body["session_id"])
        waiting = await self.frame(cookie, session_id)
        self.assertEqual(status(waiting), 204)
        self.assertEqual(waiting[1]["body"], b"")
        self.hub.on_frame(self.sources[0], frame(JPEG))
        served = await self.frame(cookie, session_id)
        self.assertEqual(status(served), 200)
        self.assertEqual(served[1]["body"], JPEG)
        names = [key for key, _ in served[0]["headers"]]
        self.assertEqual(names, [b"content-type", b"content-length", b"cache-control", b"x-content-type-options",
                                 b"cross-origin-resource-policy", b"x-frame-sequence"])
        self.assertEqual(header(served, b"content-type"), [b"image/jpeg"])
        self.assertEqual(header(served, b"cache-control"), [b"no-store"])
        self.assertEqual(header(served, b"x-content-type-options"), [b"nosniff"])
        self.assertEqual(header(served, b"content-disposition"), [])
        sequence = int(header(served, b"x-frame-sequence")[0])
        self.tick()
        self.assertEqual(status(await self.frame(cookie, session_id, sequence)), 204)
        self.hub.on_frame(self.sources[0], frame(OTHER_JPEG))
        self.assertEqual((await self.frame(cookie, session_id, sequence))[1]["body"], OTHER_JPEG)

    async def test_owner_holds_live_implicitly(self):
        session_id = await self.opened(self.owner_cookie, self.owner_csrf, self.sources[0])
        self.hub.on_frame(self.sources[0], frame(JPEG))
        self.assertEqual(status(await self.frame(self.owner_cookie, session_id)), 200)

    async def test_recordings_view_alone_is_refused_everywhere(self):
        expected = await self.denial()
        _, cookie, csrf = await self.viewer((Permission.RECORDINGS_VIEW,))
        _, live_cookie, live_csrf = await self.viewer()
        session_id = await self.opened(live_cookie, live_csrf, self.sources[0])
        self.hub.on_frame(self.sources[0], frame(JPEG))
        self.assertEqual(await self.sources_of(cookie), expected)
        self.assertEqual(await self.open(cookie, csrf, self.sources[0]), expected)
        self.assertEqual(await self.frame(cookie, session_id), expected)
        self.assertEqual(await self.close(cookie, csrf, session_id), expected)
        self.assertEqual(self.live_status().active_sessions, 1)

    async def test_uninvited_and_forged_callers_get_the_generic_denial(self):
        expected = await self.denial()
        _, cookie, csrf = await self.viewer()
        session_id = await self.opened(cookie, csrf, self.sources[0])
        forged = "__Host-session=" + "B" * 43
        self.assertEqual(await self.sources_of(None), expected)
        self.assertEqual(await self.sources_of(forged), expected)
        self.assertEqual(await self.frame(forged, session_id), expected)
        self.assertEqual(await self.frame(None, session_id), expected)
        self.assertEqual(await self.open(forged, csrf, self.sources[1]), expected)

    async def test_unknown_source_malformed_requests_and_missing_csrf_are_refused(self):
        expected = await self.denial()
        _, cookie, csrf = await self.viewer()
        for source_id in (uuid4(), self.unconfigured, self.disabled, self.yuyv):
            self.assertEqual(await self.open(cookie, csrf, source_id), expected)
        for raw in (b"{}", b'{"source_id": 1}', b'{"source_id": "x"}',
                    json.dumps({"source_id": str(self.sources[0]).upper()}).encode(),
                    json.dumps({"source_id": str(self.sources[0]), "extra": 1}).encode(),
                    b'{"source_id": "%s", "source_id": "%s"}' % (str(self.sources[0]).encode(),
                                                                 str(self.sources[0]).encode())):
            self.assertEqual(await self.open(cookie, csrf, None, raw=raw), expected)
        no_csrf = await call(self.surface, "POST", LIVE_SESSIONS_PATH, cookie=cookie,
                             body=json.dumps({"source_id": str(self.sources[0])}).encode())
        self.assertEqual(no_csrf, expected)
        session_id = await self.opened(cookie, csrf, self.sources[0])
        for query in (b"after=-1", b"after=01", b"after=x", b"after=0&after=0", b"other=1",
                      b"after=" + b"9" * 19):
            self.assertEqual(await self.frame(cookie, session_id, query=query), expected)
        self.assertEqual(status(await self.frame(cookie, session_id, query=b"")), 204)
        self.assertEqual(await self.frame(cookie, uuid4()), expected)
        self.assertEqual(await self.close(cookie, csrf, uuid4()), expected)

    async def test_copied_session_id_is_refused_and_the_owner_keeps_watching(self):
        expected = await self.denial()
        _, cookie, csrf = await self.viewer()
        session_id = await self.opened(cookie, csrf, self.sources[0])
        self.hub.on_frame(self.sources[0], frame(JPEG))
        # Another invited live viewer pasting the id into their own browser.
        _, other_cookie, other_csrf = await self.viewer()
        self.assertEqual(await self.frame(other_cookie, session_id), expected)
        self.assertEqual(await self.close(other_cookie, other_csrf, session_id), expected)
        self.assertEqual(status(await self.frame(cookie, session_id)), 200)
        self.assertEqual(self.live_status().active_sessions, 1)

    async def test_copied_session_id_of_the_same_person_in_another_session_is_refused(self):
        expected = await self.denial()
        _, key, _ = self.enroll((Permission.LIVE_VIEW,))
        cookie = await self.sign_in(key)
        csrf = await self.csrf(cookie)
        session_id = await self.opened(cookie, csrf, self.sources[0])
        second = await self.sign_in(key)
        self.assertEqual(await self.frame(second, session_id), expected)
        self.assertEqual(status(await self.frame(cookie, session_id)), 204)

    async def test_a_session_bound_to_another_proxy_identity_is_refused(self):
        expected = await self.denial()
        _, cookie, csrf = await self.viewer()
        session_id = await self.opened(cookie, csrf, self.sources[0])
        self.assertEqual(await self.frame(cookie, session_id, identity="synthetic-other@example.invalid"),
                         expected)
        self.assertEqual(status(await self.frame(cookie, session_id)), 204)


class RevocationTests(LiveRouteFixture):
    async def test_owner_revocation_of_the_person_releases_demand_at_once(self):
        expected = await self.denial()
        session_id = await self.opened(self.target_cookie, self.target_csrf, self.sources[0])
        self.hub.on_frame(self.sources[0], frame(JPEG))
        self.assertEqual(self.hub.status.viewers, 1)
        revoked = await self.admin("POST", f"/api/admin/principals/{self.target.id}/revoke", {})
        self.assertEqual(status(revoked), 204)
        await self.until(lambda: self.hub.status.viewers == 0)
        self.assertEqual(self.hub.status.retained_bytes, 0)
        self.assertEqual(await self.frame(self.target_cookie, session_id), expected)

    async def test_withdrawing_live_view_releases_demand_at_once(self):
        session_id = await self.opened(self.target_cookie, self.target_csrf, self.sources[0])
        withdrawn = await self.admin("POST", f"/api/admin/principals/{self.target.id}/permissions",
                                     {"permission": "live:view", "granted": False})
        self.assertEqual(status(withdrawn), 204)
        await self.until(lambda: self.hub.status.viewers == 0)
        self.assertEqual(await self.frame(self.target_cookie, session_id), await self.denial())

    async def test_unrelated_grant_change_keeps_other_principals_watching(self):
        _, cookie, csrf = await self.viewer()
        session_id = await self.opened(cookie, csrf, self.sources[0])
        changed = await self.admin("POST", f"/api/admin/principals/{self.target.id}/permissions",
                                   {"permission": "recordings:view", "granted": True})
        self.assertEqual(status(changed), 204)
        await asyncio.wrap_future(self.live.status())
        self.assertEqual(status(await self.frame(cookie, session_id)), 204)

    async def test_credential_revocation_releases_its_live_sessions(self):
        session_id = await self.opened(self.target_cookie, self.target_csrf, self.sources[0])
        handle = self.handle(self.target.id)
        revoked = await self.admin(
            "POST", f"/api/admin/principals/{self.target.id}/credentials/{handle}/revoke", {})
        self.assertEqual(status(revoked), 204)
        await self.until(lambda: self.hub.status.viewers == 0)
        self.assertEqual(await self.frame(self.target_cookie, session_id), await self.denial())

    async def test_revocation_outside_the_surface_is_caught_by_the_next_poll(self):
        # The local CLI commits outside this process' observer.
        session_id = await self.opened(self.target_cookie, self.target_csrf, self.sources[0])
        self.store.revoke_principal(self.target.id)
        self.assertEqual(self.hub.status.viewers, 1)
        self.assertEqual(await self.frame(self.target_cookie, session_id), await self.denial())
        self.assertEqual(self.hub.status.viewers, 0)
        self.assertEqual(self.live_status().active_sessions, 0)

    async def test_sign_out_releases_the_sessions_live_sessions(self):
        await self.opened(self.target_cookie, self.target_csrf, self.sources[0])
        signed_out = await call(self.surface, "POST", SIGN_OUT_PATH, cookie=self.target_cookie,
                                headers=[(b"x-csrf-token", self.target_csrf.encode())], content_type=None)
        self.assertEqual(status(signed_out), 204)
        await self.until(lambda: self.hub.status.viewers == 0)

    async def test_close_releases_and_a_second_close_is_refused(self):
        session_id = await self.opened(self.target_cookie, self.target_csrf, self.sources[0])
        self.hub.on_frame(self.sources[0], frame(JPEG))
        self.assertGreater(self.hub.status.retained_bytes, 0)
        self.assertEqual(status(await self.close(self.target_cookie, self.target_csrf, session_id)), 204)
        self.assertEqual((self.hub.status.viewers, self.hub.status.retained_bytes), (0, 0))
        expected = await self.denial()
        self.assertEqual(await self.close(self.target_cookie, self.target_csrf, session_id), expected)
        self.assertEqual(await self.frame(self.target_cookie, session_id), expected)


class LimitTests(LiveRouteFixture):
    async def test_d10_limits_total_per_source_and_per_principal(self):
        expected = await self.denial()
        viewers = [await self.viewer() for _ in range(3)]
        (_, a, a_csrf), (_, b, b_csrf), (_, c, c_csrf) = viewers
        await self.opened(a, a_csrf, self.sources[0])
        await self.opened(b, b_csrf, self.sources[0])
        # Two per source.
        self.assertEqual(await self.open(c, c_csrf, self.sources[0]), expected)
        await self.opened(a, a_csrf, self.sources[1])
        # Two per principal.
        self.assertEqual(await self.open(a, a_csrf, self.sources[2]), expected)
        await self.opened(b, b_csrf, self.sources[1])
        # Four in total.
        self.assertEqual(await self.open(c, c_csrf, self.sources[2]), expected)
        self.assertEqual((self.live_status().active_sessions, self.hub.status.viewers), (4, 4))

    async def test_frames_are_paced_to_five_per_second(self):
        _, cookie, csrf = await self.viewer()
        session_id = await self.opened(cookie, csrf, self.sources[0])
        self.hub.on_frame(self.sources[0], frame(JPEG))
        self.assertEqual(status(await self.frame(cookie, session_id)), 200)
        self.hub.on_frame(self.sources[0], frame(OTHER_JPEG))
        self.tick(0.15)
        self.assertEqual(status(await self.frame(cookie, session_id)), 204)
        self.tick(0.15)
        self.assertEqual(status(await self.frame(cookie, session_id)), 200)

    async def test_a_tight_poll_loop_is_refused_before_any_sqlite_read(self):
        _, cookie, csrf = await self.viewer()
        session_id = await self.opened(cookie, csrf, self.sources[0])
        expected = await self.denial()
        for _ in range(self.live.limits.poll_burst):
            self.assertEqual(status(await self.frame(cookie, session_id)), 204)
        with patch.object(self.store, "current_session", side_effect=AssertionError("must not read")):
            self.assertEqual(await self.frame(cookie, session_id), expected)
        # The budget refills with the limiter's (here: the service's) clock.
        self.tick(1.0)
        self.assertEqual(status(await self.frame(cookie, session_id)), 204)

    async def test_open_and_close_are_rate_limited_per_session(self):
        self.access.live_limiter = SourceRateLimiter(per_source_capacity=2, per_source_refill_seconds=6.0,
                                                     global_capacity=None, monotonic=self.limit_clock)
        _, cookie, csrf = await self.viewer()
        session_id = await self.opened(cookie, csrf, self.sources[0])
        self.assertEqual(status(await self.close(cookie, csrf, session_id)), 204)
        writes = self.admission.admitted
        self.assertEqual(await self.open(cookie, csrf, self.sources[0]), await self.denial())
        self.assertEqual(self.admission.admitted, writes)

    async def test_non_jpeg_and_oversized_frames_are_never_served(self):
        _, cookie, csrf = await self.viewer()
        session_id = await self.opened(cookie, csrf, self.sources[0])
        self.hub.on_frame(self.sources[0], frame(b"synthetic raw YUYV bytes"))
        self.assertEqual(status(await self.frame(cookie, session_id)), 204)
        self.tick()
        self.hub.on_frame(self.sources[0], frame(JPEG[:3] + b"x" * self.live.limits.maximum_frame_bytes))
        self.assertEqual(status(await self.frame(cookie, session_id)), 204)
        self.assertEqual(self.live_status().unservable_frames, 2)

    async def test_no_per_frame_writes_and_a_rate_limited_idle_extension(self):
        _, cookie, csrf = await self.viewer()
        session_id = await self.opened(cookie, csrf, self.sources[0])
        times = self.session_times(cookie)
        writes = self.admission.admitted
        for index in range(60):
            self.hub.on_frame(self.sources[0], frame(JPEG))
            self.tick(0.25)
            self.assertEqual(status(await self.frame(cookie, session_id, index)), 200)
        # Fifteen seconds of watching at 4 fps: not one storage-admitted write.
        self.assertEqual(self.admission.admitted, writes)
        self.assertEqual(self.session_times(cookie), times)
        self.tick(60)
        self.ceremony_clock.advance(seconds=75)
        self.assertEqual(status(await self.frame(cookie, session_id, 1000)), 204)
        self.assertEqual(self.admission.admitted, writes + 1)
        self.assertNotEqual(self.session_times(cookie), times)
        self.tick(1)
        self.assertEqual(status(await self.frame(cookie, session_id, 1000)), 204)
        self.assertEqual(self.admission.admitted, writes + 1)

    def session_times(self, cookie):
        digest = hashlib.sha256(self.token(cookie)).digest()
        with closing(self.database.connect()) as connection:
            return tuple(connection.execute(
                "SELECT last_seen_at_us, idle_expires_at_us FROM access_sessions WHERE token_digest=?",
                (digest,)).fetchone())


class RetentionAndHealthTests(LiveRouteFixture):
    async def test_a_lease_without_polls_releases_demand_and_retains_nothing(self):
        _, cookie, csrf = await self.viewer()
        session_id = await self.opened(cookie, csrf, self.sources[0])
        self.hub.on_frame(self.sources[0], frame(JPEG))
        self.assertGreater(self.hub.status.retained_bytes, 0)
        self.tick(10)
        self.assertEqual(status(await self.frame(cookie, session_id)), 200)
        self.tick(14)
        await asyncio.sleep(0.1)
        self.assertEqual(self.hub.status.viewers, 1)
        self.tick(2)
        await self.until(lambda: self.hub.status.viewers == 0)
        self.assertEqual(self.hub.status.retained_bytes, 0)
        self.hub.on_frame(self.sources[0], frame(JPEG))
        self.assertEqual(self.hub.status.retained_bytes, 0)
        self.assertEqual(await self.frame(cookie, session_id), await self.denial())
        self.assertEqual(self.live_status().lease_expiries, 1)

    async def test_refused_polls_never_renew_the_lease(self):
        _, cookie, csrf = await self.viewer()
        session_id = await self.opened(cookie, csrf, self.sources[0])
        _, other, _ = await self.viewer()
        for _ in range(4):
            self.tick(5)
            await self.frame(other, session_id)
        await self.until(lambda: self.hub.status.viewers == 0)

    async def test_offline_camera_drops_the_frame_and_reports_offline(self):
        _, cookie, csrf = await self.viewer()
        session_id = await self.opened(cookie, csrf, self.sources[0])
        self.hub.on_frame(self.sources[0], frame(JPEG))
        self.hub.on_health(health(self.sources[0], "offline"))
        self.assertEqual(self.hub.status.retained_bytes, 0)
        self.assertEqual(status(await self.frame(cookie, session_id)), 204)
        self.hub.on_frame(self.sources[0], frame(JPEG))
        self.assertEqual(status(await self.frame(cookie, session_id)), 204)
        listed = {item["id"]: item["health"] for item in payload(await self.sources_of(cookie))["sources"]}
        self.assertEqual(listed[str(self.sources[0])], "offline")
        self.hub.on_health(health(self.sources[0], "online"))
        self.hub.on_frame(self.sources[0], frame(JPEG))
        self.tick()
        self.assertEqual(status(await self.frame(cookie, session_id)), 200)

    async def test_a_closed_gate_refuses_and_ends_every_live_session(self):
        _, cookie, csrf = await self.viewer()
        session_id = await self.opened(cookie, csrf, self.sources[0])
        self.hub.on_frame(self.sources[0], frame(JPEG))
        expected = await self.denial()
        self.files.files["tcp"] = EXPOSED
        self.clock.value += DAILY_SECONDS
        self.assertFalse(self.check.tick().open)
        self.assertEqual(await self.frame(cookie, session_id), expected)
        await self.until(lambda: self.hub.status.viewers == 0)
        self.assertEqual(self.hub.status.retained_bytes, 0)

    async def test_an_epoch_change_during_the_poll_is_refused(self):
        _, cookie, csrf = await self.viewer()
        session_id = await self.opened(cookie, csrf, self.sources[0])
        self.hub.on_frame(self.sources[0], frame(JPEG))
        real = self.access.epoch
        with patch.object(self.access, "epoch", side_effect=lambda: (real() or 0) + 1):
            self.assertEqual(await self.frame(cookie, session_id), await self.denial())

    async def test_stopping_the_composition_ends_live_sessions(self):
        _, cookie, csrf = await self.viewer()
        await self.opened(cookie, csrf, self.sources[0])
        await self.stop_serving()
        await self.until(lambda: self.hub.status.viewers == 0)
        self.assertFalse(self.live.running)


class ServiceTests(unittest.TestCase):
    def test_limits_are_validated(self):
        for changes in ({"maximum_total_viewers": 0}, {"maximum_viewers_per_source": 5},
                        {"maximum_viewers_per_principal": 5}, {"lease_seconds": 0},
                        {"lease_seconds": float("nan")}, {"minimum_frame_interval_seconds": True},
                        {"sweep_interval_seconds": 20}, {"maximum_frame_bytes": 65 * 1024 * 1024}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                LiveFrameLimits(**changes)
        defaults = LiveFrameLimits()
        self.assertEqual((defaults.maximum_total_viewers, defaults.maximum_viewers_per_source,
                          defaults.maximum_viewers_per_principal, defaults.lease_seconds,
                          defaults.minimum_frame_interval_seconds, defaults.idle_extension_interval_seconds),
                         (4, 2, 2, 15.0, 0.2, 60.0))

    def test_a_stopped_service_refuses_and_releases(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        database = Database(Path(temporary.name) / "synthetic.sqlite3")
        with closing(database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        source = CameraRegistry(database, unaudited_writes=True).create_source(
            source_type=SourceType.LOCAL_UVC, name="Synthetic camera", enabled=True,
            desired_capture_profile=CaptureProfile(width=640, height=480, fps=30, pixel_format="MJPG")).id
        hub = LocalPreviewHub((source,))
        store = SimpleNamespace(current_session=lambda *a, **k: None, now=lambda: None, database=database)
        service = LiveFrameService(hub, store, validator=lambda access, source_id: True)
        with self.assertRaises(LiveFrameUnavailable):
            service.status()
        service.start()
        access = BoundLiveAccess(uuid4(), 1, uuid4())
        token = bytes(32)
        session = service.open(access, source, token, admit=_null).result(timeout=10)
        self.assertEqual(hub.status.viewers, 1)
        self.assertTrue(service.holds(token, session.session_id))
        self.assertFalse(service.holds(bytes([1]) * 32, session.session_id))
        service.stop(wait=True)
        self.assertEqual(hub.status.viewers, 0)
        self.assertFalse(service.holds(token, session.session_id))
        with self.assertRaises(LiveFrameUnavailable):
            service.open(access, source, token, admit=_null)
        # A restart serves again, with nothing left over.
        service.start()
        self.addCleanup(service.stop, wait=True)
        self.assertEqual(service.status().result(timeout=10).active_sessions, 0)

    def test_construction_requires_a_hub_and_an_access_store(self):
        with self.assertRaises(ValueError):
            LiveFrameService(object(), None)
        with self.assertRaises(ValueError):
            LiveFrameService(LocalPreviewHub(()), None)


class _Null:
    def __enter__(self):
        return None

    def __exit__(self, *exc):
        return False


def _null():
    return _Null()


class AttachTests(LiveRouteFixture):
    async def test_attach_refuses_another_database_and_replacement_while_running(self):
        other = Database(self.temporary / "other.sqlite3")
        foreign = LiveFrameService(self.hub, SimpleNamespace(
            current_session=self.store.current_session, now=self.store.now, database=other))
        with self.assertRaises(HumanAccessUnavailable):
            self.access.attach_live(foreign)
        with self.assertRaises(HumanAccessUnavailable):
            self.access.attach_live(object())
        self.assertIs(self.access.live, self.live)
        self.assertEqual(self.access.administration.principal_changed, self.live.revalidate_principal)
        _, cookie, csrf = await self.viewer()
        await self.opened(cookie, csrf, self.sources[0])
        replacement = LiveFrameService(self.hub, self.store, monotonic=self.monotonic)
        # Two services over one hub could exceed the D10 limits: refused while running.
        with self.assertRaises(HumanAccessUnavailable):
            self.access.attach_live(replacement)
        self.assertIs(self.access.live, self.live)
        self.assertEqual(self.hub.status.viewers, 1)
        await self.stop_serving()
        # Not running: the previous service has released everything first.
        self.access.attach_live(replacement)
        self.assertEqual(self.hub.status.viewers, 0)
        self.assertIs(self.access.live, replacement)
        self.live = replacement

    async def test_the_first_service_attached_while_running_starts_at_once(self):
        self.access.live = None
        self.live.stop(wait=True)
        service = LiveFrameService(self.hub, self.store, monotonic=self.monotonic)
        self.access.attach_live(service)
        self.live = service
        self.assertTrue(service.running)
        _, cookie, csrf = await self.viewer()
        await self.opened(cookie, csrf, self.sources[0])

if __name__ == "__main__":
    unittest.main()
