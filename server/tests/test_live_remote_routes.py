"""Issue #14 (Owner decision 2026-11-12, option A): remote sources in the live view.

A ``remote_agent`` source's newest live frame (``RemotePreviewHub``, written
by the capture ingest listener) is listed and served through the same S7
frame pull, live sessions and ``live:view`` checks as a local source.
Synthetic only: the fixtures of ``test_live_frame_routes`` and JPEG-shaped
bytes; frames are published to the hub directly, as the listener would
(its own path is ``test_capture_ingest_live``).
"""

import asyncio
import logging
import socket
import ssl
from uuid import uuid4

from app.auth.human_surface import HumanAccess, HumanAccessConfiguration
from app.auth.model import Permission
from app.auth.passkeys import PasskeyCeremonies
from app.cameras.registry.models import NodeHealthState
from app.cameras.remote_agent.ingest_config import (
    CaptureIngestLimits, CaptureIngestMaterial, IngestListenerConfig,
)
from app.cameras.remote_agent.live_frames import RegistryLiveSources
from app.main import create_app
from app.media.live.frame_pull import LiveFrameLimits, LiveFrameService
from app.media.live.remote_preview import RemotePreviewHub

from tests.test_capture_ingest_live import add_remote
from tests.test_hostname_reservation import checker
from tests.test_human_surface import HumanSurfaceFixture, header, payload, status
from tests.test_live_frame_routes import JPEG, OTHER_JPEG, LiveRouteFixture


class RemoteLiveFixture(LiveRouteFixture):
    def setUp(self):
        super().setUp()
        self.node = uuid4()
        self.remote_source = add_remote(self.database, self.node, name="Synthetic remote camera")
        self.remote = RemotePreviewHub(monotonic=self.monotonic)
        # The node's ingest session (generation 1), as the listener opens it.
        self.remote.open_node(self.node, 1)
        self.live = LiveFrameService(self.hub, self.store, monotonic=self.monotonic,
                                     limits=LiveFrameLimits(sweep_interval_seconds=0.02),
                                     remote=self.remote)
        self.access.attach_live(self.live)

    def publish(self, data=JPEG):
        return self.remote.publish(self.node, 1, self.remote_source, data)

    async def listed(self, cookie):
        result = await self.sources_of(cookie)
        self.assertEqual(status(result), 200)
        return {item["id"]: item for item in payload(result)["sources"]}


class RemoteLiveTests(RemoteLiveFixture):
    async def test_a_remote_source_is_listed_with_its_live_state(self):
        _, cookie, _ = await self.viewer()
        listed = await self.listed(cookie)
        # Local sources are listed as before, and the remote one beside them.
        self.assertEqual(set(listed), {*(str(source) for source in self.sources), str(self.remote_source)})
        self.assertEqual(listed[str(self.remote_source)],
                         {"id": str(self.remote_source), "name": "Synthetic remote camera",
                          "health": "offline"})
        self.publish()
        self.assertEqual((await self.listed(cookie))[str(self.remote_source)]["health"], "online")
        # No frame for longer than the freshness bound: not live any more.
        self.tick(5.5)
        self.assertEqual((await self.listed(cookie))[str(self.remote_source)]["health"], "offline")

    async def test_a_remote_source_is_opened_and_pulled_like_a_local_one(self):
        _, cookie, csrf = await self.viewer()
        # No demand yet: a frame published now is not retained.
        self.publish()
        self.assertEqual(self.remote.status.retained_bytes, 0)
        session_id = await self.opened(cookie, csrf, self.remote_source)
        self.assertEqual(status(await self.frame(cookie, session_id)), 204)
        self.publish()
        served = await self.frame(cookie, session_id)
        self.assertEqual(status(served), 200)
        self.assertEqual(served[1]["body"], JPEG)
        self.assertEqual(header(served, b"content-type"), [b"image/jpeg"])
        self.assertEqual(header(served, b"cache-control"), [b"no-store"])
        self.assertEqual(header(served, b"content-disposition"), [])
        sequence = int(header(served, b"x-frame-sequence")[0])
        self.tick()
        self.assertEqual(status(await self.frame(cookie, session_id, sequence)), 204)
        self.publish(OTHER_JPEG)
        self.assertEqual((await self.frame(cookie, session_id, sequence))[1]["body"], OTHER_JPEG)
        # A frame older than the freshness bound is never served as live.
        self.publish(JPEG)
        self.tick(5.5)
        self.assertEqual(status(await self.frame(cookie, session_id, sequence + 1)), 204)

    async def test_an_ended_ingest_session_stops_the_live_frames(self):
        _, cookie, csrf = await self.viewer()
        session_id = await self.opened(cookie, csrf, self.remote_source)
        self.publish()
        self.remote.close_node(self.node, 1)
        self.assertEqual(status(await self.frame(cookie, session_id)), 204)
        self.assertEqual((await self.listed(cookie))[str(self.remote_source)]["health"], "offline")

    async def test_recordings_view_alone_is_refused_for_a_remote_source(self):
        expected = await self.denial()
        _, cookie, csrf = await self.viewer((Permission.RECORDINGS_VIEW,))
        _, live_cookie, live_csrf = await self.viewer()
        session_id = await self.opened(live_cookie, live_csrf, self.remote_source)
        self.publish()
        self.assertEqual(await self.sources_of(cookie), expected)
        self.assertEqual(await self.open(cookie, csrf, self.remote_source), expected)
        self.assertEqual(await self.frame(cookie, session_id), expected)

    async def test_withdrawing_live_view_ends_a_remote_live_session(self):
        session_id = await self.opened(self.target_cookie, self.target_csrf, self.remote_source)
        self.publish()
        self.assertEqual(self.remote.status.viewers, 1)
        withdrawn = await self.admin("POST", f"/api/admin/principals/{self.target.id}/permissions",
                                     {"permission": "live:view", "granted": False})
        self.assertEqual(status(withdrawn), 204)
        await self.until(lambda: self.remote.status.viewers == 0)
        self.assertEqual(self.remote.status.retained_bytes, 0)
        self.assertEqual(await self.frame(self.target_cookie, session_id), await self.denial())

    async def test_a_lease_without_polls_releases_the_remote_frame(self):
        _, cookie, csrf = await self.viewer()
        await self.opened(cookie, csrf, self.remote_source)
        self.publish()
        self.assertGreater(self.remote.status.retained_bytes, 0)
        self.tick(16)
        await self.until(lambda: self.remote.status.viewers == 0)
        self.assertEqual(self.remote.status.retained_bytes, 0)
        self.publish()
        self.assertEqual(self.remote.status.retained_bytes, 0)

    async def test_disabled_and_unknown_sources_are_not_offered(self):
        expected = await self.denial()
        _, cookie, csrf = await self.viewer()
        self.registry.update_source(self.remote_source, enabled=False)
        self.assertNotIn(str(self.remote_source), await self.listed(cookie))
        self.assertEqual(await self.open(cookie, csrf, self.remote_source), expected)
        self.assertEqual(await self.open(cookie, csrf, uuid4()), expected)
        self.assertEqual(self.remote.status.viewers, 0)

    def test_without_a_remote_hub_remote_sources_are_not_offered(self):
        live = LiveFrameService(self.hub, self.store)
        listed = {view.source_id for view in live._viewable()}
        self.assertEqual(listed, set(self.sources))
        self.assertIn(self.remote_source, {view.source_id for view in self.live._viewable()})

    def test_a_revoked_registry_node_never_shows_its_source_online(self):
        # The listener refuses its frames (`RegistryLiveSources`); here the
        # hub has none, so the source is listed offline.
        other = uuid4()
        source = add_remote(self.database, other, node_state=NodeHealthState.REVOKED)
        views = {view.source_id: view.health for view in self.live._viewable()}
        self.assertEqual(views[source], "offline")

    async def test_a_remote_source_never_takes_a_local_hub_slot(self):
        _, cookie, csrf = await self.viewer()
        await self.opened(cookie, csrf, self.remote_source)
        self.assertEqual(self.hub.status.viewers, 0)
        self.assertEqual(self.remote.status.viewers, 1)
        await asyncio.sleep(0)


class ApplicationWiringTests(HumanSurfaceFixture):
    """`create_app` shares one remote hub between the listener and the frame pull."""

    def composition(self):
        check, _, _, _ = checker(clock=self.clock, session_revoker=self.revoker)
        ceremonies = PasskeyCeremonies(self.store, self.rp, session_gate=check, clock=self.ceremony_clock)
        return HumanAccess(HumanAccessConfiguration(enabled=True), assets=self.assets, store=self.store,
                           ceremonies=ceremonies, reservation=check, tick_seconds=0.01)

    @staticmethod
    def material():
        # Never handshaken here: only its shape is checked.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        with socket.create_server(("127.0.0.1", 0)) as probe:
            port = probe.getsockname()[1]
        return CaptureIngestMaterial(IngestListenerConfig("127.0.0.1", port, "127.0.0.1", 8000),
                                     CaptureIngestLimits(), context, uuid4())

    async def test_one_hub_reaches_the_listener_and_the_frame_pull(self):
        access = self.composition()
        application = create_app(self.settings(), database=self.database, human_access=access,
                                 storage_reservation=self.admission, capture_ingest=self.material())
        self.assertIsInstance(access.live.remote, RemotePreviewHub)
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        async with application.router.lifespan_context(application):
            for _ in range(500):
                if application.state.capture_ingest_state == "running":
                    break
                await asyncio.sleep(0.01)
            server = application.state.capture_ingest
            self.assertIs(server.live_preview, access.live.remote)
            self.assertIsInstance(server._live_sources, RegistryLiveSources)

    def test_without_capture_ingest_there_is_no_remote_hub(self):
        access = self.composition()
        create_app(self.settings(), database=self.database, human_access=access,
                   storage_reservation=self.admission)
        self.assertIsNone(access.live.remote)
