"""Synthetic local UVC preview wiring with server-side ``live:view`` enforcement.

There is no route: these tests drive the session layer directly and check that
authorization is decided from current server-side grants on every open and
read. Frames are fixed synthetic byte strings from an in-memory capture.
"""

from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from app.audit import AuditStore
from app.auth.live_access import live_view_validator
from app.auth.model import Permission
from app.auth.store import AccessStore
from app.cameras.uvc.capture import VideoFrame
from app.media.live import (
    AuthorizedLocalPreview, LiveAccess, LiveSessionLimits, LiveSessionUnavailable,
    LocalPreviewHub,
)
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS
from tests.test_uvc_runtime import PermitOwner, RuntimeFixture, wait_for
from app.audit import OwnerAuditService
from app.audit.integration import OwnerAdministration
from app.cameras.registry import SourceHealthState


NOW = datetime(2026, 9, 29, tzinfo=timezone.utc)
LIMITS = LiveSessionLimits(maximum_total_viewers=4, maximum_viewers_per_source=2)


def frame(data=b"synthetic-frame"):
    return VideoFrame(data, 0, 1.0)


class AccessFixture:
    def __init__(self, database):
        self.store = AccessStore(database, clock=lambda: NOW,
                                 audit=AuditStore(database, clock=lambda: NOW),
                                 unaudited_writes=True)
        self._next = 0

    def principal(self, permissions):
        self._next += 1
        identity = f"viewer-{self._next}@example.invalid"
        secret = bytes([self._next]) * 32
        principal = self.store.invite(identity, "Synthetic viewer", permissions)
        self.store.issue_enrollment(principal.id, secret, NOW + timedelta(minutes=5))
        self.store.enroll_credential(secret, identity, f"credential-{self._next}".encode(),
                                     b"synthetic-public-key", -7, 0)
        return self.access(principal.id)

    def access(self, principal_id):
        with closing(self.store.database.connect()) as connection:
            revision = connection.execute(
                "SELECT authorization_revision FROM access_principals WHERE id=?",
                (str(principal_id),),
            ).fetchone()[0]
        return LiveAccess(principal_id, revision)


class PreviewHubTests(unittest.TestCase):
    def test_zero_viewers_retain_nothing_and_frames_are_bounded(self):
        source = uuid4()
        hub = LocalPreviewHub((source,), max_frame_bytes=16)
        hub.on_frame(source, frame())
        self.assertEqual(0, hub.status.retained_bytes)
        preview = hub.source(source)
        viewer = uuid4()
        preview.add_viewer(viewer)
        hub.on_frame(source, frame())
        self.assertEqual(1, hub.latest(source).sequence)
        hub.on_frame(source, frame(b"x" * 17))
        self.assertEqual(1, hub.status.oversized_frames)
        self.assertEqual(1, hub.latest(source).sequence)
        self.assertIsNone(hub.latest(source, after_sequence=1))
        hub.on_frame(source, object())
        hub.on_frame(uuid4(), frame())
        hub.on_frame("not-a-uuid", frame())
        self.assertEqual(1, hub.status.invalid_frames)
        self.assertTrue(preview.remove_viewer(viewer))
        self.assertEqual(0, hub.status.retained_bytes)
        with self.assertRaises(LiveSessionUnavailable):
            hub.source(uuid4())
        with self.assertRaises(ValueError):
            LocalPreviewHub((source,), max_frame_bytes=0)


class LiveViewEnforcementTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Database(Path(temporary.name) / "access.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.access = AccessFixture(self.database)
        self.source = uuid4()
        self.hub = LocalPreviewHub((self.source,))
        self.preview = AuthorizedLocalPreview(self.hub, LIMITS,
                                              live_view_validator(self.database))

    def test_recordings_view_alone_cannot_open_live_preview(self):
        recorder = self.access.principal((Permission.RECORDINGS_VIEW,))
        with self.assertRaises(LiveSessionUnavailable):
            self.preview.open(recorder, self.source)
        self.assertEqual(0, self.hub.status.viewers)
        self.hub.on_frame(self.source, frame())
        self.assertEqual(0, self.hub.status.retained_bytes)

    def test_live_view_reads_frames_until_grant_is_removed(self):
        viewer = self.access.principal((Permission.LIVE_VIEW,))
        session = self.preview.open(viewer, self.source)
        self.hub.on_frame(self.source, frame())
        delivered = self.preview.read(viewer, session.session_id)
        self.assertEqual(b"synthetic-frame", delivered.data)
        self.assertIsNone(self.preview.read(viewer, session.session_id,
                                            after_sequence=delivered.sequence))

        # Grant change advances the revision; the old session fails closed and
        # its viewer demand (and retained frame) is released.
        self.access.store.set_permissions(viewer.principal_id, (Permission.RECORDINGS_VIEW,))
        with self.assertRaises(LiveSessionUnavailable):
            self.preview.read(viewer, session.session_id)
        self.assertEqual(0, self.hub.status.viewers)
        self.assertEqual(0, self.hub.status.retained_bytes)
        current = self.access.access(viewer.principal_id)
        with self.assertRaises(LiveSessionUnavailable):
            self.preview.open(current, self.source)

    def test_revoked_stale_forged_and_copied_access_are_refused(self):
        viewer = self.access.principal((Permission.LIVE_VIEW,))
        other = self.access.principal((Permission.LIVE_VIEW,))
        session = self.preview.open(viewer, self.source)
        # A copied session identifier is not enough for another principal.
        with self.assertRaises(LiveSessionUnavailable):
            self.preview.read(other, session.session_id)
        stale = LiveAccess(viewer.principal_id, viewer.authorization_revision + 1)
        with self.assertRaises(LiveSessionUnavailable):
            self.preview.open(stale, self.source)
        with self.assertRaises(LiveSessionUnavailable):
            self.preview.open(LiveAccess(uuid4(), 0), self.source)
        with self.assertRaises(LiveSessionUnavailable):
            self.preview.open(viewer, uuid4())
        self.access.store.revoke_principal(viewer.principal_id)
        with self.assertRaises(LiveSessionUnavailable):
            self.preview.read(viewer, session.session_id)
        self.assertEqual(0, self.preview.sessions.status.active_viewers)

    def test_owner_has_live_view_and_storage_errors_deny(self):
        owner = self.access.store.bootstrap_owner("owner@example.invalid", "Synthetic owner")
        access = LiveAccess(owner.id, owner.authorization_revision)
        session = self.preview.open(access, self.source)
        self.preview.close(access, session.session_id)
        self.assertEqual(0, self.hub.status.viewers)
        broken = AuthorizedLocalPreview(
            self.hub, LIMITS, live_view_validator(Database(Path("/nonexistent/x.sqlite3"))),
        )
        with self.assertRaises(LiveSessionUnavailable):
            broken.open(access, self.source)
        with self.assertRaises(ValueError):
            live_view_validator(object())


class RuntimePreviewTests(RuntimeFixture):
    """UVC worker frames reach an authorized viewer, and only that viewer."""

    def test_uvc_frames_flow_to_authorized_session_only(self):
        source = self.source()
        hub = LocalPreviewHub((source.id,))
        self.on_frame = hub.on_frame
        runtime = self.runtime(source.id)
        runtime.start()
        admin = OwnerAdministration(
            OwnerAuditService(AuditStore(self.database), PermitOwner()), self.registry,
        )
        runtime.reapprove(admin, "synthetic-owner", source.id, self.camera)
        self.assertTrue(self.wait_health(source.id, SourceHealthState.ONLINE))
        # Capture runs, but nothing is retained without authorized demand.
        self.assertEqual(0, hub.status.retained_bytes)

        access = AccessFixture(self.database)
        preview = AuthorizedLocalPreview(hub, LIMITS, live_view_validator(self.database))
        recorder = access.principal((Permission.RECORDINGS_VIEW,))
        with self.assertRaises(LiveSessionUnavailable):
            preview.open(recorder, source.id)
        viewer = access.principal((Permission.LIVE_VIEW,))
        session = preview.open(viewer, source.id)
        self.assertTrue(wait_for(lambda: preview.read(viewer, session.session_id) is not None))
        self.assertEqual(b"synthetic-frame", preview.read(viewer, session.session_id).data)
        first = preview.read(viewer, session.session_id).sequence
        self.assertTrue(wait_for(
            lambda: preview.read(viewer, session.session_id, first) is not None))
        preview.close(viewer, session.session_id)
        self.assertEqual(0, hub.status.retained_bytes)
        runtime.stop()


if __name__ == "__main__":
    unittest.main()
