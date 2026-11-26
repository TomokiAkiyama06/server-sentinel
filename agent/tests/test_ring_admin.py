"""The Owner's local ring command (Issue #16 PR D).

A real temporary-filesystem ring under a synthetic configuration; the typed
word is injected instead of a terminal. No camera, encoder or Main Server.
"""
from __future__ import annotations

import contextlib
import io
from pathlib import Path
import unittest
from unittest import mock

from media_capture_agent import ring_admin
from media_capture_agent.config import Settings
from media_capture_agent.ring import DiskRing
from media_capture_agent.ring_models import SECOND, RingConfig
from media_capture_agent.ring_service import ring_profiles
from media_capture_agent.storage import MediaStore
from tests import support
from tests.support import ring_temporary_directory
from tests.test_ring import AllowControls, Quota
from tests.test_ring_service import with_ring


NOW = 1_800_000_000.0


class RingAdminTests(unittest.TestCase):
    def setUp(self):
        self.temporary = ring_temporary_directory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.settings = Settings.parse(with_ring(support.configuration(root)),
                                       code_root=root / "code")
        self.quota = Quota(self.settings.media_root)
        self.words = []

    def store(self, settings):
        return MediaStore(settings, space=self.quota, stable_device=lambda _expected: True)

    def confirm(self, prompt):
        self.prompts.append(prompt)
        return self.words.pop(0) if self.words else ""

    def run_admin(self, *argv):
        self.prompts = []
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = ring_admin.main(list(argv), settings_loader=lambda _path: self.settings,
                                   confirm=self.confirm, clock=lambda: NOW,
                                   store_factory=self.store)
        return code, stdout.getvalue(), stderr.getvalue()

    def ring(self):
        store = self.store(self.settings)
        ring = DiskRing(self.settings, store, ledger_maximum_bytes=self.settings.ring.ledger_maximum_bytes,
                        authority=AllowControls())
        return store, ring

    def test_status_of_an_unconfigured_ring(self):
        code, stdout, stderr = self.run_admin("status", "--config", "/x")
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("ring: not configured", stdout)
        self.assertIn("incidents: none", stdout)

    def test_configure_needs_the_typed_word_and_then_persists(self):
        code, _stdout, stderr = self.run_admin("configure", "--config", "/x", "--mode", "duration",
                                               "--value", "600")
        self.assertEqual(code, 2)
        self.assertIn("refused: owner_confirmation_declined", stderr)
        self.assertIn("Type CONFIGURE to confirm", self.prompts[0])
        store, ring = self.ring()
        self.assertIsNone(ring.config)
        ring.close()
        store.close()
        self.words = ["CONFIGURE"]
        code, stdout, stderr = self.run_admin("configure", "--config", "/x", "--mode", "duration",
                                              "--value", "600")
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("ring configured", stdout)
        self.assertIn("mode=duration value=600 seconds", stdout)
        store, ring = self.ring()
        self.addCleanup(store.close)
        self.addCleanup(ring.close)
        self.assertEqual(ring.config, RingConfig("duration", 600))
        self.assertEqual(ring.profiles, {profile.source_id: profile
                                         for profile in ring_profiles(self.settings)})

    def test_capacity_takes_a_suffix_and_an_insufficient_value_is_refused(self):
        self.assertEqual(ring_admin.parse_value("capacity", "100GiB"), 100 << 30)
        self.assertEqual(ring_admin.parse_value("capacity", "4096"), 4096)
        for mode, text in (("capacity", "0"), ("capacity", "1.5GiB"), ("capacity", "10GB"),
                           ("capacity", "-1"), ("duration", "1h"), ("duration", "0")):
            with self.subTest(mode=mode, text=text), self.assertRaises(ring_admin.AdminRefused):
                ring_admin.parse_value(mode, text)
        self.words = ["CONFIGURE"]
        # The test profile bounds 10 minutes at about 0.9 MB; 4096 bytes cannot hold them.
        code, _stdout, stderr = self.run_admin("configure", "--config", "/x", "--mode", "capacity",
                                               "--value", "4096")
        self.assertEqual(code, 2)
        self.assertIn("refused: insufficient_pre_loss_capacity", stderr)

    def test_status_lists_incidents_and_delete_removes_one(self):
        store, ring = self.ring()
        now = int(NOW * SECOND)
        ring.configure(RingConfig("duration", 600), ring_profiles(self.settings), now_us=now,
                       clock_trusted=True)
        ring.observe_connection(authenticated=True, connected=True, unexpected=True, now_us=now,
                                clock_trusted=True)
        incident = ring.observe_connection(authenticated=True, connected=False, unexpected=True,
                                           now_us=now + SECOND, clock_trusted=True)
        ring.close()
        store.close()
        code, stdout, _stderr = self.run_admin("status", "--config", "/x")
        self.assertEqual(code, 0)
        self.assertIn(f"incident {incident} reason=main_connection_lost state=active", stdout)
        self.assertIn("mode=duration value=600 seconds", stdout)
        self.assertIn("safety_reserve_bytes=4096", stdout)
        self.words = ["DELETE"]
        code, stdout, stderr = self.run_admin("delete-incident", "--config", "/x", str(incident))
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("Type DELETE to confirm", self.prompts[0])
        self.assertIn(f"incident deleted: {incident}", stdout)
        code, stdout, _stderr = self.run_admin("status", "--config", "/x")
        self.assertIn("incidents: none", stdout)

    def test_refusals(self):
        code, _stdout, stderr = self.run_admin("delete-incident", "--config", "/x", "not-a-uuid")
        self.assertIn("refused: incident_id_rejected", stderr)
        code, _stdout, stderr = self.run_admin("delete-incident", "--config", "/x",
                                               "00000000-0000-4000-8000-0000000000ff")
        self.assertEqual(code, 2)
        self.assertIn("refused: incident_not_found", stderr)
        with mock.patch.object(ring_admin.os, "geteuid", return_value=0):
            code, _stdout, stderr = self.run_admin("status", "--config", "/x")
        self.assertIn("refused: run_as_service_account", stderr)

    def test_a_running_service_is_refused(self):
        from media_capture_agent.uvc_approvals import ApprovalStore
        held = ApprovalStore(self.settings)  # the service holds this lock while it runs
        self.addCleanup(held.close)
        code, _stdout, stderr = self.run_admin("status", "--config", "/x")
        self.assertEqual(code, 2)
        self.assertIn("refused: service_running", stderr)

    def test_a_deployment_without_a_ring_is_refused(self):
        plain = Path(self.temporary.name) / "plain"
        plain.mkdir()
        self.settings = Settings.parse(support.configuration(plain), code_root=plain / "code")
        code, _stdout, stderr = self.run_admin("status", "--config", "/x")
        self.assertEqual(code, 2)
        self.assertIn("refused: ring_unconfigured", stderr)


if __name__ == "__main__":
    unittest.main()
