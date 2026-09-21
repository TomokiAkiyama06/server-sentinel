"""Synthetic tests for transport-neutral authorized viewer demand."""

import unittest
from uuid import UUID

from app.media.live import (
    LiveAccess,
    LiveSessionCapacityExceeded,
    LiveSessionLimits,
    LiveSessionUnavailable,
    LiveViewerSessions,
)


PRINCIPAL = UUID(int=1)
OTHER_PRINCIPAL = UUID(int=2)
SOURCE = UUID(int=10)
OTHER_SOURCE = UUID(int=11)


class SyntheticSource:
    def __init__(self, source_id=SOURCE):
        self.source_id = source_id
        self.viewers = set()
        self.add_calls = 0
        self.remove_calls = 0
        self.fail_add = False
        self.fail_remove = False
        self.incomplete_remove = False

    def add_viewer(self, subscriber_id):
        self.add_calls += 1
        if self.fail_add:
            raise RuntimeError("synthetic add failure")
        self.viewers.add(subscriber_id)

    def remove_viewer(self, subscriber_id):
        self.remove_calls += 1
        if self.fail_remove:
            raise RuntimeError("synthetic remove failure")
        self.viewers.discard(subscriber_id)
        return not self.incomplete_remove


class AccessState:
    def __init__(self):
        self.allowed = set()

    def grant(self, principal, source, revision):
        self.allowed.add((principal, source, revision))

    def __call__(self, access, source_id):
        return (access.principal_id, source_id,
                access.authorization_revision) in self.allowed


class IdFactory:
    def __init__(self):
        self.value = 100

    def __call__(self):
        self.value += 1
        return UUID(int=self.value)


class LiveViewerSessionTests(unittest.TestCase):
    def setUp(self):
        self.access_state = AccessState()
        self.access_state.grant(PRINCIPAL, SOURCE, 1)
        self.access = LiveAccess(PRINCIPAL, 1)
        self.ids = IdFactory()
        self.sessions = LiveViewerSessions(
            LiveSessionLimits(3, 2), self.access_state,
            session_id_factory=self.ids,
        )

    def test_unauthorized_open_fails_before_allocating_pipeline_resources(self):
        source = SyntheticSource()
        with self.assertRaisesRegex(LiveSessionUnavailable,
                                    "live session unavailable"):
            self.sessions.open(LiveAccess(OTHER_PRINCIPAL, 1), source)
        self.assertEqual(source.add_calls, 0)
        self.assertEqual(self.sessions.status.active_viewers, 0)

    def test_session_id_is_bound_to_principal_and_revision(self):
        source = SyntheticSource()
        opened = self.sessions.open(self.access, source)
        for copied_access in (LiveAccess(OTHER_PRINCIPAL, 1),
                              LiveAccess(PRINCIPAL, 2)):
            with self.subTest(access=copied_access), self.assertRaisesRegex(
                    LiveSessionUnavailable, "live session unavailable"):
                self.sessions.require(copied_access, opened.session_id)
        self.assertEqual(source.viewers, {opened.session_id})

    def test_current_revision_is_revalidated_and_revocation_releases_demand(self):
        source = SyntheticSource()
        opened = self.sessions.open(self.access, source)
        self.access_state.allowed.clear()
        with self.assertRaises(LiveSessionUnavailable):
            self.sessions.require(self.access, opened.session_id)
        self.assertFalse(source.viewers)
        self.assertEqual(self.sessions.status.active_viewers, 0)

    def test_total_and_per_source_capacity_are_independent(self):
        source = SyntheticSource()
        self.sessions.open(self.access, source)
        self.sessions.open(self.access, source)
        with self.assertRaises(LiveSessionCapacityExceeded):
            self.sessions.open(self.access, source)

        self.access_state.grant(PRINCIPAL, OTHER_SOURCE, 1)
        other = SyntheticSource(OTHER_SOURCE)
        self.sessions.open(self.access, other)
        with self.assertRaises(LiveSessionCapacityExceeded):
            self.sessions.open(self.access, other)
        self.assertEqual(self.sessions.status.active_sources, 2)

    def test_each_session_drives_pipeline_first_and_last_viewer_lifecycle(self):
        source = SyntheticSource()
        first = self.sessions.open(self.access, source)
        second = self.sessions.open(self.access, source)
        self.assertEqual(source.viewers, {first.session_id, second.session_id})
        self.sessions.close(self.access, first.session_id)
        self.assertEqual(source.viewers, {second.session_id})
        self.sessions.close(self.access, second.session_id)
        self.assertFalse(source.viewers)
        self.assertEqual((source.add_calls, source.remove_calls), (2, 2))

    def test_failed_open_never_publishes_a_session(self):
        source = SyntheticSource()
        source.fail_add = True
        with self.assertRaisesRegex(RuntimeError, "synthetic add failure"):
            self.sessions.open(self.access, source)
        self.assertEqual(self.sessions.status.active_viewers, 0)

    def test_cleanup_failure_stays_visible_and_disconnect_retries(self):
        source = SyntheticSource()
        opened = self.sessions.open(self.access, source)
        source.fail_remove = True
        with self.assertRaisesRegex(RuntimeError, "live viewer cleanup failed"):
            self.sessions.close(self.access, opened.session_id)
        self.assertEqual(self.sessions.status.cleanup_failures, 1)
        self.assertEqual(self.sessions.status.active_viewers, 1)

        source.fail_remove = False
        self.assertTrue(self.sessions.disconnect(opened.session_id))
        self.assertEqual(self.sessions.status.cleanup_failures, 0)
        self.assertEqual(self.sessions.status.active_viewers, 0)

    def test_cleanup_failure_never_restores_session_access(self):
        source = SyntheticSource()
        opened = self.sessions.open(self.access, source)
        source.fail_remove = True
        with self.assertRaises(RuntimeError):
            self.sessions.close(self.access, opened.session_id)
        source.fail_remove = False
        with self.assertRaises(LiveSessionUnavailable):
            self.sessions.require(self.access, opened.session_id)
        self.assertFalse(source.viewers)
        self.assertEqual(self.sessions.status.active_viewers, 0)

    def test_nonthrowing_pipeline_cleanup_failure_remains_retryable(self):
        source = SyntheticSource()
        opened = self.sessions.open(self.access, source)
        source.incomplete_remove = True

        with self.assertRaisesRegex(RuntimeError, "live viewer cleanup failed"):
            self.sessions.close(self.access, opened.session_id)
        self.assertEqual(self.sessions.status.cleanup_failures, 1)
        self.assertEqual(self.sessions.status.active_viewers, 1)

        source.incomplete_remove = False
        self.assertTrue(self.sessions.disconnect(opened.session_id))
        self.assertEqual(self.sessions.status.active_viewers, 0)

    def test_unknown_disconnect_is_idempotently_not_removed(self):
        self.assertFalse(self.sessions.disconnect(UUID(int=999)))

    def test_revocation_keeps_nonthrowing_failed_cleanup_visible_and_retryable(self):
        source = SyntheticSource()
        opened = self.sessions.open(self.access, source)
        source.incomplete_remove = True
        self.assertEqual(self.sessions.revoke_principal(PRINCIPAL), 0)
        self.assertEqual(self.sessions.status.cleanup_failures, 1)
        self.assertEqual(self.sessions.status.active_viewers, 1)

        source.incomplete_remove = False
        self.assertTrue(self.sessions.disconnect(opened.session_id))
        self.assertEqual(self.sessions.status.active_viewers, 0)

    def test_principal_revocation_cleans_all_of_its_sources(self):
        first_source = SyntheticSource()
        second_source = SyntheticSource(OTHER_SOURCE)
        self.access_state.grant(PRINCIPAL, OTHER_SOURCE, 1)
        self.sessions.open(self.access, first_source)
        self.sessions.open(self.access, second_source)
        self.assertEqual(self.sessions.revoke_principal(PRINCIPAL), 2)
        self.assertFalse(first_source.viewers)
        self.assertFalse(second_source.viewers)

    def test_active_logical_source_cannot_mix_pipeline_generations(self):
        first = SyntheticSource()
        replacement = SyntheticSource()
        self.sessions.open(self.access, first)
        with self.assertRaises(LiveSessionUnavailable):
            self.sessions.open(self.access, replacement)
        self.assertEqual(replacement.add_calls, 0)

    def test_reused_factory_id_fails_even_after_original_session_closed(self):
        duplicate = UUID(int=900)
        sessions = LiveViewerSessions(
            LiveSessionLimits(2, 2), self.access_state,
            session_id_factory=lambda: duplicate,
        )
        source = SyntheticSource()
        first = sessions.open(self.access, source)
        sessions.close(self.access, first.session_id)
        with self.assertRaisesRegex(RuntimeError,
                                    "session identifier allocation failed"):
            sessions.open(self.access, source)
        self.assertEqual(source.add_calls, 1)

    def test_validator_exception_fails_closed_before_allocating(self):
        def broken_validator(access, source_id):
            raise RuntimeError("private auth backend detail")

        sessions = LiveViewerSessions(
            LiveSessionLimits(1, 1), broken_validator,
            session_id_factory=self.ids,
        )
        source = SyntheticSource()
        with self.assertRaisesRegex(LiveSessionUnavailable,
                                    "live session unavailable"):
            sessions.open(self.access, source)
        self.assertEqual(source.add_calls, 0)

    def test_invalid_limits_and_access_revisions_fail_closed(self):
        for values in ((0, 1), (2, 0), (1, 2), (True, 1)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                LiveSessionLimits(*values)
        for revision in (-1, True):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                LiveAccess(PRINCIPAL, revision)


if __name__ == "__main__":
    unittest.main()
