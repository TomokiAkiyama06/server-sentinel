"""Issue #144 (Owner decision 2026-10-07: serialize): the reservation check and
every session/enrollment commit share one gate.

Synthetic only: software authenticators (``webauthn_fakes``), synthetic
``/proc/net`` rows and a temporary SQLite database. Interleavings are forced
with events and a probe lock, not with timing.
"""

from contextlib import closing
from datetime import timedelta
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from app.audit import AuditStore, OwnerAuditService
from app.audit.integration import AccessAdministration, ReservationAdministration
from app.audit.model import AuditAction, AuditOutcome
from app.auth.model import AccessValidationError, Permission
from app.auth.passkeys import CeremonyDenied, PasskeyCeremonies
from app.auth.reservation import (
    DAILY_SECONDS, CheckKind, HumanAccessClosed, Reason,
)
from app.auth.reservation_store import ListenerExceptionStore, ReservationSessionRevocation
from app.auth.session_binding import SessionBindingKey
from app.auth.store import AccessStore
from app.auth.webauthn import RelyingParty
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.test_hostname_reservation import (
    SSH, V4, V6, WILDCARD_SSH, Clock, Files, SyntheticOwnerAuthorizer, checker, proc,
)
from tests.test_webauthn_ceremonies import Clock as CeremonyClock
from tests.webauthn_fakes import ORIGIN, RP_ID, SyntheticAuthenticator


VIEWER = "synthetic-viewer@example.invalid"
OWNER_SESSION = "synthetic-owner-session"
CLEAN = proc(("127.0.0.1", 8080, "0A"))
# Another listener on the reserved address: an exposure.
EXPOSED = proc(("127.0.0.1", 8080, "0A"), ("100.64.0.10", 8443, "0A"))
WAIT = 10


class ProbeLock:
    """A lock that reports when a second thread starts waiting for it."""

    def __init__(self):
        self._lock = threading.Lock()
        self.waiting = threading.Event()

    def __enter__(self):
        if not self._lock.acquire(blocking=False):
            self.waiting.set()
            self._lock.acquire()
        return self

    def __exit__(self, *exc):
        self._lock.release()
        return False


class SessionGateFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Database(Path(temporary.name) / "synthetic.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.ceremony_clock = CeremonyClock()
        self.audit = AuditStore(self.database, clock=self.ceremony_clock)
        self.access = AccessStore(self.database, clock=self.ceremony_clock, audit=self.audit,
                                  unaudited_writes=True, session_binding=SessionBindingKey.generate())
        self.revoker = ReservationSessionRevocation(self.access)
        self.exception_store = ListenerExceptionStore(self.database)
        self.clock = Clock()
        self.check, self.files, _, _ = checker(clock=self.clock, session_revoker=self.revoker,
                                               exception_store=self.exception_store)
        self.assertTrue(self.check.startup().open)
        self.ceremonies = self.ceremonies_for(self.check)
        self.service = OwnerAuditService(self.audit, SyntheticOwnerAuthorizer())

    def ceremonies_for(self, gate):
        return PasskeyCeremonies(self.access, RelyingParty(RP_ID, ORIGIN), session_gate=gate,
                                 clock=self.ceremony_clock)

    def enroll(self, code=b"v" * 32, identity=VIEWER):
        principal = self.access.invite("Synthetic viewer", (Permission.LIVE_VIEW,))
        self.access.issue_enrollment(principal.id, code, self.ceremony_clock() + timedelta(minutes=30))
        authenticator = SyntheticAuthenticator()
        creation = self.ceremonies.begin_registration(code, identity)
        self.ceremonies.finish_registration(code, identity, authenticator.register(creation))
        return principal, authenticator

    def assertion(self, authenticator):
        return authenticator.assertion(self.ceremonies.begin_authentication())

    def valid(self, grant, identity=VIEWER):
        try:
            self.access.authorize(grant.token, identity, Permission.LIVE_VIEW)
        except AccessValidationError:
            return False
        return True

    def live_sessions(self):
        with closing(self.database.connect()) as connection:
            return connection.execute(
                "SELECT count(*) FROM access_sessions WHERE invalidated_at_us IS NULL").fetchone()[0]

    def revocations(self):
        return [record for record in self.audit.list_records()
                if record.action is AuditAction.INVALIDATE_HUMAN_SESSIONS
                and record.outcome is AuditOutcome.SUCCEEDED]

    def marker_fails(self):
        return patch.object(self.revoker, "record_exposure", side_effect=OSError("synthetic marker failure"))

    def restart(self):
        """A new process: nothing in memory, only what the database holds."""
        check, files, _, _ = checker(session_revoker=self.revoker, exception_store=self.exception_store,
                                     files=Files(tcp=self.files.files["tcp"]))
        return check

    def thread(self, target, *args):
        box = {}

        def run():
            try:
                box["value"] = target(*args)
            except BaseException as error:  # reported to the test thread
                box["error"] = error

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        return worker, box


class SessionCommitRaceTests(SessionGateFixture):
    def test_commit_that_saw_access_open_is_refused_after_the_check_closes(self):
        # The #144 race: the request observes access open, the check closes
        # it for an exposure, the marker write fails so every session is
        # revoked at once, and only then does the request commit.
        _, authenticator = self.enroll()
        assertion = self.assertion(authenticator)
        self.assertTrue(self.check.access_open)
        self.files.files["tcp"] = EXPOSED
        self.clock.value += DAILY_SECONDS
        with self.marker_fails(), self.assertLogs("app.auth.reservation", "WARNING"):
            self.assertEqual(self.check.tick().reasons, (Reason.UNEXPECTED_LISTENER,))
        self.assertEqual(len(self.revocations()), 1)
        with self.assertRaises(CeremonyDenied):
            self.ceremonies.finish_authentication(VIEWER, assertion)
        self.assertEqual(self.live_sessions(), 0)
        # The exposure goes away and the process restarts before a clean
        # check, still without a marker: nothing from the race survives.
        self.files.files["tcp"] = CLEAN
        restarted = self.restart()
        self.assertTrue(restarted.startup().open)
        self.assertEqual(self.live_sessions(), 0)
        # Signing in again works once access is open.
        ceremonies = self.ceremonies_for(restarted)
        grant = ceremonies.finish_authentication(
            VIEWER, authenticator.assertion(ceremonies.begin_authentication()))
        self.assertTrue(self.valid(grant))

    def test_check_waits_for_a_commit_in_progress_and_then_revokes_it(self):
        # The commit holds the gate when the check starts: the check cannot
        # close access until it lands, and its fallback revocation then
        # covers the new session, so a restart without a marker keeps none.
        _, authenticator = self.enroll()
        assertion = self.assertion(authenticator)
        probe = ProbeLock()
        self.check._session_gate_lock = probe
        inside, proceed = threading.Event(), threading.Event()
        original = self.access.accept_assertion

        def paused(*args, **kwargs):
            inside.set()
            self.assertTrue(proceed.wait(WAIT))
            return original(*args, **kwargs)

        self.files.files["tcp"] = EXPOSED
        self.clock.value += DAILY_SECONDS
        with patch.object(self.access, "accept_assertion", side_effect=paused), self.marker_fails(), \
                self.assertLogs("app.auth.reservation", "WARNING"):
            login, login_box = self.thread(self.ceremonies.finish_authentication, VIEWER, assertion)
            self.assertTrue(inside.wait(WAIT))
            check, check_box = self.thread(self.check.tick)
            # The check reached the gate and waits: access is still open.
            self.assertTrue(probe.waiting.wait(WAIT))
            self.assertTrue(self.check.access_open)
            proceed.set()
            login.join(WAIT)
            check.join(WAIT)
        self.assertFalse(login.is_alive() or check.is_alive())
        self.assertNotIn("error", login_box)
        self.assertNotIn("error", check_box)
        grant = login_box["value"]
        self.assertEqual(check_box["value"].reasons, (Reason.UNEXPECTED_LISTENER,))
        self.assertEqual(len(self.revocations()), 1)
        self.assertFalse(self.valid(grant))
        self.files.files["tcp"] = CLEAN
        self.assertTrue(self.restart().startup().open)
        self.assertFalse(self.valid(grant))

    def test_commit_while_a_check_is_evaluating_is_refused(self):
        # The check has closed access and is still enumerating (no lock is
        # held there); a login arriving now is refused, then the check
        # reopens without revocation (no exposure).
        _, authenticator = self.enroll()
        assertion = self.assertion(authenticator)
        resolving, resume = threading.Event(), threading.Event()
        resolver = self.check._resolver
        answer = resolver.answer

        def slow_resolve(hostname):
            resolving.set()
            self.assertTrue(resume.wait(WAIT))
            return answer

        self.clock.value += DAILY_SECONDS
        with patch.object(resolver, "resolve", side_effect=slow_resolve):
            check, check_box = self.thread(self.check.tick)
            self.assertTrue(resolving.wait(WAIT))
            self.assertFalse(self.check.access_open)
            with self.assertRaises(CeremonyDenied):
                self.ceremonies.finish_authentication(VIEWER, assertion)
            resume.set()
            check.join(WAIT)
        self.assertFalse(check.is_alive())
        self.assertTrue(check_box["value"].open)
        self.assertEqual(self.live_sessions(), 0)
        self.assertEqual(self.revocations(), [])
        grant = self.ceremonies.finish_authentication(VIEWER, self.assertion(authenticator))
        self.assertTrue(self.valid(grant))

    def test_admit_refuses_while_closed_and_after_close(self):
        epoch = self.check.epoch()
        with self.check.admit(epoch):
            pass
        self.files.files["tcp"] = EXPOSED
        self.assertFalse(self.check._check(CheckKind.RETRY).open)
        self.assertIsNone(self.check.epoch())
        for stale in (None, epoch):
            with self.subTest(epoch=stale), self.assertRaises(HumanAccessClosed):
                with self.check.admit(stale):
                    self.fail("admitted while closed")
        # Reopened: an epoch taken before the close stays refused.
        self.files.files["tcp"] = CLEAN
        self.assertTrue(self.check._check(CheckKind.RETRY).open)
        with self.assertRaises(HumanAccessClosed):
            with self.check.admit(epoch):
                self.fail("admitted with an epoch from before the close")
        with self.check.admit(self.check.epoch()):
            pass
        unchecked = checker(session_revoker=self.revoker)[0]
        # Never opened: closed from construction.
        self.assertIsNone(unchecked.epoch())
        with self.assertRaises(HumanAccessClosed):
            with unchecked.admit(0):
                self.fail("admitted before any check")

    def cycle(self, *, exposure=True):
        """A whole close -> (revoke) -> reopen cycle, run while a request is paused."""
        self.files.files["tcp"] = EXPOSED if exposure else CLEAN
        if not exposure:
            self.check._resolver.answer = OSError("synthetic resolver failure")
        self.assertFalse(self.check._check(CheckKind.RETRY).open)
        self.files.files["tcp"] = CLEAN
        self.check._resolver.answer = (V4, V6)
        self.assertTrue(self.check._check(CheckKind.RETRY).open)

    def paused_during(self, target, method, call, *, exposure=True):
        """Pause ``call`` inside ``target.method`` and run a full cycle meanwhile."""
        inside, proceed = threading.Event(), threading.Event()
        original = getattr(target, method)

        def paused(*args, **kwargs):
            inside.set()
            proceed.wait(WAIT)
            return original(*args, **kwargs)

        with patch.object(target, method, side_effect=paused):
            worker, box = self.thread(call)
            self.assertTrue(inside.wait(WAIT))
            self.cycle(exposure=exposure)
            proceed.set()
            worker.join(WAIT)
        self.assertFalse(worker.is_alive())
        return box

    def test_cycle_completed_during_verification_refuses_the_session(self):
        # PR #174 review (Codex P1): the assertion is verified, the request
        # pauses, a check closes access and revokes every session, a clean
        # check reopens, and only then does the request reach the gate.
        _, authenticator = self.enroll()
        assertion = self.assertion(authenticator)
        box = self.paused_during(self.access, "assertion_subject",
                                 lambda: self.ceremonies.finish_authentication(VIEWER, assertion))
        self.assertIsInstance(box.get("error"), CeremonyDenied)
        self.assertEqual(len(self.revocations()), 1)
        self.assertEqual(self.live_sessions(), 0)

    def test_cycle_completed_during_registration_refuses_the_redemption(self):
        # Without an exposure nothing is revoked, but the request still spans a
        # close: it is refused and the invitation stays unredeemed.
        principal = self.access.invite("Synthetic pending", (Permission.LIVE_VIEW,))
        self.access.issue_enrollment(principal.id, b"p" * 32, self.ceremony_clock() + timedelta(minutes=30))
        authenticator = SyntheticAuthenticator()
        creation = self.ceremonies.begin_registration(b"p" * 32, "pending@example.invalid")
        response = authenticator.register(creation)
        box = self.paused_during(
            self.access, "consume_challenge",
            lambda: self.ceremonies.finish_registration(b"p" * 32, "pending@example.invalid", response),
            exposure=False)
        self.assertIsInstance(box.get("error"), CeremonyDenied)
        self.assertEqual(self.revocations(), [])
        with closing(self.database.connect()) as connection:
            redeemed = connection.execute("SELECT redeemed_at_us FROM access_invitations WHERE principal_id=?",
                                          (str(principal.id),)).fetchone()[0]
        self.assertIsNone(redeemed)

    def test_cycle_completed_during_step_up_refuses_the_update(self):
        owner = self.access.bootstrap_owner("Synthetic owner")
        self.access.issue_enrollment(owner.id, b"o" * 32, self.ceremony_clock() + timedelta(minutes=30))
        owner_key = SyntheticAuthenticator()
        creation = self.ceremonies.begin_registration(b"o" * 32, "owner@example.invalid")
        self.ceremonies.finish_registration(b"o" * 32, "owner@example.invalid", owner_key.register(creation))
        grant = self.ceremonies.finish_authentication("owner@example.invalid", self.assertion(owner_key))
        step_up = owner_key.assertion(self.ceremonies.begin_step_up(grant.token, "owner@example.invalid"))
        self.ceremony_clock.advance(minutes=1)
        box = self.paused_during(
            self.access, "assertion_subject",
            lambda: self.ceremonies.finish_step_up(grant.token, "owner@example.invalid", step_up),
            exposure=False)
        self.assertIsInstance(box.get("error"), CeremonyDenied)
        with closing(self.database.connect()) as connection:
            verified, established = connection.execute(
                "SELECT last_user_verification_at_us, established_at_us FROM access_sessions WHERE id=?",
                (str(grant.session_id),)).fetchone()
        self.assertEqual(verified, established)

    def test_cycle_completed_after_owner_authorization_refuses_the_invitation(self):
        # The Owner is authorized, a check closes access and revokes every
        # session (the Owner's included), a clean check reopens; the
        # invitation must not commit on that revoked authorization.
        admin = AccessAdministration(self.service, self.access, session_gate=self.check)
        principal = self.access.invite("Synthetic pending", (Permission.LIVE_VIEW,))
        expires = self.ceremony_clock() + timedelta(minutes=30)
        box = self.paused_during(
            self.service.authorizer, "require_owner",
            lambda: admin.issue_invitation(OWNER_SESSION, principal.id, b"a" * 32, expires))
        self.assertIsInstance(box.get("error"), HumanAccessClosed)
        with closing(self.database.connect()) as connection:
            count = connection.execute("SELECT count(*) FROM access_invitations WHERE principal_id=?",
                                       (str(principal.id),)).fetchone()[0]
        self.assertEqual(count, 0)
        issued = [record.outcome for record in self.audit.list_records()
                  if record.action is AuditAction.ISSUE_PRINCIPAL_INVITATION]
        self.assertEqual(issued, [AuditOutcome.FAILED])

    def challenges(self):
        with closing(self.database.connect()) as connection:
            return connection.execute("SELECT count(*) FROM access_webauthn_challenges").fetchone()[0]

    def test_challenge_insert_paused_across_a_cycle_is_refused_for_every_begin_step(self):
        # PR #174 review (Codex P1): a begin_* request starts while access is
        # open and pauses before storing its challenge; a check closes access
        # (revoking and deleting every pending challenge on an exposure) and a
        # clean check reopens; the paused request must not store its
        # challenge, or a later finish_* (with a post-reopen epoch) could use it.
        owner = self.access.bootstrap_owner("Synthetic owner")
        self.access.issue_enrollment(owner.id, b"o" * 32, self.ceremony_clock() + timedelta(minutes=30))
        owner_key = SyntheticAuthenticator()
        creation = self.ceremonies.begin_registration(b"o" * 32, "owner@example.invalid")
        self.ceremonies.finish_registration(b"o" * 32, "owner@example.invalid", owner_key.register(creation))
        grant = self.ceremonies.finish_authentication("owner@example.invalid", self.assertion(owner_key))
        pending = self.access.invite("Synthetic pending", (Permission.LIVE_VIEW,))
        self.access.issue_enrollment(pending.id, b"p" * 32, self.ceremony_clock() + timedelta(minutes=30))
        cases = {
            # With an exposure the revocation alone would void the invitation
            # and the Owner session, so those two use a close without one.
            "authentication": (lambda: self.ceremonies.begin_authentication(), True),
            "registration": (lambda: self.ceremonies.begin_registration(b"p" * 32, "pending@example.invalid"),
                             False),
            "step-up": (lambda: self.ceremonies.begin_step_up(grant.token, "owner@example.invalid"), False),
        }
        for name, (call, exposure) in cases.items():
            with self.subTest(begin=name):
                self.assertEqual(self.challenges(), 0)
                box = self.paused_during(self.ceremonies, "_challenge", call, exposure=exposure)
                self.assertIsInstance(box.get("error"), CeremonyDenied)
                self.assertEqual(self.challenges(), 0)
        # After the cycles a fresh request stores its challenge normally.
        self.ceremonies.begin_authentication()
        self.assertEqual(self.challenges(), 1)

    def test_challenge_issued_before_a_revocation_cannot_be_used_after_it(self):
        # An assertion over a challenge issued before an exposure (for example
        # one a listener answering during it received) cannot establish a
        # session after the revocation, even in a request started after reopen.
        _, authenticator = self.enroll()
        assertion = self.assertion(authenticator)
        self.cycle()
        self.assertEqual(len(self.revocations()), 1)
        with self.assertRaises(CeremonyDenied):
            self.ceremonies.finish_authentication(VIEWER, assertion)
        self.assertEqual(self.live_sessions(), 0)
        grant = self.ceremonies.finish_authentication(VIEWER, self.assertion(authenticator))
        self.assertTrue(self.valid(grant))

    def test_registration_and_step_up_are_gated(self):
        # Invitation redemption and a step-up refresh are commits of the same kind.
        owner = self.access.bootstrap_owner("Synthetic owner")
        self.access.issue_enrollment(owner.id, b"o" * 32, self.ceremony_clock() + timedelta(minutes=30))
        owner_key = SyntheticAuthenticator()
        creation = self.ceremonies.begin_registration(b"o" * 32, "owner@example.invalid")
        self.ceremonies.finish_registration(b"o" * 32, "owner@example.invalid", owner_key.register(creation))
        grant = self.ceremonies.finish_authentication("owner@example.invalid", self.assertion(owner_key))
        pending = self.access.invite("Synthetic pending", (Permission.LIVE_VIEW,))
        self.access.issue_enrollment(pending.id, b"p" * 32, self.ceremony_clock() + timedelta(minutes=30))
        pending_key = SyntheticAuthenticator()
        creation = self.ceremonies.begin_registration(b"p" * 32, "pending@example.invalid")
        step_up = self.ceremonies.begin_step_up(grant.token, "owner@example.invalid")
        # Close without an exposure: the existing session stays valid.
        self.check._resolver.answer = OSError("synthetic resolver failure")
        self.assertFalse(self.check._check(CheckKind.RETRY).open)
        with self.assertRaises(CeremonyDenied):
            self.ceremonies.finish_registration(b"p" * 32, "pending@example.invalid",
                                                pending_key.register(creation))
        with self.assertRaises(CeremonyDenied):
            self.ceremonies.finish_step_up(grant.token, "owner@example.invalid", owner_key.assertion(step_up))
        with closing(self.database.connect()) as connection:
            redeemed = connection.execute(
                "SELECT redeemed_at_us FROM access_invitations WHERE principal_id=?", (str(pending.id),)).fetchone()[0]
            verified = connection.execute(
                "SELECT last_user_verification_at_us, established_at_us FROM access_sessions WHERE id=?",
                (str(grant.session_id),)).fetchone()
        self.assertIsNone(redeemed)
        self.assertEqual(verified[0], verified[1])

    def test_invitation_issued_through_the_gate_is_refused_while_closed(self):
        admin = AccessAdministration(self.service, self.access, session_gate=self.check)
        principal = self.access.invite("Synthetic pending", (Permission.LIVE_VIEW,))
        expires = self.ceremony_clock() + timedelta(minutes=30)
        admin.issue_invitation(OWNER_SESSION, principal.id, b"a" * 32, expires)
        self.files.files["tcp"] = EXPOSED
        self.assertFalse(self.check._check(CheckKind.RETRY).open)
        with self.assertRaises(HumanAccessClosed):
            admin.issue_invitation(OWNER_SESSION, principal.id, b"b" * 32, expires)
        issued = [record.outcome for record in self.audit.list_records()
                  if record.action is AuditAction.ISSUE_PRINCIPAL_INVITATION]
        self.assertEqual(sorted(issued), sorted([AuditOutcome.SUCCEEDED, AuditOutcome.FAILED]))
        with closing(self.database.connect()) as connection:
            count = connection.execute("SELECT count(*) FROM access_invitations WHERE principal_id=?",
                                       (str(principal.id),)).fetchone()[0]
        self.assertEqual(count, 1)

    def test_ceremonies_require_a_gate(self):
        for gate in (None, object()):
            with self.subTest(gate=gate), self.assertRaises(ValueError):
                self.ceremonies_for(gate)


class MarkerUnsavedLogTests(SessionGateFixture):
    def test_unsaved_marker_is_logged_at_the_start_and_each_doubling(self):
        # #144 comment: after a successful fallback revocation a marker that
        # keeps failing used to leave no trace; it is now logged, rate-limited.
        self.files.files["tcp"] = EXPOSED
        with self.marker_fails(), self.assertLogs("app.auth.reservation", "WARNING") as logs:
            for _ in range(8):
                self.check._check(CheckKind.RETRY)
        self.assertEqual([record.msg.value for record in logs.records],
                         ["session_revocation_marker_unsaved"] * 4)  # 1, 2, 4, 8
        self.assertEqual(len(self.revocations()), 1)
        with self.assertLogs("app.auth.reservation", "WARNING") as logs:
            self.check._check(CheckKind.RETRY)
        self.assertEqual([record.msg.value for record in logs.records], ["session_revocation_marker_saved"])


class GateLockOrderTests(SessionGateFixture):
    def test_concurrent_checks_logins_and_owner_changes_do_not_deadlock(self):
        users = [self.enroll(bytes([65 + index]) * 32, f"synthetic-{index}@example.invalid")
                 for index in range(3)]
        admin = AccessAdministration(self.service, self.access, session_gate=self.check)
        reservation_admin = ReservationAdministration(self.service, self.check)
        self.files.files.update(Files(**WILDCARD_SSH.raw).files)
        reservation_admin.set_listener_exceptions(OWNER_SESSION, {SSH})
        stop = threading.Event()
        errors = []
        granted = []
        rounds = 30

        def guarded(body):
            def run():
                try:
                    body()
                except BaseException as error:
                    errors.append(error)
            return run

        def checks():
            for index in range(rounds):
                self.files.files["tcp"] = EXPOSED if index % 3 == 0 else Files(**WILDCARD_SSH.raw).files["tcp"]
                self.check._check(CheckKind.RETRY)
            stop.set()

        def changes():
            index = 0
            while not stop.is_set():
                reservation_admin.set_listener_exceptions(OWNER_SESSION, {SSH} if index % 2 else set())
                index += 1

        def logins(index):
            def run():
                principal, authenticator = users[index]
                identity = f"synthetic-{index}@example.invalid"
                while not stop.is_set():
                    try:
                        granted.append(self.ceremonies.finish_authentication(
                            identity, self.assertion(authenticator)))
                    except CeremonyDenied:
                        pass
            return run

        def invitations():
            principal = self.access.invite("Synthetic pending", (Permission.LIVE_VIEW,))
            index = 0
            while not stop.is_set():
                try:
                    admin.issue_invitation(OWNER_SESSION, principal.id, index.to_bytes(32, "big"),
                                           self.ceremony_clock() + timedelta(minutes=30))
                except Exception:
                    pass
                index += 1

        workers = [threading.Thread(target=guarded(body), daemon=True)
                   for body in (checks, changes, invitations, *(logins(index) for index in range(3)))]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(60)
        stop.set()
        self.assertEqual([worker for worker in workers if worker.is_alive()], [])
        self.assertEqual(errors, [])
        # Whether any login got through during the concurrent phase depends on
        # scheduling, so it is not asserted. Afterwards a deterministic clean
        # check opens the gate and a login succeeds through it.
        reservation_admin.set_listener_exceptions(OWNER_SESSION, {SSH})
        self.files.files["tcp"] = Files(**WILDCARD_SSH.raw).files["tcp"]
        self.assertTrue(self.check._check(CheckKind.RETRY).open)
        _, authenticator = users[0]
        grant = self.ceremonies.finish_authentication("synthetic-0@example.invalid", self.assertion(authenticator))
        self.assertTrue(self.valid(grant, "synthetic-0@example.invalid"))
        # An exposure and a clean check then revoke every session.
        self.files.files["tcp"] = EXPOSED
        self.assertFalse(self.check._check(CheckKind.RETRY).open)
        self.files.files["tcp"] = Files(**WILDCARD_SSH.raw).files["tcp"]
        self.assertTrue(self.check._check(CheckKind.RETRY).open)
        self.assertEqual(self.live_sessions(), 0)
        self.assertFalse(self.valid(grant, "synthetic-0@example.invalid"))


if __name__ == "__main__":
    unittest.main()
