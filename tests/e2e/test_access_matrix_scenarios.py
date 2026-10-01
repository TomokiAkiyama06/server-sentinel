"""Human-access matrix across the closed HTTP surface and the server-side gates.

Identities: uninvited, ``live:view`` only, ``recordings:view`` only, both,
revoked, a paired capture-node (agent) credential, and a spoofed Tailscale /
proxy identity header. Every token, identity, key and digest is generated or a
synthetic constant; no real person, device, credential or media is used.

Two layers are exercised:

* the composed Main ASGI application (``app.main.create_app``) with a
  permissive injected authorizer: every human, admin and media path answers
  every identity with the same generic ``404`` (WebSocket ``1008``) and never
  consults the authorizer, so no application information reaches anyone
  while human routes stay closed (Issues #6/#10);
* the production grant state behind future routes: ``AccessStore.authorize``,
  the ``live:view`` validator and the historical timeline gate. The timeline
  ``access`` port is a test adapter that calls ``AccessStore.authorize`` with
  ``recordings:view``; the production route adapter does not exist yet.

This is not browser, Tailscale, proxy or WebAuthn ceremony acceptance.
"""

import asyncio
from contextlib import closing
from datetime import timedelta
from pathlib import Path
import secrets
import tempfile
import unittest
from uuid import UUID, uuid4

from app.audit.store import AuditStore
from app.auth.live_access import BoundLiveAccess, authorize_live_access, live_view_validator
from app.auth.model import AccessValidationError, Permission
from app.auth.session_binding import SessionBindingKey
from app.auth.store import AccessStore
from app.cameras.remote_agent.pairing import HmacCodeVerifier, PairingLedger
from app.media.live.sessions import LiveAccess
from app.presence.access import AccessDenied
from app.presence.models import Kind, Observation, Quality
from app.presence.service import PresenceService
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.e2e.harness import (
    MixedSourceTopology,
    NetworkGuard,
    SyntheticClock,
    skip_unless_full_coverage_required,
    storage_reservation,
)


LIVE, RECORDINGS = Permission.LIVE_VIEW, Permission.RECORDINGS_VIEW
GENERIC_DENIAL = "access is unavailable"

# Human, admin and media paths a future dashboard could expose. None is mounted.
HUMAN_PATHS = (
    "/", "/health", "/version", "/login", "/enroll", "/api/auth/assert",
    "/api/live/" + str(UUID(int=101)), "/api/sources", "/api/timeline",
    "/api/recordings", "/api/recordings/" + str(UUID(int=7)),
    "/api/recordings/" + str(UUID(int=7)) + "/download",
    "/media/" + str(UUID(int=7)) + "/segment-0001.m4s",
    "/api/admin/principals", "/api/admin/pairing", "/api/admin/audit",
    "/api/diagnostics/export", "/api/agent/ingest",
)
METHODS = ("GET", "POST", "DELETE")


class Identity:
    """One caller: an opaque session token and the identity it claims."""

    def __init__(self, name, external_identity, token=None):
        self.name = name
        self.external_identity = external_identity
        # Generated per run; never a committed credential value.
        self.token = token if token is not None else secrets.token_bytes(32)
        self.principal = None
        self.session_id = None

    def headers(self):
        return [(b"cookie", b"serversentinel_session=" + self.token.hex().encode("ascii"))]


class RecordingPermit:
    """Would allow everything; the closed surface must never call it."""

    def __init__(self):
        self.calls = 0

    async def require_system_access(self, request):
        self.calls += 1

    async def require_owner_access(self, request):
        self.calls += 1


class StoreBackedTimelineAccess:
    """Test adapter: the timeline gate delegates to the production grant check."""

    def __init__(self, store):
        self.store = store

    def require_owner(self, context):
        raise AccessDenied()

    def require_recordings(self, context):
        token, identity = context
        try:
            self.store.authorize(token, identity, RECORDINGS)
        except AccessValidationError:
            raise AccessDenied() from None


async def asgi(application, path, *, method="GET", headers=(), kind="http"):
    """Minimal in-process ASGI call; no socket or network client is used."""
    messages = []
    scope = {
        "type": kind, "asgi": {"version": "3.0"}, "http_version": "1.1",
        "scheme": "http", "method": method, "path": path,
        "raw_path": path.encode("ascii"), "query_string": b"", "root_path": "",
        "headers": list(headers), "client": ("127.0.0.1", 40000),
        "server": ("127.0.0.1", 8000),
    }

    async def receive():
        if kind == "websocket":
            return {"type": "websocket.connect"}
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    await application(scope, receive, send)
    return messages


class AccessMatrixScenarios(unittest.TestCase):
    def setUp(self):
        self.network = NetworkGuard().__enter__()
        self.addCleanup(self.network.__exit__)
        self.addCleanup(lambda: self.assertEqual([], self.network.attempts))
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clock = SyntheticClock()
        self.topology = MixedSourceTopology(4)
        self.database = Database(self.root / "main.sqlite3")
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.audit = AuditStore(self.database, clock=self.clock.utcnow)
        # Owner-only mutations use the unaudited fixture mode; the audited
        # Owner boundary is covered by server/tests/test_access_pairing_audit.py.
        self.store = AccessStore(self.database, clock=self.clock.utcnow, audit=self.audit,
                                 unaudited_writes=True, session_binding=SessionBindingKey.generate())
        self.identities = {
            "live_only": self.member("live_only", (LIVE,)),
            "recordings_only": self.member("recordings_only", (RECORDINGS,)),
            "both": self.member("both", (LIVE, RECORDINGS)),
            "revoked": self.member("revoked", (LIVE, RECORDINGS)),
        }
        self.store.revoke_principal(self.identities["revoked"].principal.id)
        self.identities["uninvited"] = Identity(
            "uninvited", "synthetic-uninvited@example.invalid")
        self.node_id, self.node_material = self.paired_capture_node()
        # The node's credential material presented as a human session token,
        # with the node identity as the claimed external identity.
        self.identities["agent_credential"] = Identity(
            "agent_credential", "capture-node-" + self.node_id.hex, token=self.node_material)
        # A caller forging the "both" member's Tailscale login with no session
        # of its own: the proxy identity header alone must never authorize.
        self.identities["spoofed_header"] = Identity(
            "spoofed_header", self.identities["both"].external_identity)

    def member(self, name, permissions):
        identity = Identity(name, f"synthetic-{name.replace('_', '-')}@example.invalid")
        principal = self.store.invite("Synthetic " + name, permissions)
        secret = secrets.token_bytes(32)
        self.store.issue_enrollment(principal.id, secret, self.clock.utcnow() + timedelta(minutes=10))
        credential_id = secrets.token_bytes(32)
        self.store.enroll_credential(secret, identity.external_identity, credential_id,
                                     b"synthetic-public-key-" + name.encode("ascii"), -7, 0)
        identity.session_id = self.store.establish_session(
            principal.id, credential_id, identity.token, proxy_identity=identity.external_identity)
        identity.principal = self.store.authorize(identity.token, identity.external_identity,
                                                  permissions[0])
        return identity

    def paired_capture_node(self):
        owner = type("Owner", (), {"require_owner": lambda _self, context: None})()
        ledger = PairingLedger(self.database, HmacCodeVerifier(secrets.token_bytes(32)),
                               audit=self.audit, clock=self.clock.monotonic)
        node = self.topology.sources[1].node_id
        key_digest, serial_digest = secrets.token_hex(32), secrets.token_hex(32)
        approval, code = ledger.approve(owner, "owner", node_id=node, public_key_digest=key_digest)
        claim = ledger.redeem(enrollment_id=approval.enrollment_id,
                              public_key_digest=key_digest, code=code.value)
        ledger.activate(claim, credential_serial_digest=serial_digest)
        self.assertTrue(ledger.admits(node_id=node, public_key_digest=key_digest,
                                      credential_serial_digest=serial_digest))
        return node, bytes.fromhex(serial_digest)

    def audit_rows(self):
        with closing(self.database.connect()) as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM security_admin_audit_records").fetchone()[0]

    def outcome(self, identity, permission):
        try:
            self.store.authorize(identity.token, identity.external_identity, permission)
        except AccessValidationError as error:
            self.assertEqual(GENERIC_DENIAL, str(error))
            return False
        return True

    def test_permission_matrix_is_enforced_server_side_with_one_generic_denial(self):
        expected = {
            "uninvited": (False, False), "live_only": (True, False),
            "recordings_only": (False, True), "both": (True, True),
            "revoked": (False, False), "agent_credential": (False, False),
            "spoofed_header": (False, False),
        }
        before = self.audit_rows()
        for name, (live, recordings) in expected.items():
            identity = self.identities[name]
            with self.subTest(identity=name):
                self.assertEqual((live, recordings),
                                 (self.outcome(identity, LIVE), self.outcome(identity, RECORDINGS)))
        # Denied attempts are unauthenticated input: they never grow the audit table.
        self.assertEqual(before, self.audit_rows())

    def test_valid_session_presented_under_another_identity_header_is_denied(self):
        live_only, both = self.identities["live_only"], self.identities["both"]
        # A real session whose proxy identity header is swapped for another member.
        for permission in (LIVE, RECORDINGS):
            with self.subTest(permission=permission.value), \
                    self.assertRaisesRegex(AccessValidationError, f"^{GENERIC_DENIAL}$"):
                self.store.authorize(live_only.token, both.external_identity, permission)
        # The genuine pairing still works: the swap did not revoke anything.
        self.assertTrue(self.outcome(live_only, LIVE))

    def test_live_view_is_bound_to_live_grant_session_and_revision(self):
        validator = live_view_validator(self.database, clock=self.clock.utcnow)
        source = self.topology.sources[0].source_id
        bound = {}
        for name in ("live_only", "both"):
            identity = self.identities[name]
            bound[name] = authorize_live_access(self.store, identity.token, identity.external_identity)
            self.assertTrue(validator(bound[name], source), name)
        for name in ("recordings_only", "revoked", "uninvited", "agent_credential", "spoofed_header"):
            identity = self.identities[name]
            with self.subTest(identity=name), \
                    self.assertRaisesRegex(AccessValidationError, f"^{GENERIC_DENIAL}$"):
                authorize_live_access(self.store, identity.token, identity.external_identity)
        recordings_only = self.identities["recordings_only"]
        live_only = self.identities["live_only"]
        copied = (
            # A live session identifier copied onto another principal.
            BoundLiveAccess(recordings_only.principal.id,
                            recordings_only.principal.authorization_revision,
                            bound["live_only"].access_session_id),
            # A principal with a fabricated session identifier.
            BoundLiveAccess(live_only.principal.id, bound["live_only"].authorization_revision, uuid4()),
            # An access value that is not bound to any human session.
            LiveAccess(live_only.principal.id, bound["live_only"].authorization_revision),
        )
        for access in copied:
            self.assertFalse(validator(access, source))
        # Removing live:view (keeping recordings:view) ends the open live grant.
        self.store.set_permissions(self.identities["both"].principal.id, (RECORDINGS,))
        self.assertFalse(validator(bound["both"], source))
        self.assertTrue(validator(bound["live_only"], source))
        self.store.revoke_principal(live_only.principal.id)
        self.assertFalse(validator(bound["live_only"], source))

    def test_historical_timeline_requires_recordings_view_only(self):
        presence = PresenceService(
            self.database, access=StoreBackedTimelineAccess(self.store),
            reservation=storage_reservation, detection=lambda: True,
            storage_status=lambda: True,
        )
        source = self.topology.sources[1]
        now = self.clock.utcnow()
        recorded = presence.record(Observation(
            Kind.CAMERA_HEALTH, now, now, source_id=source.source_id, node_id=source.node_id,
            quality=Quality.SUFFICIENT, clock_trusted=True))
        window = dict(received_from=now - timedelta(seconds=1), received_to=now + timedelta(seconds=1))
        for name in ("recordings_only", "both"):
            identity = self.identities[name]
            history = presence.history((identity.token, identity.external_identity), **window)
            self.assertEqual([str(recorded.identifier)], [item["id"] for item in history["items"]])
            self.assertEqual("not_inferred", history["causality"])
        for name in ("live_only", "uninvited", "revoked", "agent_credential", "spoofed_header"):
            identity = self.identities[name]
            with self.subTest(identity=name), self.assertRaises(AccessDenied) as denied:
                presence.history((identity.token, identity.external_identity), **window)
            self.assertEqual("Not Found", str(denied.exception))

    def test_agent_credential_cannot_become_a_human_principal(self):
        agent = self.identities["agent_credential"]
        # Node credential material is not a human WebAuthn credential or principal.
        with self.assertRaises(AccessValidationError):
            self.store.establish_session(self.node_id, agent.token, secrets.token_bytes(32),
                                         proxy_identity=agent.external_identity)
        with closing(self.database.connect()) as connection:
            self.assertIsNone(connection.execute(
                "SELECT 1 FROM access_principals WHERE id=?", (str(self.node_id),)).fetchone())
            self.assertIsNone(connection.execute(
                "SELECT 1 FROM access_credentials WHERE credential_id=?", (agent.token,)).fetchone())
        for permission in (LIVE, RECORDINGS):
            self.assertFalse(self.outcome(agent, permission))

    def test_closed_human_surface_answers_every_identity_identically(self):
        try:
            from app.main import create_app
            from app.settings import Settings
        except ModuleNotFoundError:
            skip_unless_full_coverage_required(
                "FastAPI from server/requirements.lock is required for the composed app")
        data = self.root / "data"
        data.mkdir(mode=0o700)
        permit = RecordingPermit()
        application = create_app(Settings(data), database=self.database, human_authorizer=permit)
        node_header = self.identities["agent_credential"].token.hex().encode("ascii")
        spoofed = self.identities["spoofed_header"].external_identity.encode("ascii")
        header_sets = {
            name: identity.headers() for name, identity in self.identities.items()
        }
        header_sets["agent_credential"] += [
            (b"authorization", b"Bearer " + node_header),
            (b"x-ssl-client-verify", b"SUCCESS"),
            (b"x-client-cert-serial", node_header),
        ]
        header_sets["spoofed_header"] += [
            (b"tailscale-user-login", spoofed), (b"tailscale-user-name", b"Synthetic Both"),
            (b"x-forwarded-user", spoofed), (b"x-remote-user", spoofed),
            (b"x-forwarded-for", b"100.64.0.1"),
        ]
        header_sets["anonymous"] = []

        async def scenario():
            baseline = await asgi(application, "/", headers=())
            websocket_baseline = await asgi(application, "/api/live/stream", kind="websocket")
            for name, headers in header_sets.items():
                for path in HUMAN_PATHS:
                    for method in METHODS:
                        result = await asgi(application, path, method=method, headers=headers)
                        self.assertEqual(baseline, result, (name, path, method))
                result = await asgi(application, "/api/live/stream", headers=headers, kind="websocket")
                self.assertEqual(websocket_baseline, result, name)
            return baseline, websocket_baseline

        baseline, websocket_baseline = asyncio.run(scenario())
        self.assertEqual(404, baseline[0]["status"])
        self.assertEqual(b'{"detail":"Not Found"}', baseline[1]["body"])
        self.assertIn((b"cache-control", b"no-store"), baseline[0]["headers"])
        self.assertEqual([{"type": "websocket.close", "code": 1008}], websocket_baseline)
        # Nothing, including the injected permissive authorizer, was consulted.
        self.assertEqual(0, permit.calls)
        self.assertFalse(application.routes)


if __name__ == "__main__":
    unittest.main()
