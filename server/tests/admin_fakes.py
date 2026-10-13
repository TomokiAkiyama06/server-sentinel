"""Synthetic Owner sessions for access-administration tests (Issue #10 phase 2 S4).

No real person, device or credential: the Owner, its credential id, public
key and session token below are generated placeholders. The session is made
fresh the way a sign-in makes it (a verification time read with the boot
pair inside the establishing transaction), then authorized for ``OWNER_OP``
exactly as the human surface does, so the ``OwnerOperationContext`` carries a
real ``SessionView``.
"""

from contextlib import nullcontext
import os
from uuid import UUID, uuid4

from app.auth.model import PrincipalRole, PrincipalStatus
from app.auth.owner_operation import OwnerOperationContext
from app.auth.serving_gate import ServingGate
from app.auth.store import AccessStore, Requirement, _us

from tests.webauthn_fakes import OpenGate


OWNER_IDENTITY = "synthetic-owner@example.invalid"
OWNER_CREDENTIAL = b"synthetic-owner-credential-identifier"


def open_serving_gate(gate=None, stopped=lambda: False) -> ServingGate:
    """A ``ServingGate`` over a synthetic always-open gate (epoch ``0``)."""
    return ServingGate(OpenGate() if gate is None else gate, stopped=stopped)


def owner_session(store: AccessStore, *, identity: str = OWNER_IDENTITY,
                  credential_id: bytes = OWNER_CREDENTIAL, fresh: bool = True) -> bytes:
    """Create (once) the active synthetic Owner and a new session of it; return its token."""
    token = os.urandom(32)
    with store._transaction(write=True) as connection:
        at = store.now()
        row = connection.execute("SELECT id FROM access_principals WHERE role='owner'").fetchone()
        if row is None:
            owner = uuid4()
            connection.execute("INSERT INTO access_principals VALUES (?, NULL, ?, ?, ?, 0, ?, NULL)",
                               (str(owner), "Synthetic Owner", PrincipalRole.OWNER.value,
                                PrincipalStatus.ACTIVE.value, _us(at)))
        else:
            owner = UUID(row["id"])
        if connection.execute("SELECT 1 FROM access_credentials WHERE credential_id=?",
                              (credential_id,)).fetchone() is None:
            connection.execute(
                "INSERT INTO access_credentials (credential_id, principal_id, public_key, algorithm, sign_count, "
                "enrolled_at_us, handle) VALUES (?, ?, ?, -7, 0, ?, ?)",
                (credential_id, str(owner), b"synthetic-owner-public-key", _us(at), str(uuid4())))
        store.establish_session_on(connection, owner, credential_id, token, proxy_identity=identity, at=at,
                                   verified_at=at if fresh else None,
                                   verified_boot=store._boot_instant() if fresh else None)
    return token


def owner_context(store: AccessStore, *, epoch: int = 0, identity: str = OWNER_IDENTITY,
                  admit=None, **options) -> OwnerOperationContext:
    """The ``OwnerOperationContext`` of a fresh synthetic Owner session."""
    token = owner_session(store, identity=identity, **options)
    view = store.authorize_request(token, identity, Requirement.OWNER_OP,
                                   admit=admit or (lambda: nullcontext()))
    return OwnerOperationContext(view, epoch)


class StoreAdministration:
    """Fixture stand-in for ceremony tests: applies the store's ``*_on`` mutations directly.

    No Owner authorization, gate or audit record: the tests that use it are
    about ceremonies and sessions, and ``AccessAdministration`` itself is
    covered by ``test_access_administration`` / ``test_access_pairing_audit``.
    A credential is named by its id here and translated to its handle.
    """

    def __init__(self, store: AccessStore):
        self.store = store

    def _run(self, operation):
        with self.store._transaction(write=True) as connection:
            return operation(connection, self.store.now())

    def revoke_principal(self, _actor, principal_id):
        return self._run(lambda connection, at: self.store.revoke_principal_on(connection, principal_id, at=at))

    def revoke_credential(self, _actor, principal_id, credential_id):
        def revoke(connection, at):
            handle = connection.execute("SELECT handle FROM access_credentials WHERE credential_id=?",
                                        (credential_id,)).fetchone()[0]
            return self.store.revoke_credential_on(connection, principal_id, handle, at=at)
        return self._run(revoke)

    def set_permissions(self, _actor, principal_id, permissions):
        return self._run(lambda connection, at: self.store.set_permissions_on(
            connection, principal_id, permissions, at=at))


def viewer_context(store: AccessStore, principal_id: UUID, credential_id: bytes, identity: str,
                   *, epoch: int = 0) -> OwnerOperationContext:
    """A context around a non-Owner session view (what no surface ever builds)."""
    token = os.urandom(32)
    store.establish_session(principal_id, credential_id, token, proxy_identity=identity)
    view = store.authorize_request(token, identity, Requirement.SESSION, admit=lambda: nullcontext())
    return OwnerOperationContext(view, epoch)
