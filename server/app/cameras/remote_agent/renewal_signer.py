"""Renewal-only capture-node signer (ADR-0006, Issue #109 PR2).

Owner decision 2026-10-07 ("Plan B"): automatic renewal is signed by a
socket-activated, synchronous signer that runs as the static CA account
``serversentinel-ca``. It accepts exactly one request type, ``renew``; it
has no enrollment, listener, CA-creation or revocation request. The service
process (which owns the application database and serves the ingest
listener) never loads the CA private key: it sends the signer the node's
currently presented certificate and the renewal CSR over a local Unix
socket and verifies the answer against the public CA certificate.

The signer does not read the application ledger (the database keeps its
0700 service-account directory). It decides from the certificate chain and
the CA-only issuance log (``issuer_process.IssuanceLog``) alone:

* the presented certificate must be a currently valid node leaf this CA
  signed for exactly that node (fixed clientAuth profile, node and
  deployment URIs), recorded in the issuance log, and within
  ``RENEWAL_SIGNING_WINDOW`` of its expiry;
* it must not be superseded in the log: every later record of that node
  must be a renewal of exactly this certificate (an Agent that lost a
  renewal answer may ask again with the same certificate) or a sibling
  renewal of the same parent (two requests signed before either was staged;
  the ledger keeps one, which must stay renewable). A re-enrollment or a
  renewal of a sibling supersedes it;
* the node must not be revoked in the log, and the new key must be fresh:
  not the presented key, not recorded for another or a revoked node, and
  recorded for this node only as an earlier renewal of the same
  certificate (a retry);
* rate limits from the log (Owner default 2026-10-07): per node at most one
  renewal signature per ``MIN_NODE_RENEWAL_INTERVAL`` (50 minutes; a
  same-key retry of a renewal of the same certificate is exempt from this
  interval only, Owner decision 2026-11-16) and
  ``MAX_NODE_RENEWALS`` (48) per ``RATE_PERIOD`` (30 days); deployment-wide
  ``MAX_DEPLOYMENT_RENEWALS_PER_DAY`` and ``MAX_DEPLOYMENT_RENEWALS``.

It then signs one fixed-profile clientAuth leaf (``DEFAULT_NODE_VALIDITY``;
the caller cannot choose validity, subject or extensions), appends a ``node``
record with ``renewal_of`` (the presented certificate's digest) to the log
with fsync, and only then answers. An unwritable log means nothing is signed.

What a compromised service can still obtain is bounded and recorded: renewal
certificates for existing, unrevoked nodes whose logged current certificate
is near expiry, for keys it chooses, within the rate limits. It can never
read the CA key, obtain a serverAuth or CA certificate, or a certificate for
a node the CA never enrolled. The Agent's proof with its old key is deferred
(Owner decision 2026-10-07), so the signer cannot tell the real Agent from
the compromised service for such a node.

Process model (``infra/systemd/serversentinel-renewal-signer.socket`` and
``serversentinel-renewal-signer@.service``): systemd owns the listening
socket (``Accept=yes``) and starts one short-lived instance per connection,
as the CA account, with the connection on stdin/stdout. The instance checks
the peer's ``SO_PEERCRED`` uid against the service account, answers one
request and exits; no CA process stays alive between renewals.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import datetime
import hmac
import os
from pathlib import Path
import socket
import struct
import time
from typing import Callable, Iterator
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .ingest_tls import CaptureNodeIdentity
from .issuer_process import (
    Account, IssuanceLog, IssuerUnavailable, PrivilegeSeparationError, read_frame,
    verify_dropped, write_frame,
    _PR_SET_DUMPABLE, _PR_SET_NO_NEW_PRIVS, _prctl, _text, _uuid,
)
from .node_ca import (
    DEFAULT_NODE_VALIDITY, MAX_CSR_BYTES, MAX_PEM_BYTES, AuthorityValidityExceeded,
    CaptureAuthorityError, DeploymentAuthority, DeploymentTrust, IssuedNodeCredential,
    IssuerMaterialBusy, IssuerRefusedRequest, PrivateDirectory, certificate_digest,
    deployment_id_of, public_key_digest,
)


RENEWAL_SIGNER_SOCKET = Path("/run/serversentinel-renewal-signer.sock")
RENEWAL_OPERATION = "renew"
# The Agent starts renewing 30 days before expiry (agent RenewalSchedule);
# one more day tolerates clock skew between the Agent and the Main.
RENEWAL_SIGNING_WINDOW = datetime.timedelta(days=31)
MIN_NODE_RENEWAL_INTERVAL = datetime.timedelta(minutes=50)
RATE_PERIOD = datetime.timedelta(days=30)
MAX_NODE_RENEWALS = 48
# Deployment-wide caps (MVP: at most 4 active sources, so 4 nodes x 48).
MAX_DEPLOYMENT_RENEWALS = 192
MAX_DEPLOYMENT_RENEWALS_PER_DAY = 24
# A renewal waits this long for a CA conversation of the pairing CLI (or
# another renewal) to end before it is refused ``issuer_material_busy``.
LOCK_WAIT_SECONDS = 5.0
REQUEST_TIMEOUT_SECONDS = 10.0
CLIENT_TIMEOUT_SECONDS = 30.0
_REQUEST_FIELDS = frozenset({"op", "node_id", "current_certificate", "csr"})
_PEER_CREDENTIALS = struct.Struct("3i")

# Signer refusals the service reports as a policy refusal of this request;
# every other word (busy, unreadable log, broken CA material, transport) is
# the signer being unavailable.
_POLICY_REFUSALS = frozenset({"issuer_refused_request", "renewal_rate_limited",
                              "renewal_not_due", "renewal_signer_peer_refused"})


class RenewalRateLimited(IssuerRefusedRequest):
    reason = "renewal_rate_limited"


class RenewalNotDue(IssuerRefusedRequest):
    reason = "renewal_not_due"


class SignerNotSocketActivated(CaptureAuthorityError):
    reason = "renewal_signer_not_socket_activated"


class RenewalSignerUnavailable(CaptureAuthorityError):
    """The signer could not be reached or could not decide; nothing was issued."""

    reason = "renewal_signer_unavailable"

    def __init__(self, message: str, detail: str | None = None):
        super().__init__(message)
        self.detail = detail


class RenewalSignerRefused(CaptureAuthorityError):
    """The signer refused this renewal from its own log and policy."""

    reason = "renewal_signer_refused"

    def __init__(self, message: str, detail: str | None = None):
        super().__init__(message)
        self.detail = detail


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _fixed_word(value: object) -> str | None:
    if (isinstance(value, str) and 0 < len(value) <= 64 and value.isascii()
            and value.replace("_", "").isalpha() and value.islower()):
        return value
    return None


# ---------------------------------------------------------------------------
# CA side


def _record_time(record: dict) -> datetime.datetime:
    try:
        moment = datetime.datetime.fromisoformat(record["at"])
    except (KeyError, TypeError, ValueError):
        raise CaptureAuthorityError("issuer log is invalid") from None
    if moment.tzinfo is None:
        raise CaptureAuthorityError("issuer log is invalid")
    return moment


class RenewalSigner:
    """Decides and signs one renewal from the chain and the CA-only log.

    Runs only in the CA account. ``handle`` takes the CA directory lock
    (waiting up to ``lock_wait`` seconds for a pairing CLI conversation),
    loads the CA, decides, signs, logs and returns a reply frame; it never
    raises and never returns anything but a fixed word or a certificate.
    """

    def __init__(self, directory: PrivateDirectory, *,
                 clock: Callable[[], datetime.datetime] = _utc_now,
                 lock_wait: float = LOCK_WAIT_SECONDS,
                 sleep: Callable[[float], None] = time.sleep):
        self._directory = directory
        self._clock = clock
        self._log = IssuanceLog(directory, clock=clock)
        self._lock_wait = lock_wait
        self._sleep = sleep

    def handle(self, message: object) -> dict:
        try:
            node, current, csr = self._parse(message)
            with self._locked():
                authority = DeploymentAuthority.load(self._directory,
                                                     deployment_id_of(self._directory),
                                                     clock=self._clock)
                return self._renew(authority, node, current, csr)
        except CaptureAuthorityError as error:
            return {"status": "refused", "reason": error.reason}
        except Exception:
            return {"status": "refused", "reason": IssuerUnavailable.reason}

    @staticmethod
    def _parse(message: object) -> tuple[UUID, bytes, bytes]:
        # Exactly the renewal fields: no validity, profile or other operation.
        if (not isinstance(message, dict) or set(message) != _REQUEST_FIELDS
                or message["op"] != RENEWAL_OPERATION):
            raise IssuerRefusedRequest("renewal request is invalid")
        return (_uuid(message["node_id"]),
                _text(message["current_certificate"], maximum=MAX_PEM_BYTES),
                _text(message["csr"], maximum=MAX_CSR_BYTES))

    @contextmanager
    def _locked(self) -> Iterator[None]:
        deadline = time.monotonic() + self._lock_wait
        with ExitStack() as stack:
            while True:
                try:
                    stack.enter_context(self._directory.locked())
                    break
                except IssuerMaterialBusy:
                    if time.monotonic() >= deadline:
                        raise
                    self._sleep(0.05)
            yield

    def _renew(self, authority: DeploymentAuthority, node: UUID, current_pem: bytes,
               csr: bytes) -> dict:
        # Directly issued by this CA, fixed clientAuth profile, exactly this
        # node's and deployment's URIs, and currently valid.
        try:
            presented = x509.load_pem_x509_certificate(current_pem)
            current = authority.verify_issued_node_certificate(
                current_pem, node_id=node,
                public_key_digest_value=public_key_digest(presented.public_key()))
        except (ValueError, TypeError, CaptureAuthorityError):
            raise IssuerRefusedRequest("presented certificate is invalid") from None
        now = self._clock()
        if current.not_after - now > RENEWAL_SIGNING_WINDOW:
            raise RenewalNotDue("presented certificate is not due for renewal")
        try:
            new_key = DeploymentTrust.renewal_key_digest(csr)
        except CaptureAuthorityError:
            raise IssuerRefusedRequest("renewal request is invalid") from None
        records = self._log.records()
        retry = self._require_current(records, node, current, new_key)
        self._require_rate(records, node, now, retry=retry)
        issued = authority.issue_renewal_certificate(node, csr, validity=DEFAULT_NODE_VALIDITY)
        self._log.append({"type": "node", "node_id": str(node),
                          "public_key_digest": issued.public_key_digest,
                          "credential_digest": issued.credential_digest,
                          "not_after": issued.not_after.isoformat(timespec="seconds"),
                          "renewal_of": current.credential_digest})
        return {"status": "ok", "certificate": issued.certificate_pem.decode("ascii")}

    @staticmethod
    def _require_current(records: list[dict], node: UUID, current: IssuedNodeCredential,
                         new_key: str) -> bool:
        """Refuse unless ``current`` may renew to ``new_key``; True for a same-key retry."""
        name = str(node)
        if any(record["type"] == "node_revocation" and record["node_id"] == name
               for record in records):
            raise IssuerRefusedRequest("node is revoked at the issuer")
        position = None
        for index, record in enumerate(records):
            if (record["type"] == "node" and record["node_id"] == name
                    and hmac.compare_digest(record.get("credential_digest", ""),
                                            current.credential_digest)):
                position = index
        if position is None:
            # Not issued under the issuance log (for example before Issue #109).
            raise IssuerRefusedRequest("presented certificate is not in the issuance log")
        # Later records of this node that do not supersede it: renewals of
        # this certificate (a lost answer asked again) and sibling renewals of
        # the same parent (two requests signed before either was staged; the
        # ledger keeps one of them, so each must stay renewable). Anything
        # else -- a re-enrollment (no ``renewal_of``) or a renewal of a
        # sibling -- supersedes it.
        allowed = {current.credential_digest}
        parent = records[position].get("renewal_of")
        if parent is not None:
            allowed.add(parent)
        for record in records[position + 1:]:
            if (record["type"] == "node" and record["node_id"] == name
                    and record.get("renewal_of") not in allowed):
                raise IssuerRefusedRequest("presented certificate is superseded")
        if hmac.compare_digest(new_key, current.public_key_digest):
            raise IssuerRefusedRequest("renewal requires a fresh key")
        retry = False
        for record in records:
            if record["type"] != "node" or not hmac.compare_digest(record["public_key_digest"],
                                                                   new_key):
                continue
            # Only an earlier renewal of this same certificate may carry the key
            # (a retry whose staging failed); any other binding refuses.
            if record["node_id"] != name or record.get("renewal_of") != current.credential_digest:
                raise IssuerRefusedRequest("key is bound at the issuer")
            retry = True
        return retry

    @staticmethod
    def _require_rate(records: list[dict], node: UUID, now: datetime.datetime, *,
                      retry: bool) -> None:
        name = str(node)
        renewals = [(record["node_id"], _record_time(record)) for record in records
                    if record["type"] == "node" and "renewal_of" in record]
        # A record time after ``now`` (the clock moved back) counts as recent.
        mine = [moment for owner, moment in renewals if owner == name]
        # A same-key retry (Owner decision 2026-11-16) only re-signs a key the
        # log already gave this node for this certificate, so it skips the
        # interval; it still counts toward, and is refused at, every cap.
        if not retry and any(now - moment < MIN_NODE_RENEWAL_INTERVAL for moment in mine):
            raise RenewalRateLimited("node renewed too recently")
        if sum(now - moment < RATE_PERIOD for moment in mine) >= MAX_NODE_RENEWALS:
            raise RenewalRateLimited("node renewal limit reached")
        if sum(now - moment < RATE_PERIOD for _, moment in renewals) >= MAX_DEPLOYMENT_RENEWALS:
            raise RenewalRateLimited("deployment renewal limit reached")
        day = datetime.timedelta(days=1)
        if sum(now - moment < day for _, moment in renewals) >= MAX_DEPLOYMENT_RENEWALS_PER_DAY:
            raise RenewalRateLimited("deployment daily renewal limit reached")


def peer_uid(connection: socket.socket) -> int:
    """The connecting process's uid (``SO_PEERCRED``), set by the kernel."""
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEER_CREDENTIALS.size)
    _, uid, _ = _PEER_CREDENTIALS.unpack(raw)
    return uid


def serve_connection(connection: socket.socket, signer: RenewalSigner, *, service_uid: int,
                     timeout: float = REQUEST_TIMEOUT_SECONDS) -> str:
    """Answer one request on an accepted connection; return the fixed outcome word.

    Only the service account may ask: any other peer uid is refused before
    the request is read, so the CA directory is not even opened for it.
    """
    try:
        uid = peer_uid(connection)
    except OSError:
        uid = None
    descriptor = connection.fileno()
    if uid is None or uid != service_uid:
        reply = {"status": "refused", "reason": "renewal_signer_peer_refused"}
    else:
        try:
            message = read_frame(descriptor, timeout=timeout)
        except CaptureAuthorityError:
            return IssuerUnavailable.reason
        if message is None:
            return IssuerUnavailable.reason
        reply = signer.handle(message)
    try:
        write_frame(descriptor, reply)
    except CaptureAuthorityError:
        return IssuerUnavailable.reason
    return "signed" if reply.get("status") == "ok" else reply.get("reason", IssuerUnavailable.reason)


def _connection_from_stdin() -> socket.socket:
    """The accepted connection systemd passed as stdin (``StandardInput=socket``)."""
    try:
        descriptor = os.dup(0)
    except OSError:
        raise SignerNotSocketActivated("renewal signer needs a socket connection") from None
    try:
        connection = socket.socket(fileno=descriptor)
    except OSError:
        os.close(descriptor)
        raise SignerNotSocketActivated("renewal signer needs a socket connection") from None
    if connection.family != socket.AF_UNIX or connection.type != socket.SOCK_STREAM:
        connection.close()
        raise SignerNotSocketActivated("renewal signer needs a socket connection")
    return connection


def run_signer(authority_path: Path, service: Account) -> str:
    """Entry point of one systemd instance, already running as the CA account."""
    if 0 in os.getresuid() or 0 in os.getresgid():
        raise PrivilegeSeparationError("account_must_not_be_root")
    if os.getuid() == service.uid or os.getgid() == service.gid:
        raise PrivilegeSeparationError("ca_account_must_differ_from_service_account")
    try:
        _prctl(_PR_SET_NO_NEW_PRIVS, 1)
        _prctl(_PR_SET_DUMPABLE, 0)
    except OSError:
        raise PrivilegeSeparationError("privilege_drop_failed") from None
    verify_dropped(Account(os.getuid(), os.getgid()))
    with _connection_from_stdin() as connection:
        return serve_connection(connection, RenewalSigner(PrivateDirectory(authority_path)),
                                service_uid=service.uid)


# ---------------------------------------------------------------------------
# Service side


class SignerRenewalIssuer:
    """``renewal.RenewalIssuer`` for one admitted session, backed by the signer.

    Holds only public material: the CA certificate (``DeploymentTrust``,
    never ``DeploymentAuthority``) and the session's presented certificate,
    which must be exactly the certificate ``identity`` was derived from.
    """

    def __init__(self, trust: DeploymentTrust, identity: CaptureNodeIdentity,
                 presented_certificate_der: bytes, *,
                 socket_path: Path = RENEWAL_SIGNER_SOCKET,
                 timeout: float = CLIENT_TIMEOUT_SECONDS,
                 connect: Callable[[Path, float], socket.socket] | None = None):
        if isinstance(trust, DeploymentAuthority) or not isinstance(trust, DeploymentTrust):
            # The service must never hold the signing class (Issue #109).
            raise ValueError("renewal_signer_requires_public_trust")
        if (not isinstance(identity, CaptureNodeIdentity)
                or not isinstance(presented_certificate_der, bytes)
                or not 0 < len(presented_certificate_der) <= MAX_PEM_BYTES):
            raise ValueError("renewal_signer_identity_invalid")
        try:
            presented = x509.load_der_x509_certificate(presented_certificate_der)
        except ValueError:
            raise ValueError("renewal_signer_identity_invalid") from None
        if not hmac.compare_digest(certificate_digest(presented), identity.credential_digest):
            raise ValueError("renewal_signer_identity_invalid")
        self._trust = trust
        self._identity = identity
        self._presented_pem = presented.public_bytes(serialization.Encoding.PEM)
        self._socket_path = Path(socket_path)
        self._timeout = timeout
        self._connect = connect or _connect

    def renewal_key_digest(self, csr_pem: bytes) -> str:
        return self._trust.renewal_key_digest(csr_pem)

    def staged_renewal_credential(self, node_id: UUID, public_key_digest_value: str,
                                  credential_digest: str,
                                  certificate_pem: bytes) -> IssuedNodeCredential:
        return self._trust.staged_renewal_credential(node_id, public_key_digest_value,
                                                     credential_digest, certificate_pem)

    def issue_renewal_certificate(self, node_id: UUID, csr_pem: bytes, *,
                                  validity: datetime.timedelta = DEFAULT_NODE_VALIDITY
                                  ) -> IssuedNodeCredential:
        if node_id != self._identity.node_id:
            raise CaptureAuthorityError("renewal is only for the presenting node")
        if validity != DEFAULT_NODE_VALIDITY:
            # The signer always issues the fixed validity; never ask for another.
            raise CaptureAuthorityError("renewal validity is fixed by the signer")
        key_digest = self._trust.renewal_key_digest(csr_pem)
        reply = self._request({"op": RENEWAL_OPERATION, "node_id": str(node_id),
                               "current_certificate": self._presented_pem.decode("ascii"),
                               "csr": csr_pem.decode("ascii")})
        if reply.get("status") != "ok":
            detail = _fixed_word(reply.get("reason"))
            if detail == AuthorityValidityExceeded.reason:
                raise AuthorityValidityExceeded("certificate validity exceeds the deployment CA")
            if detail in _POLICY_REFUSALS:
                raise RenewalSignerRefused("renewal signer refused the request", detail)
            raise RenewalSignerUnavailable("renewal signer is unavailable", detail)
        certificate = reply.get("certificate")
        if not isinstance(certificate, str) or not certificate.isascii():
            raise RenewalSignerUnavailable("renewal signer answer is invalid")
        try:
            return self._trust.verify_issued_node_certificate(
                certificate.encode("ascii"), node_id=node_id, public_key_digest_value=key_digest)
        except CaptureAuthorityError:
            raise RenewalSignerUnavailable("renewal signer answer is invalid") from None

    def _request(self, message: dict) -> dict:
        try:
            connection = self._connect(self._socket_path, self._timeout)
        except OSError:
            raise RenewalSignerUnavailable("renewal signer is unavailable") from None
        with connection:
            try:
                write_frame(connection.fileno(), message)
                reply = read_frame(connection.fileno(), timeout=self._timeout)
            except CaptureAuthorityError:
                raise RenewalSignerUnavailable("renewal signer is unavailable") from None
        if reply is None:
            raise RenewalSignerUnavailable("renewal signer is unavailable")
        return reply


def _connect(path: Path, timeout: float) -> socket.socket:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(timeout)
        connection.connect(str(path))
        # Frames use select-based deadlines on the raw descriptor.
        connection.setblocking(True)
    except OSError:
        connection.close()
        raise
    return connection
