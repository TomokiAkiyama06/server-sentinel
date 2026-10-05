"""Automatic capture-node certificate renewal and expiry signals (Issue #13).

Owner decision 2026-09-30: node certificates default to 397 days and renew
automatically. The Agent starts renewing ``RENEWAL_WINDOW`` (30 days) before
expiry, generating a fresh key and CSR and sending it over its current,
ledger-admitted mTLS session. This module is the Main side of that exchange:

* ``renew_node_credential`` issues a certificate only for the node identity of
  the authenticated session, only while that exact credential is still the
  ledger's active one and unexpired, and only for a fresh EC P-256 key whose
  CSR requests no subject or extension. It stages the new certificate in the
  ledger. Revoked, expired, superseded or unknown credentials cannot renew and
  must re-pair.
* Supersession: the old certificate stays admitted until the new one is first
  presented; that first admission atomically promotes the new credential and
  the old certificate is no longer admitted, even though it has not expired.
  This keeps exactly one active credential per node (so revocation and audit
  stay per node) while never locking out an Agent that failed to receive or
  install the response: it keeps using the old certificate and retries.
* ``CaptureCredentialMonitor`` turns ledger expiry state and renewal refusals
  into Owner-visible local ``capture_credential_warning`` notifications through
  an injected hook. A renewal refused because the deployment CA expires before
  the requested leaf would (``renewal_ca_validity_insufficient``, Issue #127)
  is not a node problem: it raises the deployment-wide
  ``capture_trust_warning`` instead, as do an expiring CA and an expiring Main
  listener certificate when the monitor is given their expiry.

No listener or wire protocol is added here; #14/#15 carry the renewal request
over the ingest session.
"""
from __future__ import annotations

from dataclasses import dataclass
import datetime
from typing import Callable
from uuid import UUID, uuid5

from app.notifications.service import NotificationKind
from app.notifications.slack import DeliveryResult

from .ingest_tls import CaptureNodeAdmission, CaptureNodeIdentity
from .node_ca import (
    DEFAULT_NODE_VALIDITY, AuthorityValidityExceeded, CaptureAuthorityError, DeploymentAuthority,
    IssuedNodeCredential,
)
from .pairing import PairingError, PairingLedger


RENEWAL_WINDOW = datetime.timedelta(days=30)
# Warn the Owner if a credential is this close to expiry and still not renewed:
# the Agent has then retried for at least 16 days (see agent RenewalSchedule).
EXPIRY_WARNING_WINDOW = datetime.timedelta(days=14)
# Warn this long before the deployment CA stops covering a default-validity
# node leaf, and before the Main listener certificate expires (the Owner
# rotates it with ``pairing_cli rotate-listener``).
TRUST_WARNING_LEAD = datetime.timedelta(days=30)
CA_VALIDITY_REFUSAL = "renewal_ca_validity_insufficient"
_MAX_REMEMBERED_SIGNALS = 1024
# Hook results that confirm the warning was recorded locally (or retained by
# NotificationService for its own retry). FAILED, any other value, or an
# exception means it was not, and the warning stays unreported.
_CONFIRMED = frozenset({DeliveryResult.SUPPRESSED, DeliveryResult.PENDING,
                        DeliveryResult.SENT, DeliveryResult.DISABLED})
_WARNING_NAMESPACE = UUID("6f1d2c1e-5b8a-4d55-9a57-0c9b0e3f7a21")


class RenewalRefused(RuntimeError):
    """Fixed refusal reason; never contains key, CSR or certificate bytes."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def renew_node_credential(authority: DeploymentAuthority, ledger: PairingLedger,
                          admission: CaptureNodeAdmission, identity: CaptureNodeIdentity,
                          csr_pem: bytes, *,
                          validity: datetime.timedelta = DEFAULT_NODE_VALIDITY,
                          clock: Callable[[], datetime.datetime] = _utc_now,
                          monitor: "CaptureCredentialMonitor | None" = None
                          ) -> IssuedNodeCredential:
    """Issue and stage a renewal for the authenticated session's own node."""
    try:
        if not isinstance(identity, CaptureNodeIdentity):
            raise RenewalRefused("renewal_identity_invalid")
        now = clock()
        if identity.not_valid_after <= now:
            raise RenewalRefused("renewal_credential_expired")
        if not admission.is_admitted(identity):
            raise RenewalRefused("renewal_credential_not_admitted")
        try:
            issued = authority.issue_renewal_certificate(identity.node_id, csr_pem,
                                                         validity=validity)
        except AuthorityValidityExceeded:
            # The CSR was valid; the deployment CA expires before the leaf
            # would. Not the node's fault, and not fixed by retrying.
            raise RenewalRefused(CA_VALIDITY_REFUSAL) from None
        except CaptureAuthorityError:
            raise RenewalRefused("renewal_request_invalid") from None
        try:
            ledger.stage_renewal(node_id=identity.node_id,
                                 current_public_key_digest=identity.public_key_digest,
                                 current_credential_digest=identity.credential_digest,
                                 public_key_digest=issued.public_key_digest,
                                 credential_serial_digest=issued.credential_digest,
                                 not_after=issued.not_after.timestamp())
        except (PairingError, ValueError):
            raise RenewalRefused("renewal_not_eligible") from None
        return issued
    except RenewalRefused as refusal:
        if monitor is not None:
            monitor.renewal_refused(identity if isinstance(identity, CaptureNodeIdentity) else None,
                                    refusal.reason)
        raise


@dataclass(frozen=True)
class CredentialSignal:
    """What the monitor reported; contains a node UUID and fixed reason only."""

    node_id: UUID | None
    reason: str


class CaptureCredentialMonitor:
    """Raises Owner-visible local warnings for expiring or unrenewable node credentials.

    ``notify(kind, at=..., event_id=...)`` is the injected existing
    notification hook, normally ``NotificationService.record``. It must return
    a ``DeliveryResult``; only SUPPRESSED, PENDING, SENT or DISABLED confirm
    that the warning was recorded locally (or retained by the service for its
    own retry). FAILED, any other value, or an exception leaves the warning
    unreported, and the next check or refusal retries it with the same
    deterministic ``event_id`` so the local sink upserts instead of
    duplicating. Each (node, reason, expiry) is reported once per process
    once confirmed; the remembered set is bounded.

    ``ca_not_after`` (the deployment CA expiry) and ``listener_not_after``
    (the Main listener certificate expiry) are optional. When given,
    ``check`` also raises ``capture_trust_warning`` once the CA can no longer
    cover a ``node_validity`` leaf within ``TRUST_WARNING_LEAD``
    (``deployment_ca_expiring``), no longer covers one at all
    (``deployment_ca_validity_insufficient``) or has expired, and once the
    listener certificate is within ``TRUST_WARNING_LEAD`` of expiry or expired.
    """

    def __init__(self, ledger: PairingLedger,
                 notify: Callable[..., object], *,
                 warning_window: datetime.timedelta = EXPIRY_WARNING_WINDOW,
                 clock: Callable[[], datetime.datetime] = _utc_now,
                 ca_not_after: datetime.datetime | None = None,
                 listener_not_after: datetime.datetime | None = None,
                 node_validity: datetime.timedelta = DEFAULT_NODE_VALIDITY):
        if not isinstance(ledger, PairingLedger) or not callable(notify):
            raise ValueError("invalid credential monitor dependency")
        if not isinstance(warning_window, datetime.timedelta) or warning_window <= datetime.timedelta(0):
            raise ValueError("invalid credential warning window")
        if not isinstance(node_validity, datetime.timedelta) or node_validity <= datetime.timedelta(0):
            raise ValueError("invalid credential warning window")
        for value in (ca_not_after, listener_not_after):
            if value is not None and (not isinstance(value, datetime.datetime)
                                      or value.tzinfo is None):
                raise ValueError("invalid trust expiry")
        self._ledger = ledger
        self._notify = notify
        self._window = warning_window
        self._clock = clock
        self._ca_not_after = ca_not_after
        self._listener_not_after = listener_not_after
        self._node_validity = node_validity
        self._reported: set[tuple] = set()
        self.signals: list[CredentialSignal] = []
        self.notification_failed = False

    def _signal(self, key: tuple, signal: CredentialSignal, at: datetime.datetime, *,
                kind: NotificationKind = NotificationKind.CAPTURE_CREDENTIAL_WARNING) -> None:
        if key in self._reported:
            return
        event_id = uuid5(_WARNING_NAMESPACE, repr(key))
        try:
            result = self._notify(kind, at=at, event_id=event_id)
        except Exception:
            result = None
        if result not in _CONFIRMED:
            # Not marked reported: the next check or refusal retries it, with
            # the same event_id so a retry upserts rather than duplicates.
            self.notification_failed = True
            return
        if len(self._reported) >= _MAX_REMEMBERED_SIGNALS:
            self._reported.clear()
        self._reported.add(key)
        self.signals = (self.signals + [signal])[-_MAX_REMEMBERED_SIGNALS:]

    def check(self) -> tuple[CredentialSignal, ...]:
        """Report credentials inside the warning window or already expired."""
        now = self._clock()
        found = list(self._check_trust(now))
        try:
            expiries = self._ledger.credential_expiries()
        except PairingError:
            signal = CredentialSignal(None, "credential_state_unavailable")
            self._signal(("unavailable", now.date()), signal, now)
            return tuple(found) + (signal,)
        for entry in expiries:
            expires = datetime.datetime.fromtimestamp(entry.not_after, datetime.timezone.utc)
            if expires <= now:
                reason = "credential_expired"
            elif expires - now <= self._window:
                reason = "credential_expiring_without_renewal"
            else:
                continue
            signal = CredentialSignal(entry.node_id, reason)
            found.append(signal)
            self._signal((entry.node_id, reason, entry.not_after), signal, now)
        return tuple(found)

    def _check_trust(self, now: datetime.datetime) -> tuple[CredentialSignal, ...]:
        found = []
        if self._ca_not_after is not None:
            remaining = self._ca_not_after - now
            if remaining <= datetime.timedelta(0):
                reason = "deployment_ca_expired"
            elif remaining < self._node_validity:
                reason = "deployment_ca_validity_insufficient"
            elif remaining < self._node_validity + TRUST_WARNING_LEAD:
                reason = "deployment_ca_expiring"
            else:
                reason = None
            if reason is not None:
                found.append(self._trust_signal(reason, self._ca_not_after, now))
        if self._listener_not_after is not None:
            remaining = self._listener_not_after - now
            reason = ("listener_certificate_expired" if remaining <= datetime.timedelta(0)
                      else "listener_certificate_expiring" if remaining <= TRUST_WARNING_LEAD
                      else None)
            if reason is not None:
                found.append(self._trust_signal(reason, self._listener_not_after, now))
        return tuple(found)

    def _trust_signal(self, reason: str, expiry: datetime.datetime,
                      now: datetime.datetime) -> CredentialSignal:
        signal = CredentialSignal(None, reason)
        self._signal(("trust", reason, expiry.timestamp()), signal, now,
                     kind=NotificationKind.CAPTURE_TRUST_WARNING)
        return signal

    def renewal_refused(self, identity: CaptureNodeIdentity | None, reason: str) -> None:
        now = self._clock()
        if reason == CA_VALIDITY_REFUSAL:
            # Deployment-wide: one warning per day, not one per node.
            self._signal(("trust", "renewal_ca_validity_insufficient", now.date()),
                         CredentialSignal(None, "deployment_ca_validity_insufficient"), now,
                         kind=NotificationKind.CAPTURE_TRUST_WARNING)
            return
        node = identity.node_id if identity is not None else None
        self._signal((node, "renewal_refused", reason, now.date()),
                     CredentialSignal(node, "renewal_refused"), now)
