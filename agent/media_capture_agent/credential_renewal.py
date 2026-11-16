"""When to renew the node credential, and its install (Issue #109).

The ingest session (``ingest_session``) carries the request and the reply on
the connection the heartbeat opened; this module decides when a request is
due and installs an issued certificate. It holds no connection and opens
none.

* Timing is ``node_tls.RenewalSchedule`` (Owner decision 2026-09-30): from 30
  days before the installed certificate expires, retried after a failure
  with a back-off from 1 hour doubling to 24 hours. Every outcome other than
  an installed certificate is a failure for that back-off: a refusal by the
  Main, a lost or late reply, a pairing CLI holding the runtime-wide lock
  (``enrollment_in_progress``, which ``RenewalSchedule`` says to treat as
  transient), or a certificate that does not install.
* The request is ``node_tls.prepare_renewal``: one fresh key kept 0600 in
  ``pending-renewal/`` across retries, so a retry after a lost reply uses the
  same key and the Main answers it with the certificate it already staged.
* An issued certificate is installed by ``node_tls.complete_renewal`` as a
  new credential generation (same node and deployment, the installed CA, the
  pending key, outliving the current certificate); the ingest session then
  reconnects with it, which promotes it on the Main.

The installed generation is looked at again at most every
``GENERATION_CHECK_SECONDS`` (PR #425 review): a credential installed while
the service runs by another path (``enroll pair --repair expired`` after an
expiry, a rotation) re-reads the expiry and starts the schedule afresh, so a
new certificate never expires unnoticed until the service restarts.

``node_tls`` needs ``cryptography``. The service runs on the system
interpreter and must start without it (``StdlibOnlyServiceTests``), so it is
imported only here and only at the first check; without it renewal is off
with the fixed status ``renewal_dependency_unavailable`` and the node goes on
with its current credential. ``status`` is one fixed word (or ``None``) for
the service's status line; nothing here logs, and no key, CSR or certificate
byte is kept beyond the call that uses it.
"""
from __future__ import annotations

import datetime
import time
from typing import Callable


GENERATION_CHECK_SECONDS = 60.0


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _node_tls():
    from . import node_tls
    return node_tls


class CredentialRenewal:
    def __init__(self, store, *, clock: Callable[[], datetime.datetime] = _utc_now,
                 tls: Callable[[], object] = _node_tls,
                 monotonic: Callable[[], float] = time.monotonic):
        if not callable(clock) or not callable(tls) or not callable(monotonic):
            raise ValueError("invalid credential renewal dependencies")
        self._store = store
        self._clock = clock
        self._load_tls = tls
        self._tls = None
        self._unavailable = False
        self._expiry: datetime.datetime | None = None
        self._failures = 0
        self._retry_at: datetime.datetime | None = None
        # The installed generation the expiry belongs to (its certificate
        # file name), and when it was last looked at.
        self._monotonic = monotonic
        self._generation: str | None = None
        self._generation_checked: float | None = None
        # One fixed word for the status line, or None (nothing to report).
        self.status: str | None = None

    def due(self) -> bytes | None:
        """The CSR PEM to send now, or None (not due, backing off, or unable)."""
        tls = self._module()
        if tls is None:
            return None
        self._check_generation(tls)
        now = self._clock()
        if self._retry_at is not None and now < self._retry_at:
            return None
        expiry = self._installed_expiry(tls)
        if expiry is None:
            # Not readable now; looked at again after the first back-off.
            self._retry_at = now + tls.RENEWAL_FIRST_RETRY
            return None
        start = tls.RenewalSchedule.next_attempt(now, expiry, 0)
        if start is None:
            # Expired: only re-pairing helps (`enroll pair --repair expired`).
            self.status = "renewal_credential_expired"
            return None
        if now < start:
            return None
        try:
            request = tls.prepare_renewal(self._store)
        except tls.PairingRefused as refused:
            self.failed("renewal_pairing_in_progress" if str(refused) == "enrollment_in_progress"
                        else "renewal_key_unavailable")
            return None
        self.status = "renewal_requested"
        return request.csr_pem

    def issued(self, certificate_pem: bytes) -> bool:
        """Install an issued certificate as a new generation; True if installed."""
        tls = self._module()
        if tls is None:
            return False
        try:
            tls.complete_renewal(self._store, certificate_pem)
        except tls.PairingRefused as refused:
            self.failed("renewal_pairing_in_progress" if str(refused) == "enrollment_in_progress"
                        else "renewal_install_failed")
            return False
        self._failures = 0
        self._retry_at = None
        self._expiry = None
        # The next check reads the new generation (and so its expiry).
        self._generation = None
        self._generation_checked = None
        self.status = "renewal_installed"
        return True

    def failed(self, reason: str) -> None:
        """One failed attempt (a fixed word); the next waits per the schedule."""
        self.status = reason
        self._failures = min(self._failures + 1, 64)
        tls = self._tls
        expiry = self._expiry
        if tls is None or expiry is None:
            return
        self._retry_at = tls.RenewalSchedule.next_attempt(self._clock(), expiry, self._failures)

    # -- internals ---------------------------------------------------------

    def _module(self):
        if self._tls is None and not self._unavailable:
            try:
                self._tls = self._load_tls()
            except ImportError:
                self._unavailable = True
                self.status = "renewal_dependency_unavailable"
        return self._tls

    def _check_generation(self, tls) -> None:
        """Start afresh if another generation was installed since the expiry was read."""
        now = self._monotonic()
        if (self._generation_checked is not None
                and 0 <= now - self._generation_checked < GENERATION_CHECK_SECONDS):
            return
        self._generation_checked = now
        try:
            generation = tls.installed_credential(self._store).certificate_path.name
        except tls.PairingRefused:
            # `_installed_expiry` reports it.
            return
        if generation == self._generation:
            return
        if self._generation is not None:
            # Installed by another path while the service runs.
            self._expiry = None
            self._failures = 0
            self._retry_at = None
            self.status = None
        self._generation = generation

    def _installed_expiry(self, tls) -> datetime.datetime | None:
        if self._expiry is None:
            try:
                self._expiry = tls.installed_certificate_expiry(self._store)
            except tls.PairingRefused:
                self.status = "renewal_credential_unavailable"
                return None
        return self._expiry
