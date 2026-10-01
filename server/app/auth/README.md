# Human Authorization

Owns owner invitations/allowlists, independent `live:view` and `recordings:view` permissions, owner-only operations, and prompt revocation.

- Accepts Tailscale/trusted-proxy identity only through a non-bypassable local listener boundary; ordinary LAN clients cannot supply trusted identity headers directly.
- Requires application authorization in addition to private-network reachability. Tailnet membership alone grants no access.
- Treats a verified Tailscale/trusted-proxy identity as supplementary: the deployment shares one Tailscale account, so authorization requires the requesting principal's own ServerSentinel credential (WebAuthn/passkey, ADR 0004) on every human route. No route authorizes on an identity header alone.
- Verifies the transient WebAuthn data a registration or assertion carries (challenge, client data, authenticator data, signature, signature counter, user-verification flag, relying-party id and origin) and persists only public credential material, the signature counter, the backup-eligibility and backup-state flags, and owner-visible metadata. No viewer biometric template reaches the server; it never leaves the authenticator.
- Relies on the dashboard owning its browser origin, with no other application sharing it, and on that origin being a secure context (AUTH-012); browsers withhold WebAuthn elsewhere. Reserving the name is a deployment obligation (ADR-0003), and the startup/daily check over real listeners and proxy routes closes human access and notifies the Owner rather than preventing the bind.
- Treats revocation as credential-scoped rather than device-scoped, and persists the last accepted signature counter so the clone check has something to compare against. The comparison runs whenever the stored or received counter is non-zero, so a received 0 after a stored non-zero is a regression; only a stored-and-received 0 is exempt.
- Accepts `none` attestation at registration, verifying the challenge, origin/relying-party id, authenticator data, credential public key and user-verification flag instead; a present-but-invalid attestation statement fails.
- Records the authenticator's backup-eligibility and backup-state flags with the credential so the owner UI can show whether it syncs, and refuses a backup-eligible registration where the deployment requires device-bound credentials. Eligibility is fixed at registration and a differing value in a later assertion is refused and reported; backup state is refreshed from every verified assertion.
- Keeps at most the last observed proxy identity on the principal: optional and non-unique (every holder of the shared account presents the same login), owner-visible, overwritten each authentication, cleared on revocation or deletion, out of diagnostic exports, and never an authorization input. Sessions keep only its deployment-keyed HMAC binding.
- Supports revoking a single credential and revoking a whole principal, and binds sessions to the credential that created them.
- Exposes exactly two pre-credential routes, enrollment-code redemption and authentication; local owner bootstrap is a host-side action that issues an authorization for the same redemption route rather than a third endpoint. They return no application data, redemption is single-use and rate-limited, an absent/unknown/expired/redeemed code gets the uninvited response, and enrollment codes stay out of logs.
- Generates enrollment codes and bootstrap authorizations from a CSPRNG with at least 128 bits of entropy in the checked value, stores only their hash and compares in constant time; lifetime and rate limits bound guessing but do not replace the entropy.
- Requires a fresh user verification for owner-only operations. Freshness comes from the server-side session record, a stale owner session receives a distinct step-up-required response with no other data, and a cancelled or failed step-up changes nothing. Unauthenticated, uninvited and revoked requests keep receiving the generic response.
- Binds the step-up to the session: the challenge allows only `principal_session.credential_id`, and an assertion from any other registered credential is refused without updating the session's verification time.
- Keeps historical events/timeline under `recordings:view` and provides generic, non-branding denial for uninvited identities.
- Does not modify Tailscale ACLs/Grants, store Tailscale administrative credentials, or treat an agent identity as a human/admin identity.
- Separates general human/system access from Owner-only access. `require_owner_access` is an independent gate for Owner-only routes such as diagnostic export; an authorizer that implements no Owner check is denied rather than treated as the Owner.

## Current foundation

ADR-0004 (per-person WebAuthn/passkey credentials) was accepted on 2026-09-30,
alongside ADR-0003. No human route is mounted yet: route mounting stays closed
until the remaining Issue #10 gates pass.

- `webauthn.py` is pure relying-party verification over the Owner-approved
  `cryptography` package, with no WebAuthn/FIDO library. It checks the
  `clientDataJSON` type, challenge, exact origin and cross-origin markers; the
  relying-party id hash; the UP and UV flags; the BE/BS flags (BS without BE is
  malformed); the COSE key (ES256/P-256, EdDSA/Ed25519, RS256 with at least
  2048 bits); `none` attestation, or `packed` self attestation with its
  signature verified; and the assertion signature. Other attestation formats,
  including `packed` with a certificate chain, are refused rather than accepted
  unverified. CBOR parsing is strict and bounded. `RelyingParty` accepts only
  a secure-context origin (`https://host[:port]` or `http://localhost[:port]`)
  whose host equals the relying-party id. An explicit default port (`:443`
  for https, `:80` for http) is refused at construction, because browsers
  serialize `clientDataJSON.origin` without it and the exact comparison could
  never match.
- `passkeys.py` (`PasskeyCeremonies`) composes that verifier with the store:
  invitation redemption (registration), sign-in (authentication) and Owner
  step-up. Every failure before a session exists is one `CeremonyDenied` with
  a fixed message and no chained cause. There are only two distinct outcomes:
  `StepUpRequired`, returned only to a valid but stale Owner session, and
  `DeviceBoundCredentialRequired`, returned only after a verified ceremony
  with a valid invitation, where the deployment requires device-bound
  credentials.
- `store.py` persists challenge digests only. Each challenge is single-use,
  bound to its ceremony, and to its invitation or session where the ceremony
  has one. It is deleted on use or expiry, and a backward clock step refuses
  it. The store also enforces the counter rule, marks a credential whose BE
  changed as inconsistent and revokes that credential's sessions in the same
  transaction, and establishes sessions with the ADR-0003 lifetimes (30 minutes
  idle, 12 hours absolute). A session records its user-verification time, and
  `authorize_owner` enforces the ADR-0003 five-minute step-up freshness. A
  session created by the low-level `establish_session` records no verification
  time, so it is never fresh.
- Shared Tailscale login (ADR-0004 §1, SPECIFICATION §11.4/§11.8): the
  invitation and the passkey credential are the only per-person key. An
  invitation carries no proxy identity, the enrollment secret alone selects
  the invitation, and the discoverable credential alone selects the principal
  at sign-in, so several invited people behind one Tailscale login each
  register and sign in with their own passkey. `access_principals.external_identity`
  is nullable and non-unique (migration 18): it holds only the identity last
  observed at authentication, is overwritten on every sign-in and step-up, is
  cleared on principal revocation, and is never compared with anything.
- Session binding (`session_binding.py`): every ceremony and session check
  requires a present, well-formed trusted-proxy identity (ADR-0003 rejects a
  missing human identity). A session stores only
  `HMAC-SHA-256(key, canonical identity)` in `external_identity_binding`,
  never the raw value, and each later request recomputes it and compares in
  constant time. The binding is cleared whenever the session is invalidated
  (revocation, grant change, inconsistent credential). A session past its
  idle or absolute lifetime is invalidated and loses its binding in every
  authorization, owner-authorization and step-up transaction (committed
  separately when that request is denied), at every session establishment,
  and through `AccessStore.end_expired_sessions()`, the bounded sweep that the
  runtime must schedule when routes are mounted so expired rows are cleared
  even when no request arrives. The read-only `current_session` lookup does
  not write. The
  deployment-local key is a 32-byte file (`Settings.session_binding_key_path`)
  created once with mode `0600` in a directory owned by the service account
  and not group/other writable; a wrong owner, mode, link count, size or a
  symlink fails closed rather than being repaired or replaced. The only extra
  link tolerated is a creation staging name (`.<name>.<16 hex>.tmp`) of the
  same file, left by a concurrent start that has not removed it yet or by one
  that died between publishing and cleanup; it is removed before the
  single-link check. The key never
  enters the database, logs, errors, `repr`, pickling or diagnostics, and an
  `AccessStore` without it establishes and accepts no session.
- Binding mismatch policy (Owner decision, 2026-09-30, PR #107): a request
  whose identity does not reproduce the binding of an otherwise current
  session receives the generic denial for that request only. The session is
  neither revoked nor sent to step-up, because in the shared-account
  deployment a mismatch cannot identify a person and revoking on it would let
  anyone with a stolen cookie sign its holder out. The mismatch is audited as
  `detect_session_proxy_identity_mismatch` (actor `system`, outcome `denied`,
  target the principal's logical UUID; never an identity, binding, token or
  session id). The record is non-amplifiable: at most one per session per
  `BINDING_MISMATCH_AUDIT_INTERVAL` (10 minutes), with later mismatches in the
  window — including after a backward clock step — only incrementing
  `access_sessions.binding_mismatch_suppressed`. A request without an
  otherwise current session (unknown, expired or revoked token) records
  nothing, so no record can be produced without a valid session token. If the
  append fails, or the storage reservation refuses the write before the
  coalescing decision, the request is still denied and the loss is counted in
  `audit_delivery_failed` / `undelivered_audit_records`. The binding is
  therefore a necessary consistency signal, never an authorization input.
- Audit: sign-in (`authenticate_principal`), step-up
  (`verify_principal_step_up`), an inconsistent credential
  (`mark_principal_credential_inconsistent`) and a counter regression
  (`detect_principal_credential_sign_count_regression`) commit their records
  in the same transaction as their effect. As with redemption, an attempt that
  matches no credential writes nothing.

Not implemented yet, and required before routes open:

- the HTTP routes and their cookie handling;
- per-source rate limiting (only the per-code attempt bound exists here);
- the decision whether any path (for example a strictly local
  `http://localhost` Owner) may run without a trusted-proxy identity; until
  the routes are built one is required on every ceremony and session check
  (Owner decision, 2026-09-30);
- the runtime composition that loads the session-binding key with
  `SessionBindingKey.load_or_create(Settings.session_binding_key_path)` and
  hands it to `AccessStore` (no human route constructs the store yet);
- delivery of `CredentialFindingSink` to the Owner notification channel;
- local owner bootstrap and recovery commands;
- the startup/daily listener and route reservation check.

Owner-only mutations — invitation, invitation issue, grant change, single
credential revocation and principal revocation — are exposed as `*_on`
methods on a caller-owned transaction and reached at runtime only through
`app.audit.integration.AccessAdministration`, which authorizes the Owner and
commits each mutation with its security audit record. The plain wrappers refuse
with `UnauditedAccessWriteError` unless the store is constructed with
`unaudited_writes=True` for non-runtime fixtures. Invitation redemption
(`enroll_credential`) records its own audit row in the redemption transaction
and therefore requires `audit=`; the log receives only the principal's logical
UUID. A redemption that matches no valid invitation records nothing and does
not affect health; when a matched redemption's audit append or commit fails,
the redemption rolls back and the lost outcome is counted in the store's
`audit_delivery_failed` / `undelivered_audit_records` health instead of being
appended separately. See `server/app/audit/README.md`.

## Hostname reservation check (ADR-0003)

`reservation.py` verifies, and does not prevent, the dedicated-hostname
reservation. `HostnameReservationCheck.startup()` and the daily `tick()` run an
injected listener enumerator (`ProcNetListeners`, parsing `/proc/net/tcp`,
`/proc/net/tcp6`, `/proc/net/udp` and `/proc/net/udp6` text from an injected
reader) and an injected proxy-route
enumerator (`ServeStatusRoutes`, parsing Tailscale Serve status JSON from an
injected source). `access_open` is `False` until a check passes, and any of the
following closes it:

- a TCP LISTEN or unconnected UDP socket (for example HTTP/3/QUIC) other than
  the recorded proxy sockets on a reserved address, a wildcard (`0.0.0.0` /
  `::`) listener, or an IPv4-mapped equivalent, on any port, unless it is a
  wildcard bind covered by an Owner listener exception. Recorded proxy sockets
  are TCP at the configured origin port only; a proxy socket on any other port
  of the reserved name is refused as configuration. Connected UDP client
  sockets answer only their peer and are not counted;
- any Serve route other than the single `https://<host>:<port>/` proxy to the
  loopback human listener (other paths, ports, `http`, raw TCP forwards, empty
  TLS listeners, Funnel), or a duplicate of it;
- the expected mapping or the loopback human listener being absent;
- the isolation mode (`IsolationMode`) not being stated;
- an enumeration that raises, returns unrecognised output, or exceeds its
  timeout; a hung enumeration is never stacked by a later check.

A failing startup/daily check closes access before emitting an identifier-free
`ReservationFault` (reasons and counts only) to the injected Owner sink; a
failed delivery is counted and retried on the next tick. While closed the
check is retried every five minutes, re-notifying only when the reasons change,
and a later passing check reopens access. After a close that may have exposed
a session cookie (an unexpected listener or route, or an enumeration error or
timeout that cannot rule one out: `EXPOSURE_REASONS`), a passing check reopens
only after the injected `session_revoker` has revoked every human session
(Owner decision, 2026-09-30). `reservation_store.ReservationSessionRevocation`
does that through `AccessStore.invalidate_all_sessions_on`, which advances the
existing `access_deployment_state.authorization_generation` and invalidates
every `access_sessions` row (no migration), in one transaction with a `system`
`invalidate_human_sessions` audit record on a fixed logical ID. Everyone, the
Owner included, signs in again with their credential, and pending enrollment
authorizations from the previous generation must be reissued. The exposure is
recorded as a marker in `application_metadata` first, so a restart before the
revocation still revokes before opening (an unreadable marker also revokes).
Without a revoker, or when revocation or its audit append fails (rolled back
together, with a `failed` record attempted), access stays closed with a
`SESSION_REVOCATION_UNAVAILABLE` / `SESSION_REVOCATION_FAILED` fault; a failure
to record the marker is reported the same way. Other closes (missing mapping,
missing human listener, unstated isolation, unreadable exceptions) show no
other answer on the name and reopen without revocation. A process binding the reserved
address between two checks is not seen until the next check: detection bounds
the exposure window, and only the Owner-recorded deployment isolation removes
it. `/proc/net` covers one network namespace.

Owner listener exceptions (`ListenerException`: protocol `tcp` or `udp`, port,
optional address family, bind scope `wildcard`) let a system service such as
`sshd` on tcp/22 or `tailscaled` on its UDP port bind a wildcard address without
closing access. An exception covers only its own protocol. `/proc/net` does not
show `IPV6_V6ONLY` and a `::` socket may also accept IPv4, so a `::` bind is
treated as dual-stack: only an exception without a family covers it, an `ipv4`
exception covers `0.0.0.0` only, and an `ipv6`-only exception is rejected. The set is empty
by default, typed, bounded to 16 entries, and is never read from deployment
configuration. An exception never matches the dashboard port, the loopback
human listener port or a recorded proxy socket port (for either protocol, so
UDP/443 is never exempt), and never matches a bind
to a reserved address: `100.64.x.y:22` still closes access when `0.0.0.0:22`
is allowed. The only runtime path that changes it is
`app.audit.integration.ReservationAdministration`, which authorizes the Owner,
writes the set and a `change_security_setting` audit record in one SQLite
transaction, then applies the set and re-checks immediately so narrowing it
closes access at once. Concurrent changes are serialized from staging through
apply, so the live set always matches the latest committed one; startup, daily
and retry checks take the same lock, so a check still evaluating a superseded
set cannot publish its verdict after a change has committed. `reservation_store.ListenerExceptionStore` persists the
set as versioned JSON under one fixed key of the foundation
`application_metadata` key/value table (no migration), and `startup()` loads it
before the first check. A missing row is the empty default; an unreadable,
corrupt (including duplicate JSON members), or no longer valid value (for example one covering the dashboard
port) loads as the empty set, never a wider set, and
`LISTENER_EXCEPTIONS_UNREADABLE` stays in every verdict (access closed, Owner
fault) until the stored value loads again on a later check or an audited Owner
change rewrites it, whether or not any listener currently needs an exception.
Faults still carry only reasons and counts.

Each expected endpoint (the loopback human listener and each recorded proxy
socket) passes as exactly one socket. Independent `SO_REUSEPORT` sockets show
as identical `/proc/net` rows, and every extra copy is counted as an
`UNEXPECTED_LISTENER` (an exposure reason): another process sharing the
endpoint would receive requests and session cookies. The same applies to a
wildcard endpoint covered by a listener exception: one exception allows one
socket per distinct endpoint it covers (for example `0.0.0.0:22` and `:::22`),
and each identical extra row is unexpected. Exceptions stay port-only; a
service that opens several `SO_REUSEPORT` sockets on an excepted port keeps
access closed.

Nothing here is wired into the application or a route yet, reads the host
implicitly, runs `tailscale`, changes Tailscale ACLs/Grants, or needs Tailscale
administrative credentials. The assumed `tailscale serve status --json` shape
is unverified against an installed Tailscale; unrecognised keys fail closed.
