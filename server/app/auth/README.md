# Human Authorization

Owns owner invitations/allowlists, independent `live:view` and `recordings:view` permissions, owner-only operations, and prompt revocation.

- Accepts Tailscale/trusted-proxy identity only through a non-bypassable local listener boundary; ordinary LAN clients cannot supply trusted identity headers directly.
- Requires application authorization in addition to private-network reachability. Tailnet membership alone grants no access.
- Treats a verified Tailscale/trusted-proxy identity as supplementary: the deployment shares one Tailscale account, so authorization requires the requesting principal's own ServerSentinel credential (WebAuthn/passkey, ADR 0004) on every human route. No route authorizes on an identity header alone.
- Verifies the transient WebAuthn data a registration or assertion carries (challenge, client data, authenticator data, signature, signature counter, user-verification flag, relying-party id and origin) and persists only public credential material, the signature counter, the backup-eligibility and backup-state flags, and owner-visible metadata. No viewer biometric template reaches the server; it never leaves the authenticator.
- Relies on the dashboard owning its browser origin, with no other application sharing it, and on that origin being a secure context (AUTH-012); browsers withhold WebAuthn elsewhere. Reserving the name is a deployment obligation (ADR-0003), and the startup/daily check over real listeners and proxy routes closes human access and notifies the Owner on what it can see rather than preventing the bind; kernel forwarding to the reserved address (nftables/iptables DNAT or REDIRECT, TPROXY, eBPF `sk_lookup`, IPVS) is outside it (see below).
- Treats revocation as credential-scoped rather than device-scoped, and persists the last accepted signature counter so the clone check has something to compare against. The comparison runs whenever the stored or received counter is non-zero, so a received 0 after a stored non-zero is a regression; only a stored-and-received 0 is exempt.
- Accepts `none` attestation at registration, verifying the challenge, origin/relying-party id, authenticator data, credential public key and user-verification flag instead; a present-but-invalid attestation statement fails.
- Records the authenticator's backup-eligibility and backup-state flags with the credential so the owner UI can show whether it syncs, and refuses a backup-eligible registration where the deployment requires device-bound credentials. Eligibility is fixed at registration and a differing value in a later assertion is refused and reported; backup state is refreshed from every verified assertion.
- Keeps at most the last observed proxy identity on the principal: optional and non-unique (every holder of the shared account presents the same login), stored but never returned or shown, not even to the Owner (Owner decision D14: in the shared-account deployment it does not tell people apart), overwritten each authentication, cleared on revocation or deletion, out of diagnostic exports, and never an authorization input. Sessions keep only its deployment-keyed HMAC binding.
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
alongside ADR-0003. The production entry points still mount no human route.
Issue #10 phase 1 adds the human route foundation (`human_surface.py`, below):
an embedder can open the passkey sign-in ceremony and a session
self-description route only through a validated composition that the
deployment explicitly enabled, behind a fully configured reservation check.

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

No path runs without a trusted-proxy identity: one is required on every
ceremony and session check (Owner decision, 2026-09-30), and there is no
strictly local `http://localhost` Owner path (Owner decision, 2026-10-11).
The human composition accepts only the reserved `https` origin; the
verifier's `http://localhost` support is not reachable from any human route.

Not implemented yet, and required before routes open in production:

- the remaining HTTP routes: every live, recording, timeline, event and
  administration route, including every `OWNER_OP` route (later Issue #10
  phases, #19). Sign-out and the CSRF token exist since phase 2 S1,
  invitation redemption and the local bootstrap/recovery command since S2,
  and the Owner step-up routes since S3 (below);
- the Owner's administration routes (S4b: invitation, re-issue, grant
  change, revocations and the inventory read) and the local `list` /
  `revoke-principal` / `revoke-credential` commands (S4c). S4a builds the
  store and `AccessAdministration` they will call ("Owner access
  administration", below); until S4b the only runtime issuer of an
  enrollment code is the local command, which covers the Owner only;
- the deployment-file key and production composition that build the
  `HostnameReservationCheck` (Serve status source, `SockDiagOwners`,
  `GetaddrinfoResolver`), load the session-binding key with
  `SessionBindingKey.load_or_create(Settings.session_binding_key_path)` and
  pass a `HumanAccess` to `create_app` (no production path builds one yet);
- delivery of `CredentialFindingSink` and `ReservationFault` to the Owner
  notification channel.

Owner-only mutations — invitation (with its code), code re-issue, grant
change, single credential revocation and principal revocation — are exposed
as `*_on` methods on a caller-owned transaction and reached at runtime only
through `app.audit.integration.AccessAdministration` (`HumanAccess.administration`),
which authorizes the Owner and commits each mutation with its security audit
record. Every one of them commits inside `admit(epoch)` of the epoch its
`OWNER_OP` authorization was made under (Owner decision D6, 2026-10-11; S4a):
while human access is closed, or after a close, reopen, `stop()` or failed
tick since that epoch, it is a failed operation with its `failed` record and
changes nothing (see "Owner access administration" below). An emergency revocation while access is closed is
done over SSH with a local command (Owner recovery exists since S2, see
"Bootstrap and recovery commands"; a per-person local revocation command is
not built yet). The plain wrappers refuse
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
reservation. `HostnameReservationCheck.startup()` and the daily `tick()`
re-resolve the reserved hostname through an injected `resolver`
(`GetaddrinfoResolver` in production) and run an
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
  of the reserved name is refused as configuration. Each recorded proxy socket
  must be created by the configured `proxy_owner` (a `ProcessIdentity`:
  systemd unit and uid, for example `tailscaled.service` with uid 0), verified
  through `socket_owners` like a listener exception: a confirmed other creator
  counts as `UNEXPECTED_LISTENER` (an exposure) and an unverifiable one as
  `LISTENER_OWNER_UNVERIFIED` (closed, no revocation). Connected UDP client
  sockets answer only their peer and are not counted;
- a loopback human upstream that is not the socket-activated upstream of this
  ServerSentinel process (Issue #126, Owner decision 2026-10-07). systemd
  creates it through `server-sentinel-upstream.socket` as uid 0 on a loopback
  port below 1024 and passes it to the unprivileged backend
  (`app.systemd.activated_listener`, which refuses a passed socket that is not
  exactly the configured listening `human_host:human_port` and marks it
  non-inheritable). Each check requires that socket to be in this process's
  own `/proc/self/fd` (`OwnSocketInodes`, the injected `own_sockets`), created
  in the `.socket` unit's cgroup by uid 0 (`ReservationConfig.upstream_owner`,
  through `socket_owners`), on a port below
  `/proc/sys/net/ipv4/ip_unprivileged_port_start` (the injected
  `unprivileged_port_start`), and held by no other process in the
  ServerSentinel unit's cgroups (`socket_owners.held_only_by_requester`, a
  same-uid `/proc/<pid>/fd` scan). A single replacement bound by another
  process (no `SO_REUSEPORT` duplicate row), a confirmed other creator, or the
  socket shared with another unit process counts as `UNEXPECTED_LISTENER`
  (an exposure). An unreadable own fd table or unit process, a socket without
  an inode, no `own_sockets`, an unresolved creator, or a port at or above
  `ip_unprivileged_port_start` (a configuration error: for example the backend
  was not socket-activated and bound the port itself; the creator is then not
  compared) counts as `LISTENER_OWNER_UNVERIFIED` (closed, no revocation). An
  upstream created in `/init.scope` by uid 0 (systemd listened from PID 1
  because the host has no cgroup-BPF support, Issue #157) has its own reason,
  `UPSTREAM_CREATED_IN_INIT_SCOPE`, also closed without revocation; PID 1's
  `/init.scope` is never accepted as the socket unit;
- a recorded proxy socket that is absent (`PROXY_LISTENER_MISSING`). This is
  proxy drift or failure with nothing else seen answering, so, like a
  resolution failure, it closes access without revocation and reopens once
  every recorded socket is back with its recorded owner;
- any Serve route other than the single `https://<host>:<port>/` proxy to the
  loopback human listener (other paths, ports, `http`, raw TCP forwards, empty
  TLS listeners, Funnel), or a duplicate of it;
- the expected mapping or the loopback human listener being absent;
- the isolation mode (`IsolationMode`) not being stated;
- a resolved address set that differs from the configured `reserved_addresses`
  (`RESERVED_ADDRESSES_CHANGED`); listeners are checked against the union of
  both sets, so a bind to an address the name gained is also counted;
- a hostname resolution that is missing (no resolver), fails, returns nothing
  usable or exceeds its timeout (`HOSTNAME_RESOLUTION_UNAVAILABLE` /
  `HOSTNAME_RESOLUTION_TIMEOUT`);
- an enumeration that raises, returns unrecognised output, or exceeds its
  timeout; a hung enumeration is never stacked by a later check.

A failing startup/daily check closes access before emitting an identifier-free
`ReservationFault` (reasons and counts only) to the injected Owner sink; a
failed delivery is counted and retried on the next tick. While closed the
check is retried every five minutes, re-notifying only when the reasons change,
and a later passing check reopens access. After a close that may have exposed
a session cookie (an unexpected listener or route, a resolved address set that
differs from the configuration, or a listener/route enumeration error or
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
When the marker cannot be written, every human session is revoked at once
instead (access is already closed, so no later request is admitted until
reopening revokes again); until one of the two commits, each check retries both and keeps
`SESSION_REVOCATION_FAILED` (Owner decision, 2026-10-01). Once that immediate
revocation has committed, the five-minute retries of the same closed period do
not repeat it, even while the exposure and the marker failure continue
(Issue #120): a repeat would advance the generation again, add an audit record
and void the enrollment authorizations issued during the outage. The revocation
before reopening still runs. The marker write itself keeps being retried on
every check until it commits (PR #134); while it stays unsaved, the
identifier-free log event `session_revocation_marker_unsaved` is written when
the failure streak starts and each time it doubles, and
`session_revocation_marker_saved` once it commits.

Session gate (Issue #144, Owner decision 2026-10-07: serialize). The check and
every commit that creates a human session, updates a session's user-verification
time, creates or redeems an enrollment authorization, or stores a WebAuthn
challenge share one lock, `HostnameReservationCheck.admit()`:
`PasskeyCeremonies.finish_authentication()` (new session),
`finish_step_up()` (user-verification time) and `finish_registration()`
(invitation redemption) run their store commit inside it, and so does every
`AccessAdministration` mutation (invitation and re-issue included). Neither
`PasskeyCeremonies` nor `AccessAdministration` can be constructed without a
gate (`session_gate=None` is refused, Issue #181), the human route composition
accepts only the `HostnameReservationCheck` itself, and `AccessAdministration`
accepts only the composition's `ServingGate` (`app.auth.serving_gate`, Issue
#232 item 1), never the raw check, so an Owner mutation is also refused after
`HumanAccess.stop()` or a failed tick. Each of these requests first takes the gate epoch
(`HostnameReservationCheck.epoch()`), before it consumes its challenge,
verifies an assertion or authorizes the Owner, and commits inside
`admit(epoch)`. The epoch advances, under the lock, every time an open verdict
closes, and is `None` while access is closed. Inside the lock the commit
re-checks right before its SQLite write transaction that access is open and the
epoch unchanged, and is refused otherwise (generic denial; a `failed` audit
record for the Owner operation). The check takes the same lock to close access
at its start, and the verdict stays closed until any required revocation has
committed. That is the essential property: a request commits only if access
stayed open from its start to its commit, so no revocation ran in between.
It either committed before the close, so every later revocation covers it, or
is refused (at once, before any challenge is consumed or assertion verified,
when access is already closed at its start), also when a whole close, revoke
and reopen cycle completed while it
was verifying (PR #174 review); it can no longer commit after the immediate
fallback revocation, and an invitation can no longer commit on an Owner
authorization that a revocation ended. A challenge is issued by an earlier
request, so `begin_registration()`, `begin_authentication()` and
`begin_step_up()` store theirs the same way: the epoch is taken at the start of
the `begin` request and the insert commits inside `admit(epoch)` (they are the
only callers of the store's challenge inserts). A revocation deletes every
pending WebAuthn challenge, so every challenge either committed before a close
and is deleted by the revocation that follows, or is never stored (PR #174
review); an assertion over a challenge issued before a revocation (for example
one a listener answering during the exposure received) cannot establish a
session afterwards. The challenge row carries no authorization generation: with
gated inserts any revocation either precedes the whole `begin` request or
deletes the row, so a generation would add nothing, and the table has no
column for one without a migration. A request that merely spans a close without an
exposure is refused too and simply starts again. The check also takes the lock
again to decide and commit (the marker, the fallback and reopening revocations
and the published verdict); doing that inside the gate is defense in depth. A restart that
finds no marker after a committed fallback revocation (the residual risk of PR
#134) thus finds no session or enrollment authorization from before the close.
Lock order, outermost first: `exception_change_lock`, `_check_lock`, the
session gate lock, then the SQLite write lock (`BEGIN IMMEDIATE`). Session
paths take only the last two, in that order. Enumeration, hostname resolution
and Owner fault delivery run outside the gate lock. Under it run only local
work: the SQLite write transactions, their storage admission (the audit
store's free-space reservation) and the identifier-free marker log event. The verdict lives in the check's memory, so the check and every
session-establishing path must run in one process (the backend runs a single
`uvicorn.Server` from `app.systemd.build_server`, without worker processes); a
second serving process would have no gate. The check records `os.getpid()` when
it is built and every gate entry compares it before taking any lock (Issue
#181): in another process, such as a `fork()` child holding a copy of an open
verdict that no check closes, `access_open` is false, `epoch()` reports closed
(`None`, so callers keep their closed-at-start denial or failed audited
operation) and `admit()` raises `HumanAccessClosed`. This fails closed; it is
not a multi-process mode. Local bootstrap/recovery commands and per-source
rate limiting are described in "Human route foundation" below (Issue #181,
#10). The low-level
`AccessStore.establish_session` / `issue_enrollment` wrappers are fixture and
local entries outside the gate and must not be reached from a human route.
Every human authorization commits its idle-expiry touch (`last_seen`) inside
`admit(epoch)`: `authorize_request` on the routes and `authorize_owner(admit=...)`
for an Owner operation (Issue #10 phase 2 S1, #228). The two step-up routes
are the exception: they authorize with `authorize_request(touch=False)`, the
same checks without the touch, and only a successful step-up touches the
session, inside `accept_assertion` (Owner step-up, below). Only the expiry sweep, and
the bare `authorize()` that fixtures call without `admit`, write outside the
gate. Neither ever makes a session valid: revocation advances the authorization
generation and invalidates every row in one transaction, so a write committed
after it finds the session invalid and is refused, and one committed before it
is revoked with the row.

Two cases do not revoke twice. A fallback revocation that commits in the same
check that reopens access, while access has never been open in this process (a
clean startup, for example with an unreadable marker), already is the reopening
revocation (Issue #145). A fallback from an earlier check, or one after access
has been open in this process, does not count, and reopening revokes again
(kept as defense in depth for a commit outside the gate). And once the marker
is known to be stored for the closed period (written in this period, or read as
pending at startup), a failed rewrite neither revokes nor counts as a marker
failure (Issue #144): the stored marker already carries the requirement across
a restart.
A check without a revoker never opens access, before or after any exposure,
and keeps `SESSION_REVOCATION_UNAVAILABLE`: nothing durable could carry a
revocation requirement across a restart, so a restart after an exposure must
not reopen with the earlier sessions still valid. When revocation or its audit
append fails (rolled back together, with a `failed` record attempted), access
stays closed with a `SESSION_REVOCATION_FAILED` fault; a failure to record the
marker is reported the same way. Other closes (missing mapping,
missing human listener, unstated isolation, unreadable exceptions, and a
missing, failed or timed-out hostname resolution) show no other answer on the
name and reopen without revocation. A resolution failure keeps access closed
but is not an exposure (Owner decision, 2026-10-01): once the resolver answers
again with exactly the configured set, access reopens with existing sessions
intact, unless an exposure was seen meanwhile. A process binding the reserved
address between two checks is not seen until the next check: detection bounds
the exposure window, and only the Owner-recorded deployment isolation removes
it. `/proc/net` covers one network namespace. The check sees only sockets in `/proc/net` and Serve status. Traffic the kernel redirects before it reaches a listening socket on the reserved address — nftables/iptables DNAT or REDIRECT (for example Docker with `userland-proxy=false`), TPROXY, eBPF `sk_lookup` or IPVS — is not visible to it, so it cannot claim that nothing else answers; the deployment isolation must exclude such forwarding, and the Owner verifies it manually.

Owner listener exceptions (`ListenerException`: protocol `tcp` or `udp`, port,
optional address family, bind scope `wildcard`, and the creating unit and uid) let a
system service such as `sshd` on tcp/22 or `tailscaled` on its UDP port bind a
wildcard address without closing access. An exception covers only its own
protocol. A port alone never exempts a socket (Owner decision, 2026-10-01): each
exception names its creating systemd system `unit` (a `.service` or `.socket`
unit) and `uid` (Owner decision, 2026-10-07, replacing the executable-path
identity: for example `ssh.socket` with uid 0 for tcp/22, `tailscaled.service`
with uid 0 for its UDP port). A port-only, executable-path or malformed entry
is rejected, and a stored executable-path or unit-without-uid set (store
format version 1 or 2) fails closed as `LISTENER_EXCEPTIONS_OUTDATED` until the
Owner re-enters it.

Each check reads the socket inode from `/proc/net` (listener enumeration stays
there) and asks the injected `socket_owners` for each verified socket's
creator. In production that is `app.auth.sock_diag.SockDiagOwners`: the
unprivileged backend sends `NETLINK_SOCK_DIAG` `inet_diag` dump requests for
the TCP LISTEN and unconnected UDP tables (IPv4 and IPv6) of its own network
namespace and reads each socket's uid and `INET_DIAG_CGROUP_ID`, the cgroup v2
id of the cgroup the socket was created in, which it maps to a path by
`stat`ing `/sys/fs/cgroup` (a cgroup id equals its directory's inode on a
64-bit kernel). systemd creates a `.socket` unit's sockets in that unit's
cgroup (`/system.slice/ssh.socket`) and a service's sockets in the service's
cgroup; only root can move a process into a `system.slice` cgroup. The socket
matches only when its cgroup path is exactly `/system.slice/<unit>` and its uid
is the recorded one; a `user.slice` path (whose user manager can create a unit
of any name), a sub-cgroup or another slice names no unit and does not match.
Every dump first confirms that a loopback probe listener of the backend's own
appears with the backend's cgroup and effective uid, so a refused netlink
socket, a kernel without the cgroup attribute or a cgroup view that does not
match (for example `ProtectControlGroups=private`) fails closed before any
listener is judged.

A socket created in another existing cgroup, or by another uid, counts as
`UNEXPECTED_LISTENER` (an exposure) only when an immediate second dump in the
same check reports the same creator; a mismatch the second dump does not repeat
(the socket went away or changed, or the dump failed) is
`LISTENER_OWNER_UNVERIFIED`. So is every creator the check cannot establish: a
socket in `/proc/net` that is not in the dump, and a lookup that fails, times
out or fails its self-check. A creator whose cgroup cannot be resolved (no
cgroup attribute, a cgroup id that names no existing cgroup, the root cgroup
or `/init.scope`) is unverified while its uid is one of the expected
identities' uids, and always for `/init.scope` with uid 0 (PID 1's own
sockets); with a uid none of them has it is another creator, an exposure once
the second dump confirms it (Owner decision, 2026-10-07). A unit matches a
socket created in `/system.slice/<unit>` or below nested system slices
(`/system.slice/system-cups.slice/cups.service`, every component in between a
`.slice`); exceptions and proxy owners name `.service` or `.socket` units
only. A kernel-owned socket (inode 0 in `/proc/net`, for example a kernel
WireGuard UDP socket) has no creator to look up and stays unverified, so
human access stays closed while one is on a covered port even with an
exception. For the human upstream, another unit process holding the socket is
an exposure only when the same process (pid and start time) still holds it in
a second scan about 100 ms later and again in a third scan about 100 ms
after that (Issue #160): a child between `fork` and `exec` (for example a
`subprocess` with `close_fds=True`) holds every descriptor, because
close-on-exec acts only at `exec`, and on a loaded host it can stay there
longer than one gap, so the third scan gives it a second gap. The executable
the holder runs does not matter: a process that keeps the descriptor through
all three scans (also a `fork` child that never execs) is an exposure. A
holder not seen in all three scans is unverified, and so is the upstream while
any process of the unit is unreadable in the last scan; the same process
unreadable in every scan fails the lookup, which is unverified as well
(Issue #172). Unverified closes access
without revocation and reopens once the creator verifies again (Owner
decisions, 2026-10-05 and 2026-10-07). The resolver is mandatory: without
`socket_owners` access never opens.

What this cannot show (residual risk accepted by the Owner, 2026-10-07): the
cgroup is the socket's creator, recorded when it was created, not its current
holder. A legitimate creator that is compromised and hands its listening
descriptor to another process (`fork`, `SCM_RIGHTS`) is not detected; for the
human upstream, the same-uid scan covers the ServerSentinel unit's own
processes only. No privileged helper, capability or root is involved; the
2026-10-01 plan for one (closed PR #142) was dropped because reading other
processes' descriptors needs `CAP_SYS_PTRACE`. With socket activation
allowed, the Main Server keeps Ubuntu's `ssh.socket`; the exception is
`tcp/22` created by `ssh.socket` as uid 0 (steps in `server/docs/DEPLOYMENT.md`). `/proc/net` does not
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
before the first check. Format version 2 stores the owner; a version 1
(port-only) value is not migrated, since its owner cannot be inferred, and
loads as the empty set with `LISTENER_EXCEPTIONS_OUTDATED` in every verdict
(access closed, Owner fault) until the Owner enters the exceptions again
through the audited path. A missing row is the empty default; an unreadable,
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
and each identical extra row is unexpected. An exception allows one socket per
endpoint even for its own process, so a service that opens several
`SO_REUSEPORT` sockets on an excepted port keeps access closed.

Nothing here reads the host implicitly, runs `tailscale`, changes Tailscale
ACLs/Grants, or needs Tailscale administrative credentials. The check is wired
into the application only through the phase 1 `HumanAccess` composition below,
whose lifespan task runs `startup()` and then `tick()` every 30 seconds; no
production path builds one yet. The assumed `tailscale serve status --json`
shape is unverified against an installed Tailscale; unrecognised keys fail
closed.

## Human route foundation (Issue #10 phase 1, phase 2 S1 and S2)

`human_surface.py` replaces the closed surface only when `create_app` receives a
`HumanAccess`. Constructing one requires `HumanAccessConfiguration(enabled=True)`,
a `HostnameReservationCheck` with every opening input (`opening_configured`:
hostname resolver, socket owner resolver, own socket table, unprivileged port
start and session revoker), `PasskeyCeremonies` gated by exactly that check over
this audited `AccessStore` with a session-binding key, and a relying party
whose origin is the reserved `https://<hostname>[:<port>]` of the check. Any
other combination raises `HumanAccessUnavailable` and the listener stays
closed. No deployment-file key builds a `HumanAccess` yet.

Every HTTP request passes, in this order, before any handler runs:

0. the route table (`ROUTES`, Issue #10 phase 2 S1): an exact method, a
   strict path pattern (`fullmatch` on the decoded path, whose raw form must be
   present and identical, so a percent-encoded spelling matches nothing and an
   ASGI server that omits `raw_path` matches nothing either, Issue #232) and a strict
   per-route query allowlist (no S1 route accepts any parameter; an unknown,
   repeated, valueless, percent-encoded or over-long parameter, or a query
   longer than 512 bytes, is a denial). An unmatched request still passes the
   checks below before its denial;
1. reserved secure-context origin: exactly one `Host` equal to the reserved
   authority, and an `Origin`, when present, exactly equal to the reserved
   origin; an absent `Origin` is accepted only for `GET /api/session` (every
   mutating route requires it);
2. trusted-proxy path: the actual transport peer and the local listener
   address are loopback (`Forwarded`/`X-Forwarded-For` are never read), checked
   before the identity header is read, then exactly one canonical
   `Tailscale-User-Login` (printable ASCII, no space, no comma-joined value, no
   RFC 2047 encoded word);
3. the reservation verdict (`access_open`, pid-guarded) and this composition
   serving (`HumanAccess.stopped`);
4. for a session route, `HumanSurface._authorize`: the read-only token
   pre-check, the gate epoch (`HumanAccess.epoch()`), then
   `AccessStore.authorize_request(token, identity, requirement,
   admit=lambda: access.admit(epoch))` (credential-backed session, binding,
   lifetimes, revocation, the requirement, the CSRF token of a mutating route,
   idle touch) committed inside `admit(epoch)`, so access stayed open from the
   epoch to the commit and a request refused by a close in between writes
   nothing (no idle touch extends the session; lock order gate -> storage
   admission -> SQLite, denial bookkeeping after the gate is released). Later
   writes of the same request reuse `admit(epoch)`. The ceremonies take the
   epoch and `admit()` themselves, through the same composition gate.

Mounted routes, and nothing else (every other method, path, query string,
WebSocket and error path gets the generic not-found denial; no FastAPI router,
OpenAPI or error handler is reachable):

| Route | Credential | Result |
|---|---|---|
| `POST /api/auth/registration/options` | none; body `{"code"}` (redemption rate limit) | `PasskeyCeremonies.begin_registration()` creation options |
| `POST /api/auth/registration` | the invitation code and the registration itself (redemption rate limit) | `204`, no body, no cookie; `409 {"detail":"device_bound_credential_required"}` only as described below |
| `POST /api/auth/authentication/options` | none (rate-limited) | `PasskeyCeremonies.begin_authentication()` options |
| `POST /api/auth/authentication` | the assertion itself (rate-limited) | `204`, `Set-Cookie: __Host-session=…; Path=/; Secure; HttpOnly; SameSite=Strict` |
| `GET /api/session` | session (`SESSION`) | `{"csrf": …, "role": …, "permissions": […]}` of the caller only |
| `POST /api/auth/sign-out` | session (`SESSION`) + exact `Origin` + `X-CSRF-Token` | `204`, `Set-Cookie: __Host-session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict` |
| `POST /api/auth/step-up/options` | Owner session (`OWNER_READ`) + exact `Origin` + `X-CSRF-Token` (step-up rate limit) | `PasskeyCeremonies.begin_step_up()` request options (S3, below) |
| `POST /api/auth/step-up` | the same, and the assertion of the session's own credential (step-up rate limit) | `204`, no body, no cookie (S3, below) |

The session route grants nothing and returns only the caller's own role,
permissions (the Owner holds both) and CSRF token. With sign-out it is the
only route a non-Owner session reaches in this phase (the step-up routes
are Owner-only), so a `live:view`-only or
`recordings:view`-only person reaches nothing they lack. Bodies are bounded (1 KiB options, 64 KiB assertion or registration), JSON
with duplicate members is refused, and a ceremony refusal never sets a cookie.

Accepted disclosure: `POST /api/auth/authentication/options` answers `200`
with a fresh challenge and the `rpId` to any caller on the trusted proxy path
while access is open, before any credential is presented. Discoverable-
credential sign-in cannot work otherwise, so this differs from the generic
denial on purpose. It reveals that a ServerSentinel relying party answers at
the reserved name; it does not identify anyone and returns no principal,
credential or application data. The origin, trusted-path, reservation and
rate-limit checks bound who reaches it and how often; they do not hide it
from a holder of the shared login.

Storage admission and session revocation binding. Every human-access write
(challenge rows, session creation and touches, expiry sweeps, the
reservation revocation) is admitted through the same storage admission as
audit writes: `create_app` binds the composition's audit store to the Main
storage policy (or the embedder's injected reservation), a store already
wired to a different reservation is refused, and until it is bound every
request gets the generic denial. A refused admission (unbound policy,
`STORAGE_HARD_STOP`, replaced filesystem) is a denial and writes nothing.
`create_app` also refuses a composition whose `AccessStore` (and its audit
store) uses a database other than the application's own, since the
application's admission verifies only that database's filesystem and
reserve. Reads of the access state never take an admission and therefore
never create a database: they open the existing file `mode=ro`
(`Database.connect_read_only`), so a request after the verified filesystem
disappeared (mount-point directory left behind) is denied instead of creating
a fallback `state.sqlite3`.
The reservation check's session revoker must be a
`ReservationSessionRevocation` of exactly the composition's `AccessStore`,
so an exposure revokes the sessions this surface authorizes, and its stored
listener-exception source, when it has one, must be a
`ListenerExceptionStore` on that same database.

Storage lockout (Owner decision, 2026-10-11: accepted, fail closed; the
product requirement is REQUIREMENTS.md STORE-006). Sign-in
writes a challenge row and a session, and every session check writes (idle
touch, expiry sweep). So while storage admission is refused or unbound
(`STORAGE_HARD_STOP`, a lost or replaced recording filesystem, a deployment
without storage thresholds, or a monitoring runtime that has not started),
all human access is denied, the Owner's included: no one can sign in, and an
already signed-in session is denied on its next request. Recovery is done
over SSH on the Main Server host itself, not through the dashboard. No
exception path for the Owner exists, by that decision.

Admission latency (availability only). The storage admission runs on the
monitoring runtime's single owning worker (`RuntimeStorageAdmission`), so
every admitted write of this surface, which includes every sign-in step,
every session route that reaches `authorize_request` and every
`AccessStore.authorize()` (the idle touch is a write in both), waits in that
worker's queue behind any long monitoring job (a storage evaluation,
recording self-test step or retention batch), and while it holds the
admission through commit the worker is parked for it. Such a wait can delay a
human request (the admission has no timeout of its own); it never grants
access, and a request that cannot be admitted is the generic denial. The
commits made inside `admit(epoch)` (the ceremony commits and the
`authorize_request` transaction of a session route) wait for that
admission while holding the session gate, so a check's close can wait behind
them as well (availability only): a commit that wins this race committed
while access was still open, before the close, and any revocation that close
requires covers it (Issue #144). The
read-only pre-check (`session_may_be_current`) takes no admission.

Every future data route must be authorized through the reservation gate.
While a gated commit waits for the storage admission, a check's close waits
for the gate lock, so the published verdict (`access_open`) stays open for
up to one in-flight monitoring job plus the SQLite busy timeout. After the
check has closed access, it enumerates the hostname, listeners, routes and
socket owners, each under its enumeration timeout, before it decides on an
exposure. So the exposure revocation and the Owner fault come at least that
much later than the change that caused them. A request authorized through
the gate (`epoch()` before authorization, then the commit inside
`admit(epoch)`, as `authorize_request` does) is refused as soon as the close
has run. A route that called `AccessStore.authorize()` (or `authorize_owner()`)
outside the gate, even after reading `access_open`, could keep serving
through that whole window and after it. No such route is mounted, and the
route-side entry (`authorize_request`) refuses a call without `admit`. Any
later live, recording, timeline or administration route declares its
`Requirement` in `ROUTES` and goes through `_authorize`, never a bare
`authorize()` call.

Startup. A `HumanAccess` serves requests only while a `run()` of the current
lifespan holds (Codex PR #219): every request is denied (`stopped`) from
construction, so a composition whose lifespan never runs (disabled or not yet
started) serves nothing, and from the start of each `run()` until the check's
`startup()` has returned, so a restarted lifespan never serves on the verdict
the previous lifespan left behind. A `startup()` or periodic `tick()` that
raises may have failed before it closed the previous verdict (for example a
raising clock read), so requests are denied again and `startup()` is retried
on each tick until it returns. Requests are denied again once `run()` ends,
since nothing re-checks the verdict after that.

Shutdown. `create_app`'s shutdown first calls `HumanAccess.stop()` (every later
request is denied and `run()` starts no further startup, tick or sweep), then
cancels `HumanAccess.run()` and waits for it before unbinding the storage
admission or stopping the monitoring runtime. The check's `startup()`/`tick()`
and the expiry sweep run on worker threads that cancellation cannot stop, so
`run()` defers the cancellation until the in-flight call returns
(`app.completion.run_to_completion`): no verdict is published and no marker,
revocation or expiry write happens after the admission is unbound. That wait
is bounded by the one in-flight call: the check's enumeration timeout for each
enumeration, plus, for a write, at most one in-flight monitoring job ahead of
it in the storage admission (the Main storage policy admission waits for the
monitoring worker without a timeout of its own), plus the SQLite busy timeout.

Rate limiting (Issue #181 item 4, `rate_limit.py`). Both ceremony routes are
charged to a per-source token bucket and a global one before the ceremony
takes the gate or any SQLite lock, so a flood cannot hold the gate lock that
the check's close waits for. The source key is the verified proxy identity,
the only source attribute the backend can trust (the peer is always the
loopback proxy and forwarded headers are client-controlled). In the shared
Tailscale account every person presents the same login, so the per-source
bucket is shared by the room: a holder of the shared login can delay others'
sign-in (availability only, never access). The Owner accepted this keying and
the defaults below as is (Owner decision, 2026-10-11). Defaults: 20 requests
burst and one every 3 s per source, 120 burst and two per second globally, at most 256
source buckets (an identity digest, never the value; a full table evicts only
a refilled bucket and otherwise refuses). A refused request gets the generic
denial and at most one value-free `human_request_rate_limited` event per
minute. Session reads are not charged. A request without a well-formed
`__Host-session` cookie is denied before any storage access, and a
well-formed cookie whose token names no live session row (unknown, forged,
invalidated or past its idle/absolute expiry) is denied by a read-only
lookup (`AccessStore.session_may_be_current`, one deferred read transaction)
before the session gate lock or any SQLite write lock is taken. Only a token
that names a live row goes through epoch, `authorize_request` (write
transaction) and `admit()`, so a flood of random 43-character cookies by a
holder of the shared login neither takes the gate lock nor writes. An expired
row skipped this way is cleared by the periodic sweep instead of the denied
request. Forged-cookie denials are not charged to the bucket either, so they
cannot delay sign-in or a current session's reads, and their read-only
lookups are not bounded further (Owner decision, 2026-10-11, accepted as is).
The lookup takes no gate lock and no SQLite write lock, but its read still
takes SQLite's SHARED lock (rollback journal), so a forged-cookie flood can
still contend with writers; that contention is bounded by the SQLite busy
timeout, and a lookup or write that fails under it is a fail-closed denial,
never access.

### Gated authorization, CSRF and sign-out (Issue #10 phase 2, S1)

Requirements (`store.Requirement`). Every route in `ROUTES` declares one:
`PRE_CREDENTIAL` (the two sign-in ceremony routes, which gate themselves),
`SESSION`, `LIVE`, `RECORDINGS`, `OWNER_READ` or `OWNER_OP`.
`AccessStore.authorize_request` checks it server-side in the authorization
transaction: `LIVE` needs the Owner or `live:view`, `RECORDINGS` the Owner or
`recordings:view` (each on its own; historical timeline and events belong to
`RECORDINGS`), `OWNER_READ` the Owner, and `OWNER_OP` the Owner with a user
verification fresher than five minutes. It returns a `SessionView` (session
id, principal id, role, authorization revision, permissions; the credential
id is left out of `repr`). `admit` is mandatory; `PRE_CREDENTIAL` is never
satisfied by it.

Refusals (Owner decision D3). Every refusal is the same generic `404
{"detail":"Not Found"}` with `no-store` and no other header, byte for byte.
The single exception is an otherwise valid Owner session on an `OWNER_OP`
route whose user verification is stale: it gets the fixed `403
{"detail":"step_up_required"}`. That outcome is decided under the gate with
the epoch unchanged, never for a non-owner, a wrong CSRF token, another proxy
identity or a closed gate, and it commits no idle touch (Owner decision
S4-2, Issue #238 item 1): only a request that is served extends the session.
No `OWNER_OP` route is mounted yet (S4b adds the Owner's permission
management); the mapping, and its resolution through the S3 step-up routes,
is exercised through a synthetic route in the tests.

CSRF (Owner decision D2). `SessionBindingKey` derives a CSRF subkey from the
deployment's session-binding key under its own domain label, and a session's
token is `HMAC-SHA-256(subkey, domain || session id)`, sent unpadded base64url
(43 characters). It is not stored: `GET /api/session` returns it, and a
mutating session route requires exactly one `X-CSRF-Token` header equal to it
(constant-time comparison, inside the authorization transaction before the
idle touch, so a refused mutation does not extend the session) in addition to
the exact `Origin`. A token never validates another session, never equals a
proxy-identity binding, and never reaches a URL, log or audit record. The
`SameSite=Strict` `__Host-` cookie remains the first defense; the header
check does not rely on it.

Sign-out (Owner decision D7). `POST /api/auth/sign-out` (empty body or `{}`)
authorizes `SESSION` with the CSRF token (one `admit(epoch)`), then
`AccessStore.sign_out` commits, inside a second, separate `admit(epoch)` with
the same epoch (Issue #232 item 3), the invalidation of the session row,
the clearing of its keyed binding and a `sign_out_principal` audit record
(actor `owner` or `invited_user`, target the principal's logical UUID only;
never a token, session id, credential id or identity). The response clears the
cookie (`Max-Age=0` with the attributes it was set with). Afterwards the old
cookie, through the Back button or a copy, is the generic denial everywhere.
A failed audit append rolls the sign-out back (counted in
`audit_delivery_failed`) and the request is denied. While human access is
closed the sign-out is denied and changes nothing (accepted by D7); the
session then ends by expiry, by revocation, or by the reservation's
revocation on an exposure. A close, revocation or `stop()` between the two
commits refuses the second one, and a change that ended the session in
between makes it the generic denial; the race is harmless because sign-out
only removes access. Sign-out ends one session, not the credential: a
synced passkey can sign in again from any device that holds it.

### Invitation redemption (Issue #10 phase 2, S2)

Two pre-credential routes redeem an invitation (AUTH-013). The code is in
the JSON body only, never in a URL or query string, and the response never
echoes it.

- `POST /api/auth/registration/options`, body exactly `{"code": "<code>"}`:
  `PasskeyCeremonies.begin_registration` binds a fresh registration challenge
  to the invitation and counts one attempt (`MAX_REDEMPTION_ATTEMPTS` = 5 per
  code, in the same conditional update), inside `admit(epoch)`. `200` with
  the creation options: the reserved rp id (also its name), the invitee's own
  display name and principal handle, the challenge, the algorithms,
  `excludeCredentials` (only the principal's usable credentials: not revoked
  and not marked inconsistent, so after `recover` an authenticator still
  holding the revoked Owner passkey under the same user handle can replace
  it), `residentKey: required`, `userVerification:
  required` and `attestation: "none"`. No camera, recording, timeline,
  product or deployment data.
- `POST /api/auth/registration`, body `{"code", "credential", "label"?}`
  (label: 1-64 characters, no control character):
  `PasskeyCeremonies.finish_registration` consumes the challenge, verifies the
  registration server-side (client data type `webauthn.create`, challenge,
  exact origin, rp id hash, UP and UV, attestation `none` or `packed` self
  attestation, algorithm, BE/BS) and commits the credential, the redemption
  and its `redeem_principal_invitation` audit record in one conditional
  transaction inside `admit(epoch)`. Of concurrent redemptions of one code
  exactly one succeeds. Success is `204` with no body and no cookie: the
  person then signs in like anyone else.

Order: the route table, `Origin` (exact; required, as for every mutating
route), the trusted-proxy path and the reservation verdict as for every route;
then the redemption limiter, the `application/json` body (strict: no
duplicate member, no extra member, no NaN), the strict decoding of the code
(`invitation_code.parse_invitation_code`); only then the ceremony, which
takes the gate and SQLite. There is no CSRF token before a session exists;
the exact `Origin`, the JSON content type and the single-use challenge bound
to the invitation are what bind the two steps to the reserved origin.

Codes (Owner decision D5, `invitation_code.py`): 20 bytes (160 bits) from
`secrets.token_bytes`, stored as SHA-256 of all 20 bytes; shown as 32
Crockford base32 characters (no `I`, `L`, `O`, `U`) in eight groups of four,
`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`; single use. The server accepts only
that exact canonical form; the Web page (S5/S6) normalizes typed input (case,
spaces, aliases) before sending it.

Constant-time comparison (AUTH-013, PR #234 review). A row is located by
`lookup_key`, a domain-separated SHA-256 of the secret truncated to 128 bits
(`store._lookup_key`), and its stored `secret_digest` is then compared with
`hmac.compare_digest`. SQLite's index comparison only ever sees the lookup
key, which reveals neither the secret nor its verification digest. A row
issued before the lookup key existed (migration 22) has none and is never
found: issue it again.

Lifetime (Owner decisions D5 and 2026-10-11). The deployment key
`invitation_lifetime_hours` (integer 1-168, default 24, `Settings.invitation_lifetime`,
validated by `invitation_code.invitation_lifetime`) is the lifetime of every
invitation, the console Owner code and future Owner-issued ones alike.
`AccessStore(invitation_lifetime=...)` refuses to issue an invitation whose
expiry lies further ahead (and never beyond 7 days); `invitation_expiry(at)`
is what the bootstrap command uses.

Clock continuity (Owner decision 2026-10-11, `boot_clock.py`). At issuance
`issue_enrollment_on` records the kernel boot id
(`/proc/sys/kernel/random/boot_id`) and `CLOCK_BOOTTIME` next to the
wall-clock issue and expiry times; if either cannot be read it issues nothing
(`InvitationClockUnavailable`). Both redemption steps (options and finish)
read them again, each time as one pair with the wall-clock reading they are
compared with, taken together inside the step's own transaction right before
the decision, after every gate, storage-admission and lock wait (PR #234
review): a slow commit path is never read as a rollback, and an invitation
that expired, or a wall clock stepped back, during such a wait is refused
(options then counts no attempt, stores no challenge and returns no display
name). They require,
besides the wall-clock window: on the same boot, a monotonic elapsed time that
is `>= 0` and below the lifetime, and a wall-clock elapsed time that does not
lag it by more than 30 seconds (the allowance for the instant between the two
reads of a pair; NTP slews both clocks together, so only a step separates
them). A wall clock stepped back is
therefore refused rather than extending the code; one stepped forward only
ends the code earlier. After a reboot the readings are not comparable and the
wall-clock window decides (a rollback across a reboot is not detectable). A
row without the pair, or a host where it cannot be read now, is refused. Every
refusal is the generic denial.

Decision time of the other ceremony steps (PR #234 review). The same rule
applies to every store step a `PasskeyCeremonies` request commits:
`issue_authentication_challenge`, `consume_challenge`, `begin_step_up` and
`accept_assertion` read the wall clock inside their own transaction, after the
storage admission and the SQLite write lock, so a challenge that expired, or
an Owner session whose idle or absolute lifetime ended, during such a wait is
refused rather than consumed or refreshed; stored times (challenge issue and
expiry, last use, session start, step-up verification) are that same reading.
The ceremonies pass no time to these steps; the `at`/`now` arguments pin the
reading for deterministic tests and direct callers only.

Rate limit (Owner decision D4, `rate_limit.redemption_rate_limiter`): a
separate `SourceRateLimiter` keyed by the verified proxy identity: per
source a burst of 5 and one more every 12 seconds, with at most 256 source
buckets (SHA-256 keyed, fail closed when full), and no global bucket (Owner
decision 2026-10-11, Codex review of PR #234: a global bucket would let one
Tailnet member drain it and stop every other source, the Owner redeeming a
recovery code included). The total is bounded by the per-source buckets, the
bounded source table and the per-code attempt limit. It is charged before the body is parsed and before
any gate or SQLite work, so a flood of guesses costs no lock and no write. It
never spends the sign-in buckets, and a sign-in flood never spends it;
`HumanAccess` refuses one object for both. Both steps are charged, so a
person redeeming once uses two tokens. In the shared-account deployment the
per-source bucket is the room's (an availability trade-off, as for sign-in).

Refusals: an absent, malformed, unknown, expired, redeemed, revoked,
attempt-exhausted, revision-stale or generation-stale code, a limited
request, a failed verification, a wrong shape and a closed gate all get the
generic `404`, byte for byte. The one distinct outcome is `409
{"detail":"device_bound_credential_required"}`: only for a valid invitation
whose verified authenticator is backup eligible where the deployment requires
device-bound credentials, decided under the gate inside the redemption
transaction (`AccessStore.enroll_credential(require_device_bound=...)`) only
after the invitation the body code names proved valid on both clocks and is
the one the consumed challenge was bound to (otherwise the generic `404`);
the invitation stays unredeemed.

Refusal record (AUTH-013, Codex review of PR #234). A refused attempt writes
no audit record, so unauthenticated guesses cannot grow the audit table.
Instead every redemption request refused after the limiter (shape, code
format, unknown or invalid code, failed verification) increments the
value-free counter `HumanAccess.refused_redemptions`, and the event
`invitation_redemption_refused` is logged on the first refusal and each time
the count reaches a power of two. Neither carries the code, an identity, the
invitation or the reason. Requests refused by the limiter are counted by the
limiter (`human_request_rate_limited`). The response stays the generic `404`.

In-flight requests after stop (Issue #228 item 1). The composition installs a
`ServingGate` around the reservation (`PasskeyCeremonies.guard_session_gate`),
and both the routes' `_authorize` and the ceremonies use it: `epoch()` is
`None` while the composition is stopped, and `admit()` re-reads `stopped`
after taking the gate lock. A request that had already passed the entry
checks when `stop()` ran, or when a periodic check failed, is therefore
refused at its commit and writes nothing. A commit admitted before `stop()`
may still complete. One `PasskeyCeremonies` serves exactly one composition.

Lifecycle visibility (Issue #228 items 2-4). `HumanAccess.state`
(`not_started`, `starting`, `serving`, `check_failing`, `stopped`, `failed`)
and `check_failures` (consecutive failed startup/periodic checks) are
value-free and readable through `application.state.human_access`; a `run()`
that ends with an unexpected exception sets `failed` and logs
`human_access_run_failed`. A second `run()` while one is running raises
`HumanAccessAlreadyRunning` and changes nothing. A failing expiry sweep logs
`human_access_sweep_failed` when the streak starts and each time it doubles.
No Owner notification is emitted yet; delivering it belongs with the other
reservation faults (see "Not implemented yet").

Owner operation and live authorization. `PasskeyCeremonies.authorize_owner_operation`
commits `authorize_owner` inside `admit(epoch)` (#228 item 5), so the Owner
decision, its idle touch and `StepUpRequired` are all made while access stayed
open. `live_access.authorize_live_access` requires `admit` and binds the live
grant to the session id read in the same gated transaction.

### Owner step-up (Issue #10 phase 2, S3)

Owner decisions (2026-10-12, PR #236). (1) The step-up routes stay
`OWNER_READ`: only an Owner session, fresh or stale, reaches them; every
other caller gets the generic `404`. (2) Step-up has its own rate-limit
bucket, separate from sign-in and redemption (below). (3) A session whose
last verification was on another boot, or that has no recorded boot pair
(established before migration 23), is stale and must step up (fail closed).

Routes. `POST /api/auth/step-up/options` (empty body or `{}`) and `POST
/api/auth/step-up` (the JSON assertion, at most 64 KiB) are mounted with the
`OWNER_READ` requirement, exact `Origin` and `X-CSRF-Token`. `OWNER_READ`,
not `OWNER_OP`, so that a stale Owner can reach them (refreshing is their
point); not `SESSION`, so that a non-Owner is refused inside the
authorization transaction: a non-Owner, an
uninvited caller and anyone without a valid session get the generic `404`
and learn nothing about step-up. Each request is charged to the step-up
limiter (`rate_limit.step_up_rate_limiter`, `HumanAccess.step_up_limiter`:
per verified proxy identity a burst of 5 and one more every 12 seconds, no
global bucket, the same shape as redemption) before its body is parsed and
before any gate or SQLite work (SPECIFICATION: repeated failed step-ups are
rate-limited); a refusal there is counted by the limiter
(`human_request_rate_limited`), not by `refused_step_ups`. It is a separate
object with separate buckets, and `HumanAccess` refuses to be built when one
`SourceRateLimiter` object would serve two of sign-in, redemption and
step-up, so a sign-in flood cannot stop the Owner's step-up and a step-up
flood never spends the sign-in buckets. The request is then authorized by `_authorize` inside `admit(epoch)`, and the
ceremony step (`PasskeyCeremonies.begin_step_up` / `finish_step_up`) receives
that same epoch: before it consumes or verifies anything the gate's current
epoch must still equal it, and its commit runs inside a second
`admit(epoch)`, so a close, a close/reopen cycle, `stop()` or a failed tick
between the authorization and the commit refuses the step and writes
nothing.

Options. The response is only the WebAuthn request options:
`challenge`, `rpId`, `timeout`, `userVerification: "required"` and
`allowCredentials` holding exactly the session's own credential. The
challenge is bound to the session (`access_webauthn_challenges.session_id`),
expires with the challenge lifetime, and a new options request replaces the
session's pending one, so a session holds at most one and cannot fill the
bounded challenge table that sign-in shares.

Finish. The assertion is verified like a sign-in (type, challenge, exact
origin, rpId hash, UP, UV, signature, counter, BE/BS), and it must come from
the credential that created the session: an assertion from any other
credential — another person's passkey at the same workstation, or the Owner's
own second passkey — is refused and changes nothing. The commit
(`accept_assertion(step_up_session_id=...)`) re-checks that the session is
the Owner's, current and bound to this proxy identity, and records the new
verification time with the kernel boot id and `CLOCK_BOOTTIME` read in the
same transaction, with a `verify_principal_step_up` audit record (actor
`owner`, the principal's logical UUID only). Success is `204` with no body
and no cookie; the client then retries the Owner operation, which is
re-checked server-side. A cancelled, failed or refused step-up changes no
verification time, counter, backup state, idle expiry or audit record; the
only write is a consumed challenge. The one exception is a credential finding
(below).

Idle expiry (PR #236 review). Both step-up routes authorize with
`authorize_request(touch=False)`: every session check runs (idle and absolute
expiry at the in-gate request time, proxy-identity binding, CSRF, Owner role),
but `last_seen` and `idle_expires_at` are not written. Only a successful
step-up moves them, in `accept_assertion`'s transaction under the same
`admit(epoch)` (lock order gate -> storage admission -> SQLite). The options
route is read-only too: requesting a challenge proves nobody's presence, and
an options-plus-failed-finish loop would otherwise renew an unattended Owner
session until its 12-hour absolute expiry (AGENTS.md: idle and absolute
limits; a failed step-up changes nothing).

Challenge consumption (PR #236 review). Before verification the pending
challenge is only read (`AccessStore.pending_step_up_challenge`). A successful
step-up deletes it in the commit transaction itself
(`accept_assertion(step_up_challenge=...)`, inside `admit(epoch)`, lock order
gate -> storage admission -> SQLite), so a refused commit rolls the deletion
back. A step-up refused by the session gate — `stop()`, a failed check tick or
a close/reopen after the epoch check — is therefore a no-op: the challenge
stays pending until it is answered or expires (a close that revokes sessions
deletes it). An assertion whose envelope or client data (type, origin) does
not parse is refused before its challenge is known and consumes nothing, as
before. Every other refusal (bad signature, missing UP/UV, rpId hash, counter
or BE/BS, another credential or session, an unknown or expired challenge, a
commit refused inside its transaction) spends the challenge through `consume_challenge` in its own transaction, again inside
`admit(epoch)`, so it stays single use; only when the gate refuses that
consumption too is it left to expire. A verified assertion with a credential
finding (backup eligibility changed: the credential is marked inconsistent and
its sessions end; or a counter that does not advance: a regression record)
is refused too, but `_verified_assertion` only returns the finding, signature
verification staying outside the lock. Inside `admit(epoch)` (gate -> storage
admission -> SQLite) a single SQLite transaction,
`AccessStore.record_step_up_finding`, first deletes this session's pending
step-up challenge (`challenge_digest`, ceremony `step_up` and `session_id` all
match) and writes the finding and its audit record only if that DELETE
removed the row and it was still inside its issue-to-expiry window. If it
removed nothing — a concurrent finish of the same assertion spent the
challenge first, and its `accept_assertion` may have advanced the counter this
attempt compared against (5 -> 7 read as 7 -> 7), or a racing finish of the
same regressing answer recorded the finding first (one challenge yields at
most one finding and one notification), or a new options request replaced
the challenge after the pending read — or the removed row had
expired, nothing else is written: no mark, no regression record, no audit
record and no Owner notification, and the finish is refused. The Owner
notification is sent only after a commit that recorded the finding. A gate
refusal there records, invalidates and notifies nothing and leaves the
challenge pending. If the transaction itself fails (for example a refused
storage admission or a SQLite error), the DELETE rolls back with the finding;
the refusal then spends the challenge through `consume_challenge` under a new
`admit(epoch)` (the gate lock is not reentrant, so this runs after the first
admission is released), so the challenge stays single use while the unchanged
stored credential lets the next assertion detect the finding again; if the
gate refuses that consumption too, it expires unused. Sign-in
(`finish_authentication`) keeps recording a finding at once: its challenge is
already consumed before verification. Each refused finish increments the value-free
`HumanAccess.refused_step_ups`, and `owner_step_up_refused` is logged on the
first refusal and each power of two, with no token, CSRF token, challenge,
credential, identity or reason.

Freshness (ADR-0003: five minutes; `boot_clock.step_up_fresh`, migration 23).
An `OWNER_OP` request is fresh only when the session's last user verification
(sign-in or step-up) has a recorded boot pair from the same boot and both
`0 <= now - verified < 5 minutes` on the wall clock and on `CLOCK_BOOTTIME`,
the wall clock not lagging the monotonic one by more than one second. So it
is stale at exactly five minutes after the in-transaction verification time;
a wall clock stepped back after the verification makes it stale (fail closed)
instead of stretching the window, and one stepped behind the session's last
activity refuses every request of that session until the clock passes it
again; a wall clock stepped forward ends the window early; a reboot, a
session without a pair (established before migration 23, or while the boot
clock was unreadable) and an unreadable boot clock are stale. A step-up while
the boot clock cannot be read is refused, since it could never make the
session fresh. A stale Owner gets `403 {"detail":"step_up_required"}` on an
`OWNER_OP` route (D3); everyone else the generic `404`.

Limits. Step-up proves that the person holding the session's credential and
passing its user verification is present now; it cannot tell who that is
when a credential is deliberately lent, and it does not end the session: a
stale Owner session left open still serves `OWNER_READ` and every non-Owner
operation until its idle or absolute lifetime ends or it is signed out.
Under the shared login the step-up limiter's per-source bucket is the room's:
it is charged before authorization, so anyone behind the shared login can
spend it and delay the Owner's step-up (availability only, never access),
but it no longer shares a bucket with sign-in or redemption.

Clock slewing. The one-second allowance in `step_up_fresh` covers the
instant between the two reads of a pair, not a slew rate: chrony's default
`maxslewrate` is 83333 ppm (up to 25 s over five minutes), not ntpd's
500 ppm. `clock_gettime(2)` documents `CLOCK_MONOTONIC`, and so
`CLOCK_BOOTTIME`, as following adjtime/NTP adjustments, so a slew should move
both clocks together and only a step (chrony `makestep`, a manual set, a
kernel leap second) separate them. Should a chrony slew back nevertheless
separate them by more than a second, a just-verified session turns stale:
the Owner operation answers `403 step_up_required` and the Owner steps up
again (fail closed, availability only; it never lengthens the window).
MANUAL_TEST records the observation on the real host.

### Owner access administration (Issue #10 phase 2 S4a)

S4a hardens the store and `AccessAdministration`; it mounts no route (S4b
adds routes A1-A6, S4c the local CLI, S6 the Web screen). Owner decisions
S4-1 .. S4-8 (2026-10-13) apply.

- Authorization (S4-1). Every mutation (invitation, re-issue, grant change,
  principal and credential revocation) is an `OWNER_OP`: a fresh Owner
  session (step-up within five minutes). Reading the inventory is
  `OWNER_READ`. `HumanAccess.administration` is
  `AccessAdministration(OwnerAuditService(store.audit, HumanOwnerAuthorizer()), store, session_gate=HumanAccess.gate)`.
  `HumanOwnerAuthorizer` (`owner_operation.py`) accepts only an
  `OwnerOperationContext(session, epoch)`, which `HumanSurface._owner_operation`
  builds after `_authorize(..., OWNER_OP)` accepted the request inside
  `admit(epoch)`; a non-Owner context is denied as `invited_user`, anything
  else (a token, a login, a capture-node credential) as `unauthenticated`.
- Same epoch (S4a item 2). Each method takes `epoch=` from the route's
  `_Authorized.epoch`, never a fresh `epoch()`, and the context must carry
  the same epoch: the mutation commits inside `ServingGate.admit(epoch)`
  (gate -> storage admission -> SQLite, non-reentrant gate lock), so a close,
  reopen, `stop()` or failed tick since the authorization refuses it.
- In-transaction re-check (S4a item 3). The local `recover` and revocation
  commands commit outside the gate (D6), so after `BEGIN IMMEDIATE` the
  mutation reads the session again (`AccessStore.require_owner_session_on`):
  not invalidated, the same principal and credential, still the active Owner
  at the authorization revision the request saw, the deployment generation
  unchanged, the credential usable, idle and absolute lifetimes not passed,
  and the verification still fresh (else `StepUpRequired`). Every time the
  mutation depends on (an invitation's expiry included) is read inside that
  transaction. A refusal is a failed operation with its `failed` record.
- Invitation (S4-4, S4-8). `invite` commits the principal, its grants and
  its one code in one transaction (`invite_with_invitation_on`) with two
  records, `invite_principal` then `issue_principal_invitation` (as the local
  bootstrap does), and returns `(principal id, code, expires_at)`; the
  expiry is the in-transaction time plus the deployment's
  `invitation_lifetime` (PR #234 rule). `create_app` refuses a `HumanAccess`
  whose store's `invitation_lifetime` differs from
  `Settings.invitation_lifetime` (Issue #235 item 3). At most 64 principals
  that are not revoked (`MAX_PRINCIPALS`, the Owner included) and at most one
  pending code per principal (`MAX_PENDING_INVITATIONS`): beyond either the
  store raises `AccessLimitReached`, which the surface answers with the
  generic denial.
- Re-issue (S4-4). `reissue_invitation` revokes the principal's other unused
  codes and issues one, for an invited or an active principal (an active one
  registers another credential with it); refused for a revoked principal and
  for the Owner.
- Grants as a delta (S4-5). `change_permission(principal, permission,
  granted)` (and `set_permissions`) read and write in one transaction. A
  no-op changes nothing: no revision bump, no session ends. A real change
  advances the principal's revision and ends its sessions, while its pending
  code stays valid (the pending invitation's `principal_revision` advances
  with the principal's). `live:view` and `recordings:view` are independent.
- The Owner is never a target (S4-3): grant changes, both revocations and
  re-issue refuse the Owner principal; only the local `recover` changes the
  Owner's credentials.
- Credential handle (migration 24). Each credential has a random UUID
  `handle`, backfilled for existing rows, unique, required on insert and
  fixed (triggers). `revoke_credential` names a credential by
  `(principal id, handle)`; the WebAuthn credential id never reaches a URL,
  log or audit record. Revocation is credential-scoped: a synced passkey is
  revoked on every device it exists on.
- Inventory. `AccessStore.admin_inventory()` is one read-only transaction:
  per principal `id`, `display_name`, `role`, `status`, `created_at`,
  `revoked_at`, `permissions`, `invitation` (`pending`, `expires_at`) and
  `credentials` (`handle`, `label`, `status`, `inconsistency_reason`,
  `backup_eligible`, `backup_state`, `created_at`, `last_used_at`,
  `revoked_at`). It never returns the last observed proxy identity (Owner
  decision D14), credential ids, public keys, signature counters, digests or
  any session data.
- Nothing logs or audits a code, credential id or handle, identity or
  display name; audit records carry the principal's logical UUID only.

### Bootstrap and recovery commands and the session gate (Issue #181 item 2)

`python -m app.auth.bootstrap_cli bootstrap|recover --config <deployment.json>`
(Issue #10 phase 2 S2), run as the service account; the deployment steps are
in `server/docs/DEPLOYMENT.md`. Owner decision (2026-10-11): they do not go
through the server gate, and the deployment authorization generation (its
revocation by advancing) is what keeps them safe.

- They cannot use the gate: it lives in the serving process's memory, and in
  any other process the pid guard reports it closed, so a command that called
  `epoch()`/`admit()` would always be refused. A command opening its own
  `HostnameReservationCheck` would hold a second, unsynchronized verdict.
- They do not create sessions, store challenges or update a session's
  user-verification time; they create the Owner principal and issue one
  enrollment authorization (bootstrap) or advance the generation, revoke the
  old Owner and issue one (recovery). Every enrollment authorization records
  the generation it was issued under, and redemption refuses it once the
  generation has advanced (ADR-0003 bootstrap step 6, `issue_enrollment_on` /
  `enroll_credential`).
- So an authorization that a command commits before a reservation revocation
  is voided by that revocation, and one committed after it was shown only on
  the local console, never to the listener that caused the exposure.
  Redemption itself is the HTTP route, which goes through the gate like every
  other enrollment commit.
- A recovery advances the generation itself and invalidates every session in
  the same transaction, so it needs no gate to end sessions; the serving
  process sees the new generation on the next request.

What they do:

- `bootstrap` refuses unless no Owner principal exists (any status; the
  `access_one_owner` index refuses a concurrent second one). It reads the
  Owner's display name and the confirmation word `BOOTSTRAP` from the
  controlling terminal, then in one transaction creates the Owner `invited`
  with no credential, issues one code (the deployment's invitation lifetime)
  under the current generation and
  appends `invite_principal` and `issue_principal_invitation` (actor `owner`,
  the local administrative boundary as for the pairing CLI; target the
  Owner's logical UUID).
- `recover` refuses unless an Owner exists. It reads an optional new display
  name and the word `RECOVER`, then in one transaction
  (`AccessStore.recover_owner_on`): advances the generation (every session
  ends, every pending challenge is deleted, every outstanding invitation of
  everyone is void and must be issued again), revokes every credential of the
  Owner (credential-scoped: a synced passkey stops on every device it is on)
  and its pending invitations, clears its last observed proxy identity,
  advances its revision, sets it `invited` and issues one new code; it
  appends `invalidate_human_sessions` (fixed human-sessions id),
  `revoke_principal_credential` (when one was revoked) and
  `issue_principal_invitation`. The Owner keeps its logical UUID. Recordings,
  other principals' grants and credentials, and capture nodes are untouched.
- Both load `--config` exactly as the launcher does (`Deployment.load`) and
  take the database and the invitation lifetime from it
  (`deployment_configuration_rejected` otherwise), refuse unless running as
  its `service_uid` (and as root), refuse without a controlling terminal
  (`/dev/tty`) before any change, refuse when the boot clock cannot be read
  (`invitation_clock_unavailable`), read nothing secret from arguments or the
  environment, pin the existing database file (canonical path, regular file with one link
  owned by the running account, not group/other writable; never created or
  migrated) and re-verify it before each commit. The code is written only to
  the controlling terminal, after the commit; stdout gets the Owner's logical
  UUID and the expiry. A refusal changes nothing and records nothing, except
  `committed_code_not_shown`: the commit happened but writing the code to the
  terminal failed, so the code is lost; `recover` (also after `bootstrap`)
  issues a replacement.
- After a `recover` the Owner reviews principals, grants, credentials and the
  audit log: whoever held the Owner session before may have invited others
  (S4 onward), and `recover` leaves other principals as they are.

Limits: the writes are a few bounded rows and are not admitted through the
running server's storage policy (as for the pairing CLI). If writing the code
to the terminal fails after the commit, the code is lost
(`committed_code_not_shown`); run `recover`. The
running server's in-memory state does not change: it sees the new generation
on its next request. The low-level `establish_session` / `issue_enrollment`
wrappers stay unreachable from any human route.
