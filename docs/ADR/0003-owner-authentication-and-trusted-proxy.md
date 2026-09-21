# ADR-0003: Owner authentication and the trusted human-access boundary

Status: Accepted
Date: 2026-09-20
Owner approval recorded: 2026-09-21
Issue: [#6](https://github.com/TomokiAkiyama06/server-sentinel/issues/6)

## Context and approval boundary

AUTH-001 through AUTH-011 already require private reachability, independent
application invitations and permissions, Owner-only administration, prompt
revocation, and generic denial without deployment metadata. ADR-0001 and
ADR-0002 remain authoritative. This document proposes the implementation choices
below; it does not accept them on the Owner's behalf or activate human access.

The Owner approved the recommended choices in this record on 2026-09-21.
Issue #6 remains open until the full boundary is implemented and verified. Issue
#7 may build a backend that denies every human request; authenticated route
activation in Issue #10 still waits for implementation/review of the full
boundary.

## Proposed decisions requiring Owner confirmation

| Decision | Recommended choice | Alternative and consequence |
|---|---|---|
| Initial Owner and recovery | A privileged local administrative command on the Main Server creates/rebinds the single Owner and locally authorizes its one credential enrollment. No remote first-visitor setup or remote account recovery. | Per-person credentials leave no alternative: enrolling on first connection would let any holder of the shared login claim Owner, and requiring a credential first makes the first login impossible. The single-use local authorization is the residual attack surface, and it is bounded, principal-bound, and non-reusable. |
| Human identity and trust | Tailscale Serve over private HTTPS, forwarding to a loopback-only human backend on a host whose local processes are trusted. Match a deployment-scoped exact login identity to the application allowlist as a supplementary check, never as the authoritative authenticator. | An equivalent isolated authentication proxy can supply a stable issuer/subject, but needs its own reviewed adapter and deployment validation before support. |
| Hostname reservation | A hostname dedicated to ServerSentinel on every scheme and port, held by a dedicated network identity or a single-purpose node that the Owner records. Startup and daily checks enumerate actual listeners and proxy routes for the name and close access on any other answer. | Sharing the name by path keeps one browser origin, and sharing it by port still keeps one cookie scope because cookies are not port-scoped, so a neighbor receives or replays the Owner's session. Configuration enumeration alone cannot see a direct bind, so without the deployment isolation the checks only bound the exposure window. |
| Sessions and revocation | Server-side opaque sessions bound to verified identity and to the per-person credential that established them; 30-minute idle and 12-hour absolute lifetimes, and a 5-minute user-verification freshness window for Owner operations. Recheck current grants on every request and cancel active delivery on revocation, with a maximum five-second watchdog. | Owner-approved on 2026-09-21. A future change records its usability/resource tradeoff before implementation. |

No option permits Tailnet membership alone, automatic Tailscale policy changes,
public Internet exposure, a developer identity service, or capture-node access to
human APIs. Recovery changes application authorization only; it does not rotate
unrelated keys or alter the network's ACLs/Grants.

## Proposed bootstrap and recovery

The local administrative command operates through an OS-protected administration
boundary available only to the deployment administrator. It is not an HTTP route,
a shared bearer password, or a permission of the normal application service
account. An existing administrator-controlled local/SSH terminal may run it;
ServerSentinel does not configure SSH or grant remote administration.

Owner bootstrap must provision the Owner's first per-person credential, because
the session contract below admits no one without a credential assertion. Leaving
enrollment to the first browser connection would let any holder of the shared
Tailscale login claim the Owner credential, since that login names the account
and not the person; requiring an existing credential would make the first login
impossible. The local boundary resolves both, and the steps are symmetric with
recovery.

1. Verify administrative authority, the expected deployment/state directory, and
   the trusted proxy configuration. Refuse symlink/path substitution and unsafe
   state-file ownership or permissions.
2. Read the Owner's intended external login from protected interactive input and
   show the proposed binding locally for explicit confirmation. Do not infer the
   Owner from the first visitor, local username, an environment variable, a
   Tailnet administrator role, or a capture-node credential.
3. Within one transaction, create the deployment-scoped Owner principal only if
   none exists. Record an audit event without raw identity headers or credentials.
   Concurrent bootstrap attempts cannot create a second Owner.
4. In the same local step, authorize exactly one credential enrollment for that
   Owner principal: a single-use, short-lived authorization carrying the
   principal, its issue time, its expiry, and the principal and deployment
   authorization generations it was issued against. The server keeps only a
   digest of the secret. It is displayed on the local administrative console
   and nowhere else; it never enters logs, diagnostics, audit records, URLs,
   query strings, referrers, or any reusable plaintext storage. Access stays
   closed until it is redeemed.
5. The Owner carries it from that console to the browser they will use and
   submits it once to the redemption endpoint on the reserved origin, over the
   private-network HTTPS path this design already requires, and registers an
   authenticator with user verification. That is the invitation-redemption path
   of the shared-account ADR rather than a new route: the value travels in a
   request body, never in a URL, and the response sets no cookie and returns no
   application data. Where the Main Server has a usable local browser, the same
   ceremony runs over the loopback boundary and the authorization does not
   leave the host; the remote case is the one that accepts the manual transfer
   and is bounded by the short lifetime, the single use, and rate limiting.
6. Redemption requires the authorization, a verified identity matching the
   binding, and both current generations. It is refused when the authorization
   is spent or expired, when the current time predates its issue time, when
   expiry cannot be reliably established after a restart or clock step, or when
   either generation has advanced — so recovery, revocation, and any other
   generation change void every outstanding authorization atomically without
   tracking them individually. Redemption is rate-limited, grants no
   application access by itself, and the Owner authenticates afterwards like
   anyone else. Every refusal is the one generic response.
7. An expired, unredeemed, voided, or already-redeemed authorization leaves
   human access closed; only the local administrator can issue another. The
   first browser connection therefore cannot enroll on verified identity alone.
   The authorization is not a bearer credential for application data, is not
   reusable, and bypasses neither the private-network gate nor any later
   credential assertion.

Recovery requires the same administrative local boundary and explicit
confirmation of the replacement identity. Stop admission of human requests,
increment a deployment authorization generation, invalidate all human sessions,
cancel active delivery, revoke the old Owner binding together with every
credential enrolled under it, void every outstanding enrollment
authorization by that generation change, and bind exactly one new Owner
atomically. The
replacement Owner enrolls a credential through the same locally authorized,
single-use enrollment as bootstrap step 4 before any session exists, so
recovery never leaves a usable credential behind. Persist the audit outcome
before reopening admission; crash or storage failure leaves access closed.
Media and non-owner invitations are preserved, but prior sessions must be
re-established. Recovery does not erase recordings, alter biometric enrollment,
change capture-node credentials, or operate Tailscale administration. Restoring
an authorization database backup must also advance the generation and
invalidate all restored sessions before serving.

## Proposed proxy and identity boundary

```text
Human browser
  -> private Tailscale HTTPS / Serve
  -> dedicated loopback-only human backend
  -> verified proxy identity + active application principal
  -> current session + current permission
  -> permitted handler

Capture agent -> separate authenticated ingest listener -> agent protocol only
Local administrator -> protected local administrative command
  -> Owner bootstrap/recovery + one single-use credential enrollment
```

The approved binding uses an explicit loopback address; wildcard or LAN listeners
are startup errors. IPv4/IPv6, Docker publishing, reverse proxies, port forwarding,
and host network namespaces must not expose the upstream listener. A Compose
mapping cannot publish it on all host interfaces. The application checks the
actual transport peer, never a client-controlled `Forwarded`/`X-Forwarded-For`
value, before interpreting identity. Being a loopback peer alone does not prove
Serve: this design expressly trusts processes in that host/network namespace.
An untrusted shared host requires a separately reviewed isolated local boundary;
it is not supported by silently assuming loopback authenticates local processes.

Tailscale documents that Serve replaces inbound identity headers, supplies
`Tailscale-User-Login` for human user traffic, and omits human identity for tagged
devices and public Funnel traffic. Shared-device users can also have identity
headers. This proposal therefore checks application invitations for every such
identity and rejects missing human identity. No display-name, profile-picture,
app-capability, subnet-address, or tag value grants application access. Profile
image URLs are not fetched or embedded. See [Tailscale Serve identity
headers](https://tailscale.com/docs/features/tailscale-serve#identity-headers).

The verified proxy identity is a supplementary gate, not the authoritative
authenticator. The target deployment shares one Tailscale account across a
research room, so a verified login names that account rather than the person
behind the request, and every holder of it reaches this listener from the same
network position. Application authorization therefore rests on a per-person
ServerSentinel credential that the Owner issues by invitation and can revoke
individually; WebAuthn/passkey is the design goal. That deployment constraint
and the choice of mechanism belong to a separate shared-Tailnet-account ADR
added by its own pull request, while this record keeps the boundary mechanics
around it: Owner bootstrap and recovery, the trusted-proxy path, and sessions
and revocation. Where the two overlap, a verified login never suffices alone; a
request carrying a verified login and an active invitation but no
credential-backed session is denied exactly like an uninvited one. The identity
key rules that follow define that supplementary check, not the application
principal.

The identity key is `(deployment-configured proxy issuer, exact login)`. The
issuer is server-side configuration, never an HTTP header. Require exactly one
nonempty login header, bounded length, and no control characters or ambiguous
comma-joined values. Reject invalid/unsupported encodings; never guess, trim,
case-fold, or use display names to merge identities. The first adapter supports
printable ASCII login values only; an RFC2047 encoded value fails closed until a
reviewed canonicalization adapter exists. Local provisioning/invitation applies
the same validation. All examples/tests use invented `.invalid` identities.

Serve's login is an identity-provider-controlled name, not a permanent immutable
subject. The Owner must revoke the application binding before deleting,
transferring, or reassigning the corresponding upstream account. A detected login
change needs explicit rebinding; it never auto-migrates permissions. Reassignment
of the same upstream login cannot be independently detected by this adapter.
This limitation is part of the proposed choice; deployments that cannot accept
it need a reviewed stable issuer/subject adapter before activation. Changing the
proxy issuer/Tailnet deployment invalidates sessions and requires re-approval of
bindings, rather than carrying grants into a new identity authority.

No Tailscale admin credential or local daemon-control socket is handed to the
application. Tailscale policy remains externally managed. Serve configuration
must be private-only and is verified during deployment; Funnel is unsupported.
There is no assertion of concealment from Tailnet or infrastructure admins.

## Proposed session contract

After verified identity, an active Owner-approved invitation, and a successful
per-person credential assertion, a same-origin session-establishment operation
creates a cryptographically random opaque session ID. Persist only its digest
and bind the record to the principal, exact identity key, the credential handle
that established it, the time of that user verification, authorization
generation, issue time, last use, and expiry. Revoking one credential
invalidates the sessions bound to it without revoking the principal's other
credentials or its invitation. The cookie is host-only with a neutral `__Host-`
name, `Secure`, `HttpOnly`, `Path=/`, no `Domain`, and `SameSite=Strict`. No
URL/session parameter, localStorage token, client-selected session identifier,
or self-contained permission-bearing JWT is accepted. Rotate the ID at
establishment and privilege changes.

ServerSentinel requires an exclusive hostname, not merely an exclusive path.
The reserved name serves this deployment alone on every scheme and port, and
the configured `https://<host>[:<port>]` is the only thing routed under it: no
other application, static tree, alias, additional port, or catch-all forward
answers for that name, and path-based co-hosting is unsupported. Two distinct
scopes make the hostname, rather than the origin, the unit of reservation.

The first is the browser origin. `Path=/` sends the session cookie to every
path of that host, and script served from another path of it runs in this same
origin, so one compromised neighbor can call session establishment and API
paths as the currently proxy-verified user, present the exact reserved
`Origin`, read any CSRF token handed to the frontend, and reach Owner
operations. Nothing in the request distinguishes that script from the
dashboard, so host-only cookies, `SameSite`, and same-origin checks cannot be
the boundary.

The second is the cookie scope, which is wider than the origin because cookies
are not port-scoped. A host-only `__Host-` cookie is sent to every HTTPS port
of the reserved name, so an application answering at
`https://<host>:<other-port>` receives the Owner's opaque session ID even
though it is a different origin. Under a shared Tailscale login it can replay
that session through Serve as the same supplementary identity, arriving behind
the per-person credential gate instead of passing through it, and neither
`SameSite=Strict` nor the `__Host-` prefix prevents this. A second application
therefore takes its own hostname. Another port, path prefix, subdirectory, or
shared `__Host-` cookie scope does not separate it, and neither does a reverse
proxy that merges both behind one name.

Reserving the hostname is a property of the host, not of a configuration file,
and the checks below detect violations rather than prevent them. Enumerating
Serve/reverse-proxy routes is not sufficient on its own: any local process may
bind another HTTPS port on the node's Tailscale address without appearing in
that configuration, and it may do so after the check, which no configuration
change would re-trigger. Because cookies are not port-scoped, such a listener
receives the session cookie exactly as a configured neighbor would. Saying that
startup refuses any other application on the name would therefore be a claim
this design cannot keep.

The reservation is consequently a deployment obligation, recorded and
acknowledged by the Owner, met by one of two isolations: ServerSentinel holds
its own network identity — a dedicated host, VM, or network namespace with its
own Tailscale address, so no other process can bind the reserved name — or the
node is administered as single-purpose, where only this deployment and its
proxy may bind that address and the restriction is enforced outside the
application by OS/service policy. This is the same trust assumption already
stated for the loopback boundary: processes in that host/network namespace are
trusted, and an untrusted shared host is unsupported.

Within that obligation the application verifies what it can observe. At
startup, and again on the existing daily schedule rather than only on
configuration change, it enumerates the actual sockets bound to the reserved
address together with the Serve/reverse-proxy routes for the whole name — every
scheme and port, not only the configured origin — and refuses to serve when any
listener or route other than this human listener and its proxy answers for the
name, when the expected single mapping is absent, when the deployment record
does not state which isolation is in force, or when the enumeration cannot be
performed. It fails closed instead of guessing, and a violation found on a
later check closes human access and notifies the Owner like any other integrity
finding.

The residual limitation is stated rather than designed away: a process that
binds the reserved address between two checks can receive cookies until the
next check, and the application cannot prevent a local process from binding at
all. Detection bounds the exposure window; only the deployment isolation
removes it. The reservation check precedes identity, session, and permission
evaluation.

The session is an additional application state boundary. Every human request
still needs the same verified proxy identity and current invitation/grant; a
copied cookie or media URL alone never authorizes. Approved timeouts are 30
minutes idle and 12 hours absolute, checked server-side. Active authorized
playback counts as activity; it does not extend absolute expiry. Restart/clock
uncertainty must not extend lifetime; invalidate sessions when expiry cannot be
reliably established. A time before session establishment or before its last
accepted activity is rejected, so a backward clock step never revives access. Logout invalidates server state and closes that session's
active streams. Because Tailscale identity remains authenticated, a user with an
active invitation can explicitly establish another session; logout is not user
revocation and does not force upstream identity-provider reauthentication.

The session does not retain another raw copy of the proxy identity. It stores
only HMAC-SHA-256 over the canonical verified identity with a deployment-local
secret kept outside the database, recomputes that binding for every request and
compares it in constant time. Session invalidation clears the binding; it is
never displayed and is excluded from diagnostics and exports.

Validate an exact configured HTTPS Host/origin, require exact same-origin
Origin for session establishment and state-changing requests, deny cross-origin
CORS, and use a session-bound CSRF token for subsequent changes. Read requests
must have no state-changing side effects. WebSocket handshakes require the
configured Origin and current authorization. A present `Origin` that is not
exactly the reserved origin is rejected on every request, including reads. An
absent `Origin` is accepted only for non-mutating reads, because browsers omit
it for same-origin navigations; establishment, state-changing requests, and
handshakes require the exact value and deny an absent one. Owner operations
under AUTH-008 additionally require a user verification newer than a proposed
five-minute freshness window, evaluated server-side from the session record.
A verification time that is not between the session's establishment and now is
unusable rather than fresh, so a backward clock step or restored future
timestamp requires the step-up again;
the response for an otherwise authorized but stale Owner session is defined
with the shared-account ADR, and a failed or cancelled step-up performs
nothing. Token material and raw identity/cookie headers never enter logs,
diagnostics, URLs, or public CI artifacts. The cookie and lifetime choices
follow the design principles in [OWASP Session
Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
and [OWASP CSRF
Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html);
those sources do not select the proposed product timeout values.

## Proposed permission and revocation contract

| Requested capability | Current authorization |
|---|---|
| Current live media and source state needed for live viewing | `live:view` or Owner |
| Recording list, browser playback, historical timeline/events | `recordings:view` or Owner |
| Invitations, permission changes, camera/node configuration, retention/security settings, biometric changes, destructive recording operations | Owner |
| Non-owner recording download/export | Unavailable in MVP, including with both viewer grants |
| Product/version/schema/detailed health and application assets | Active authorized principal with the endpoint's explicit permission; no pre-auth exposure |
| Enrollment redemption and credential assertion, before any credential or session exists | Verified identity, and for redemption an unspent, unexpired authorization current for both generations. Rate-limited, no application data, assets, or deployment metadata, no session cookie on failure, generic response on every refusal |
| Unknown/unregistered route, unsupported method, human route through ingest | Deny |

The generic denial is the same non-branding response for absent, malformed,
uninvited, revoked, and insufficiently privileged identities, independent of
resource existence. Authentication/authorization precedes resource lookup,
redirects, validation errors, application assets, OpenAPI/docs, health, and error
handlers. Omit server/product/version headers and session cookies on denial;
use `Cache-Control: no-store` for protected responses, including media and denial.
Proxies must not append product metadata. Local health supervision uses a separate
local process mechanism, never a public unauthenticated HTTP health exception.

Issue #8's static dashboard shell is a development/mock artifact until Issue #10
integrates authorized delivery. Its HTML, JavaScript, CSS, favicons, source maps,
service workers, and application configuration must not be deployed from a
separate unauthenticated static host or public bucket. The human listener guards
the entire asset namespace before any file/fallback response. A minimal neutral
same-origin session handshake may be supplied only after verified identity and
active invitation; it cannot expose dashboard assets to arbitrary visitors. The
only surface reachable before a credential exists is the enumerated pair above —
enrollment redemption and credential assertion — together with the minimal
neutral markup and script those two need; the listener serves no other path,
asset, or fallback to a request without a credential-backed session, and the
pair itself returns no application data. Unknown routes and SPA fallback pass
through the same gate. UI permission hiding
is presentation only and never substitutes for server authorization.

Permissions are read from current authoritative application state; sessions do
not cache an independent grant. Mutations serialize the authorization check with
their protected effect so revocation cannot race an already queued administrative
write. Revocation commits the new state, invalidates affected sessions, and
signals every worker/delivery task before reporting success. New requests fail
immediately after commit. A stream rechecks before each bounded emission and is
cancelled on the revocation signal. A watchdog revalidates within five seconds
in the proposed design; an unavailable permission store or missed cross-worker
signal must stop delivery by that deadline. Bound write sizes/timeouts and queued
output so a blocked network write cannot bypass cancellation indefinitely.
Previously delivered bytes and browser buffers cannot be recalled.

Re-invitation is a new authorization generation and never revives an old session.
Permission reduction, principal revocation, recovery, issuer change, expiry, and
logout all apply to manifests, segments, range requests, WebSockets, and long-lived
responses. Human session credentials are never accepted by capture ingest, and
capture credentials are never accepted by the human boundary.

## Threat cases and validation

| Threat or transition | Design evidence |
|---|---|
| Stale enrollment authorization survives recovery; redemption replayed after a backward clock step | Generation-bound, single-use authorization refused outside its issue-to-expiry window |
| First visitor claims Owner; shared-login holder enrolls the Owner credential; replay/concurrent bootstrap | Local-only explicit bootstrap, single-use local enrollment authorization, uniqueness transaction, no bootstrap HTTP route |
| LAN/forwarded-header spoof; ingest-to-human bypass | Actual peer and listener separation; deployment reachability tests required |
| Missing/duplicate/tagged/shared-but-uninvited identity | Strict adapter, no identity fallback, application allowlist |
| Co-hosted application on the same origin, or on another port of the same hostname, reads or replays the session cookie | Hostname held by a dedicated network identity or single-purpose node; startup and daily listener/route enumeration close access on any other answer, with the between-check window stated |
| Shared Tailscale account holder without an invitation or per-person credential | Supplementary proxy identity; credential-backed session required on every human route |
| Copied cookie/URL; wrong issuer; identity reassignment | Session identity binding; documented upstream login-reuse limitation |
| Permission change, expiry, logout, recovery, re-invitation | Current state and generation validation; delivery cancellation |
| `live:view` requests historical data or both grants request export | Independent permission matrix; unavailable non-owner export |
| Unknown route/error path leaks product or resource existence | Global generic denial before router/data lookup |
| Auth database unavailable; recovery crash; missing boundary configuration | Fail closed with no application metadata |

`tests/models/human_access.py` is an executable, dependency-free design model.
Its synthetic tests exercise the gate combinations and authorization
transitions; it is neither production authentication code nor evidence that
sockets, proxy headers, cryptographic cookies, CSRF, database transactions,
clock handling, or real stream cancellation have been implemented. The model
receives evidence as explicit inputs and tests policy composition, rather than
pretending to verify those inputs. The hostname reservation, the origin
evidence of a request, and the credential that established a session enter the
same way, and every evidence field defaults to the value that denies. The model
checks that a deployment without a verified reservation stays closed, that a
bootstrapped Owner authorizes nothing until the single-use local enrollment is
redeemed once, and that a session whose credential was revoked stops
authorizing. The pre-credential redemption path is a separate function there,
because the request gate itself denies everything without a credential-backed
session. It cannot enumerate listeners, inspect proxy configuration, or
verify an authenticator. Session timeout/watchdog numbers remain proposals even
though tests can exercise boundary values.

## Alternatives and consequences

- First-visitor ownership, LAN trust, Tailnet-role ownership, browser headers as
  identity, and agent-as-Owner are rejected by existing requirements.
- Stateless permission tokens complicate prompt revocation; server-side current
  authorization is proposed instead.
- Password/SSO account administration hosted by the project conflicts with the
  no-developer-cloud model. An independent deployment-local identity provider
  would add setup/recovery scope and needs its own Owner decision.
- A remote first-visitor bootstrap is rejected: under a shared Tailscale login
it grants Owner to whoever connects first. The local command keeps the
privileged decision outside the human HTTP listener and reduces the remote
ceremony to redeeming one short-lived, single-use, principal-bound enrollment
authorization.
- Trusted-host loopback is simpler but does not protect against malicious local
  processes, a compromised proxy, host administrators, or upstream account reuse.
  The proposed design states these trust assumptions explicitly.

## Follow-up and completion

Owner approval of the decision table must be recorded with provenance before
changing Status to Accepted, closing #6, or enabling dependent human access.
The PR may be reviewed as a Proposed design without that approval.

Issue #7 supplies the fail-closed backend shell. Issue #10 implements the approved
bootstrap/proxy/invitation/session boundary and negative tests against real route
handlers. Issue #19 implements media delivery authorization/cancellation, and
#27/#28 test cross-component and real private-network/browser behavior. Deployment
verification must include real IPv4/IPv6/LAN bypass attempts, exact installed
Serve behavior, Docker exposure, clock/restart/session cases, and active
phone/Mac/desktop playback revocation. Until these exist, no production-security
or hardware/network/browser acceptance is claimed.
