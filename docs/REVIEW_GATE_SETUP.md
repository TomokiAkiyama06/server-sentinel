# Dedicated-App review gate: deployment proposal and offline policy

Issue [#4](https://github.com/TomokiAkiyama06/server-sentinel/issues/4) remains
**open**. The checked-in implementation provides an offline receipt validator,
a disabled candidate ruleset generator, a self-hosted delivery adapter, a
provider review collector, an App-JWT installation-token exchange adapter whose
RS256 signer is deliberately **not** implemented (Owner decision below), and
synthetic tests for all of them. There is no registered App, deployed
publisher, installed enforcement, or completed GitHub test-PR acceptance.
Everything here is verified only against mocks. Continue the current manual current-HEAD/current-base review
procedure in [CLAUDE_REVIEW_SETUP.md](CLAUDE_REVIEW_SETUP.md); that document also records the temporary suspension of Claude review automation.

## Capability assessment

Read-only GitHub inspection for this proposal found:

| Inspection | Result |
|---|---|
| Repository ownership / visibility | Personal account (`User`) / public |
| Current operator permission | `admin: true` |
| Repository rulesets | Active baseline rule `23728669`: PR-only, strict required `CI` from GitHub Actions, thread resolution, no force push/deletion or bypass |
| `main` branch protection | `404 Branch not protected` |
| Existing CI check issuer | Shared GitHub Actions App, ID `15368` |
| `GET /user/installations` | `403`: the current token cannot enumerate App installations; this does not establish that no App is installed |

These are an inspection snapshot, not a permanent assertion. The Issue's older
statement that the connected operator lacks repository administration rights is
superseded by this inspection. The [CI baseline rule](https://github.com/TomokiAkiyama06/server-sentinel/rules/23728669)
was applied separately under the Owner's CI instruction and re-read through the
API. It protects `main` without bypass actors, but its shared GitHub Actions
issuer does not implement #4's dedicated review provenance. Classic branch
protection remains unset because the baseline uses a ruleset. This preparation
does not change settings.

GitHub documents Required workflows at the **organization or enterprise** level.
The current personal repository cannot use that route in place. Moving ownership
or buying a different plan is an Owner decision; neither is part of this change.
[GitHub: Required workflows](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-workflows-to-pass-before-merging).

A dedicated GitHub App is the alternative for the current ownership. Required
checks can identify an expected App, while ordinary name-only checks cannot
distinguish a forged success from another writer. Require strict up-to-date
checks and the test-merge binding below for base freshness.
[GitHub: required status checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-status-checks-to-pass-before-merging).

## Owner setup needed before implementation can be enabled

1. Choose an Owner-controlled execution location for the trusted reviewer and
   publisher. A local process that polls GitHub can avoid an inbound listener.
   This proposal does not create external hosting or deploy any process. The
   selected execution/key boundary needs Owner confirmation before deployment.
2. In personal Settings → Developer settings → GitHub Apps → New GitHub App,
   register a private App owned by the Owner. Use the public repository URL as
   its homepage, disable webhooks for the polling option, and leave user OAuth
   callbacks unset. Do not add unrelated managers.
3. Grant repository **Checks: read/write**, **Contents: read**, **Pull requests:
   read**, and **Metadata: read**. Add **Actions: read** only if the chosen
   collector reads workflow metadata. No contents/workflows/administration write
   or account/organization permissions are needed by this proposal. If GitHub's
   expected-source selector requires **Commit statuses: read/write**, add that
   narrowly scoped permission after verifying the requirement; do not substitute
   a general personal token. The App never writes source or merges PRs.
4. Install the App on **only** `TomokiAkiyama06/server-sentinel`. Record its numeric
   App ID, slug and installation ID in Owner-controlled deployment policy outside
   the PR checkout. Confirm identity in the installation UI; a name alone is not
   evidence. Review the granted permissions against the selected APIs.
5. Generate the App private key in its settings and place it directly in the
   Owner's secret store or a restricted file outside every repository/workspace.
   Do not paste it into conversation, Issues, logs, shell command arguments, or a
   repository secret accessible to arbitrary same-repository workflows. Restrict
   file/directory access to the publisher account. Review processes get no App
   key or publisher token; give them only fixed source/diff data. Installation
   tokens must be short lived and restricted to the one repository and required
   permissions. Key compromise allows check forgery; rotation is an Owner action.
6. Implement and review the collector/publisher contract below using the chosen
   execution boundary, then perform the synthetic GitHub test-PR matrix before
   enabling the rule on `main`.

GitHub's permission guidance requires selecting only the APIs the App uses;
installation grants remain separate from registration.
[GitHub: choosing App permissions](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app).
Private-key lifecycle and protection are described in
[GitHub: managing App private keys](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps).

Registration cannot be completed merely by reusing the repository-admin CLI
token. GitHub's documented manifest route starts with an Owner browser flow and
exchanges the resulting temporary code for sensitive App configuration. No
manifest exchange or credential generation was attempted here.
[GitHub: registering an App from a manifest](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest).

## Trusted collector and publisher contract

The checked-in foundation now contains no-network publisher primitives:
`receipt_summary(context, reviewer)` and
`successful_check_run_request(context, reviewer)`. They produce a canonical,
bounded receipt and the only successful Check Run request shape. They bind the
fixed reviewer name and every context field and target the current test-merge
SHA. They take neither an App identity nor a credential, cannot select another
target, and do not accept a caller-provided conclusion.

They are **not** a GitHub client or a review provider adapter. The self-hosted
deployment still needs an Owner-operated collector that verifies reviewer
provenance and a separately reviewed App-authenticated delivery adapter. It
must call the primitive only after the corresponding review has passed and
after it has re-read the same live context. Any unavailable provider, unknown
review result, stale context, or delivery error leaves the required check
absent or blocking; it must never turn an error into `neutral`, `skipped`, or
`success`.

`scripts/ci/review_gate_publisher.py` now supplies the narrow delivery adapter
foundation. At runtime it accepts only an absolute path in
`SERVER_SENTINEL_REVIEW_GATE_CONFIG`; that JSON file and its private-key path
must be private regular files outside every checkout. It opens each file before
checking its descriptor, so a path replacement between a metadata check and a
read cannot substitute material. It rejects group/other permissions, final-path
symlinks, unexpected owners, unexpected JSON fields, weak/missing installation
tokens, malformed GitHub responses, changed context, a missing or
incorrect test-merge parent pair, and a Check Run response from any App other
than the configured dedicated App. It uses fixed GitHub.com HTTPS API paths,
disables proxies and redirects, and has no subprocess, git, shell, checkout,
webhook, ruleset, or App-registration operation.

The configuration contains only routing identity:

```json
{"repository":"TomokiAkiyama06/server-sentinel","repository_id":123,
 "app_id":456,"app_slug":"server-sentinel-review-gate",
 "installation_id":789,"private_key_path":"/etc/server-sentinel/review-gate.pem"}
```

Keep it outside the repository, mode `0600`. Set the short-lived installation
token only in the publisher service environment as
`SERVER_SENTINEL_REVIEW_GATE_INSTALLATION_TOKEN`; do not write it into this
file. Alternatively `review_gate_app_token.py` (below) exchanges an App JWT for
the token in memory and passes it as `installation_token=` to
`load_app_credentials`; the environment variable is then unused. The
`AppCredentials` repr omits the key and token. This foundation does not create
a key, token, App, installation, check source, or ruleset.

The publisher must execute reviewed, pinned code and load policy from its trusted
deployment, never from the PR. Neither same-repository nor fork code may run with
reviewer credentials, the App private key, or an installation write token. Do not
promote PR artifacts, workflow names, success strings, comments, or a claimed
`app_id` into authenticated evidence. The same-repository Claude workflow is an
operational review today; its arbitrary branch-controlled workflow is not an App
attestation. Its secret must also be isolated before trusting additional writers.

Collect both reviewers from authenticated reviewer APIs or execute the reviewers
in the isolated trusted process. Verify the actual issuer, exact request/run ID,
successful complete response, and no unresolved important/critical findings.
Codex's `Reviewed commit` alone lacks a base binding and is insufficient. Record
the exact review request context before invoking either engine. Reactions, an
author display name, or a subsequent request comment do not establish that the
review was performed against that context. Missing provider provenance fails
closed.

### Provider review collector (`review_gate_collector.py`)

The collector converts an authenticated Codex or Claude **GitHub pull-request
review** into the fixed receipt from `successful_check_run_request`. It never
executes a provider and never posts the trigger comment. Publication goes
through `ReviewCollector.collect_and_publish()` (see "Publication and
supersession" below); a success is posted only via `publish_success`, which
re-reads the live context again before posting.

Provider policy lives in an external private JSON file named by
`SERVER_SENTINEL_REVIEW_COLLECTOR_CONFIG` (same `0600` / outside-checkout /
no-symlink rules as the publisher configuration):

```json
{"state_dir": "/var/lib/server-sentinel-review-gate",
 "providers": {"codex": {"user_id": 123, "user_login": "<provider-app>[bot]",
   "max_review_runtime_seconds": 1800,
   "pass_markers": ["<exact no-findings phrase>"],
   "blocking_markers": ["<P0 marker>", "<P1 marker>"],
   "non_blocking_markers": ["<suggestion-only marker>"]}}}
```

`user_id` is the numeric account ID of the provider App's bot user; the login
must also match and GitHub must report `type: "Bot"`. The shared GitHub Actions
bot (`github-actions[bot]`, user ID `41898282`), anything performed via the
Actions App (`15368`) and `dependabot[bot]` are refused as configuration and
ignored as evidence. This is what makes a review posted by a PR workflow's
`GITHUB_TOKEN` worthless: it can copy every word, but not the bot identity.
Lookalike logins and a matching login with another ID are counted in the
decision as `ignored_untrusted_reviews`, never as a pass. Codex and Claude must
have distinct identities. The current same-repository Claude workflow posts as
the Actions bot and therefore cannot satisfy this collector; a trusted Claude
path needs its own App identity or an isolated trusted process (Owner decision).

Flow and binding:

1. Before posting any trigger (for example `@codex review`), call
   `request_review(reviewer, live_context, source)`. It durably records the
   complete `Context`, the highest review ID currently listed on the PR
   (watermark) and the request time, under a per-PR lock, with an atomic
   `0600` write and directory fsync in `state_dir` (a `0700` directory owned by
   the publisher account, outside every checkout). A repeated call for the same
   active context returns the same request (retrying trigger delivery never
   creates a second request). `force_new=True` supersedes it, but is refused
   while a success this collector published still stands; call
   `revoke_published()` first so the old success cannot satisfy the required
   check during the rerun.
2. `collect(reviewer, read_live_context, source)` re-reads the live context
   before and after reading the complete, paginated reviews and each candidate's
   inline comments. Any HEAD, base, merge-base, diff or test-merge difference
   from the request marks the request `invalidated` durably; it can never pass
   again, even if the old context returns. A new request is required, and the
   same-HEAD review that preceded it is below its watermark. The unlocked first
   read can be overtaken by a concurrent `request_review` for a newer context
   (even within the same clock second, so timestamps cannot order them). A
   mismatch therefore only notes the request ID seen under the lock and
   re-reads the live context: only if that fresh read still differs and the
   same request is still current is the request invalidated. If the request
   was replaced meanwhile, or the fresh read matches, the decision is
   `pending` (`live_context_read_predates_request`).
3. A review counts only if it is from the configured bot, has an ID above the
   watermark, targets the recorded HEAD, and was submitted at least
   `max_review_runtime_seconds` + 300 s (clock skew allowance) after the
   request. GitHub reviews carry only `commit_id`; this delay is the only way to
   exclude a review that was started under an older base (automatic review on
   push, a human `@codex review`) and finished after the new request.
   Earlier passing reviews are ignored as ambiguous; earlier *failing* ones
   still block. Consequently a provider run that finishes inside the bound
   (the normal case when the bound is set correctly) leaves the decision
   `pending`: after the bound has elapsed with the context unchanged, post the
   trigger again **without** `force_new` (the same request is reused) and the
   new review, submitted after `earliest`, can count. This doubles provider
   runs per context; a cheaper binding needs provider-side request/base
   provenance and is an Owner decision.
4. A counted review passes only with state `COMMENTED` or `APPROVED`, a pass
   marker in the body, no blocking marker, and every inline comment carrying a
   non-blocking marker and no blocking marker. Any other trusted same-HEAD
   review above the watermark blocks. No clean review yet is `pending`.

Decisions are `pass`, `pending`, `blocked` or `invalidated` with a fixed reason
code; only `pass` carries a check-run request. Malformed or oversized evidence,
a truncated listing (the watermark review must still be listed), a listing that
regressed, more than 1000 reviews / 300 comments per review / 20 candidate
reviews, a corrupt, foreign or non-private ledger record, an unavailable lock
(30 s bound) and every API error raise `CollectorFailure`, leaving the check
absent. Logs carry reviewer, PR, request ID, status and reason code only;
review text is never logged.

### Publication and supersession

GitHub evaluates a required check by the **latest** attempt with that name on
the test-merge SHA, and nothing removes an earlier success. The collector
therefore records, in the same private ledger record (schema version 2), the
success it posted, or may have posted, per reviewer: request ID, test-merge
SHA, Check Run ID (once confirmed) and state (`publishing` / `success` /
`revoking`).

- `collect_and_publish(reviewer, pr_number, read_live_context, source, client,
  credentials)` is one reconciliation pass, bound to `pr_number` and the
  configured repository: a live read naming another PR or repository fails
  before any ledger is touched (and supersedes `pr_number`'s standing
  success, which that pass could not verify). A `pass` for the ledger's current
  active request posts one success; if that exact success is already recorded
  **and** GitHub still lists it as the dedicated App's latest attempt of that
  check on the test-merge SHA, the pass is a no-op, so polling and restart
  recovery do not create further runs. The verification is one read of
  `GET /repos/{owner}/{repo}/commits/{test_merge_sha}/check-runs` filtered by
  `check_name`, `app_id` and `filter=all` (paged, at most 10 pages; covered by
  the **Checks: read** permission above). The recorded run must have the highest
  run ID among that App's runs of the check and read `completed` / `success`.
  An incomplete or changing listing is treated as "not latest" (supersede,
  then post a new success); a failed read raises and supersedes the standing
  success (fail closed).
- The per-PR ledger lock is held for the **whole** pass (collection and the
  resulting publication or revocation), so a pass only ever publishes or
  revokes what its own collection observed. Overlapping passes cannot revoke a
  success published from newer evidence, nor publish from evidence a newer
  non-passing collection already superseded. A pass that cannot take the lock
  within the lock timeout fails without changing anything (another pass is
  running); the next scheduled or event-driven pass retries. Automated
  reconciliation must use `collect_and_publish`; composing `collect()`,
  `publish()` and `revoke_published()` separately does not have this property.
- A `publishing` record is saved **before** the success is sent. If the
  outcome is then ambiguous (API error, lost or malformed response, crash, or
  a failed ledger write after GitHub accepted the post), the success is still
  tracked: the error path supersedes it immediately, and otherwise the next
  outcome supersedes it (a later `pass` first posts a failure attempt, then a
  new success). An untracked success therefore cannot remain the latest
  attempt.
- Every other outcome (`blocked`, `pending` after `force_new`, `invalidated`),
  a `pass` for a request that was superseded in the meantime, and any
  collection error supersede a standing success with a newer attempt of the
  same name on its test-merge SHA: `status: completed`, `conclusion: failure`
  (never `neutral` / `skipped`, which satisfy a required check), fixed output
  without review text.
- Before that failure attempt is posted the ledger is set to `revoking`. A
  crash or API error during revocation is retried on the next pass and the
  record is never taken for the current success.
- If the `revoking` state cannot be written (read-only or full `state_dir`),
  the failure attempt is still posted, best effort, and the ledger write error
  is raised (fail closed): an unwritable ledger never leaves the old success
  as GitHub's latest attempt. The ledger then still names that success, so
  the running collector remembers the key in memory and never reuses that
  record as the current success: once `state_dir` is writable again, the next
  pass revokes and clears it and, on a clean review, posts a new success.
  A restarted publisher or another worker has no such memory, but a clean
  pass there still refuses to reuse the stale record because the latest-attempt
  verification above sees the newer failure; it supersedes the record and
  posts a new success. The `review success revocation not recorded` error log
  and the `review success is not the latest attempt` warning identify the case.
  The run-ID ordering and `filter=all` listing have been exercised only with a
  synthetic transport; confirm them against GitHub (MANUAL_TEST) before
  relying on this recovery.
- If collection fails **and** the revocation fails, `CollectorFailure` is
  raised with a fixed message; the ledger still holds the standing success (or
  `revoking`) and the next pass retries.

Recovery: a corrupt ledger record is not deleted automatically. The Owner
inspects and removes `state_dir/<repository_id>-<pr>-<reviewer>.json`, then a
new request and review are needed. Deleting a record never produces a pass by
itself, but it forgets a standing success: first confirm on GitHub that the
latest attempt of that check on the current test merge is not `success`, or
post a failure attempt, before deleting.

Residual limits (need Owner decision and real GitHub acceptance): marker
strings and the provider runtime bound are Owner policy, not verified provider
formats; a provider that reviews longer than the bound can still be
misattributed; a prompt-injected provider can emit a pass marker; the watermark
assumes GitHub review IDs increase over time.

### App-JWT installation token exchange (`review_gate_app_token.py`)

`open_token_source(config, checkout_root, transport, signer_factory)` loads the
external key with the publisher's descriptor checks and hands it only to the
signer. `InstallationTokenSource.token()` builds an App JWT (`alg: RS256`,
`iat` = now - 60 s, `exp` = now + 540 s, `iss` = App ID) and POSTs to
`/app/installations/<id>/access_tokens` requesting `repository_ids: [<repo>]`
and exactly `checks: write`, `contents: read`, `metadata: read`,
`pull_requests: read`. The answer must echo exactly those permissions,
`repository_selection: "selected"`, only the configured repository, a
`ghs_`-form token and an expiry between 5 minutes and 1 hour (+5 minutes skew)
away. The token is cached in memory, refreshed once fewer than 5 minutes
remain, single-flight across threads, and dropped on any failure or
`invalidate()`. There is no retry loop; the caller retries on its next pass.

The key, JWT and token are held only in memory: never in files, `os.environ`,
subprocess arguments, log records, `repr()` or exception text, and failures
raise `TokenFailure` with fixed messages and no exception chain at all
(neither `__cause__` nor `__context__`, so even code that ignores
`__suppress_context__` cannot reach a transport or key-backend diagnostic).
Any exception a signer raises, including a `TokenFailure` a custom signer
builds from a PEM-parser message, is replaced by the fixed message. Synthetic
tests assert this for success, transport failure, a leaking signer and a
signer raising `TokenFailure` with key text.

**RS256 is not implemented.** Python's standard library has no RSA signature
primitive, and no already-pinned dependency in this repository provides one.
The default `UnconfiguredRs256Signer` refuses to sign, so exchange fails closed.
Choosing between adding a reviewed crypto dependency (for example the
Apache-2.0/BSD `cryptography` package, pinned with hashes), signing through a
system `openssl` binary (key path only, never key bytes, in argv), or a
hand-written standard-library RSA implementation is an Owner / license decision
(AGENTS.md sections 13 and 18). Until then, keep using the environment-token
path or leave the publisher disabled.

Construct a `Context` from the authenticated target repository ID, PR number,
`refs/heads/main`, current head/base commit IDs, a unique merge-base commit ID,
the current GitHub test-merge commit ID, and SHA-256 of
`canonical_no_rename_diff()` bytes. The isolated collector and publisher both
read complete recursive base/head Git trees through authenticated REST, then use
this fixed sorted manifest of changed `path`, mode and blob/gitlink SHA. A
rename is deliberately an old-path removal plus a new-path addition. Do not use
GitHub's rendered `.diff`, local `git diff`, compare-file patches, a web diff,
or a PR artifact: rename detection and renderer configuration would make those
representations differ between review and publication.

Do not trust the single `merge_base_commit` selected by GitHub's compare API as
proof of uniqueness. The publisher walks authenticated Git commit parent
objects to their roots, derives all best common ancestors, and requires exactly
one. The traversal is bounded to 4096 distinct commits; exhausting that budget,
a missing/malformed parent object, no common ancestor, or a criss-cross history
with multiple best common ancestors fails closed. A deployment whose repository
history exceeds the bound needs a separately reviewed, trusted graph collector;
do not weaken or skip this proof.

Invalidate previous successes before rerunning either review. Handle PR opens,
updates, retargets, reopenings, review reruns and base pushes; polling must also
reconcile missed events. On base advancement require the branch to incorporate
the current base and run both reviews again. Serialize publication per PR and
discard out-of-order completions. Re-read the complete context immediately before
publishing each result, and invalidate both on a mismatch. A final recheck alone
cannot eliminate a subsequent base-update race. Strict up-to-date protection
alone is also insufficient when the new base is already an ancestor of the PR
head. Therefore publish required checks **only on the current GitHub test-merge
commit**, never on PR HEAD. Verify the merge commit's parents equal the fixed
base/head and re-read its live ref before publication. Unknown mergeability or a
missing/changing merge ref fails closed. A changed base creates a new test-merge
context with no old success; the head fallback must likewise have no success
under these dedicated check names. Validate that behavior in actual GitHub tests
before activation. Do not enable merge queues without a separately reviewed
merge-group context implementation.
[GitHub: test merge versus head checks](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks#conflicts-between-head-commit-and-test-merge-commit).

The dedicated App publishes two check names from `CHECK_NAMES` in
[`review_gate_policy.py`](../scripts/ci/review_gate_policy.py), with `completed` /
`success` only after the corresponding trusted review passes. All other outcomes
must map to a blocking conclusion or stay pending: GitHub treats skipped/neutral
checks as passing, so the publisher must never emit those conclusions. Each `output.summary` is
bounded JSON with exactly `schema_version: 1`, `reviewer: "codex"` or `"claude"`,
`outcome: "pass"`, and `context` with every `Context` field. No raw review text,
source excerpt, secret, or media is published. The publisher must retain trusted
provenance for audit outside PR-controlled storage.

`validate_reviews(before, after, runs, issuer)` verifies these receipts against
GitHub's authenticated check-run `app.id`/`app.slug`, test-merge target, and context.
Its caller must fetch complete API pagination and select the current authoritative
attempt per reviewer; old successful attempts cannot hide a new pending or failed
attempt. Duplicate/missing attempts, duplicate JSON keys, malformed receipts,
and cross-PR/repository replay are rejected. This offline validator authenticates
nothing by itself and is not wired into the existing CI as a required review gate.
[GitHub: check-run API](https://docs.github.com/en/rest/checks/runs#get-a-check-run).

## Candidate ruleset and activation

Run the generator with the **verified dedicated** App ID and slug:

```sh
python3 scripts/ci/review_gate_policy.py \
  --app-id <verified-app-id> --app-slug <verified-app-slug> > /tmp/review-ruleset.json
```

It prints a **disabled** rule for `main`, no bypass actors, two required check
names pinned with `integration_id`, strict up-to-date checks, PR-only changes,
thread resolution, deletion prevention and force-push prevention. No setting is
applied. The candidate is additive: preserve all existing CI, approval and other
rules. It is not a backup/restore replacement for a repository's full protection.
Shared GitHub Actions/Dependabot identities are refused. Do not change the
required source to "any source" to make a blocked check pass.

After the publisher and test matrix pass, export the current rulesets and branch
protection to a safe local change record. In Settings → Rules → Rulesets, add the
reviewed rule, verify both expected App sources and strict freshness, and activate
it without bypass actors. Re-read the applied settings through the GitHub API.
Existing rules remain in place; maintain the separately required `CI` check.
The Owner/admin remains trusted because administrators can edit protections.

The independent `CI` baseline rule is already active. Preserve it when adding the
review gate; this candidate only encodes #4's additional review requirements.
[GitHub: ruleset API](https://docs.github.com/en/rest/repos/rules#create-a-repository-ruleset).

## Acceptance and recovery

Run the actual GitHub test-PR matrix in [MANUAL_TEST.md](../MANUAL_TEST.md#y-github-review-gate-enforcement)
on an isolated synthetic test branch with an equivalent rule first. Record public
test PR/run/check IDs, head/base/merge-base/diff digests, actual issuer IDs, API
rule snapshots and merge refusals; never secret values. Unit tests prove only the
offline policy, not GitHub protection, App isolation, or fork execution.

If the publisher is unavailable, keep merges blocked and restore its last reviewed
deployment/key access. For compromised credentials, the Owner revokes the affected
App key/token, restores the trusted execution boundary, then reruns both reviews
before merging. Do not re-label old successes. Do not disable the rule, add a broad
bypass, or accept another issuer as an automatic recovery action. Any deliberate
Owner emergency override must be recorded; it does not satisfy normal acceptance.
Before enabling additional writers, complete all #4 acceptance checks and re-read
current protection. Registration alone is not completion of #4.
