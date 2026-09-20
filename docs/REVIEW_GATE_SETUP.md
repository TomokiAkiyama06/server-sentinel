# Dedicated-App review gate: deployment proposal and offline policy

Issue [#4](https://github.com/TomokiAkiyama06/server-sentinel/issues/4) remains
**open**. The checked-in implementation provides an offline receipt validator,
a disabled candidate ruleset generator, and synthetic policy tests. There is no
App publisher, trusted evidence collector, installed enforcement, or completed
GitHub test-PR acceptance. Continue the manual current-HEAD/current-base review
procedure in [CLAUDE_REVIEW_SETUP.md](CLAUDE_REVIEW_SETUP.md).

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

## Trusted collector and publisher contract (not implemented)

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
closed. The provider adapters and their hostile-input tests remain required work.

Construct a `Context` from the authenticated target repository ID, PR number,
`refs/heads/main`, current head/base commit IDs, a unique merge-base commit ID,
the current GitHub test-merge commit ID, and SHA-256 of these exact diff bytes.
Reject multiple merge bases. Use clean,
trusted git configuration, disable external diff/textconv, and fetch immutable
objects without executing PR hooks or reading PR git configuration:

```sh
git -c core.quotePath=true diff --no-ext-diff --no-textconv --no-color \
  --no-renames --diff-algorithm=myers --no-indent-heuristic \
  --src-prefix=a/ --dst-prefix=b/ --unified=3 --inter-hunk-context=0 \
  <fixed-base-sha>...<fixed-head-sha>
```

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
