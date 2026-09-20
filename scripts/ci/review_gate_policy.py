#!/usr/bin/env python3
"""Offline policy helpers for the proposed dedicated-App review gate (#4).

This module neither authenticates JSON nor publishes checks or changes GitHub
settings. Its caller must obtain context and check runs directly from GitHub
and trusted git objects, and load issuer policy outside the PR branch. See
docs/REVIEW_GATE_SETUP.md. The command only prints a DISABLED candidate ruleset.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import re


CHECK_NAMES = {
    "codex": "ServerSentinel Codex review",
    "claude": "ServerSentinel Claude review",
}


class PolicyFailure(ValueError):
    """Unusable evidence; messages never include supplied evidence contents."""


@dataclass(frozen=True)
class Issuer:
    app_id: int
    app_slug: str

    def __post_init__(self):
        if (type(self.app_id) is not int or self.app_id <= 0
                or not isinstance(self.app_slug, str)
                or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", self.app_slug)
                or self.app_slug in {"github-actions", "dependabot"}
                or self.app_id == 15368):  # github.com GitHub Actions shared App
            raise PolicyFailure("a dedicated, Owner-verified App is required")


@dataclass(frozen=True)
class Context:
    repository_id: int
    pr_number: int
    base_ref: str
    head_sha: str
    base_sha: str
    merge_base_sha: str
    diff_sha256: str
    test_merge_sha: str

    def __post_init__(self):
        if any(type(value) is not int or value <= 0
               for value in (self.repository_id, self.pr_number)):
            raise PolicyFailure("invalid repository or PR identity")
        # The candidate gate protects main only. Retargeting requires a new policy.
        if self.base_ref != "refs/heads/main":
            raise PolicyFailure("unsupported base ref")
        for value, length in ((self.head_sha, 40), (self.base_sha, 40),
                              (self.merge_base_sha, 40), (self.diff_sha256, 64),
                              (self.test_merge_sha, 40)):
            if not isinstance(value, str) or not re.fullmatch(f"[0-9a-f]{{{length}}}", value):
                raise PolicyFailure("invalid context digest")
        if self.test_merge_sha in {self.head_sha, self.base_sha}:
            raise PolicyFailure("checks must target the distinct current test merge")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyFailure("duplicate receipt field")
        result[key] = value
    return result


def validate_reviews(context_before: Context, context_after: Context,
                     runs: list[dict], issuer: Issuer) -> None:
    """Validate a *trusted API snapshot*, never caller/PR-supplied attestations.

    Only the current authoritative attempt for each required name may be passed.
    Missing/duplicate attempts are rejected. A real adapter must choose attempts
    from complete API pagination and invalidate old successes before a rerun.
    Check runs must target the current test merge, never the PR head. Deployment
    still requires actual GitHub freshness/spoof-rejection acceptance tests.
    """
    if context_before != context_after:
        raise PolicyFailure("review context changed")
    if not isinstance(runs, list) or len(runs) != 2:
        raise PolicyFailure("both authoritative review attempts are required")
    expected_names = set(CHECK_NAMES.values())
    for run in runs:
        if (not isinstance(run, dict) or not isinstance(run.get("name"), str)
                or run["name"] not in expected_names):
            raise PolicyFailure("missing or ambiguous reviewer")
        name = run["name"]
        expected_names.remove(name)
        app = run.get("app")
        if (not isinstance(app, dict) or type(app.get("id")) is not int
                or app["id"] != issuer.app_id or app.get("slug") != issuer.app_slug):
            raise PolicyFailure("review issuer mismatch")
        if (run.get("status") != "completed" or run.get("conclusion") != "success"
                or run.get("head_sha") != context_before.test_merge_sha):
            raise PolicyFailure("review attempt is not successful for current test merge")
        output = run.get("output")
        raw = output.get("summary") if isinstance(output, dict) else None
        if not isinstance(raw, str) or len(raw) > 4096:
            raise PolicyFailure("missing or oversized receipt")
        try:
            receipt = json.loads(raw, object_pairs_hook=_unique_pairs)
        except (ValueError, RecursionError):
            raise PolicyFailure("invalid review receipt") from None
        reviewer = next(key for key, value in CHECK_NAMES.items() if value == name)
        expected = {"schema_version": 1, "reviewer": reviewer, "outcome": "pass",
                    "context": asdict(context_before)}
        # JSON equality alone treats true as 1: compare canonical encodings too.
        if (receipt != expected
                or json.dumps(receipt, sort_keys=True) != json.dumps(expected, sort_keys=True)):
            raise PolicyFailure("receipt does not bind the complete current context")


def candidate_ruleset(issuer: Issuer) -> dict:
    """Return an additive, disabled candidate; never mutate existing protection."""
    return {
        "name": "ServerSentinel dedicated-App reviews (candidate)",
        "target": "branch",
        "enforcement": "disabled",
        "bypass_actors": [],
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "pull_request", "parameters": {
                "dismiss_stale_reviews_on_push": True,
                "require_code_owner_review": False,
                "require_last_push_approval": False,
                "required_approving_review_count": 0,
                "required_review_thread_resolution": True,
            }},
            {"type": "required_status_checks", "parameters": {
                "strict_required_status_checks_policy": True,
                "do_not_enforce_on_create": False,
                "required_status_checks": [
                    {"context": name, "integration_id": issuer.app_id}
                    for name in CHECK_NAMES.values()
                ],
            }},
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-id", type=int, required=True)
    parser.add_argument("--app-slug", required=True)
    args = parser.parse_args()
    try:
        candidate = candidate_ruleset(Issuer(args.app_id, args.app_slug))
    except PolicyFailure as exc:
        parser.exit(1, f"Review policy refused: {exc}\n")
    print(json.dumps(candidate, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
