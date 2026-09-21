"""Synthetic deployment-policy checks; no App or repository enforcement exists."""

from copy import deepcopy
from dataclasses import asdict, replace
import json
import unittest

from scripts.ci import review_gate_policy as gate


class ReviewGatePolicyTests(unittest.TestCase):
    def setUp(self):
        self.issuer = gate.Issuer(900001, "synthetic-review-gate")
        self.context = gate.Context(900002, 1, "refs/heads/main", "a" * 40,
                                    "b" * 40, "c" * 40, "d" * 64, "f" * 40)
        self.runs = []
        for reviewer, name in gate.CHECK_NAMES.items():
            self.runs.append({
                "name": name,
                "app": {"id": self.issuer.app_id, "slug": self.issuer.app_slug},
                "status": "completed", "conclusion": "success",
                "head_sha": self.context.test_merge_sha,
                "output": {"summary": json.dumps({
                    "schema_version": 1, "reviewer": reviewer, "outcome": "pass",
                    "context": asdict(self.context),
                })},
            })

    def validate(self, runs=None, after=None):
        gate.validate_reviews(self.context, after or self.context,
                              self.runs if runs is None else runs, self.issuer)

    def test_both_exact_context_receipts_from_dedicated_app(self):
        self.validate()
        self.validate(list(reversed(self.runs)))

    def test_publisher_foundation_emits_only_fixed_success_payloads(self):
        for reviewer, name in gate.CHECK_NAMES.items():
            with self.subTest(reviewer=reviewer):
                request = gate.successful_check_run_request(self.context, reviewer)
                self.assertEqual(request, {
                    "name": name,
                    "head_sha": self.context.test_merge_sha,
                    "status": "completed",
                    "conclusion": "success",
                    "output": {
                        "title": f"{reviewer} review passed",
                        "summary": gate.receipt_summary(self.context, reviewer),
                    },
                })
                self.assertLessEqual(len(request["output"]["summary"]), 4096)
                synthetic_run = deepcopy(request)
                synthetic_run["app"] = {
                    "id": self.issuer.app_id, "slug": self.issuer.app_slug,
                }
                runs = deepcopy(self.runs)
                runs[list(gate.CHECK_NAMES).index(reviewer)] = synthetic_run
                self.validate(runs)

    def test_publisher_refuses_unrecognized_reviewer_or_caller_conclusion(self):
        for reviewer in (None, "", "Codex", "github-actions", "other"):
            with self.subTest(reviewer=reviewer), self.assertRaises(gate.PolicyFailure):
                gate.successful_check_run_request(self.context, reviewer)
        signature = gate.successful_check_run_request
        self.assertNotIn("conclusion", signature.__code__.co_varnames)

    def test_publisher_receipt_is_canonical_and_binds_every_context_field(self):
        raw = gate.receipt_summary(self.context, "codex")
        self.assertEqual(raw, json.dumps({
            "schema_version": gate.RECEIPT_SCHEMA_VERSION,
            "reviewer": "codex", "outcome": "pass",
            "context": asdict(self.context),
        }, sort_keys=True, separators=(",", ":")))
        for field, value in {
            "repository_id": 900003, "pr_number": 2,
            "base_sha": "e" * 40, "merge_base_sha": "e" * 40,
            "diff_sha256": "e" * 64, "test_merge_sha": "e" * 40,
        }.items():
            with self.subTest(field=field):
                changed = replace(self.context, **{field: value})
                self.assertNotEqual(raw, gate.receipt_summary(changed, "codex"))

    def test_each_review_is_required_without_duplicate_or_extra_attempts(self):
        for runs in ([], self.runs[:1], self.runs * 2, [self.runs[0]] * 2, None):
            with self.subTest(runs=runs), self.assertRaises(gate.PolicyFailure):
                gate.validate_reviews(self.context, self.context, runs, self.issuer)

    def test_same_name_success_cannot_replace_expected_issuer(self):
        for index in range(2):
            for app in ({"id": 15368, "slug": "github-actions"},
                        {"id": 900003, "slug": self.issuer.app_slug},
                        {"id": self.issuer.app_id, "slug": "different-app"},
                        {"id": True, "slug": self.issuer.app_slug}, None):
                with self.subTest(index=index, app=app):
                    runs = deepcopy(self.runs)
                    runs[index]["app"] = app
                    with self.assertRaises(gate.PolicyFailure):
                        self.validate(runs)

    def test_non_success_outcomes_and_unfinished_reviews_fail(self):
        for field, values in {
            "conclusion": [None, "failure", "neutral", "skipped", "cancelled", "timed_out"],
            "status": [None, "queued", "in_progress"],
            "head_sha": [None, "e" * 40, self.context.head_sha],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    runs = deepcopy(self.runs)
                    runs[1][field] = value
                    with self.assertRaises(gate.PolicyFailure):
                        self.validate(runs)

    def test_stale_or_replayed_context_field_is_rejected(self):
        for field, value in {
            "repository_id": 900003, "pr_number": 2, "base_ref": "refs/heads/other",
            "head_sha": "e" * 40, "base_sha": "e" * 40,
            "merge_base_sha": "e" * 40, "diff_sha256": "e" * 64,
            "test_merge_sha": "e" * 40,
        }.items():
            with self.subTest(field=field):
                runs = deepcopy(self.runs)
                receipt = json.loads(runs[0]["output"]["summary"])
                receipt["context"][field] = value
                runs[0]["output"]["summary"] = json.dumps(receipt)
                with self.assertRaises(gate.PolicyFailure):
                    self.validate(runs)

    def test_same_head_changed_base_requires_new_reviews(self):
        after = replace(self.context, base_sha="e" * 40)
        self.assertEqual(after.head_sha, self.context.head_sha)
        with self.assertRaises(gate.PolicyFailure):
            self.validate(after=after)

    def test_current_test_merge_must_be_rechecked_even_when_head_is_unchanged(self):
        after = replace(self.context, test_merge_sha="e" * 40)
        with self.assertRaises(gate.PolicyFailure):
            self.validate(after=after)
        with self.assertRaises(gate.PolicyFailure):
            replace(self.context, test_merge_sha=self.context.head_sha)

    def test_fork_reviews_require_the_same_receipts_without_fork_credentials(self):
        # A PR's target repository ID stays authoritative for fork PRs too.
        # No secret, workspace or fork-controlled claimed issuer is an input.
        self.validate()
        runs = deepcopy(self.runs)
        receipt = json.loads(runs[0]["output"]["summary"])
        receipt["context"]["repository_id"] = 900003
        runs[0]["output"]["summary"] = json.dumps(receipt)
        with self.assertRaises(gate.PolicyFailure):
            self.validate(runs)

    def test_receipt_is_strict_bounded_and_not_a_comment_or_markdown_report(self):
        for raw in (None, "Reviewed commit: " + self.context.head_sha,
                    "null", "[]", "{}", "x" * 4097,
                    '["' + "x" * 20 + '"]', "[" * 1500 + "]" * 1500):
            with self.subTest(raw_type=type(raw)):
                runs = deepcopy(self.runs)
                runs[0]["output"]["summary"] = raw
                with self.assertRaises(gate.PolicyFailure):
                    self.validate(runs)
        for update in ({"schema_version": True}, {"outcome": "unknown"},
                       {"reviewer": "claude"}, {"extra": "ignored"}):
            runs = deepcopy(self.runs)
            receipt = json.loads(runs[0]["output"]["summary"])
            receipt.update(update)
            runs[0]["output"]["summary"] = json.dumps(receipt)
            with self.assertRaises(gate.PolicyFailure):
                self.validate(runs)

    def test_duplicate_receipt_fields_are_rejected(self):
        for key, value in (("schema_version", "1"), ("pr_number", "1")):
            runs = deepcopy(self.runs)
            raw = runs[0]["output"]["summary"]
            raw = raw.replace(f'"{key}": {value}', f'"{key}": {value}, "{key}": {value}')
            runs[0]["output"]["summary"] = raw
            with self.assertRaises(gate.PolicyFailure):
                self.validate(runs)

    def test_invalid_policy_or_context_is_rejected(self):
        for app_id, slug in ((0, "synthetic"), (True, "synthetic"), (15368, "synthetic"),
                             (900001, "github-actions"), (900001, "bad slug")):
            with self.assertRaises(gate.PolicyFailure):
                gate.Issuer(app_id, slug)
        for field, value in (("pr_number", True), ("base_ref", "main"),
                             ("head_sha", "a" * 39), ("diff_sha256", "D" * 64)):
            with self.assertRaises(gate.PolicyFailure):
                replace(self.context, **{field: value})

    def test_candidate_is_disabled_strict_pinned_and_has_no_bypass(self):
        candidate = gate.candidate_ruleset(self.issuer)
        self.assertEqual(candidate["enforcement"], "disabled")
        self.assertEqual(candidate["bypass_actors"], [])
        self.assertEqual(candidate["conditions"]["ref_name"],
                         {"include": ["refs/heads/main"], "exclude": []})
        rules = {rule["type"]: rule for rule in candidate["rules"]}
        self.assertTrue({"deletion", "non_fast_forward", "pull_request"} <= rules.keys())
        checks = rules["required_status_checks"]["parameters"]
        self.assertTrue(checks["strict_required_status_checks_policy"])
        self.assertFalse(checks["do_not_enforce_on_create"])
        self.assertEqual(checks["required_status_checks"], [
            {"context": name, "integration_id": self.issuer.app_id}
            for name in gate.CHECK_NAMES.values()
        ])


if __name__ == "__main__":
    unittest.main()
