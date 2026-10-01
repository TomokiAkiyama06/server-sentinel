"""Synthetic tests for the #4 provider review collector; no GitHub access."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.parse

from scripts.ci import review_gate_collector as collector
from scripts.ci import review_gate_policy as gate
from scripts.ci import review_gate_publisher as publisher


START = 1_900_000_000
RUNTIME = 600
CODEX_BOT = {"id": 900101, "login": "synthetic-codex[bot]", "type": "Bot"}
CLAUDE_BOT = {"id": 900102, "login": "synthetic-claude[bot]", "type": "Bot"}
ACTIONS_BOT = {"id": collector.GITHUB_ACTIONS_USER_ID,
               "login": "github-actions[bot]", "type": "Bot"}
PASS = "SYNTHETIC-PASS: no major issues"
BLOCK = "SYNTHETIC-P1"
SUGGEST = "SYNTHETIC-P3"


def iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def identity(reviewer="codex", bot=CODEX_BOT):
    return collector.ProviderIdentity(
        reviewer=reviewer, user_id=bot["id"], user_login=bot["login"],
        max_review_runtime_seconds=RUNTIME, pass_markers=(PASS,),
        blocking_markers=(BLOCK,), non_blocking_markers=(SUGGEST,))


class Clock:
    def __init__(self, now=START):
        self.now = now

    def __call__(self):
        return self.now


class FakeSource:
    def __init__(self, repository="owner/repository"):
        self.repository = repository
        self.reviews: list[dict] = []
        self.comments: dict[int, list[dict]] = {}
        self.issue_comments: list[dict] = []
        # Full commit SHAs GitHub knows; a short SHA resolves only if unique.
        self.commits: set[str] = {"a" * 40}
        self.resolved: list[str] = []
        self.next_id = 5000
        self.next_comment_id = 8000

    def add(self, head_sha, submitted, user=CODEX_BOT, body=PASS,
            state="COMMENTED", comments=(), **extra):
        self.next_id += 1
        review = {"id": self.next_id, "user": None if user is None else dict(user), "commit_id": head_sha,
                  "state": state, "body": body, "submitted_at": iso(submitted),
                  **extra}
        self.reviews.append(review)
        self.comments[self.next_id] = [
            {"id": 70000 + index, "pull_request_review_id": self.next_id, "body": text}
            for index, text in enumerate(comments)]
        return review

    def add_comment(self, commit_prefix, created, user=CODEX_BOT, body=PASS,
                    updated=None, reviewed=None):
        self.next_comment_id += 1
        if reviewed is None:
            reviewed = f"\n\n**Reviewed commit:** `{commit_prefix}`\n\n<details>about</details>"
        comment = {"id": self.next_comment_id,
                   "user": None if user is None else dict(user),
                   "body": f"Codex Review: {body}{reviewed}",
                   "created_at": iso(created),
                   "updated_at": iso(created if updated is None else updated)}
        self.issue_comments.append(comment)
        return comment

    def list_issue_comments(self, pr_number):
        return [dict(comment) for comment in self.issue_comments]

    def resolve_commit(self, prefix):
        self.resolved.append(prefix)
        matches = [sha for sha in self.commits if sha.startswith(prefix)]
        if len(matches) != 1:
            raise collector.CollectorFailure("short commit SHA is ambiguous")
        return matches[0]

    def list_reviews(self, pr_number):
        if not isinstance(self.reviews, list):
            return self.reviews
        return [dict(review) for review in self.reviews]

    def list_review_comments(self, pr_number, review_id):
        return [dict(comment) for comment in self.comments.get(review_id, [])]


class FakeCheckRuns:
    """Records Check Run posts; GitHub echoes them under the dedicated App."""

    def __init__(self, issuer):
        self.issuer = issuer
        self.posts: list[dict] = []
        self.fail = False
        self.after_accept: str | None = None  # GitHub accepted, then ...
        self.list_fail = False
        self.list_pages = 0
        self.hidden_runs = 0  # runs GitHub counts but never returns

    def post_json(self, path, token, payload):
        if self.fail:
            raise publisher.PublisherFailure("GitHub API request failed")
        assert path == "/repos/owner/repository/check-runs", path
        self.posts.append(payload)
        mode = self.after_accept if payload["conclusion"] == "success" else None
        if mode == "raise":
            raise publisher.PublisherFailure("GitHub API request failed")
        if mode == "crash":
            raise KeyboardInterrupt
        if mode == "no_id":
            return {**payload, "app": {"id": self.issuer.app_id,
                                       "slug": self.issuer.app_slug}}
        return {**payload, "id": len(self.posts),
                "app": {"id": self.issuer.app_id, "slug": self.issuer.app_slug}}

    def get_json(self, path, token):
        """List this App's runs of one check on one commit, as GitHub does.

        Every accepted post is a run (id = its position), whether or not its
        response reached the caller.
        """
        if self.fail or self.list_fail:
            raise publisher.PublisherFailure("GitHub API request failed")
        route, _, query = path.partition("?")
        prefix = "/repos/owner/repository/commits/"
        assert route.startswith(prefix) and route.endswith("/check-runs"), path
        sha = route[len(prefix):-len("/check-runs")]
        fields = dict(part.split("=", 1) for part in query.split("&"))
        assert fields["app_id"] == str(self.issuer.app_id), path
        assert fields["filter"] == "all" and fields["per_page"] == "100", path
        name = urllib.parse.unquote(fields["check_name"])
        runs = [{**post, "id": index + 1,
                 "app": {"id": self.issuer.app_id, "slug": self.issuer.app_slug}}
                for index, post in enumerate(self.posts)
                if post["name"] == name and post["head_sha"] == sha]
        page = int(fields["page"])
        self.list_pages += 1
        return {"total_count": len(runs) + self.hidden_runs,
                "check_runs": runs[(page - 1) * 100:page * 100]}


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.checkout = root / "checkout"
        self.checkout.mkdir()
        self.state = root / "state"
        self.state.mkdir(mode=0o700)
        self.clock = Clock()
        self.context = gate.Context(900002, 12, "refs/heads/main", "a" * 40,
                                    "b" * 40, "c" * 40, "d" * 64, "f" * 40)
        self.live = self.context
        self.source = FakeSource()
        self.issuer = gate.Issuer(900001, "synthetic-review-gate")
        self.collector = self.make_collector()

    def tearDown(self):
        self.temp.cleanup()

    def make_collector(self):
        store = collector.LedgerStore(self.state, self.checkout)
        return collector.ReviewCollector(
            store, {"codex": identity(), "claude": identity("claude", CLAUDE_BOT)},
            self.clock)

    def read_live(self):
        return self.live

    def late(self):
        return START + RUNTIME + collector.CLOCK_SKEW_ALLOWANCE_SECONDS

    def collect(self, reviewer="codex", read=None, source=None):
        return self.collector.collect(reviewer, read or self.read_live,
                                      source or self.source)

    def test_trusted_clean_review_becomes_policy_receipt(self):
        self.source.add(self.context.head_sha, START - 10)  # before the request
        outcome = self.collector.request_review("codex", self.live, self.source)
        self.assertTrue(outcome.created)
        self.source.add(self.context.head_sha, self.late())
        decision = self.collect()
        self.assertEqual((decision.status, decision.reason), ("pass", "trusted_clean_review"))
        self.assertEqual(decision.check_run_request,
                         gate.successful_check_run_request(self.context, "codex"))
        self.assertEqual(decision.context, self.context)
        # The receipt validates against the offline policy for the dedicated App.
        issuer = gate.Issuer(900001, "synthetic-review-gate")
        runs = [{**gate.successful_check_run_request(self.context, name),
                 "app": {"id": issuer.app_id, "slug": issuer.app_slug}}
                for name in gate.CHECK_NAMES]
        gate.validate_reviews(self.context, self.context, runs, issuer)

    def test_trusted_clean_issue_comment_passes_for_the_exact_head(self):
        # Codex reports "no findings" as an issue comment naming a short SHA.
        self.source.add_comment("a" * 10, START - 10)  # before the request
        self.collector.request_review("codex", self.live, self.source)
        self.assertEqual(self.collect().status, "pending")
        self.source.add_comment("a" * 10, self.late())
        decision = self.collect()
        self.assertEqual((decision.status, decision.reason), ("pass", "trusted_clean_review"))
        self.assertEqual(decision.check_run_request,
                         gate.successful_check_run_request(self.context, "codex"))
        self.assertEqual(self.source.resolved, ["a" * 10])

    def test_issue_comment_for_another_commit_or_too_early_never_passes(self):
        self.collector.request_review("codex", self.live, self.source)
        self.source.commits.add("b" * 40)
        self.source.add_comment("b" * 10, self.late())  # another commit
        self.source.add_comment("a" * 10, self.late() - 1)  # inside the runtime bound
        for user in (None, ACTIONS_BOT, {**CODEX_BOT, "id": 1},
                     {**CODEX_BOT, "type": "User"}):
            self.source.add_comment("a" * 10, self.late(), user=user)
        self.source.add_comment("a" * 10, self.late(), body="usage limit reached",
                                reviewed="")  # not a result comment
        decision = self.collect()
        self.assertEqual(decision.status, "pending")
        self.assertEqual(decision.ignored_untrusted_reviews, 4)

    def test_ambiguous_issue_comment_fails_closed(self):
        cases = {
            # Another known commit shares the short SHA: never attributed.
            "colliding_prefix": dict(prefix="a" * 10),
            "edited_after_posting": dict(prefix="a" * 10, updated=self.late() + 60),
            "blocking_marker": dict(prefix="a" * 10, body=PASS + " " + BLOCK),
            "no_reviewed_commit": dict(prefix="a" * 10, reviewed=""),
            "two_reviewed_commits": dict(
                prefix="a" * 10,
                reviewed=("\n**Reviewed commit:** `aaaaaaaaaa`"
                          "\n**Reviewed commit:** `bbbbbbbbbb`")),
            "uppercase_or_short_sha": dict(prefix="AAAAAAAAAA"),
            "six_hex_digits": dict(prefix="a" * 6),
        }
        for name, case in cases.items():
            with self.subTest(case=name):
                self.source = FakeSource()
                if name == "colliding_prefix":
                    self.source.commits.add("a" * 10 + "e" * 30)
                self.collector.request_review("codex", self.live, self.source,
                                              force_new=True)
                prefix = case.pop("prefix")
                self.source.add_comment(prefix, self.late(), **case)
                self.source.add(self.context.head_sha, self.late())  # a clean review
                if name == "colliding_prefix":
                    with self.assertRaises(collector.CollectorFailure):
                        self.collect()
                else:
                    self.assertEqual(self.collect().status, "blocked")

    def test_issue_comment_below_the_request_watermark_is_ignored(self):
        self.collector.request_review("codex", self.live, self.source)
        self.source.add_comment("a" * 10, self.late())
        self.assertEqual(self.collect().status, "pass")
        outcome = self.collector.request_review("codex", self.live, self.source,
                                                force_new=True)
        self.assertEqual(outcome.request.comment_watermark,
                         self.source.issue_comments[-1]["id"])
        self.assertEqual(self.collect().status, "pending")

    def test_claude_uses_the_same_contract_with_its_own_identity(self):
        self.collector.request_review("claude", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())  # Codex bot, not Claude
        self.assertEqual(self.collect("claude").status, "pending")
        self.source.add(self.context.head_sha, self.late(), user=CLAUDE_BOT)
        decision = self.collect("claude")
        self.assertEqual(decision.status, "pass")
        self.assertEqual(decision.check_run_request["name"], gate.CHECK_NAMES["claude"])

    def test_base_update_invalidates_same_head_request_and_old_review(self):
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())
        self.assertEqual(self.collect().status, "pass")
        # The base advances; the PR HEAD is unchanged.
        self.live = replace(self.context, base_sha="e" * 40, test_merge_sha="9" * 40)
        self.assertEqual(self.live.head_sha, self.context.head_sha)
        decision = self.collect()
        self.assertEqual((decision.status, decision.reason),
                         ("invalidated", "context_changed_since_request"))
        self.assertIsNone(decision.check_run_request)
        # Invalidation is durable: even if the old context returns, no pass.
        self.live = self.context
        self.assertEqual(self.collect().status, "invalidated")
        # A new request for the new base ignores the same-HEAD review that
        # predates it, so the old success cannot be carried over.
        self.live = replace(self.context, base_sha="e" * 40, test_merge_sha="9" * 40)
        self.clock.now = START + 5000
        self.assertTrue(self.collector.request_review("codex", self.live, self.source).created)
        self.assertEqual(self.collect().status, "pending")

    def test_stale_live_read_does_not_invalidate_a_newer_concurrent_request(self):
        old_context = self.context
        new_context = replace(self.context, base_sha="e" * 40, test_merge_sha="9" * 40)
        for advance in (1, 0):  # 0: both processes sample the same clock second.
            with self.subTest(advance=advance):
                for path in self.state.glob("*.json"):
                    path.unlink()
                reads = []

                def stale_read():
                    # Only the collector's first, unlocked read is stale: while
                    # it runs, another process records the newer request.
                    reads.append(1)
                    if len(reads) == 1:
                        self.clock.now += advance
                        self.collector.request_review("codex", new_context, self.source)
                        return old_context
                    return new_context
                decision = self.collect(read=stale_read)
                self.assertEqual((decision.status, decision.reason),
                                 ("pending", "live_context_read_predates_request"))
                self.assertIsNone(decision.check_run_request)
                # The newer request survives and passes with a late clean review.
                self.live = new_context
                self.source.add(new_context.head_sha, self.clock.now + RUNTIME
                                + collector.CLOCK_SKEW_ALLOWANCE_SECONDS)
                self.assertEqual(self.collect().status, "pass")
                # A genuine change after the request is still invalidated.
                self.live = old_context
                self.assertEqual(self.collect().reason, "context_changed_since_request")

    def test_mismatch_confirmation_stays_pending_if_request_is_replaced_again(self):
        first = replace(self.context, base_sha="e" * 40, test_merge_sha="9" * 40)
        second = replace(self.context, base_sha="7" * 40, test_merge_sha="8" * 40)
        self.collector.request_review("codex", first, self.source)
        reads = []

        def racing_read():
            reads.append(1)
            if len(reads) == 2:  # the confirmation read races a third request
                self.collector.request_review("codex", second, self.source)
            return self.context
        decision = self.collect(read=racing_read)
        self.assertEqual((decision.status, decision.reason),
                         ("pending", "live_context_read_predates_request"))
        self.live = second
        self.assertEqual(self.collect().status, "pending")  # still active

    def test_every_context_field_change_during_collection_invalidates(self):
        for field, value in {"head_sha": "e" * 40, "base_sha": "e" * 40,
                             "merge_base_sha": "e" * 40, "diff_sha256": "e" * 64,
                             "test_merge_sha": "e" * 40}.items():
            with self.subTest(field=field):
                self.clock.now += 10_000
                self.live = self.context
                self.collector.request_review("codex", self.live, self.source,
                                              force_new=True)
                self.source.add(self.context.head_sha, self.clock.now + 10_000)
                changed = replace(self.context, **{field: value})
                calls = []

                def racing_read():
                    calls.append(1)
                    return self.context if len(calls) == 1 else changed
                decision = self.collect(read=racing_read)
                self.assertEqual((decision.status, decision.reason),
                                 ("invalidated", "context_changed_during_collection"))
                self.assertIsNone(decision.check_run_request)

    def test_review_started_under_an_older_base_is_not_attributed(self):
        self.collector.request_review("codex", self.live, self.source)
        # Submitted after the request but within the provider runtime bound:
        # it may have been triggered before the base changed.
        self.source.add(self.context.head_sha, self.late() - 1)
        self.assertEqual(self.collect().reason, "awaiting_unambiguous_review")
        self.source.add(self.context.head_sha, self.late())
        self.assertEqual(self.collect().status, "pass")

    def test_spoofed_github_token_issuer_is_rejected(self):
        self.collector.request_review("codex", self.live, self.source)
        spoofs = (
            ACTIONS_BOT,  # a PR workflow's GITHUB_TOKEN review
            {**CODEX_BOT, "id": 900999},  # same login, other account
            {**CODEX_BOT, "login": "synthetic-codex"},  # same ID, not the bot login
            {**CODEX_BOT, "type": "User"},
        )
        for user in spoofs:
            self.source.add(self.context.head_sha, self.late(), user=user)
        self.source.add(self.context.head_sha, self.late(),
                        performed_via_github_app={"id": collector.GITHUB_ACTIONS_APP_ID,
                                                  "slug": "github-actions"})
        self.source.add(self.context.head_sha, self.late(), user=None)  # deleted
        decision = self.collect()
        self.assertEqual(decision.status, "pending")
        self.assertEqual(decision.ignored_untrusted_reviews, len(spoofs) + 2)
        self.assertIsNone(decision.check_run_request)

    def test_github_actions_identity_can_never_be_configured(self):
        for bot in (ACTIONS_BOT, {**ACTIONS_BOT, "id": 900103},
                    {"id": 900104, "login": "dependabot[bot]"},
                    {"id": 900105, "login": "plain-user"},
                    {"id": True, "login": "x[bot]"}):
            with self.subTest(bot=bot), self.assertRaises(collector.CollectorFailure):
                collector.ProviderIdentity("codex", bot["id"], bot["login"], RUNTIME,
                                           (PASS,), (BLOCK,), (SUGGEST,))
        with self.assertRaises(collector.CollectorFailure):
            collector.ReviewCollector(
                collector.LedgerStore(self.state, self.checkout),
                {"codex": identity(), "claude": identity("claude", CODEX_BOT)})

    def test_non_clean_results_block_and_never_pass(self):
        cases = (
            {"state": "CHANGES_REQUESTED"}, {"state": "DISMISSED"},
            {"state": "PENDING"}, {"body": "no marker"}, {"body": None},
            {"body": PASS + " " + BLOCK},
            {"comments": ("unclassified finding",)},
            {"comments": (SUGGEST + " fine", BLOCK + " " + SUGGEST)},
        )
        for extra in cases:
            with self.subTest(extra=extra):
                self.clock.now += 10_000
                self.collector.request_review("codex", self.live, self.source,
                                              force_new=True)
                late = self.clock.now + 10_000
                self.source.add(self.context.head_sha, late, **extra)
                self.source.add(self.context.head_sha, late)  # a clean one too
                decision = self.collect()
                self.assertEqual((decision.status, decision.reason),
                                 ("blocked", "provider_result_not_clean"))
                self.assertIsNone(decision.check_run_request)

    def test_early_failing_review_blocks_even_if_ambiguous(self):
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, START + 1, state="CHANGES_REQUESTED")
        self.source.add(self.context.head_sha, self.late())
        self.assertEqual(self.collect().status, "blocked")

    def test_suggestion_only_comments_do_not_block(self):
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late(),
                        comments=(SUGGEST + " naming",))
        self.assertEqual(self.collect().status, "pass")

    def test_review_of_other_head_or_before_watermark_is_ignored(self):
        self.source.add(self.context.head_sha, self.late())  # before the request
        self.collector.request_review("codex", self.live, self.source)
        self.source.add("e" * 40, self.late())
        self.assertEqual(self.collect().status, "pending")

    def test_request_is_idempotent_and_survives_restart(self):
        first = self.collector.request_review("codex", self.live, self.source)
        again = self.collector.request_review("codex", self.live, self.source)
        self.assertFalse(again.created)
        self.assertEqual(first.request, again.request)
        restarted = self.make_collector()
        self.assertFalse(restarted.request_review("codex", self.live, self.source).created)
        self.source.add(self.context.head_sha, self.late())
        self.assertEqual(restarted.collect("codex", self.read_live, self.source).status,
                         "pass")
        record = self.state / "900002-12-codex.json"
        self.assertEqual(os.stat(record).st_mode & 0o777, 0o600)
        self.assertEqual([p.name for p in self.state.iterdir() if p.suffix == ".tmp"], [])

    def test_missing_request_is_pending(self):
        self.source.add(self.context.head_sha, self.late())
        decision = self.collect()
        self.assertEqual((decision.status, decision.reason), ("pending", "no_review_request"))

    def test_corrupt_or_foreign_ledger_fails_closed(self):
        self.collector.request_review("codex", self.live, self.source)
        record = self.state / "900002-12-codex.json"
        original = record.read_text()
        data = json.loads(original)
        bad_records = (
            "{", "[]", json.dumps({**data, "extra": 1}),
            json.dumps({**data, "schema_version": True}),
            json.dumps({**data, "state": "passed"}),
            json.dumps({**data, "reviewer": "claude"}),
            json.dumps({**data, "context": {**data["context"], "pr_number": 13}}),
            json.dumps({**data, "context": {**data["context"], "head_sha": "x"}}),
            original.replace('"state"', '"state":"active","state"', 1),
            "x" * (collector.MAX_LEDGER_BYTES + 1),
        )
        for raw in bad_records:
            with self.subTest(raw=raw[:40]):
                record.write_text(raw)
                os.chmod(record, 0o600)
                with self.assertRaises(collector.CollectorFailure):
                    self.collect()
        record.write_text(original)
        os.chmod(record, 0o644)
        with self.assertRaises(collector.CollectorFailure):
            self.collect()
        os.chmod(record, 0o600)
        record.unlink()
        record.symlink_to(self.state / "elsewhere.json")
        with self.assertRaises(collector.CollectorFailure):
            self.collect()

    def test_state_directory_must_be_private_and_outside_checkout(self):
        inside = self.checkout / "state"
        inside.mkdir(mode=0o700)
        loose = Path(self.temp.name) / "loose"
        loose.mkdir()
        os.chmod(loose, 0o755)
        for path in (inside, loose, Path("relative"), Path(self.temp.name) / "missing"):
            with self.subTest(path=str(path)), self.assertRaises(collector.CollectorFailure):
                collector.LedgerStore(path, self.checkout)

    def test_ledger_write_failure_is_visible_and_leaves_no_partial_record(self):
        original = os.replace

        def failing_replace(*args, **kwargs):
            raise OSError("synthetic disk full")
        os.replace = failing_replace
        try:
            with self.assertRaisesRegex(collector.CollectorFailure, "write failed"):
                self.collector.request_review("codex", self.live, self.source)
        finally:
            os.replace = original
        self.assertEqual(list(self.state.glob("*.json")), [])
        self.assertEqual(list(self.state.glob(".*.tmp")), [])
        self.assertEqual(self.collect().reason, "no_review_request")

    def test_hostile_or_incomplete_listings_fail_closed(self):
        self.source.add(self.context.head_sha, START - 10)
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())
        good = self.source.reviews
        for reviews in (
            None, [], [good[1]],  # watermark review missing: truncated listing
            good + [dict(good[1])],  # duplicate ID
            good + [{"id": True}],
            [dict(good[0]), {**good[1], "user": "synthetic"}],
            [dict(good[0]), {**good[1], "commit_id": "A" * 40}],
            [dict(good[0]), {**good[1], "submitted_at": "yesterday"}],
            [dict(good[0]), {**good[1], "body": "x" * (collector.MAX_TEXT_CHARS + 1)}],
            [dict(good[0])] * (collector.MAX_REVIEWS + 1),
        ):
            with self.subTest(size=None if reviews is None else len(reviews)):
                self.source.reviews = reviews
                with self.assertRaises(collector.CollectorFailure):
                    self.collect()
        self.source.reviews = good
        for _ in range(collector.MAX_CANDIDATE_REVIEWS):
            self.source.add(self.context.head_sha, self.late())
        with self.assertRaisesRegex(collector.CollectorFailure, "too many"):
            self.collect()
        self.source.reviews = good
        self.source.comments[good[1]["id"]] = [
            {"id": 1, "pull_request_review_id": 999, "body": SUGGEST}]
        with self.assertRaises(collector.CollectorFailure):
            self.collect()

    def test_listing_regression_blocks_new_request(self):
        self.source.add(self.context.head_sha, START - 10)
        self.collector.request_review("codex", self.live, self.source)
        self.source.reviews = []
        with self.assertRaisesRegex(collector.CollectorFailure, "regressed"):
            self.collector.request_review("codex", self.live, self.source, force_new=True)

    def test_busy_lock_times_out_instead_of_hanging(self):
        import fcntl
        self.collector.request_review("codex", self.live, self.source)
        lock = os.open(self.state / "900002-12.lock", os.O_RDWR)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            original = collector.LOCK_TIMEOUT_SECONDS
            collector.LOCK_TIMEOUT_SECONDS = 0.1
            try:
                with self.assertRaisesRegex(collector.CollectorFailure, "busy"):
                    self.collect()
            finally:
                collector.LOCK_TIMEOUT_SECONDS = original
        finally:
            os.close(lock)
        self.assertEqual(self.collect().status, "pending")

    def test_logs_carry_reason_codes_but_no_review_text(self):
        secret_text = "SYNTHETIC-REVIEW-BODY-SHOULD-NOT-BE-LOGGED"
        with self.assertLogs("server_sentinel.review_gate.collector", "DEBUG") as logs:
            self.collector.request_review("codex", self.live, self.source)
            self.source.add(self.context.head_sha, self.late(),
                            body=PASS + " " + secret_text)
            self.collect()
        joined = "\n".join(logs.output)
        self.assertIn("status=pass", joined)
        self.assertNotIn(secret_text, joined)

    def publication(self):
        client = FakeCheckRuns(self.issuer)
        config = publisher.RuntimeConfig("owner/repository", self.context.repository_id,
                                         self.issuer, 900003,
                                         Path(self.temp.name) / "key.pem")
        credentials = publisher.AppCredentials(config, b"synthetic-key", "t" * 40)
        patcher = mock.patch.object(publisher, "collect_live_context",
                                    lambda *args: self.live)
        patcher.start()
        self.addCleanup(patcher.stop)
        return client, credentials

    def reconcile(self, client, credentials, reviewer="codex", source=None,
                  collector_=None):
        return (collector_ or self.collector).collect_and_publish(
            reviewer, self.context.pr_number, self.read_live, source or self.source,
            client, credentials)

    def ledger(self, reviewer="codex"):
        return json.loads((self.state / f"900002-12-{reviewer}.json").read_text())

    def test_publish_requires_a_passing_decision(self):
        client, credentials = self.publication()
        for decision in (
            collector.CollectorDecision("pending", "x", "codex"),
            collector.CollectorDecision("pass", "x", "codex", "0" * 32,
                                        {"forged": True}, 0, self.context),
            collector.CollectorDecision("pass", "x", "codex", "0" * 32,
                                        gate.successful_check_run_request(
                                            self.context, "codex"), 0, None),
        ):
            with self.subTest(status=decision.status), self.assertRaises(
                    collector.CollectorFailure):
                self.collector.publish(client, credentials, decision)
        self.assertEqual(client.posts, [])

    def test_pass_is_published_once_across_polls_and_restart(self):
        client, credentials = self.publication()
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())
        for _ in range(3):
            self.assertEqual(self.reconcile(client, credentials).status, "pass")
        restarted = self.make_collector()
        self.assertEqual(self.reconcile(client, credentials, collector_=restarted).status,
                         "pass")
        self.assertEqual([post["conclusion"] for post in client.posts], ["success"])
        self.assertEqual(self.ledger()["published"],
                         {"request_id": self.ledger()["request_id"],
                          "test_merge_sha": self.context.test_merge_sha,
                          "check_run_id": 1, "state": "success"})

    def test_superseded_pass_decision_is_never_posted(self):
        client, credentials = self.publication()
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())
        stale = self.collect()
        self.assertEqual(stale.status, "pass")
        self.collector.request_review("codex", self.live, self.source, force_new=True)
        self.assertFalse(self.collector.publish(client, credentials, stale)["published"])
        self.assertEqual(client.posts, [])

    def test_later_blocking_review_supersedes_the_published_success(self):
        client, credentials = self.publication()
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())
        self.assertEqual(self.reconcile(client, credentials).status, "pass")
        self.source.add(self.context.head_sha, self.late() + 5, body=BLOCK)
        for _ in range(2):
            self.assertEqual(self.reconcile(client, credentials).status, "blocked")
        self.assertEqual([(post["conclusion"], post["head_sha"]) for post in client.posts],
                         [("success", self.context.test_merge_sha),
                          ("failure", self.context.test_merge_sha)])
        self.assertIsNone(self.ledger()["published"])
        self.assertEqual(client.posts[1]["name"], gate.CHECK_NAMES["codex"])

    def test_force_new_rerun_requires_revoking_the_standing_success(self):
        client, credentials = self.publication()
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())
        self.reconcile(client, credentials)
        with self.assertRaises(collector.CollectorFailure):
            self.collector.request_review("codex", self.live, self.source, force_new=True)
        self.assertTrue(self.collector.revoke_published(client, credentials, "codex", 12))
        self.assertFalse(self.collector.revoke_published(client, credentials, "codex", 12))
        self.clock.now = self.late() + 10
        self.assertTrue(self.collector.request_review(
            "codex", self.live, self.source, force_new=True).created)
        self.assertEqual(self.reconcile(client, credentials).status, "pending")
        self.source.add(self.context.head_sha, self.clock.now + RUNTIME
                        + collector.CLOCK_SKEW_ALLOWANCE_SECONDS)
        self.assertEqual(self.reconcile(client, credentials).status, "pass")
        self.assertEqual([post["conclusion"] for post in client.posts],
                         ["success", "failure", "success"])

    def test_collection_error_supersedes_the_published_success(self):
        client, credentials = self.publication()
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())
        self.reconcile(client, credentials)
        good = self.source.reviews
        self.source.reviews = "unavailable"
        with self.assertRaises(collector.CollectorFailure):
            self.reconcile(client, credentials)
        self.assertEqual([post["conclusion"] for post in client.posts],
                         ["success", "failure"])
        self.source.reviews = good
        self.assertEqual(self.reconcile(client, credentials).status, "pass")
        self.assertEqual(len(client.posts), 3)

    def test_failed_revocation_is_retried_and_never_reads_as_current(self):
        client, credentials = self.publication()
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())
        self.reconcile(client, credentials)
        client.fail = True
        with self.assertRaises(publisher.PublisherFailure):
            self.collector.revoke_published(client, credentials, "codex", 12)
        self.assertEqual(self.ledger()["published"]["state"], "revoking")
        client.fail = False
        # Same request, same test merge: the revoking record must not be
        # mistaken for the current success; revoke first, then post anew.
        self.assertEqual(self.reconcile(client, credentials).status, "pass")
        self.assertEqual([post["conclusion"] for post in client.posts],
                         ["success", "failure", "success"])
        self.assertEqual(self.ledger()["published"]["state"], "success")

    def test_ambiguous_success_publication_is_tracked_and_revoked(self):
        original_save = collector.LedgerStore.save

        def failing_success_save(store, request):
            if request.published is not None and request.published.state == "success":
                raise collector.CollectorFailure("review request ledger write failed")
            return original_save(store, request)
        for mode in ("lost_response", "malformed_response", "ledger_write"):
            with self.subTest(mode=mode):
                for path in self.state.glob("*.json"):
                    path.unlink()
                client, credentials = self.publication()
                self.source = FakeSource()
                self.collector.request_review("codex", self.live, self.source)
                self.source.add(self.context.head_sha, self.late())
                client.after_accept = {"lost_response": "raise",
                                       "malformed_response": "no_id"}.get(mode)
                with mock.patch.object(
                        collector.LedgerStore, "save",
                        failing_success_save if mode == "ledger_write" else original_save):
                    with self.assertRaises(Exception):
                        self.reconcile(client, credentials)
                # GitHub accepted the success; the error path superseded it.
                self.assertEqual([post["conclusion"] for post in client.posts],
                                 ["success", "failure"])
                self.assertIsNone(self.ledger()["published"])
                client.after_accept = None
                self.assertEqual(self.reconcile(client, credentials).status, "pass")
                self.assertEqual(self.ledger()["published"]["state"], "success")

    def test_crash_after_accepted_success_is_revoked_after_restart(self):
        for later in ("pass", "blocked"):
            with self.subTest(later=later):
                for path in self.state.glob("*.json"):
                    path.unlink()
                client, credentials = self.publication()
                self.source = FakeSource()
                self.collector.request_review("codex", self.live, self.source)
                self.source.add(self.context.head_sha, self.late())
                client.after_accept = "crash"
                with self.assertRaises(KeyboardInterrupt):  # the process dies
                    self.reconcile(client, credentials)
                self.assertEqual(self.ledger()["published"]["state"], "publishing")
                client.after_accept = None
                if later == "blocked":
                    self.source.add(self.context.head_sha, self.late() + 5, body=BLOCK)
                restarted = self.make_collector()
                self.assertEqual(self.reconcile(client, credentials,
                                                collector_=restarted).status, later)
                expected = ["success", "failure"] + (["success"] if later == "pass" else [])
                self.assertEqual([post["conclusion"] for post in client.posts], expected)

    def test_reconciliation_is_bound_to_the_supplied_pull_request(self):
        client, credentials = self.publication()
        other = replace(self.context, pr_number=13, test_merge_sha="9" * 40)
        # PR 12 has a published success; PR 13 has an active request.
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())
        self.reconcile(client, credentials)
        self.collector.request_review("codex", other, self.source)
        other_before = (self.state / "900002-13-codex.json").read_text()
        self.source.add(other.head_sha, self.late() + 5, body=BLOCK)  # 13 would block
        foreign_repository = replace(self.context, repository_id=900009)
        for wrong in (other, foreign_repository):
            with self.subTest(pr=wrong.pr_number, repository=wrong.repository_id):
                with self.assertRaises(collector.CollectorFailure):
                    self.collector.collect_and_publish(
                        "codex", 12, lambda wrong=wrong: wrong, self.source,
                        client, credentials)
        # Nothing was decided or written for the other PR; PR 12's success,
        # which this pass could not verify, was superseded.
        self.assertEqual((self.state / "900002-13-codex.json").read_text(), other_before)
        self.assertFalse((self.state / "900009-12-codex.json").exists())
        self.assertEqual([(post["conclusion"], post["head_sha"]) for post in client.posts],
                         [("success", self.context.test_merge_sha),
                          ("failure", self.context.test_merge_sha)])

    def test_reconciliation_refuses_a_source_for_another_repository(self):
        client, credentials = self.publication()
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())
        self.assertEqual(self.reconcile(client, credentials).status, "pass")
        # Same PR number and head commit (e.g. a fork), but another repository's
        # reviews: a trusted pass there must never count here.
        foreign = FakeSource("other/repository")
        foreign.add(self.context.head_sha, self.late())
        unnamed = FakeSource()
        del unnamed.repository
        unnamed.add(self.context.head_sha, self.late())
        for wrong in (foreign, unnamed):
            with self.subTest(source=getattr(wrong, "repository", None)):
                with self.assertRaisesRegex(collector.CollectorFailure,
                                            "another repository"):
                    self.reconcile(client, credentials, source=wrong)
        # The standing success, which these passes could not verify, was
        # superseded exactly once and no new success was published.
        self.assertEqual([post["conclusion"] for post in client.posts],
                         ["success", "failure"])
        self.assertIsNone(self.ledger()["published"])
        # A pass collected directly from such a source is never published.
        foreign_pass = self.collector.collect("codex", self.read_live, foreign)
        self.assertEqual(foreign_pass.status, "pass")
        with self.assertRaisesRegex(collector.CollectorFailure, "another repository"):
            self.collector.publish(client, credentials, foreign_pass)
        self.assertEqual(len(client.posts), 2)
        # GitHub repository names are case-insensitive.
        self.assertEqual(self.reconcile(
            client, credentials, source=FakeSource("Owner/Repository")).status,
            "pending")

    def test_unwritable_ledger_still_supersedes_the_standing_success(self):
        client, credentials = self.publication()
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())
        self.reconcile(client, credentials)
        standing = self.ledger()["published"]
        self.source.add(self.context.head_sha, self.late() + 5, body=BLOCK)

        def read_only_save(store, request):  # read-only or full state directory
            raise collector.CollectorFailure("review request ledger write failed")
        for outcome in ("blocked", "collection_error"):
            with self.subTest(outcome=outcome):
                posts_before = len(client.posts)
                good = self.source.reviews
                if outcome == "collection_error":
                    self.source.reviews = "unavailable"
                with mock.patch.object(collector.LedgerStore, "save", read_only_save):
                    with self.assertRaises(collector.CollectorFailure):
                        self.reconcile(client, credentials)
                self.source.reviews = good
                # The old success is no longer GitHub's latest attempt even
                # though the revoking state could not be recorded.
                self.assertEqual([(post["conclusion"], post["head_sha"])
                                  for post in client.posts[posts_before:]],
                                 [("failure", self.context.test_merge_sha)])
                self.assertEqual(self.ledger()["published"], standing)
        # Once the ledger is writable the stale record is cleared.
        self.assertEqual(self.reconcile(client, credentials).status, "blocked")
        self.assertIsNone(self.ledger()["published"])
        self.assertEqual(client.posts[-1]["conclusion"], "failure")

    def test_clean_pass_republishes_after_an_unrecorded_revocation(self):
        client, credentials = self.publication()
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())
        self.reconcile(client, credentials)
        good = self.source.reviews
        self.source.reviews = "unavailable"

        def read_only_save(store, request):
            raise collector.CollectorFailure("review request ledger write failed")
        with mock.patch.object(collector.LedgerStore, "save", read_only_save):
            with self.assertRaises(collector.CollectorFailure):
                self.reconcile(client, credentials)
        self.assertEqual(self.ledger()["published"]["state"], "success")  # stale
        self.assertEqual(client.posts[-1]["conclusion"], "failure")
        # The ledger is writable again and the evidence is clean: the stale
        # record must not be reused while GitHub's latest attempt is failure.
        self.source.reviews = good
        self.assertEqual(self.reconcile(client, credentials).status, "pass")
        self.assertEqual(client.posts[-1]["conclusion"], "success")
        self.assertEqual(self.ledger()["published"]["state"], "success")
        # Later polls reuse the new success without further runs.
        posts = len(client.posts)
        self.assertEqual(self.reconcile(client, credentials).status, "pass")
        self.assertEqual(len(client.posts), posts)

    def test_restarted_or_other_worker_republishes_after_an_unrecorded_revocation(self):
        # The failure attempt was posted by a worker whose ledger write failed;
        # a restarted process or another worker has no memory of it and must
        # still not reuse the stale success record while GitHub's latest
        # attempt is that failure.
        for case in ("restart", "other_worker"):
            with self.subTest(case=case):
                self.setUp()
                client, credentials = self.publication()
                other = self.make_collector()
                self.collector.request_review("codex", self.live, self.source)
                self.source.add(self.context.head_sha, self.late())
                self.reconcile(client, credentials,
                               collector_=other if case == "other_worker" else None)
                good = self.source.reviews
                self.source.reviews = "unavailable"

                def read_only_save(store, request):
                    raise collector.CollectorFailure("review request ledger write failed")
                with mock.patch.object(collector.LedgerStore, "save", read_only_save):
                    with self.assertRaises(collector.CollectorFailure):
                        self.reconcile(client, credentials)
                self.assertEqual(self.ledger()["published"]["state"], "success")  # stale
                self.assertEqual(client.posts[-1]["conclusion"], "failure")
                self.source.reviews = good
                recovering = self.make_collector() if case == "restart" else other
                self.assertEqual(self.reconcile(client, credentials,
                                                collector_=recovering).status, "pass")
                self.assertEqual(client.posts[-1]["conclusion"], "success")
                self.assertEqual(self.ledger()["published"]["check_run_id"],
                                 len(client.posts))
                posts = len(client.posts)
                self.assertEqual(self.reconcile(client, credentials,
                                                collector_=recovering).status, "pass")
                self.assertEqual(len(client.posts), posts)
                self.tearDown()

    def test_attempt_limit_stops_republishing_on_every_poll(self):
        client, credentials = self.publication()
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())
        self.reconcile(client, credentials)
        # So many attempts exist that the latest one can never be verified.
        client.hidden_runs = publisher.MAX_CHECK_RUN_ATTEMPTS
        for _ in range(4):
            with self.assertRaisesRegex(collector.CollectorFailure, "attempt limit"):
                self.reconcile(client, credentials)
        # The standing success was superseded once; nothing was posted after.
        self.assertEqual([post["conclusion"] for post in client.posts],
                         ["success", "failure"])
        self.assertIsNone(self.ledger()["published"])
        client.hidden_runs = publisher.MAX_CHECK_RUN_ATTEMPTS - 3
        self.assertEqual(self.reconcile(client, credentials).status, "pass")
        self.assertEqual(client.posts[-1]["conclusion"], "success")

    def test_unverifiable_latest_attempt_is_never_reused(self):
        client, credentials = self.publication()
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())
        self.reconcile(client, credentials)
        # An incomplete listing proves nothing: supersede and republish.
        client.hidden_runs = 1
        self.assertEqual(self.reconcile(client, credentials).status, "pass")
        self.assertEqual([post["conclusion"] for post in client.posts],
                         ["success", "failure", "success"])
        client.hidden_runs = 0
        # A listing that cannot be read at all fails closed: the standing
        # success is superseded and the error is raised.
        client.list_fail = True
        with self.assertRaises(publisher.PublisherFailure):
            self.reconcile(client, credentials)
        self.assertEqual(client.posts[-1]["conclusion"], "failure")
        self.assertIsNone(self.ledger()["published"])
        client.list_fail = False
        self.assertEqual(self.reconcile(client, credentials).status, "pass")
        self.assertEqual(client.posts[-1]["conclusion"], "success")

    def test_overlapping_pass_cannot_revoke_a_newer_success(self):
        client, credentials = self.publication()
        self.collector.request_review("codex", self.live, self.source)
        other = self.make_collector()
        outcomes = []

        class Overlap(logging.Handler):
            # Runs a second reconciliation right after the first one has
            # decided "pending", while its revocation is still to come.
            def emit(handler, record):
                if outcomes or "status=pending" not in record.getMessage():
                    return
                outcomes.append("started")
                self.source.add(self.context.head_sha, self.late())
                try:
                    outcomes.append(self.reconcile(client, credentials,
                                                   collector_=other).status)
                except collector.CollectorFailure:
                    outcomes.append("busy")
        handler = Overlap()
        collector.LOG.addHandler(handler)
        try:
            with mock.patch.object(collector, "LOCK_TIMEOUT_SECONDS", 0.1):
                self.assertEqual(self.reconcile(client, credentials).status, "pending")
        finally:
            collector.LOG.removeHandler(handler)
        self.assertEqual(outcomes, ["started", "busy"])
        self.assertEqual(self.reconcile(client, credentials, collector_=other).status,
                         "pass")
        # No failure attempt ever superseded the success of the newer evidence.
        self.assertEqual([post["conclusion"] for post in client.posts], ["success"])
        self.assertEqual(self.ledger()["published"]["state"], "success")

    def test_context_change_supersedes_success_on_the_old_test_merge(self):
        client, credentials = self.publication()
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.context.head_sha, self.late())
        self.reconcile(client, credentials)
        self.live = replace(self.context, base_sha="e" * 40, test_merge_sha="9" * 40)
        self.assertEqual(self.reconcile(client, credentials).status, "invalidated")
        self.assertEqual(client.posts[-1]["head_sha"], self.context.test_merge_sha)
        self.assertEqual(client.posts[-1]["conclusion"], "failure")
        # A new request for the new context carries no stale success forward.
        self.clock.now = self.late() + 10
        self.collector.request_review("codex", self.live, self.source)
        self.assertIsNone(self.ledger()["published"])

    def test_external_config_loader(self):
        config = Path(self.temp.name) / "collector.json"
        entry = {"user_id": CODEX_BOT["id"], "user_login": CODEX_BOT["login"],
                 "max_review_runtime_seconds": RUNTIME, "pass_markers": [PASS],
                 "blocking_markers": [BLOCK], "non_blocking_markers": [SUGGEST]}
        config.write_text(json.dumps({"state_dir": str(self.state),
                                      "providers": {"codex": entry}}))
        os.chmod(config, 0o600)
        env = {collector.COLLECTOR_CONFIG_ENV: str(config)}
        loaded = collector.load_collector(env, self.checkout, self.clock)
        self.assertTrue(loaded.request_review("codex", self.live, self.source).created)
        for bad in ({"state_dir": str(self.state), "providers": {}},
                    {"state_dir": str(self.state), "providers": {"codex": {**entry, "x": 1}}},
                    {"state_dir": str(self.state),
                     "providers": {"codex": {**entry, "user_id": ACTIONS_BOT["id"]}}},
                    {"state_dir": str(self.state),
                     "providers": {"codex": {**entry, "pass_markers": []}}},
                    {"state_dir": str(self.checkout), "providers": {"codex": entry}}):
            with self.subTest(bad=list(bad)):
                config.write_text(json.dumps(bad))
                with self.assertRaises(collector.CollectorFailure):
                    collector.load_collector(env, self.checkout, self.clock)
        os.chmod(config, 0o644)
        with self.assertRaises(collector.CollectorFailure):
            collector.load_collector(env, self.checkout, self.clock)
        with self.assertRaises(collector.CollectorFailure):
            collector.load_collector({}, self.checkout, self.clock)


class GitHubReviewSourceTests(unittest.TestCase):
    class Client:
        def __init__(self, pages):
            self.pages, self.paths = pages, []

        def get_list(self, path, token):
            self.paths.append(path)
            page = int(path.rsplit("page=", 1)[1])
            return self.pages[page - 1] if page <= len(self.pages) else []

    def test_complete_pagination_and_bounds(self):
        full = [{"id": i} for i in range(1, 101)]
        client = self.Client([full, [{"id": 101}]])
        source = collector.GitHubReviewSource(client, "owner/repository", "token-value")
        self.assertEqual(len(source.list_reviews(12)), 101)
        self.assertEqual(client.paths, [
            "/repos/owner/repository/pulls/12/reviews?per_page=100&page=1",
            "/repos/owner/repository/pulls/12/reviews?per_page=100&page=2"])
        self.assertNotIn("token-value", repr(source))
        client = self.Client([full] * collector.GitHubReviewSource.MAX_PAGES)
        source = collector.GitHubReviewSource(client, "owner/repository", "t")
        with self.assertRaisesRegex(collector.CollectorFailure, "verification limit"):
            source.list_reviews(12)
        client = self.Client([full] * 3)
        source = collector.GitHubReviewSource(client, "owner/repository", "t")
        self.assertEqual(len(source.list_review_comments(12, 5)), 300)
        client = self.Client([full] * 4)
        source = collector.GitHubReviewSource(client, "owner/repository", "t")
        with self.assertRaisesRegex(collector.CollectorFailure, "verification limit"):
            source.list_review_comments(12, 5)
        client = self.Client([{"not": "a list"}])
        source = collector.GitHubReviewSource(client, "owner/repository", "t")
        with self.assertRaises(collector.CollectorFailure):
            source.list_reviews(12)
        for args in ((0,), (True,)):
            with self.assertRaises(collector.CollectorFailure):
                source.list_reviews(*args)
        with self.assertRaises(collector.CollectorFailure):
            collector.GitHubReviewSource(client, "owner/repo/extra", "t")

    def test_issue_comments_and_short_sha_resolution(self):
        full = [{"id": i} for i in range(1, 101)]
        client = self.Client([full, [{"id": 101}]])
        responses = {}

        def get_json(path, token):
            client.paths.append(path)
            response = responses[path]
            if isinstance(response, Exception):
                raise response
            return response
        client.get_json = get_json
        source = collector.GitHubReviewSource(client, "owner/repository", "t")
        self.assertEqual(len(source.list_issue_comments(12)), 101)
        self.assertEqual(client.paths[0],
                         "/repos/owner/repository/issues/12/comments?per_page=100&page=1")
        route = "/repos/owner/repository/commits/aaaaaaaaaa"
        responses[route] = {"sha": "a" * 40}
        self.assertEqual(source.resolve_commit("a" * 10), "a" * 40)
        # GitHub refuses an ambiguous short SHA; a malformed answer is no answer.
        for response in (publisher.PublisherFailure("GitHub API request failed"),
                         {"sha": "a" * 10}, {}):
            responses[route] = response
            with self.assertRaises(collector.CollectorFailure):
                source.resolve_commit("a" * 10)
        for bad in ("a" * 6, "A" * 10, "a" * 41, "aaaaaaa/../x", 7):
            with self.assertRaises(collector.CollectorFailure):
                source.resolve_commit(bad)
        client = self.Client([full] * collector.GitHubReviewSource.MAX_PAGES)
        source = collector.GitHubReviewSource(client, "owner/repository", "t")
        with self.assertRaisesRegex(collector.CollectorFailure, "verification limit"):
            source.list_issue_comments(12)

    def test_source_built_from_credentials_reads_the_configured_repository(self):
        config = publisher.RuntimeConfig("owner/repository", 900002,
                                         gate.Issuer(900001, "synthetic-review-gate"),
                                         900003, Path("/nonexistent/key.pem"))
        credentials = publisher.AppCredentials(config, b"synthetic-key", "t" * 40)
        client = self.Client([[{"id": 1}]])
        source = collector.GitHubReviewSource.for_credentials(client, credentials)
        self.assertEqual(source.repository, "owner/repository")
        self.assertEqual(len(source.list_reviews(12)), 1)
        self.assertEqual(client.paths,
                         ["/repos/owner/repository/pulls/12/reviews?per_page=100&page=1"])

    def test_publisher_transport_allows_only_fixed_queries(self):
        from scripts.ci.review_gate_publisher import PublisherFailure, UrllibGitHubTransport
        url = UrllibGitHubTransport._url
        self.assertTrue(url("/repos/o/r/pulls/1/reviews?per_page=100&page=10")
                        .endswith("page=10"))
        self.assertTrue(url("/repos/o/r/git/trees/" + "a" * 40 + "?recursive=1"))
        runs = "/repos/o/r/commits/" + "a" * 40 + "/check-runs"
        query = "?check_name=ServerSentinel%20Codex%20review&app_id=7&filter=all&per_page=100&page=1"
        self.assertTrue(url(runs + query).endswith("page=1"))
        for path in (runs + query.replace("filter=all", "filter=latest"),
                     runs + query + "&status=completed",
                     "/repos/o/r/pulls/1/reviews" + query,
                     runs + "?check_name=a#b&app_id=7&filter=all&per_page=100&page=1"):
            with self.subTest(path=path), self.assertRaises(PublisherFailure):
                url(path)
        for path in ("/x?per_page=100&page=0", "/x?per_page=100&page=100",
                     "/x?per_page=50&page=1", "/x?recursive=1&a=b",
                     "/x?per_page=100&page=1?y", "/x%2f?recursive=1", "x", "/x#y"):
            with self.subTest(path=path), self.assertRaises(PublisherFailure):
                url(path)


class FakeLiveGitHub(FakeCheckRuns):
    """Serves a synthetic PR, its ancestry and trees, counting every read."""

    def __init__(self, issuer, depth=40):
        super().__init__(issuer)
        def sha(n):
            return f"{n:040x}"
        self.graph = {sha(1): ()}
        for n in range(2, depth + 1):  # shared linear history up to the merge base
            self.graph[sha(n)] = (sha(n - 1),)
        self.merge_base = sha(depth)
        self.base = sha(0xB0000 + 1)
        self.head = sha(0xA0000 + 1)
        self.graph[self.base] = (self.merge_base,)
        self.graph[self.head] = (self.merge_base,)
        self.test_merge = sha(0xF0000 + 1)
        self.reads: dict[str, int] = {}
        self.corrupt: set[str] = set()
        # Requested by commit SHA, as the publisher does; like GitHub, each
        # response names the root tree's own SHA, never the commit's.
        self.trees = {
            self.base: {"sha": sha(0xC0000 + 1), "truncated": False, "tree": [
                {"path": "a.txt", "mode": "100644", "type": "blob", "sha": "1" * 40}]},
            self.head: {"sha": sha(0xC0000 + 2), "truncated": False, "tree": [
                {"path": "a.txt", "mode": "100644", "type": "blob", "sha": "2" * 40}]},
        }
        self.tree_responses: dict[str, dict] = {}  # path -> overriding response

    def get_json(self, path, token):
        self.reads[path] = self.reads.get(path, 0) + 1
        repo = "/repos/owner/repository"
        if path in self.corrupt:
            return {"sha": "8" * 40, "parents": []}
        if path == f"{repo}/pulls/12":
            return {"number": 12, "base": {"ref": "main", "sha": self.base,
                                           "repo": {"id": 900002}},
                    "head": {"sha": self.head}}
        if path == f"{repo}/git/ref/pull/12/merge":
            return {"object": {"sha": self.test_merge}}
        if path == f"{repo}/git/commits/{self.test_merge}":
            return {"sha": self.test_merge, "tree": {"sha": self.tree_sha(self.test_merge)},
                    "parents": [{"sha": self.base}, {"sha": self.head}]}
        if path.startswith(f"{repo}/git/commits/"):
            sha = path.rsplit("/", 1)[1]
            return {"sha": sha, "tree": {"sha": self.tree_sha(sha)},
                    "parents": [{"sha": p} for p in self.graph[sha]]}
        if path in self.tree_responses:
            return json.loads(json.dumps(self.tree_responses[path]))
        if path.startswith(f"{repo}/git/trees/"):
            return json.loads(json.dumps(self.trees[path.rsplit("/", 1)[1].split("?")[0]]))
        return super().get_json(path, token)

    def tree_sha(self, commit):
        if commit in self.trees:
            return self.trees[commit]["sha"]
        return f"{int(commit, 16) + 0xD000000:040x}"

    def object_reads(self):
        return {path: count for path, count in self.reads.items() if "/git/" in path
                and "/git/ref/" not in path}


class LiveContextCacheTests(unittest.TestCase):
    """Immutable commit/tree objects are read once across live-context rechecks."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.checkout = root / "checkout"
        self.checkout.mkdir()
        state = root / "state"
        state.mkdir(mode=0o700)
        self.clock = Clock()
        self.issuer = gate.Issuer(900001, "synthetic-review-gate")
        self.github = FakeLiveGitHub(self.issuer)
        config = publisher.RuntimeConfig("owner/repository", 900002, self.issuer, 900003,
                                         root / "key.pem")
        self.credentials = publisher.AppCredentials(config, b"synthetic-key", "t" * 40)
        self.collector = collector.ReviewCollector(
            collector.LedgerStore(state, self.checkout), {"codex": identity()}, self.clock)
        self.source = FakeSource()
        self.live = publisher.collect_live_context(FakeLiveGitHub(self.issuer), config,
                                                   "t" * 40, 12)

    def tearDown(self):
        self.temp.cleanup()

    def reconcile(self):
        return self.collector.collect_and_publish("codex", 12, None, self.source,
                                                  self.github, self.credentials)

    def test_passing_reconciliation_reads_each_git_object_once(self):
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.live.head_sha, START + RUNTIME + collector.CLOCK_SKEW_ALLOWANCE_SECONDS)
        decision = self.reconcile()
        self.assertEqual(decision.status, "pass")
        self.assertEqual(decision.context, self.live)
        self.assertEqual([post["conclusion"] for post in self.github.posts], ["success"])
        objects = self.github.object_reads()
        self.assertEqual(len(objects), len(self.github.graph) + 1 + 2)  # + test merge, trees
        self.assertEqual(set(objects.values()), {1})
        # Mutable PR and merge-ref state is read fresh for every recheck.
        self.assertEqual(self.github.reads["/repos/owner/repository/pulls/12"], 3)
        self.assertEqual(self.github.reads["/repos/owner/repository/git/ref/pull/12/merge"], 3)
        # A later poll reuses the immutable objects as well.
        self.assertEqual(self.reconcile().status, "pass")
        self.assertEqual(set(self.github.object_reads().values()), {1})
        self.assertEqual(self.github.reads["/repos/owner/repository/pulls/12"], 5)

    def test_changed_mutable_state_is_still_seen(self):
        self.collector.request_review("codex", self.live, self.source)
        self.source.add(self.live.head_sha, START + RUNTIME + collector.CLOCK_SKEW_ALLOWANCE_SECONDS)
        self.assertEqual(self.reconcile().status, "pass")
        new_head = f"{0xA0000 + 2:040x}"
        self.github.graph[new_head] = (self.github.head,)
        self.github.trees[new_head] = self.github.trees[self.github.head]
        self.github.head = new_head
        self.github.test_merge = f"{0xF0000 + 2:040x}"
        decision = self.reconcile()
        self.assertEqual((decision.status, decision.reason),
                         ("invalidated", "context_changed_since_request"))

    def test_only_valid_content_addressed_objects_are_cached(self):
        cache = publisher.GitObjectCache(max_entries=2)
        transport = publisher.CachingGitHubTransport(self.github, cache)
        repo = "/repos/owner/repository"
        wrong = f"{repo}/git/commits/{'9' * 40}"
        self.github.corrupt.add(wrong)  # answers with another object's identity
        for _ in range(2):
            transport.get_json(wrong, "t")
        self.assertEqual(self.github.reads[wrong], 2)
        for _ in range(2):
            transport.get_json(f"{repo}/pulls/12", "t")
        self.assertEqual(self.github.reads[f"{repo}/pulls/12"], 2)
        paths = [f"{repo}/git/commits/{f'{n:040x}'}" for n in (1, 2, 3)]
        for path in paths:
            transport.get_json(path, "t")
        value = transport.get_json(paths[2], "t")
        value["parents"].append({"sha": "7" * 40})  # a caller's mutation never reaches the cache
        self.assertEqual(transport.get_json(paths[2], "t")["parents"], [{"sha": f"{2:040x}"}])
        transport.get_json(paths[0], "t")  # evicted by the bound
        self.assertEqual(self.github.reads[paths[0]], 2)
        self.assertEqual(self.github.reads[paths[2]], 1)

    def test_tree_is_cached_only_once_bound_to_its_commit_tree(self):
        cache = publisher.GitObjectCache()
        transport = publisher.CachingGitHubTransport(self.github, cache)
        repo = "/repos/owner/repository"
        commit = f"{repo}/git/commits/{self.github.head}"
        tree = f"{repo}/git/trees/{self.github.head}?recursive=1"
        genuine = self.github.trees[self.github.head]
        # Before the commit is known, nothing binds the tree to it.
        for _ in range(2):
            transport.get_json(tree, "t")
        self.assertEqual(self.github.reads[tree], 2)
        transport.get_json(commit, "t")
        unrelated = dict(genuine, sha=self.github.trees[self.github.base]["sha"])
        identityless = {key: value for key, value in genuine.items() if key != "sha"}
        for response in (identityless, unrelated, dict(genuine, sha=self.github.head)):
            with self.subTest(response=response.get("sha")):
                self.github.tree_responses[tree] = response
                before = self.github.reads[tree]
                for _ in range(2):
                    self.assertEqual(transport.get_json(tree, "t"), response)
                self.assertEqual(self.github.reads[tree], before + 2)
        del self.github.tree_responses[tree]
        before = self.github.reads[tree]
        for _ in range(2):
            self.assertEqual(transport.get_json(tree, "t"), genuine)
        self.assertEqual(self.github.reads[tree], before + 1)
        # A commit response without a usable tree identity binds nothing.
        other = f"{repo}/git/trees/{self.github.base}?recursive=1"
        base_commit = f"{repo}/git/commits/{self.github.base}"
        cache.put(base_commit, {"sha": self.github.base, "parents": []})
        for _ in range(2):
            transport.get_json(other, "t")
        self.assertEqual(self.github.reads[other], 2)


logging.getLogger("server_sentinel").addHandler(logging.NullHandler())

if __name__ == "__main__":
    unittest.main()
