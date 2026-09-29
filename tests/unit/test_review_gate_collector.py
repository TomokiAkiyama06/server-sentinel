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
    def __init__(self):
        self.reviews: list[dict] = []
        self.comments: dict[int, list[dict]] = {}
        self.next_id = 5000

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

    def test_publisher_transport_allows_only_fixed_queries(self):
        from scripts.ci.review_gate_publisher import PublisherFailure, UrllibGitHubTransport
        url = UrllibGitHubTransport._url
        self.assertTrue(url("/repos/o/r/pulls/1/reviews?per_page=100&page=10")
                        .endswith("page=10"))
        self.assertTrue(url("/repos/o/r/git/trees/" + "a" * 40 + "?recursive=1"))
        for path in ("/x?per_page=100&page=0", "/x?per_page=100&page=100",
                     "/x?per_page=50&page=1", "/x?recursive=1&a=b",
                     "/x?per_page=100&page=1?y", "/x%2f?recursive=1", "x", "/x#y"):
            with self.subTest(path=path), self.assertRaises(PublisherFailure):
                url(path)


logging.getLogger("server_sentinel").addHandler(logging.NullHandler())

if __name__ == "__main__":
    unittest.main()
