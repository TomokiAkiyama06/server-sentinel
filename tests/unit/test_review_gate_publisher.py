"""Synthetic tests for the isolated #4 self-hosted delivery adapter."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts.ci.review_gate_policy import Context, Issuer
from scripts.ci import review_gate_publisher as publisher


class FakeGitHub:
    def __init__(self, context: Context, issuer: Issuer):
        self.context, self.issuer = context, issuer
        self.posts: list[tuple[str, str, dict]] = []
        self.diff = b"synthetic fixed diff\n"
        self.graph = {
            context.head_sha: (context.merge_base_sha,),
            context.base_sha: (context.merge_base_sha,),
            context.merge_base_sha: (),
        }

    def get_json(self, path, token):
        c = self.context
        if path.endswith(f"/pulls/{c.pr_number}"):
            return {"number": c.pr_number, "base": {"ref": "main", "sha": c.base_sha,
                    "repo": {"id": c.repository_id}}, "head": {"sha": c.head_sha}}
        if path.endswith(f"/git/ref/pull/{c.pr_number}/merge"):
            return {"object": {"sha": c.test_merge_sha}}
        if path.endswith(f"/git/commits/{c.test_merge_sha}"):
            return {"sha": c.test_merge_sha,
                    "parents": [{"sha": c.base_sha}, {"sha": c.head_sha}]}
        marker = "/git/commits/"
        if marker in path:
            sha = path.rsplit(marker, 1)[1]
            return {"sha": sha,
                    "parents": [{"sha": parent} for parent in self.graph[sha]]}
        raise AssertionError(path)

    def get_bytes(self, path, token, accept):
        self.assert_diff_request(path, accept)
        return self.diff

    def assert_diff_request(self, path, accept):
        assert path.endswith(f"/pulls/{self.context.pr_number}")
        assert accept == "application/vnd.github.v3.diff"

    def post_json(self, path, token, payload):
        self.posts.append((path, token, payload))
        return {**payload, "app": {"id": self.issuer.app_id, "slug": self.issuer.app_slug}}


class ReviewGatePublisherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.config_path = self.root / "review-gate.json"
        self.key_path = self.root / "review-gate.pem"
        self.issuer = Issuer(900001, "synthetic-review-gate")
        self.diff = b"synthetic fixed diff\n"
        self.context = Context(900002, 12, "refs/heads/main", "a" * 40, "b" * 40,
                               "c" * 40, hashlib.sha256(self.diff).hexdigest(), "f" * 40)
        self._write_runtime_files()
        self.environ = {publisher.CONFIG_ENV: str(self.config_path),
                        publisher.TOKEN_ENV: "x" * 40}

    def tearDown(self):
        self.temp.cleanup()

    def _write_runtime_files(self):
        self.config_path.write_text(json.dumps({"repository": "owner/repository",
            "repository_id": self.context.repository_id, "app_id": self.issuer.app_id,
            "app_slug": self.issuer.app_slug, "installation_id": 900003,
            "private_key_path": str(self.key_path)}))
        fence = b"-" * 5
        self.key_path.write_bytes(fence + b"BEGIN PRIVATE KEY" + fence + b"\n"
                                  + b"a" * 64 + b"\n" + fence
                                  + b"END PRIVATE KEY" + fence + b"\n")
        os.chmod(self.config_path, 0o600)
        os.chmod(self.key_path, 0o600)

    def credentials(self):
        config = publisher.load_runtime_config(self.environ, self.checkout)
        return publisher.load_app_credentials(config, self.environ, self.checkout)

    def test_external_private_runtime_material_loads_and_publishes_fixed_request(self):
        credentials = self.credentials()
        fake = FakeGitHub(self.context, self.issuer)
        response = publisher.publish_success(fake, credentials, self.context, "codex")
        self.assertEqual(response["app"], {"id": self.issuer.app_id, "slug": self.issuer.app_slug})
        self.assertEqual(len(fake.posts), 1)
        path, token, request = fake.posts[0]
        self.assertEqual(path, "/repos/owner/repository/check-runs")
        self.assertEqual(token, self.environ[publisher.TOKEN_ENV])
        self.assertEqual(request["head_sha"], self.context.test_merge_sha)
        self.assertEqual(request["name"], "ServerSentinel Codex review")
        self.assertNotIn("private_key", json.dumps(request))

    def test_every_live_context_change_blocks_before_post(self):
        credentials = self.credentials()
        for field, value in {"head_sha": "e" * 40, "base_sha": "e" * 40,
                             "merge_base_sha": "e" * 40,
                             "test_merge_sha": "e" * 40}.items():
            with self.subTest(field=field):
                fake = FakeGitHub(replace(self.context, **{field: value}), self.issuer)
                with self.assertRaises(publisher.PublisherFailure):
                    publisher.publish_success(fake, credentials, self.context, "codex")
                self.assertEqual(fake.posts, [])
        fake = FakeGitHub(self.context, self.issuer)
        fake.diff = b"changed diff\\n"
        with self.assertRaises(publisher.PublisherFailure):
            publisher.publish_success(fake, credentials, self.context, "codex")
        self.assertEqual(fake.posts, [])

    def test_configuration_key_and_token_fail_closed_outside_checkout_only(self):
        for update in ({}, {publisher.CONFIG_ENV: str(self.checkout / "missing")},
                       {publisher.CONFIG_ENV: str(self.checkout / "inside.json")}):
            if update.get(publisher.CONFIG_ENV, "").endswith("inside.json"):
                inside = self.checkout / "inside.json"
                inside.write_text("{}")
                os.chmod(inside, 0o600)
            with self.subTest(update=update), self.assertRaises(publisher.PublisherFailure):
                publisher.load_runtime_config(update, self.checkout)
        os.chmod(self.config_path, 0o644)
        with self.assertRaises(publisher.PublisherFailure):
            publisher.load_runtime_config(self.environ, self.checkout)
        os.chmod(self.config_path, 0o600)
        config = publisher.load_runtime_config(self.environ, self.checkout)
        link = self.root / "review-gate-link.json"
        link.symlink_to(self.config_path)
        with self.assertRaises(publisher.PublisherFailure):
            publisher.load_runtime_config({publisher.CONFIG_ENV: str(link)}, self.checkout)
        for env in ({publisher.CONFIG_ENV: str(self.config_path)},
                    {**self.environ, publisher.TOKEN_ENV: "bad"}):
            with self.subTest(env=env), self.assertRaises(publisher.PublisherFailure):
                publisher.load_app_credentials(config, env, self.checkout)

    def test_github_rsa_private_key_delimiter_is_accepted(self):
        fence = b"-" * 5
        self.key_path.write_bytes(fence + b"BEGIN RSA PRIVATE KEY" + fence + b"\n"
                                  + b"a" * 64 + b"\n" + fence
                                  + b"END RSA PRIVATE KEY" + fence + b"\n")
        credentials = self.credentials()
        self.assertTrue(credentials.private_key_pem.startswith(
            b"-----BEGIN RSA PRIVATE KEY-----"))

    def test_unique_merge_base_rejects_criss_cross_and_incomplete_proof(self):
        fake = FakeGitHub(self.context, self.issuer)
        left, right = "d" * 40, "e" * 40
        root = "9" * 40
        fake.graph = {
            self.context.base_sha: (left, right),
            self.context.head_sha: (right, left),
            left: (root,), right: (root,), root: (),
        }
        repo = "/repos/owner/repository"
        with self.assertRaisesRegex(publisher.PublisherFailure,
                                    "multiple merge bases"):
            publisher.unique_merge_base(fake, repo, "token",
                                        self.context.base_sha,
                                        self.context.head_sha)
        with self.assertRaisesRegex(publisher.PublisherFailure,
                                    "exceeds verification limit"):
            publisher.unique_merge_base(fake, repo, "token",
                                        self.context.base_sha,
                                        self.context.head_sha, max_commits=2)
        for limit in (0, publisher._MAX_ANCESTRY_COMMITS + 1, True):
            with self.subTest(limit=limit), self.assertRaisesRegex(
                    publisher.PublisherFailure,
                    "invalid ancestry verification limit"):
                publisher.unique_merge_base(fake, repo, "token",
                                            self.context.base_sha,
                                            self.context.head_sha,
                                            max_commits=limit)

    def test_bad_test_merge_or_post_response_fails_closed(self):
        credentials = self.credentials()
        fake = FakeGitHub(self.context, self.issuer)
        original = fake.get_json
        def bad_merge(path, token):
            response = original(path, token)
            if path.endswith(f"/git/commits/{self.context.test_merge_sha}"):
                response["parents"] = [{"sha": self.context.head_sha}]
            return response
        fake.get_json = bad_merge
        with self.assertRaises(publisher.PublisherFailure):
            publisher.publish_success(fake, credentials, self.context, "claude")
        self.assertEqual(fake.posts, [])
        fake = FakeGitHub(self.context, self.issuer)
        def forged(path, token, request):
            return {**request, "app": {"id": 15368, "slug": "github-actions"}}
        fake.post_json = forged
        with self.assertRaises(publisher.PublisherFailure):
            publisher.publish_success(fake, credentials, self.context, "claude")


if __name__ == "__main__":
    unittest.main()
