"""Synthetic App-JWT -> installation token tests; no GitHub or real key.

The signer here is a deterministic stand-in with an RSA-2048-sized output.  It
is not RS256 and proves only the adapter's structure and secret handling.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import traceback
import unittest
from unittest import mock

from scripts.ci import review_gate_app_token as app_token
from scripts.ci import review_gate_publisher as publisher
from scripts.ci.review_gate_policy import Issuer


NOW = 1_900_000_000
# Built at runtime so no token-shaped literal exists in the repository.
SYNTHETIC_TOKEN = "ghs" + "_" + "SyntheticInstallationToken0123456789ab"
SYNTHETIC_TOKEN_2 = "ghs" + "_" + "SyntheticInstallationToken0123456789cd"


def iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def unb64(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


class SyntheticSigner:
    def __init__(self, key: bytes):
        self._key = key
        self.inputs: list[bytes] = []

    def __repr__(self):
        return "SyntheticSigner()"

    def sign(self, signing_input: bytes) -> bytes:
        self.inputs.append(signing_input)
        digest = hashlib.sha256(self._key + signing_input).digest()
        return digest * 8  # 256 bytes, the size of an RSA-2048 signature


class MockTransport:
    def __init__(self, config, tokens=(SYNTHETIC_TOKEN,), lifetime=3600):
        self.config = config
        self.tokens = list(tokens)
        self.lifetime = lifetime
        self.calls: list[tuple[str, str, dict]] = []
        self.now = NOW
        self.override: dict | None = None
        self.error: Exception | None = None

    def post_json(self, path, token, payload):
        self.calls.append((path, token, payload))
        if self.error is not None:
            raise self.error
        response = {
            "token": self.tokens[min(len(self.calls), len(self.tokens)) - 1],
            "expires_at": iso(self.now + self.lifetime),
            "permissions": dict(payload["permissions"]),
            "repository_selection": "selected",
            "repositories": [{"id": self.config.repository_id, "name": "repository"}],
        }
        if self.override:
            response.update(self.override)
        return response

    def get_json(self, path, token):
        raise AssertionError("unexpected GET")

    def get_bytes(self, path, token, accept):
        raise AssertionError("unexpected GET")

    def get_list(self, path, token):
        raise AssertionError("unexpected GET")


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now


class AppTokenTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.checkout = root / "checkout"
        self.checkout.mkdir()
        self.key_path = root / "synthetic-app.pem"
        fence = b"-" * 5
        # Synthetic random body in PEM framing; not an RSA key.
        self.key_body = base64.b64encode(os.urandom(96))
        self.key_path.write_bytes(fence + b"BEGIN RSA PRIVATE KEY" + fence + b"\n"
                                  + self.key_body + b"\n" + fence
                                  + b"END RSA PRIVATE KEY" + fence + b"\n")
        os.chmod(self.key_path, 0o600)
        self.config = publisher.RuntimeConfig(
            repository="owner/repository", repository_id=900002,
            issuer=Issuer(900001, "synthetic-review-gate"),
            installation_id=900003, private_key_path=self.key_path)
        self.clock = Clock()
        self.transport = MockTransport(self.config)
        self.signers: list[SyntheticSigner] = []

    def tearDown(self):
        self.temp.cleanup()

    def factory(self, key):
        signer = SyntheticSigner(key)
        self.signers.append(signer)
        return signer

    def source(self):
        return app_token.open_token_source(self.config, self.checkout, self.transport,
                                           self.factory, self.clock)

    def test_jwt_claims_header_and_signature_segment(self):
        signer = SyntheticSigner(b"synthetic")
        jwt = app_token.build_app_jwt(900001, signer, NOW).reveal()
        header, claims, signature = jwt.split(".")
        self.assertEqual(json.loads(unb64(header)), {"alg": "RS256", "typ": "JWT"})
        body = json.loads(unb64(claims))
        self.assertEqual(body, {"iat": NOW - 60, "exp": NOW + 540, "iss": 900001})
        self.assertLessEqual(body["exp"] - body["iat"], 600)
        self.assertEqual(signer.inputs, [(header + "." + claims).encode("ascii")])
        self.assertEqual(unb64(signature), signer.sign(signer.inputs[0]))
        for app_id, now in ((0, NOW), (True, NOW), (900001, 0), (900001, 1.5)):
            with self.subTest(app_id=app_id, now=now), self.assertRaises(
                    app_token.TokenFailure):
                app_token.build_app_jwt(app_id, signer, now)

    def test_exchange_requests_one_repository_and_fixed_permissions(self):
        source = self.source()
        self.assertEqual(source.token(), SYNTHETIC_TOKEN)
        (path, bearer, payload), = self.transport.calls
        self.assertEqual(path, "/app/installations/900003/access_tokens")
        self.assertEqual(payload, {"repository_ids": [900002],
                                   "permissions": app_token.REQUESTED_PERMISSIONS})
        self.assertEqual(bearer.count("."), 2)  # the App JWT, not a stored token
        self.assertEqual(self.signers[0]._key, self.key_path.read_bytes())

    def test_cached_until_refresh_margin_then_refreshed(self):
        self.transport.tokens = [SYNTHETIC_TOKEN, SYNTHETIC_TOKEN_2]
        source = self.source()
        self.assertEqual(source.token(), SYNTHETIC_TOKEN)
        self.clock.now = NOW + 3600 - app_token.REFRESH_MARGIN_SECONDS - 1
        self.assertEqual(source.token(), SYNTHETIC_TOKEN)
        self.assertEqual(len(self.transport.calls), 1)
        self.clock.now = NOW + 3600 - app_token.REFRESH_MARGIN_SECONDS
        self.transport.now = self.clock.now
        self.assertEqual(source.token(), SYNTHETIC_TOKEN_2)
        self.assertEqual(len(self.transport.calls), 2)
        source.invalidate()
        source.token()
        self.assertEqual(len(self.transport.calls), 3)

    def test_concurrent_callers_share_one_exchange(self):
        source = self.source()
        gate = threading.Event()
        original = self.transport.post_json

        def slow(path, token, payload):
            gate.wait(5)
            return original(path, token, payload)
        self.transport.post_json = slow
        results: list[str] = []
        threads = [threading.Thread(target=lambda: results.append(source.token()))
                   for _ in range(4)]
        for thread in threads:
            thread.start()
        gate.set()
        for thread in threads:
            thread.join(5)
        self.assertEqual(results, [SYNTHETIC_TOKEN] * 4)
        self.assertEqual(len(self.transport.calls), 1)

    def test_response_without_optional_repositories_is_accepted(self):
        # GitHub's documented 201 response may omit ``repositories``; the
        # outbound ``repository_ids`` already narrowed the grant.
        original = self.transport.post_json

        def without_repositories(path, token, payload):
            response = original(path, token, payload)
            del response["repositories"]
            return response
        self.transport.post_json = without_repositories
        self.assertEqual(self.source().token(), SYNTHETIC_TOKEN)
        self.assertEqual(self.transport.calls[0][2]["repository_ids"],
                         [self.config.repository_id])
        # Without the array, repository_selection must still be "selected".
        self.transport.override = {"repository_selection": "all"}
        with self.assertRaises(app_token.TokenFailure):
            self.source().token()

    def test_invalid_responses_fail_closed_and_drop_cache(self):
        cases = (
            {"token": "not-a-token"}, {"token": None},
            {"expires_at": iso(NOW + 7200)},  # longer than GitHub's 1h
            {"expires_at": iso(NOW + 60)},    # would expire inside the margin
            {"expires_at": "tomorrow"},
            {"permissions": {**app_token.REQUESTED_PERMISSIONS,
                             "administration": "write"}},
            {"permissions": {**app_token.REQUESTED_PERMISSIONS, "contents": "write"}},
            {"permissions": {"checks": "write"}},
            {"repository_selection": "all"},
            {"repositories": []},
            {"repositories": [{"id": 900002}, {"id": 900009}]},
            {"repositories": [{"id": 900009}]},
            {"repositories": [{"id": True}]},
            {"repositories": None},
            {"repositories": {"id": 900002}},
        )
        for override in cases:
            with self.subTest(override=list(override)):
                self.transport.override = override
                source = self.source()
                with self.assertRaises(app_token.TokenFailure):
                    source.token()
                self.assertIn("cached=False", repr(source))
        self.transport.override = None
        source = self.source()
        source.token()
        self.clock.now = NOW + 4000
        self.transport.error = publisher.PublisherFailure("GitHub API request failed")
        with self.assertRaisesRegex(app_token.TokenFailure, "exchange failed"):
            source.token()
        self.assertIn("cached=False", repr(source))

    def test_signer_failures_fail_closed(self):
        source = app_token.open_token_source(self.config, self.checkout, self.transport,
                                             clock=self.clock)  # default signer
        with self.assertRaisesRegex(app_token.TokenFailure, "Owner decision pending"):
            source.token()
        self.assertEqual(self.transport.calls, [])

        class Short:
            def sign(self, data):
                return b"x" * 16

        class Exploding:
            def sign(self, data):
                raise ValueError("synthetic failure")
        for signer in (Short(), Exploding()):
            with self.subTest(signer=type(signer).__name__):
                source = app_token.InstallationTokenSource(
                    self.config, signer, self.transport, self.clock)
                with self.assertRaisesRegex(app_token.TokenFailure, "signing failed"):
                    source.token()
        self.assertEqual(self.transport.calls, [])

        def broken_factory(key):
            raise ValueError("bad key")
        with self.assertRaisesRegex(app_token.TokenFailure, "could not be initialised"):
            app_token.open_token_source(self.config, self.checkout, self.transport,
                                        broken_factory, self.clock)
        os.chmod(self.key_path, 0o644)
        with self.assertRaisesRegex(app_token.TokenFailure, "key is unavailable"):
            self.source()

    def test_secrets_never_reach_logs_argv_env_repr_or_errors(self):
        capture = _Capture()
        root = logging.getLogger()
        previous = root.level
        root.addHandler(capture)
        root.setLevel(logging.DEBUG)
        env_before = dict(os.environ)
        argv_before = list(sys.argv)
        errors: list[BaseException] = []
        texts: list[str] = []
        try:
            with mock.patch.object(subprocess, "Popen",
                                   side_effect=AssertionError("subprocess")), \
                    mock.patch.object(os, "system",
                                      side_effect=AssertionError("system")):
                source = self.source()
                token = source.token()
                credentials = publisher.load_app_credentials(
                    self.config, {}, self.checkout, installation_token=token)
                texts += [repr(source), str(source), repr(credentials),
                          repr(self.signers[0])]
                jwt = self.transport.calls[0][1]
                # A failing refresh after secrets were materialised.
                self.clock.now = NOW + 4000
                self.transport.error = publisher.PublisherFailure(
                    "GitHub API request failed " + jwt)
                for action in (source.token,
                               lambda: app_token.build_app_jwt(
                                   1, _LeakySigner(self.key_body), NOW)):
                    try:
                        action()
                    except app_token.TokenFailure as exc:
                        errors.append(exc)
        finally:
            root.removeHandler(capture)
            root.setLevel(previous)
        self.assertEqual(len(errors), 2)
        for exc in errors:
            self.assertIsNone(exc.__cause__)
            # Not even a suppressed context may retain the JWT or key text.
            self.assertIsNone(exc.__context__)
            texts += [str(exc), repr(exc),
                      "".join(traceback.format_exception(exc))]
        texts += capture.messages
        self.assertTrue(capture.messages)  # the adapter did log its events
        self.assertEqual(dict(os.environ), env_before)
        self.assertEqual(sys.argv, argv_before)
        secrets = (SYNTHETIC_TOKEN, jwt, jwt.split(".")[2],
                   self.key_body.decode("ascii"), self.key_body.decode("ascii")[:24])
        for secret in secrets:
            for text in texts + list(os.environ.values()) + sys.argv:
                self.assertNotIn(secret, text)
        with self.assertRaises(TypeError):
            import pickle
            pickle.dumps(app_token.build_app_jwt(1, SyntheticSigner(b"k"), NOW))

    def test_token_failure_raised_by_a_custom_signer_is_redacted(self):
        key_text = self.key_body.decode("ascii")

        class TokenFailureSigner:
            def sign(self, data):
                raise app_token.TokenFailure("PEM parse error near " + key_text)

        class ForgedMarkerSigner:
            def sign(self, data):
                raise app_token._SignerNotConfigured("backend said " + key_text)
        capture = _Capture()
        logger = logging.getLogger("server_sentinel.review_gate.app_token")
        logger.addHandler(capture)
        try:
            for signer, message in ((TokenFailureSigner(), "App JWT signing failed"),
                                    (ForgedMarkerSigner(),
                                     app_token.UNCONFIGURED_SIGNER_MESSAGE)):
                with self.subTest(signer=type(signer).__name__):
                    source = app_token.InstallationTokenSource(
                        self.config, signer, self.transport, self.clock)
                    with self.assertRaises(app_token.TokenFailure) as caught:
                        source.token()
                    exc = caught.exception
                    self.assertEqual(str(exc), message)
                    self.assertIsNone(exc.__cause__)
                    self.assertIsNone(exc.__context__)
                    self.assertNotIn(key_text[:24],
                                     "".join(traceback.format_exception(exc)))
        finally:
            logger.removeHandler(capture)
        self.assertTrue(capture.messages)
        for text in capture.messages:
            self.assertNotIn(key_text[:24], text)
        self.assertEqual(self.transport.calls, [])

    def test_env_token_path_still_works_and_is_redacted(self):
        credentials = publisher.load_app_credentials(
            self.config, {publisher.TOKEN_ENV: SYNTHETIC_TOKEN}, self.checkout)
        self.assertEqual(credentials.installation_token, SYNTHETIC_TOKEN)
        self.assertNotIn(SYNTHETIC_TOKEN, repr(credentials))
        self.assertNotIn(self.key_body.decode("ascii"), repr(credentials))
        with self.assertRaises(publisher.PublisherFailure):
            publisher.load_app_credentials(self.config, {}, self.checkout,
                                           installation_token="short")


class _LeakySigner:
    """A signer whose failure message would leak key text if propagated."""

    def __init__(self, key_body: bytes):
        self._key_body = key_body

    def sign(self, data):
        raise RuntimeError("cannot parse " + self._key_body.decode("ascii"))


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())
        if record.exc_info:
            self.messages.append("".join(traceback.format_exception(*record.exc_info)))


logging.getLogger("server_sentinel").addHandler(logging.NullHandler())

if __name__ == "__main__":
    unittest.main()
