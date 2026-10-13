"""Issue #10 phase 2 S5b: serving the sign-in shell and the application assets.

Owner decisions D1 and S5-1 .. S5-5 (2026-10-11, 2026-10-14). Synthetic only:
an invented Web build (``tests.web_asset_fakes``), software authenticators, a
temporary SQLite database and an in-process ASGI driver. No browser, socket,
Tailscale or real authenticator is involved, so CSP enforcement, caching and
rendering in a real browser are not verified here (``MANUAL_TEST.md``).
"""

import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch

from app.auth import reservation as reservation_module
from app.auth import web_assets as web_assets_module
from app.auth.human_surface import (
    SESSION_COOKIE, SESSION_PATH, HumanAccess, HumanAccessConfiguration, HumanAccessUnavailable,
    send_generic_denial,
)
from app.auth.invitation_code import InvalidInvitationCode, format_invitation_code, parse_invitation_code
from app.auth.model import Permission
from app.auth.passkeys import PasskeyCeremonies
from app.auth.reservation import DAILY_SECONDS
from app.auth.web_assets import APP_CSP, SHELL_CSP, WebAssets, WebAssetsUnavailable
from app.main import create_app
from app.settings import ConfigurationError, Settings
from app.storage.database import Database

from tests.test_human_surface import (
    EXPOSED, LAN, LOOPBACK, OTHER_LOGIN, UPSTREAM, VIEWER, HumanSurfaceFixture, call, status,
)
from tests.test_hostname_reservation import HOST, Resolver
from tests.web_asset_fakes import APP, SHELL, manifest_for, write_build


ORIGIN = f"https://{HOST}"
SHELL_ROUTES = (("/", "index.html"), ("/s.js", "s.js"), ("/s.css", "s.css"))
APP_ROUTES = (("/app/", "index.html"), ("/app/app.js", "app.js"), ("/app/app.css", "app.css"),
              ("/app/icon.svg", "icon.svg"), ("/app/synthetic-license.txt", "synthetic-license.txt"),
              ("/app/app.js.LEGAL.txt", "app.js.LEGAL.txt"),
              ("/app/synthetic-LICENSE.txt", "synthetic-LICENSE.txt"))
TYPES = {"html": b"text/html; charset=utf-8", "js": b"text/javascript; charset=utf-8",
         "css": b"text/css; charset=utf-8", "svg": b"image/svg+xml",
         "txt": b"text/plain; charset=utf-8"}


def expected_headers(name, body, csp):
    return [
        (b"content-type", TYPES[name.rpartition(".")[2]]),
        (b"content-length", str(len(body)).encode()),
        (b"cache-control", b"no-store"),
        (b"x-content-type-options", b"nosniff"),
        (b"referrer-policy", b"no-referrer"),
        (b"cross-origin-opener-policy", b"same-origin"),
        (b"cross-origin-resource-policy", b"same-origin"),
        (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
        (b"content-security-policy", csp.encode()),
    ]


async def generic_denial():
    """The unknown-route denial, straight from the one denial function."""
    sent = []

    async def send(message):
        sent.append(message)

    await send_generic_denial(send)
    return sent


async def call_raw(application, path, raw_path, *, cookie=None):
    """A GET whose ``raw_path`` differs from its decoded ``path``."""
    headers = [(b"host", HOST.encode()), (b"tailscale-user-login", VIEWER.encode())]
    if cookie is not None:
        headers.append((b"cookie", cookie.encode()))
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "scheme": "http",
             "method": "GET", "path": path, "raw_path": raw_path, "query_string": b"",
             "root_path": "", "headers": headers, "client": LOOPBACK, "server": UPSTREAM}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await application(scope, receive, send)
    return sent


# Header variants a browser or a client may send; none may change a byte.
REQUEST_VARIANTS = (
    (),
    ((b"accept", b"text/html"),),
    ((b"accept", b"*/*"), (b"accept-language", b"en-US,en;q=0.5")),
    ((b"accept-encoding", b"gzip, br"),),
    ((b"if-none-match", b'"synthetic"'), (b"if-modified-since", b"Thu, 01 Jan 2026 00:00:00 GMT")),
    ((b"range", b"bytes=0-3"),),
    ((b"user-agent", b"synthetic-agent/1"), (b"referer", ORIGIN.encode() + b"/")),
    ((b"sec-fetch-mode", b"navigate"), (b"sec-fetch-site", b"none"), (b"sec-fetch-dest", b"document")),
)


class WebAssetFixture(HumanSurfaceFixture):
    def session_times(self):
        with closing(self.database.connect()) as connection:
            return [tuple(row) for row in connection.execute(
                "SELECT id, last_seen_at_us, idle_expires_at_us, invalidated_at_us FROM access_sessions"
                " ORDER BY id").fetchall()]

    def audit_rows(self):
        return self.count("SELECT count(*) FROM audit_events")


class ShellTests(WebAssetFixture):
    async def test_shell_is_byte_identical_for_every_requester(self):
        owner, owner_key, _ = self.enroll(owner=True)
        owner_cookie = await self.sign_in(owner_key)
        viewer, viewer_key, _ = self.enroll((Permission.LIVE_VIEW,))
        viewer_cookie = await self.sign_in(viewer_key)
        revoked, revoked_key, _ = self.enroll((Permission.RECORDINGS_VIEW,))
        revoked_cookie = await self.sign_in(revoked_key)
        self.store.revoke_principal(revoked.id)
        self.enroll()  # invited and enrolled, never signed in
        expiring, expiring_key, _ = self.enroll()
        expired_cookie = await self.sign_in(expiring_key)
        cookies = (None, owner_cookie, viewer_cookie, revoked_cookie, expired_cookie,
                   SESSION_COOKIE + "=" + "A" * 43, SESSION_COOKIE + "=forged", "other=1",
                   f"{viewer_cookie}; {owner_cookie}")
        baselines = {}
        for path, name in SHELL_ROUTES:
            baseline = await call(self.surface, "GET", path, origin=None)
            self.assertEqual(status(baseline), 200)
            self.assertEqual(baseline[1]["body"], SHELL[name])
            baselines[path] = baseline
        self.ceremony_clock.advance(minutes=31)  # every session above is now expired
        for path, _ in SHELL_ROUTES:
            for identity in (VIEWER, OTHER_LOGIN, "synthetic-unknown@example.invalid"):
                for cookie in cookies:
                    for origin in (None, ORIGIN):
                        for variant in REQUEST_VARIANTS:
                            with self.subTest(path=path, identity=identity, cookie=cookie, origin=origin,
                                              variant=variant):
                                result = await call(self.surface, "GET", path, identity=identity,
                                                    cookie=cookie, origin=origin, headers=variant)
                                self.assertEqual(result, baselines[path])

    async def test_shell_headers_are_exactly_the_fixed_list(self):
        for path, name in SHELL_ROUTES:
            with self.subTest(path=path):
                result = await call(self.surface, "GET", path, origin=None)
                self.assertEqual(len(result), 2)
                self.assertEqual(result[0], {"type": "http.response.start", "status": 200,
                                             "headers": expected_headers(name, SHELL[name], SHELL_CSP)})
                self.assertEqual(result[1], {"type": "http.response.body", "body": SHELL[name]})
                names = {key for key, _ in result[0]["headers"]}
                for absent in (b"set-cookie", b"etag", b"last-modified", b"server", b"date",
                               b"content-encoding", b"accept-ranges", b"vary", b"x-powered-by"):
                    self.assertNotIn(absent, names)
        # Exactly web/scripts/policy.mjs SHELL_CSP (S5a, PR #246).
        self.assertEqual(SHELL_CSP, "default-src 'none'; script-src 'self'; style-src 'self'; "
                                    "connect-src 'self'; img-src 'none'; font-src 'none'; "
                                    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
                                    "require-trusted-types-for 'script'; trusted-types 'none'")

    async def test_shell_takes_no_session_sqlite_lock_or_limiter(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        admitted, before = self.admission.admitted, self.database.path.read_bytes()
        times = self.session_times()
        refuse = AssertionError("the shell must not consult this")
        with patch.object(self.store, "session_may_be_current", side_effect=refuse), \
                patch.object(self.store, "authorize_request", side_effect=refuse), \
                patch.object(self.access.gate, "admit", side_effect=refuse), \
                patch.object(self.access.gate, "epoch", side_effect=refuse), \
                patch.object(self.check, "admit", side_effect=refuse), \
                patch.object(Database, "connect", side_effect=refuse), \
                patch.object(self.access.rate_limiter, "allow", side_effect=refuse), \
                patch.object(self.access.redemption_limiter, "allow", side_effect=refuse), \
                patch.object(self.access.step_up_limiter, "allow", side_effect=refuse), \
                patch.object(self.access.admin_limiter, "allow", side_effect=refuse):
            for _ in range(50):
                for path, name in SHELL_ROUTES:
                    result = await call(self.surface, "GET", path, cookie=cookie)
                    self.assertEqual(result[1]["body"], SHELL[name])
        self.assertEqual(self.admission.admitted, admitted)
        self.assertEqual(self.database.path.read_bytes(), before)
        self.assertEqual(self.session_times(), times)

    async def test_gate_failures_equal_the_unknown_route_denial(self):
        expected = await generic_denial()
        self.assertEqual(expected, await call(self.surface, "GET", "/no-such-route"))
        cases = (
            dict(host="other.example.invalid"), dict(host=None), dict(host=HOST + ":444"),
            dict(origin="https://other.example.invalid"), dict(origin="null"),
            dict(origin="http://" + HOST),
            dict(client=LAN), dict(server=("192.0.2.1", 8080)), dict(client=None),
            dict(identity=None), dict(identity="two,people@example.invalid"),
            dict(identity="=?utf-8?q?x?=@example.invalid"),
            dict(headers=((b"tailscale-user-login", OTHER_LOGIN.encode()),)),
            dict(headers=((b"host", HOST.encode()),)),
        )
        for path, _ in SHELL_ROUTES + APP_ROUTES:
            for case in cases:
                with self.subTest(path=path, case=case):
                    self.assertEqual(await call(self.surface, "GET", path, **case), expected)

    async def test_unadmitted_closed_stopped_and_forked_compositions_deny_the_shell(self):
        expected = await generic_denial()
        # Storage admission not bound.
        with patch.object(self.access, "_storage_admission", None):
            self.assertFalse(self.access.storage_admitted)
            for path, _ in SHELL_ROUTES:
                self.assertEqual(await call(self.surface, "GET", path), expected)
        # A fork child of the gate's process (pid guard).
        with patch.object(self.check, "_gate_pid", reservation_module.os.getpid() + 1):
            for path, _ in SHELL_ROUTES:
                self.assertEqual(await call(self.surface, "GET", path), expected)
        self.assertEqual(status(await call(self.surface, "GET", "/")), 200)
        # Closed reservation verdict.
        self.files.files["tcp"] = EXPOSED
        self.clock.value += DAILY_SECONDS
        self.assertFalse(self.check.tick().open)
        for path, _ in SHELL_ROUTES:
            self.assertEqual(await call(self.surface, "GET", path), expected)

    async def test_a_stopped_composition_denies_the_shell(self):
        expected = await generic_denial()
        self.assertEqual(status(await call(self.surface, "GET", "/")), 200)
        self.access.stop()
        for path, _ in SHELL_ROUTES:
            self.assertEqual(await call(self.surface, "GET", path), expected)

    async def test_path_and_query_variants_are_denied(self):
        _, authenticator, _ = self.enroll(owner=True)
        cookie = await self.sign_in(authenticator)
        expected = await generic_denial()
        for path in ("/S.js", "/s.JS", "/s.js/", "/s.css/", "//", "//s.js", "/./s.js", "/app/../s.js",
                     "/index.html", "/shell/index.html", "/shell/s.js", "/s.js.map", "/s", "/s.mjs",
                     "/manifest.json", "/app", "/app//", "/app/x", "/app/index.html", "/app/App.js",
                     "/app//app.js", "/app/./app.js", "/app/app.js/", "/app/.app.js",
                     "/app/manifest.json", "/app/shell/s.js", "/app/s.js", "/app/" + "a" * 65, "/app/APP.JS", "/app/app.js.legal.txt",
                     "/assets/app.js", "/favicon.ico", "/sw.js", "/app/app.js.map"):
            for value in (None, cookie):
                with self.subTest(path=path, cookie=value):
                    self.assertEqual(await call(self.surface, "GET", path, cookie=value), expected)
        for path, raw in (("/s.js", b"/%73.js"), ("/s.js", b"/s%2Ejs"), ("/app/app.js", b"/app%2Fapp.js"),
                          ("/", b"/%2F"), ("/app/", b"/app%2F"), ("/s.css", b"/S.css")):
            with self.subTest(raw=raw):
                self.assertEqual(await call_raw(self.surface, path, raw, cookie=cookie), expected)
        # Queries follow the route table's strict allowlist: no asset route
        # accepts a parameter; an empty query string is no parameter.
        for path, _ in SHELL_ROUTES + APP_ROUTES:
            for query in (b"x", b"x=1", b"v=1", b"=", b"&"):
                with self.subTest(path=path, query=query):
                    self.assertEqual(await call(self.surface, "GET", path, cookie=cookie, query=query),
                                     expected)
            self.assertEqual(status(await call(self.surface, "GET", path, cookie=cookie, query=b"")), 200)

    async def test_other_methods_and_websockets_are_denied(self):
        _, authenticator, _ = self.enroll(owner=True)
        cookie = await self.sign_in(authenticator)
        expected = await generic_denial()
        for path, _ in SHELL_ROUTES + APP_ROUTES:
            for method in ("HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH", "TRACE"):
                with self.subTest(path=path, method=method):
                    self.assertEqual(await call(self.surface, method, path, cookie=cookie), expected)
            self.assertEqual(await call(self.surface, "GET", path, cookie=cookie, kind="websocket"),
                             [{"type": "websocket.close", "code": 1008}])

    async def test_a_change_on_disk_after_loading_is_never_served(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        for directory, contents in (("shell", SHELL), ("app", APP)):
            for name in contents:
                (self.assets_dir / directory / name).write_bytes(b"replaced on disk\n")
        (self.assets_dir / "app" / "new.js").write_bytes(b"added on disk\n")
        (self.assets_dir / "manifest.json").write_text("{}")
        for path, name in SHELL_ROUTES:
            self.assertEqual((await call(self.surface, "GET", path))[1]["body"], SHELL[name])
        for path, name in APP_ROUTES:
            self.assertEqual((await call(self.surface, "GET", path, cookie=cookie))[1]["body"], APP[name])
        self.assertEqual(await call(self.surface, "GET", "/app/new.js", cookie=cookie), await generic_denial())


class ApplicationAssetTests(WebAssetFixture):
    async def test_any_active_session_gets_the_application_including_no_permission(self):
        for permissions, owner in (((), False), ((Permission.LIVE_VIEW,), False),
                                   ((Permission.RECORDINGS_VIEW,), False), ((), True)):
            _, authenticator, _ = self.enroll(permissions, owner=owner)
            cookie = await self.sign_in(authenticator)
            for path, name in APP_ROUTES:
                for origin in (None, ORIGIN):
                    with self.subTest(permissions=permissions, owner=owner, path=path, origin=origin):
                        result = await call(self.surface, "GET", path, cookie=cookie, origin=origin)
                        self.assertEqual(result, [
                            {"type": "http.response.start", "status": 200,
                             "headers": expected_headers(name, APP[name], APP_CSP)},
                            {"type": "http.response.body", "body": APP[name]}])

    def test_application_policy_is_the_web_meta_policy_with_frame_ancestors(self):
        # Exactly web/scripts/policy.mjs APP_CSP (S5a, PR #246): the former
        # meta policy plus the frame-ancestors a meta element cannot carry.
        self.assertEqual(APP_CSP, "default-src 'none'; script-src 'self'; style-src 'self'; "
                                  "connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; "
                                  "form-action 'none'; frame-ancestors 'none'")

    async def test_unknown_names_are_the_generic_denial_for_a_valid_session(self):
        _, authenticator, _ = self.enroll(owner=True)
        cookie = await self.sign_in(authenticator)
        expected = await generic_denial()
        for name in ("missing.js", "index.html", "app.js.map", "a", "0", "app-js", "icon.svg.txt",
                     "App.js", "APP.JS", "app.js.legal.txt", "Index.html"):
            with self.subTest(name=name):
                self.assertEqual(await call(self.surface, "GET", "/app/" + name, cookie=cookie), expected)

    async def test_application_is_denied_without_a_current_session(self):
        expected = await generic_denial()
        principal, authenticator, credential = self.enroll()
        cookie = await self.sign_in(authenticator)
        variants = (None, SESSION_COOKIE + "=", SESSION_COOKIE + "=" + "A" * 43,
                    SESSION_COOKIE + "=" + base64_token(), f"{cookie}; {cookie}",
                    "session=" + cookie.split("=", 1)[1])
        for path, _ in APP_ROUTES:
            for value in variants:
                with self.subTest(path=path, cookie=value):
                    self.assertEqual(await call(self.surface, "GET", path, cookie=value), expected)
            # Binding mismatch: the cookie under another proxy login.
            with self.subTest(path=path, binding="other login"):
                self.assertEqual(await call(self.surface, "GET", path, cookie=cookie, identity=OTHER_LOGIN),
                                 expected)

    async def test_expired_revoked_and_generation_stale_sessions_are_denied(self):
        expected = await generic_denial()

        async def signed_in(permissions=(Permission.LIVE_VIEW,)):
            principal, authenticator, credential = self.enroll(permissions)
            cookie = await self.sign_in(authenticator)
            self.assertEqual(status(await call(self.surface, "GET", "/app/", cookie=cookie)), 200)
            return principal, credential, cookie

        principal, _, cookie = await signed_in()
        self.store.revoke_principal(principal.id)
        self.assertEqual(await call(self.surface, "GET", "/app/", cookie=cookie), expected)

        principal, credential, cookie = await signed_in()
        with self.store._transaction(write=True) as connection:
            handle = connection.execute("SELECT handle FROM access_credentials WHERE credential_id=?",
                                        (credential.credential_id,)).fetchone()[0]
            self.store.revoke_credential_on(connection, principal.id, handle, at=self.ceremony_clock())
        self.assertEqual(await call(self.surface, "GET", "/app/app.js", cookie=cookie), expected)

        _, _, cookie = await signed_in()
        with closing(self.database.connect()) as connection, connection:
            connection.execute("UPDATE access_deployment_state SET authorization_generation ="
                               " authorization_generation + 1 WHERE singleton=1")
        self.assertEqual(await call(self.surface, "GET", "/app/", cookie=cookie), expected)

        _, _, cookie = await signed_in()
        self.ceremony_clock.advance(hours=13)  # past the absolute lifetime
        self.assertEqual(await call(self.surface, "GET", "/app/", cookie=cookie), expected)

    async def test_asset_requests_never_extend_the_idle_expiry(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        before = self.session_times()
        for minutes in (5, 10, 10, 4):  # 29 minutes after sign-in
            self.ceremony_clock.advance(minutes=minutes)
            for path, _ in APP_ROUTES:
                self.assertEqual(status(await call(self.surface, "GET", path, cookie=cookie)), 200)
        self.assertEqual(self.session_times(), before)
        self.ceremony_clock.advance(minutes=2)  # 31 minutes: idle expired
        expected = await generic_denial()
        for path, _ in APP_ROUTES:
            self.assertEqual(await call(self.surface, "GET", path, cookie=cookie), expected)
        self.assertEqual(await call(self.surface, "GET", SESSION_PATH, cookie=cookie), expected)

    async def test_a_session_read_still_extends_while_assets_do_not(self):
        # Control for the test above: the same fixture does extend on the
        # session self-description, so the assets' touch=False is what holds.
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        before = self.session_times()
        self.ceremony_clock.advance(minutes=5)
        self.assertEqual(status(await call(self.surface, "GET", SESSION_PATH, cookie=cookie)), 200)
        self.assertNotEqual(self.session_times(), before)

    async def test_denied_asset_requests_write_nothing(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        admitted, before = self.admission.admitted, self.database.path.read_bytes()
        expected = await generic_denial()
        for path, _ in APP_ROUTES:
            for value in (None, SESSION_COOKIE + "=" + base64_token(), SESSION_COOKIE + "=x"):
                self.assertEqual(await call(self.surface, "GET", path, cookie=value), expected)
            self.assertEqual(await call(self.surface, "GET", path, cookie=cookie, query=b"x=1"), expected)
            self.assertEqual(await call(self.surface, "HEAD", path, cookie=cookie), expected)
        self.assertEqual(self.admission.admitted, admitted)
        self.assertEqual(self.database.path.read_bytes(), before)

    async def test_close_between_epoch_and_admit_denies_the_asset(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        before = self.session_times()
        original = self.check.epoch
        resolver = self.check._resolver

        def close_after_epoch():
            epoch = original()
            resolver.answer = OSError("synthetic resolver failure")
            self.clock.value += DAILY_SECONDS
            self.assertFalse(self.check.tick().open)
            return epoch

        expected = await generic_denial()
        with patch.object(self.check, "epoch", side_effect=close_after_epoch):
            self.assertEqual(await call(self.surface, "GET", "/app/", cookie=cookie), expected)
        self.assertEqual(self.session_times(), before)
        resolver.answer = Resolver().answer
        self.clock.value += DAILY_SECONDS
        self.assertTrue(self.check.tick().open)
        self.assertEqual(status(await call(self.surface, "GET", "/app/", cookie=cookie)), 200)

    async def test_revocation_between_epoch_and_admit_denies_the_asset(self):
        principal, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        original = self.check.epoch

        def revoke_after_epoch():
            epoch = original()
            self.store.revoke_principal(principal.id)
            return epoch

        with patch.object(self.check, "epoch", side_effect=revoke_after_epoch):
            self.assertEqual(await call(self.surface, "GET", "/app/app.js", cookie=cookie),
                             await generic_denial())

    async def test_stop_between_epoch_and_admit_denies_the_asset(self):
        _, authenticator, _ = self.enroll()
        cookie = await self.sign_in(authenticator)
        original = self.check.epoch

        def stop_after_epoch():
            epoch = original()
            self.access.stop()
            return epoch

        with patch.object(self.check, "epoch", side_effect=stop_after_epoch):
            self.assertEqual(await call(self.surface, "GET", "/app/", cookie=cookie), await generic_denial())


def base64_token():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


class LoaderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory = self.root / "build"

    def refused(self, directory):
        with self.assertRaises(WebAssetsUnavailable) as raised:
            WebAssets.load(directory)
        self.assertEqual(str(raised.exception), "web assets are unavailable")

    def test_a_valid_build_is_frozen_in_memory(self):
        assets = WebAssets.load(write_build(self.directory))
        self.assertEqual(assets.directory, self.directory.resolve())
        self.assertEqual(assets.shell_index.body, SHELL["index.html"])
        self.assertEqual(assets.shell_script.body, SHELL["s.js"])
        self.assertEqual(assets.shell_style.body, SHELL["s.css"])
        self.assertEqual(assets.app_index.body, APP["index.html"])
        for name in APP:
            if name != "index.html":
                self.assertEqual(assets.app_file(name).body, APP[name])
                self.assertEqual(assets.app_file(name).sha256, hashlib.sha256(APP[name]).hexdigest())
        for name in ("index.html", "missing.js", "../shell/s.js", "App.js", "app.js.legal.txt", "", None, 1,
                     "a" * 65):
            self.assertIsNone(assets.app_file(name))
        self.assertIsInstance(assets.shell_index.body, bytes)
        with self.assertRaises(TypeError):
            assets._app["x"] = assets.app_index

    def test_manifest_types_must_be_exactly_the_build_content_types(self):
        for name, kind in (("shell/s.js", "text/javascript"), ("shell/index.html", "text/html"),
                           ("app/icon.svg", "image/svg+xml; charset=utf-8"),
                           ("app/app.css", "TEXT/CSS; charset=utf-8"), ("app/app.js", "text/javascript;charset=utf-8")):
            with self.subTest(name=name, kind=kind):
                document = manifest_for(SHELL, APP)
                document["files"][name]["type"] = kind
                self.refused(write_build(self.root / secrets.token_hex(4), manifest=document))

    def test_only_the_loader_builds_an_asset_set(self):
        with self.assertRaises(WebAssetsUnavailable):
            WebAssets(object(), self.directory, {}, {})

    def test_directory_must_be_an_absolute_existing_path(self):
        write_build(self.directory)
        for value in (None, str(self.directory), Path("relative/build"), self.root / "missing",
                      self.directory / "manifest.json"):
            with self.subTest(value=value):
                self.refused(value)

    def test_missing_files_are_refused(self):
        for relative in ("manifest.json", "shell/index.html", "shell/s.js", "shell/s.css",
                         "app/index.html", "app/app.js"):
            with self.subTest(missing=relative):
                directory = write_build(self.root / ("missing-" + relative.replace("/", "-")))
                (directory / relative).unlink()
                self.refused(directory)

    def test_shell_and_app_indexes_are_required_in_the_manifest(self):
        for shell, app in ((dict(SHELL, **{"extra.js": b"x"}), APP),
                           ({k: v for k, v in SHELL.items() if k != "s.css"}, APP),
                           (SHELL, {k: v for k, v in APP.items() if k != "index.html"})):
            with self.subTest(shell=sorted(shell), app=sorted(app)):
                directory = self.root / secrets.token_hex(4)
                write_build(directory, shell=shell, app=app)
                self.refused(directory)

    def test_a_modified_or_resized_file_is_refused(self):
        for relative, body in (("shell/s.js", SHELL["s.js"][:-1] + b"!"), ("app/app.js", APP["app.js"] + b"x"),
                               ("app/index.html", b""), ("shell/index.html", SHELL["index.html"][:-1])):
            with self.subTest(relative=relative, size=len(body)):
                directory = write_build(self.root / secrets.token_hex(4))
                (directory / relative).write_bytes(body)
                self.refused(directory)

    def test_a_manifest_digest_or_size_that_does_not_match_is_refused(self):
        for field, value in (("sha256", "0" * 64), ("size", 1), ("sha256", "A" * 64), ("sha256", "0" * 63),
                             ("size", -1), ("size", True), ("size", 1.0), ("size", "3"),
                             ("type", "text/plain"), ("type", "application/javascript"), ("type", None)):
            with self.subTest(field=field, value=value):
                document = manifest_for(SHELL, APP)
                document["files"]["shell/s.js"][field] = value
                self.refused(write_build(self.root / secrets.token_hex(4), manifest=document))

    def test_extra_files_and_directories_are_refused(self):
        for relative in ("extra.txt", "shell/extra.js", "app/unlisted.js", "assets/app.js", ".hidden"):
            with self.subTest(extra=relative):
                directory = write_build(self.root / secrets.token_hex(4))
                (directory / relative).parent.mkdir(exist_ok=True)
                (directory / relative).write_bytes(b"synthetic\n")
                self.refused(directory)
        directory = write_build(self.root / "nested")
        (directory / "app" / "nested").mkdir()
        self.refused(directory)

    def test_nested_or_unreachable_names_and_unknown_extensions_are_refused(self):
        for name in ("app.js.map", "data.json", "icon.png", "font.woff2", "noext",
                     ".hidden.js", "-x.js", "a" * 62 + ".js", "x.mjs", "x.wasm", "x.html.gz"):
            with self.subTest(name=name):
                directory = self.root / secrets.token_hex(4)
                self.refused(write_build(directory, app=dict(APP, **{name: b"synthetic\n"})))
        document = manifest_for(SHELL, APP)
        document["files"]["app/sub/x.js"] = document["files"].pop("app/app.js")
        self.refused(write_build(self.root / "sub", manifest=document))
        for path in ("other/x.js", "x.js", "/shell/s.js", "shell//s.js", "shell/../app/x.js"):
            with self.subTest(path=path):
                document = manifest_for(SHELL, APP)
                document["files"][path] = document["files"]["app/app.js"]
                self.refused(write_build(self.root / secrets.token_hex(4), manifest=document))

    def test_symlinks_and_special_files_are_refused(self):
        target = self.root / "outside.js"
        target.write_bytes(APP["app.js"])
        directory = write_build(self.root / "link-file")
        (directory / "app" / "app.js").unlink()
        os.symlink(target, directory / "app" / "app.js")
        self.refused(directory)
        directory = write_build(self.root / "link-dir")
        other = write_build(self.root / "other-build")
        os.rename(directory / "shell", self.root / "moved-shell")
        os.symlink(other / "shell", directory / "shell")
        self.refused(directory)
        directory = write_build(self.root / "link-manifest")
        os.rename(directory / "manifest.json", self.root / "moved-manifest.json")
        os.symlink(self.root / "moved-manifest.json", directory / "manifest.json")
        self.refused(directory)
        directory = write_build(self.root / "fifo")
        (directory / "app" / "app.js").unlink()
        os.mkfifo(directory / "app" / "app.js")
        self.refused(directory)

    def test_the_configured_directory_may_be_a_symlink_the_deployment_controls(self):
        build = write_build(self.root / "release-build")
        link = self.root / "current"
        os.symlink(build, link)
        self.assertEqual(WebAssets.load(link).directory, build.resolve())

    def test_size_count_and_manifest_caps_are_enforced(self):
        with patch.object(web_assets_module, "MAX_FILE_BYTES", len(APP["index.html"]) - 1):
            self.refused(write_build(self.root / "file-cap"))
        with patch.object(web_assets_module, "MAX_TOTAL_BYTES", sum(map(len, APP.values())) - 1):
            self.refused(write_build(self.root / "total-cap"))
        with patch.object(web_assets_module, "MAX_FILES", len(SHELL) + len(APP) - 1):
            self.refused(write_build(self.root / "count-cap"))
        with patch.object(web_assets_module, "MAX_MANIFEST_BYTES", 64):
            self.refused(write_build(self.root / "manifest-cap"))

    def test_malformed_manifests_are_refused(self):
        valid = manifest_for(SHELL, APP)
        files = json.dumps(valid["files"])
        for text in ("", "[]", "null", "{}", '{"files": []}', '{"files": {}, "version": 1}',
                     '{"files": ' + files + ', "files": ' + files + '}',
                     '{"files": ' + files[:-1] + ', "shell/s.js": {}}',
                     json.dumps({"files": dict(valid["files"], **{"shell/s.js": dict(
                         valid["files"]["shell/s.js"], extra=1)})}),
                     json.dumps({"files": dict(valid["files"], **{"shell/s.js": {"sha256": "0" * 64}})}),
                     '{"files": NaN}', "\xff"):
            with self.subTest(text=text[:40]):
                directory = write_build(self.root / secrets.token_hex(4))
                (directory / "manifest.json").write_bytes(text.encode("utf-8", "surrogateescape")
                                                          if text != "\xff" else b"\xff")
                self.refused(directory)

    def test_a_body_that_is_not_utf8_is_refused(self):
        self.refused(write_build(self.directory, app=dict(APP, **{"app.js": b"\xff\xfe"})))


class CompositionTests(WebAssetFixture):
    def test_human_access_requires_a_verified_asset_set(self):
        for assets in (None, object(), self.assets_dir, {"shell": {}}):
            with self.subTest(assets=type(assets).__name__), self.assertRaises(HumanAccessUnavailable):
                HumanAccess(HumanAccessConfiguration(enabled=True), store=self.store,
                            ceremonies=PasskeyCeremonies(self.store, self.rp, session_gate=self.check),
                            reservation=self.check, assets=assets)
        self.assertIs(self.access.assets, self.assets)

    def test_create_app_requires_the_settings_asset_directory(self):
        other = write_build(self.temporary / "other-build")
        for settings in (Settings(self.temporary), Settings(self.temporary, web_assets_dir=other),
                         Settings(self.temporary, web_assets_dir=self.temporary / "missing")):
            with self.subTest(settings=settings.web_assets_dir), self.assertRaises(TypeError):
                create_app(settings, database=self.database, human_access=self.access,
                           storage_reservation=self.admission)
        create_app(self.settings(), database=self.database, human_access=self.access,
                   storage_reservation=self.admission)

    def test_settings_validate_the_asset_directory(self):
        for value in ("/absolute/as/text", Path("relative")):
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                Settings(self.temporary, web_assets_dir=value)
        self.assertIsNone(Settings(self.temporary).web_assets_dir)


class ShellInvitationCodeContractTests(unittest.TestCase):
    """The shell's code normalization must end in what the server parses.

    S5a (PR #246) left this Python side of the cross-check to S5b: the
    vectors and the normalization table are copied from
    ``web/tests/signin.test.mjs``. The server parses only the canonical
    display form, so the shell must normalize every accepted spelling to it.
    """

    SERVER_VECTORS = (
        ("0000000000000000000000000000000000000000", "0000-0000-0000-0000-0000-0000-0000-0000"),
        ("ffffffffffffffffffffffffffffffffffffffff", "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ"),
        ("000102030405060708090a0b0c0d0e0f10111213", "000G-40R4-0M30-E209-185G-R38E-1W81-24GK"),
        ("c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadb", "S34W-NJYC-SQ7C-ZM6H-TB9X-9NEP-TZCD-KPPV"),
    )
    CANONICAL = "S34W-NJYC-SQ7C-ZM6H-TB9X-9NEP-TZCD-KPPV"
    # Inputs the shell normalizes (to the right-hand side) or refuses (None).
    NORMALIZATION = (
        (CANONICAL, CANONICAL),
        ("s34w-njyc-sq7c-zm6h-tb9x-9nep-tzcd-kppv", CANONICAL),
        ("S34WNJYCSQ7CZM6HTB9X9NEPTZCDKPPV", CANONICAL),
        ("  S34W NJYC SQ7C ZM6H TB9X 9NEP TZCD KPPV  ", CANONICAL),
        ("S3-4WN-JYCSQ7CZM6HTB9X9NEPTZCD-KPP-V", CANONICAL),
        ("S34W\tNJYC\nSQ7C ZM6H TB9X 9NEP TZCD KPPV", CANONICAL),
        ("\uff33\uff13\uff14\uff37\uff0d\uff2e\uff2a\uff39\uff23\u3000\uff33\uff31\uff17\uff23"
         "\uff0d\uff3a\uff2d\uff16\uff28\uff0d\uff34\uff22\uff19\uff38\uff0d\uff19\uff2e\uff25"
         "\uff30\uff0d\uff34\uff3a\uff23\uff24\uff0d\uff2b\uff30\uff30\uff36", CANONICAL),
        ("S34W\u30fc NJYC\u2010SQ7C\u2013ZM6H\u2014TB9X\u22129NEP-TZCD-KPPV", CANONICAL),
        ("OOOO-oooo-0000-0000-0000-0000-0000-0000", "0000-0000-0000-0000-0000-0000-0000-0000"),
        ("IiLl-1111-0000-0000-0000-0000-0000-0000", "1111-1111-0000-0000-0000-0000-0000-0000"),
        ("S34W-NJYC-SQ7C-ZM6H-TB9X-9NEP-TZCD-KPPU", None),
        ("S34W-NJYC-SQ7C-ZM6H-TB9X-9NEP-TZCD-KPP", None),
        ("S34W-NJYC-SQ7C-ZM6H-TB9X-9NEP-TZCD-KPPVV", None),
        ("S34W-NJYC-SQ7C-ZM6H-TB9X-9NEP-TZCD-KPP*", None),
        ("S34W_NJYC_SQ7C_ZM6H_TB9X_9NEP_TZCD_KPPV", None),
        ("S34W.NJYC.SQ7C.ZM6H.TB9X.9NEP.TZCD.KPPV", None),
        ("", None),
        ("-" * 40, None),
        ("S" * 300, None),
        ("\u00c434W-NJYC-SQ7C-ZM6H-TB9X-9NEP-TZCD-KPPV", None),
    )

    def test_the_shell_vectors_are_the_server_encoding(self):
        for hex_value, display in self.SERVER_VECTORS:
            with self.subTest(display=display):
                self.assertEqual(format_invitation_code(bytes.fromhex(hex_value)), display)
                self.assertEqual(parse_invitation_code(display), bytes.fromhex(hex_value))

    def test_every_normalized_spelling_is_what_the_server_parses(self):
        for typed, normalized in self.NORMALIZATION:
            with self.subTest(typed=typed):
                if normalized is None:
                    # Refused by the shell; never canonical for the server either.
                    with self.assertRaises(InvalidInvitationCode):
                        parse_invitation_code(typed)
                    continue
                self.assertEqual(format_invitation_code(parse_invitation_code(normalized)), normalized)
                if typed != normalized:
                    # The server accepts only the canonical form, so the
                    # shell's normalization is required, not cosmetic.
                    with self.assertRaises(InvalidInvitationCode):
                        parse_invitation_code(typed)


if __name__ == "__main__":
    unittest.main()
