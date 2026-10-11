"""Issue #10 phase 2 S2: invitation redemption routes and the code format.

Synthetic only: software authenticators (``webauthn_fakes``), synthetic
``/proc/net`` rows, a temporary SQLite database and the in-process ASGI
driver of ``test_human_surface``. Every identity is an invented ``.invalid``
value and every code is generated in the test process. Mock only: no
browser, Tailscale, proxy or real authenticator is involved.
"""

import asyncio
from datetime import timedelta
import json
import logging
import secrets
import unittest
from unittest.mock import patch

from app.auth.bootstrap_cli import bootstrap_owner
from app.auth.human_surface import (
    AUTHENTICATION_OPTIONS_PATH, REGISTRATION_OPTIONS_PATH, REGISTRATION_PATH, SESSION_PATH,
    HumanAccess, HumanAccessConfiguration, HumanAccessUnavailable,
)
from app.auth.invitation_code import (
    ALPHABET, CODE_BYTES, DISPLAY_LENGTH, INVITATION_LIFETIME, InvalidInvitationCode,
    format_invitation_code, new_invitation_code, parse_invitation_code,
)
from app.auth.model import Permission
from app.auth.passkeys import PasskeyCeremonies
from app.auth.rate_limit import (
    REDEMPTION_GLOBAL_CAPACITY, REDEMPTION_PER_SOURCE_CAPACITY, REDEMPTION_PER_SOURCE_REFILL_SECONDS,
    SourceRateLimiter, redemption_rate_limiter,
)
from app.auth.store import MAX_REDEMPTION_ATTEMPTS

from tests.test_hostname_reservation import Clock
from tests.test_human_surface import (
    HOST, ORIGIN, OTHER_LOGIN, VIEWER, HumanSurfaceFixture, call, header, payload, status,
)
from tests.webauthn_fakes import SyntheticAuthenticator


REDEEMED = "SELECT count(*) FROM security_admin_audit_records WHERE action='redeem_principal_invitation'"
OPTION_KEYS = ["attestation", "authenticatorSelection", "challenge", "excludeCredentials",
               "pubKeyCredParams", "rp", "timeout", "user"]


class InvitationCodeTests(unittest.TestCase):
    def test_codes_carry_160_random_bits_in_eight_unambiguous_groups(self):
        secret, code = new_invitation_code()
        self.assertEqual(len(secret), CODE_BYTES)
        self.assertGreaterEqual(CODE_BYTES * 8, 128)
        self.assertEqual(len(code), DISPLAY_LENGTH)
        groups = code.split("-")
        self.assertEqual([len(group) for group in groups], [4] * 8)
        self.assertFalse(set("ILOU") & set(code))
        self.assertTrue(set("".join(groups)) <= set(ALPHABET))
        self.assertEqual(parse_invitation_code(code), secret)
        self.assertEqual(format_invitation_code(secret), code)
        self.assertNotEqual(new_invitation_code()[1], code)
        for secret in (bytes(CODE_BYTES), b"\xff" * CODE_BYTES, secrets.token_bytes(CODE_BYTES)):
            self.assertEqual(parse_invitation_code(format_invitation_code(secret)), secret)
        self.assertEqual(INVITATION_LIFETIME, timedelta(hours=24))

    def test_only_the_exact_canonical_form_parses(self):
        _, code = new_invitation_code(lambda size: bytes(range(size)))
        plain = code.replace("-", "")
        for value in (code.lower(), plain, " " + code, code + "\n", code[:-1], code + "0",
                      code.replace("-", " "), code.replace("-", "--", 1), "-" + code[:-1],
                      code[:5] + "I" + code[6:], code[:5] + "O" + code[6:], code[:5] + "L" + code[6:],
                      code[:5] + "U" + code[6:], code[:5] + "٠" + code[6:], code.encode(), None, 7,
                      "", "0" * DISPLAY_LENGTH):
            with self.subTest(value=repr(value)[:20]), self.assertRaises(InvalidInvitationCode) as refused:
                parse_invitation_code(value)
            self.assertNotIn(code, str(refused.exception))
        for secret in (b"", b"x" * 16, b"x" * 21, "x" * 20):
            with self.assertRaises(InvalidInvitationCode):
                format_invitation_code(secret)
        with self.assertRaises(InvalidInvitationCode):
            new_invitation_code(lambda size: b"short")


class RedemptionFixture(HumanSurfaceFixture):
    def setUp(self):
        super().setUp()
        # A roomy limiter unless a test exercises the D4 values themselves.
        self.access.redemption_limiter = SourceRateLimiter(
            per_source_capacity=1000, global_capacity=1000, monotonic=self.limit_clock)

    def invite(self, permissions=(Permission.LIVE_VIEW,), *, lifetime=INVITATION_LIFETIME):
        principal = self.store.invite("Synthetic invitee", permissions)
        secret, code = new_invitation_code()
        self.store.issue_enrollment(principal.id, secret, self.ceremony_clock() + lifetime)
        return principal, code

    async def options(self, code, **options):
        return await call(self.surface, "POST", REGISTRATION_OPTIONS_PATH,
                          body=json.dumps({"code": code}).encode(), **options)

    async def finish(self, code, credential, label=None, **options):
        body = {"code": code, "credential": credential}
        if label is not None:
            body["label"] = label
        return await call(self.surface, "POST", REGISTRATION_PATH, body=json.dumps(body).encode(), **options)

    async def redeem(self, code, authenticator=None, **options):
        authenticator = authenticator or SyntheticAuthenticator()
        begun = await self.options(code)
        self.assertEqual(status(begun), 200)
        credential = authenticator.register(payload(begun), **{"origin": ORIGIN, "rp_id": HOST, **options})
        return authenticator, await self.finish(code, credential)


class RedemptionTests(RedemptionFixture):
    async def test_redemption_registers_one_credential_and_returns_no_application_data(self):
        principal, code = self.invite((Permission.RECORDINGS_VIEW,))
        begun = await self.options(code)
        self.assertEqual(status(begun), 200)
        options = payload(begun)
        # Only what the browser ceremony needs: no camera, recording,
        # timeline, product or deployment data, and never the code.
        self.assertEqual(sorted(options), OPTION_KEYS)
        self.assertEqual(options["rp"], {"id": HOST, "name": HOST})
        self.assertEqual(options["user"]["displayName"], "Synthetic invitee")
        self.assertEqual(options["authenticatorSelection"]["userVerification"], "required")
        self.assertEqual(options["attestation"], "none")
        self.assertNotIn(code, begun[1]["body"].decode())
        self.assertEqual(header(begun, b"set-cookie"), [])
        authenticator = SyntheticAuthenticator()
        finished = await self.finish(code, authenticator.register(options, origin=ORIGIN, rp_id=HOST),
                                     label="Synthetic key")
        self.assertEqual(status(finished), 204)
        self.assertEqual(finished[0]["headers"], [(b"cache-control", b"no-store")])
        self.assertEqual(finished[1]["body"], b"")
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 1)
        self.assertEqual(self.count("SELECT label FROM access_credentials"), "Synthetic key")
        self.assertEqual(self.count(REDEEMED), 1)
        (record,) = [item for item in self.audit.list_records()
                     if item.action.value == "redeem_principal_invitation"]
        self.assertEqual((record.actor_category.value, record.target_logical_id), ("invited_user", principal.id))
        # Redemption granted no session: the person signs in like anyone else.
        self.assertEqual(self.count("SELECT count(*) FROM access_sessions"), 0)
        cookie = await self.sign_in(authenticator)
        session = await call(self.surface, "GET", SESSION_PATH, cookie=cookie)
        self.assertEqual(payload(session)["permissions"], ["recordings:view"])
        # Single use: the same code is now the generic denial.
        self.assertEqual(await self.options(code), await self.denial())

    async def test_console_bootstrap_code_redeems_through_the_same_route_then_signs_in(self):
        # The local command's transaction (no HTTP bootstrap route exists).
        secret, code = new_invitation_code()
        owner, _ = bootstrap_owner(self.store, "Synthetic owner", secret, at=self.ceremony_clock())
        authenticator, finished = await self.redeem(code)
        self.assertEqual(status(finished), 204)
        cookie = await self.sign_in(authenticator)
        session = payload(await call(self.surface, "GET", SESSION_PATH, cookie=cookie))
        self.assertEqual((session["role"], session["permissions"]), ("owner", ["live:view", "recordings:view"]))
        (record,) = [item for item in self.audit.list_records()
                     if item.action.value == "redeem_principal_invitation"]
        self.assertEqual((record.actor_category.value, record.target_logical_id), ("owner", owner))
        self.assertEqual(await self.options(code), await self.denial())

    async def test_every_bad_code_gets_the_byte_identical_denial(self):
        expected = await self.denial()
        _, expired = self.invite(lifetime=timedelta(minutes=1))
        _, redeemed = self.invite()
        self.assertEqual(status((await self.redeem(redeemed))[1]), 204)
        revoked_principal, revoked = self.invite()
        self.store.revoke_principal(revoked_principal.id)
        regranted_principal, regranted = self.invite()
        # A grant change advances the principal's revision: its code is void.
        self.store.set_permissions(regranted_principal.id, (Permission.RECORDINGS_VIEW,))
        exhausted_principal, exhausted = self.invite()
        for _ in range(MAX_REDEMPTION_ATTEMPTS):
            self.assertEqual(status(await self.options(exhausted)), 200)
        _, generation = self.invite()
        self.revoker.revoke_all_human_sessions()
        self.ceremony_clock.advance(minutes=2)
        unknown = new_invitation_code()[1]
        bodies = {
            "unknown": {"code": unknown}, "expired": {"code": expired}, "redeemed": {"code": redeemed},
            "revoked": {"code": revoked}, "exhausted": {"code": exhausted},
            "generation_advanced": {"code": generation}, "revision_advanced": {"code": regranted},
            "absent": {}, "null": {"code": None},
            "lower_case": {"code": unknown.lower()}, "ungrouped": {"code": unknown.replace("-", "")},
            "number": {"code": 7}, "extra_member": {"code": unknown, "next": "/"},
        }
        for name, body in bodies.items():
            with self.subTest(code=name):
                self.assertEqual(await call(self.surface, "POST", REGISTRATION_OPTIONS_PATH,
                                            body=json.dumps(body).encode()), expected)
                credential = SyntheticAuthenticator().register(
                    {"challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "user": {"id": "AAAA"}},
                    origin=ORIGIN, rp_id=HOST)
                self.assertEqual(await call(self.surface, "POST", REGISTRATION_PATH,
                                            body=json.dumps(dict(body, credential=credential)).encode()),
                                 expected)
        for raw in (b"", b"[]", b'"code"', b"{", b'{"code": "a", "code": "b"}', b'{"code": NaN}'):
            with self.subTest(raw=raw):
                self.assertEqual(await call(self.surface, "POST", REGISTRATION_OPTIONS_PATH, body=raw), expected)
                self.assertEqual(await call(self.surface, "POST", REGISTRATION_PATH, body=raw), expected)
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 1)
        self.assertEqual(self.count(REDEEMED), 1)
        self.assertEqual(self.count(
            f"SELECT attempt_count FROM access_invitations WHERE principal_id='{exhausted_principal.id}'"),
            MAX_REDEMPTION_ATTEMPTS)

    async def test_a_code_that_does_not_parse_never_reaches_the_gate_or_sqlite(self):
        expected = await self.denial()
        admitted = self.admission.admitted
        with patch.object(self.ceremonies, "begin_registration",
                          side_effect=AssertionError("parsed before the gate")) as begin, \
                patch.object(self.ceremonies, "finish_registration",
                             side_effect=AssertionError("parsed before the gate")) as finish, \
                patch.object(self.store, "begin_registration",
                             side_effect=AssertionError("no SQLite")):
            for value in ("abcd", new_invitation_code()[1].lower(), "", 12):
                self.assertEqual(await self.options(value), expected)
                self.assertEqual(await self.finish(value, {"id": "x"}), expected)
        begin.assert_not_called()
        finish.assert_not_called()
        self.assertEqual(self.admission.admitted, admitted)

    async def test_registration_is_verified_server_side(self):
        expected = await self.denial()
        cases = {
            "user_verification_missing": dict(uv=False),
            "user_presence_missing": dict(up=False),
            "foreign_origin": dict(origin="https://other.example.invalid"),
            "foreign_rp_id": dict(rp_id="other.example.invalid"),
            "assertion_type": dict(kind="webauthn.get"),
            "foreign_challenge": dict(challenge="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            "invalid_attestation": dict(fmt="packed", statement={"alg": -7, "sig": b"\x00" * 70}),
        }
        for name, options in cases.items():
            with self.subTest(case=name):
                _, code = self.invite()
                _, finished = await self.redeem(code, **options)
                self.assertEqual(finished, expected)
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)
        # Request shape: the label, the credential object and the members are strict.
        principal, code = self.invite()
        begun = payload(await self.options(code))
        credential = SyntheticAuthenticator().register(begun, origin=ORIGIN, rp_id=HOST)
        for body in ({"code": code, "credential": credential, "label": ""},
                     {"code": code, "credential": credential, "label": "x" * 65},
                     {"code": code, "credential": credential, "label": "bad\nlabel"},
                     {"code": code, "credential": credential, "label": 5},
                     {"code": code, "credential": [credential]},
                     {"code": code, "credential": credential, "session": "x"},
                     {"credential": credential}):
            with self.subTest(body=sorted(body)):
                self.assertEqual(await call(self.surface, "POST", REGISTRATION_PATH,
                                            body=json.dumps(body).encode()), expected)
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)
        self.assertEqual(self.count(REDEEMED), 0)
        # Those shape refusals never reached the ceremony: the challenge is
        # still pending and the invitation redeems with it.
        self.assertEqual(status(await self.finish(code, credential)), 204)
        self.assertEqual(self.count(
            f"SELECT attempt_count FROM access_invitations WHERE principal_id='{principal.id}'"), 1)

    async def test_origin_host_and_trusted_path_are_required(self):
        expected = await self.denial()
        _, code = self.invite()
        body = json.dumps({"code": code}).encode()
        for options in (dict(origin=None), dict(origin="https://other.example.invalid"),
                        dict(host="other.example.invalid"), dict(identity=None),
                        dict(client=("192.0.2.50", 40000)), dict(content_type=None),
                        dict(content_type=b"text/plain"), dict(query=b"code=" + code.encode())):
            with self.subTest(options=sorted(options)):
                self.assertEqual(await call(self.surface, "POST", REGISTRATION_OPTIONS_PATH, body=body,
                                            **options), expected)
        # The code never travels in a URL: no route accepts it there.
        for path in (REGISTRATION_OPTIONS_PATH + "/" + code, "/api/auth/registration/" + code):
            self.assertEqual(await call(self.surface, "POST", path, body=body), expected)
        self.assertEqual(self.count("SELECT attempt_count FROM access_invitations"), 0)

    async def test_missing_raw_path_is_the_generic_denial(self):
        expected = await self.denial()
        _, code = self.invite()
        for omit in (True, False):
            sent = []
            scope = {
                "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "scheme": "http",
                "method": "POST", "path": REGISTRATION_OPTIONS_PATH, "raw_path": None,
                "query_string": b"", "root_path": "",
                "headers": [(b"host", HOST.encode()), (b"origin", ORIGIN.encode()),
                            (b"tailscale-user-login", VIEWER.encode()),
                            (b"content-type", b"application/json")],
                "client": ("127.0.0.1", 40000), "server": ("127.0.0.1", 8080),
            }
            if omit:
                del scope["raw_path"]

            async def receive():
                return {"type": "http.request", "body": json.dumps({"code": code}).encode(),
                        "more_body": False}

            async def send(message):
                sent.append(message)

            await self.surface(scope, receive, send)
            self.assertEqual(sent, expected)
        self.assertEqual(self.count("SELECT attempt_count FROM access_invitations"), 0)

    async def test_concurrent_redemptions_of_one_code_register_exactly_one_credential(self):
        expected = await self.denial()
        principal, code = self.invite()
        first, second = payload(await self.options(code)), payload(await self.options(code))
        credentials = [SyntheticAuthenticator().register(options, origin=ORIGIN, rp_id=HOST)
                       for options in (first, second)]
        results = await asyncio.gather(*(self.finish(code, credential) for credential in credentials))
        self.assertEqual(sorted(status(result) for result in results), [204, 404])
        self.assertIn(expected, results)
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 1)
        self.assertEqual(self.count(REDEEMED), 1)
        self.assertEqual(self.count(
            f"SELECT count(*) FROM access_invitations WHERE principal_id='{principal.id}' "
            "AND redeemed_at_us IS NOT NULL"), 1)
        # A retry of the loser stays the generic denial (idempotent).
        self.assertEqual(await self.finish(code, credentials[0]), expected)
        self.assertEqual(await self.finish(code, credentials[1]), expected)

    async def test_device_bound_policy_has_its_fixed_409_only_for_a_valid_invitation(self):
        self.ceremonies.require_device_bound = True
        expected = await self.denial()
        _, code = self.invite()
        _, refused = await self.redeem(code, SyntheticAuthenticator(backup_eligible=True))
        self.assertEqual(status(refused), 409)
        self.assertEqual(refused[1]["body"], b'{"detail":"device_bound_credential_required"}')
        self.assertEqual(header(refused, b"cache-control"), [b"no-store"])
        self.assertEqual(header(refused, b"set-cookie"), [])
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)
        # The invitation stays unredeemed; a device-bound authenticator succeeds.
        self.assertEqual(status((await self.redeem(code))[1]), 204)
        # Without a valid invitation the same registration is the generic denial.
        self.assertEqual(status(await self.options(code)), 404)
        unknown = new_invitation_code()[1]
        credential = SyntheticAuthenticator(backup_eligible=True).register(
            {"challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "user": {"id": "AAAA"}},
            origin=ORIGIN, rp_id=HOST)
        self.assertEqual(await self.finish(unknown, credential), expected)

    async def test_closed_access_refuses_redemption_without_consuming_an_attempt(self):
        _, code = self.invite()
        expected = await self.denial()
        self.access.stop()
        self.assertEqual(await self.options(code), expected)
        self.assertEqual(self.count("SELECT attempt_count FROM access_invitations"), 0)

    async def test_the_code_never_reaches_a_log_record(self):
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(self.format(record) + repr(record.__dict__))

        handler = Capture(logging.DEBUG)
        root = logging.getLogger()
        level = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            principal, code = self.invite()
            secret = parse_invitation_code(code)
            self.assertEqual(status((await self.redeem(code))[1]), 204)
            for _ in range(3):
                await self.options(code)
                await self.options(code.lower())
            self.access.redemption_limiter = redemption_rate_limiter(monotonic=Clock())
            for _ in range(REDEMPTION_PER_SOURCE_CAPACITY + 2):
                await self.options(code)
        finally:
            root.removeHandler(handler)
            root.setLevel(level)
        self.assertTrue(records)  # at least the value-free rate-limit event
        text = "\n".join(records)
        for form in (code, code.lower(), code.replace("-", ""), secret.hex(), repr(secret)):
            self.assertNotIn(form, text)
        self.assertNotIn(VIEWER, text)


class RedemptionRateLimitTests(RedemptionFixture):
    def setUp(self):
        super().setUp()
        self.redemption_clock = Clock()
        self.access.redemption_limiter = redemption_rate_limiter(monotonic=self.redemption_clock)
        # Every test here is limited at least once; the event is value-free.
        self.limited_logs = self.assertLogs("app.auth.rate_limit", "WARNING")
        self.limited_logs.__enter__()
        self.addCleanup(self.limited_logs.__exit__, None, None, None)

    async def test_flood_is_throttled_per_source_before_the_gate_without_starving_sign_in(self):
        expected = await self.denial()
        _, code = self.invite()
        limiter = self.access.redemption_limiter
        self.assertEqual((limiter.per_source_capacity, limiter.per_source_refill_seconds),
                         (REDEMPTION_PER_SOURCE_CAPACITY, REDEMPTION_PER_SOURCE_REFILL_SECONDS))
        for _ in range(REDEMPTION_PER_SOURCE_CAPACITY):
            self.assertEqual(await self.options(new_invitation_code()[1]), expected)
        admitted = self.admission.admitted
        with patch.object(self.ceremonies, "begin_registration",
                          side_effect=AssertionError("limited before the gate")) as begin, \
                patch.object(self.ceremonies, "finish_registration",
                             side_effect=AssertionError("limited before the gate")) as finish:
            # Even the valid code is refused while the source is throttled.
            self.assertEqual(await self.options(code), expected)
            self.assertEqual(await self.finish(code, {"id": "x"}), expected)
        begin.assert_not_called()
        finish.assert_not_called()
        self.assertEqual(self.admission.admitted, admitted)
        self.assertEqual(self.count("SELECT attempt_count FROM access_invitations"), 0)
        self.assertEqual(limiter.limited, 2)
        # Sign-in has its own buckets and is untouched by the flood.
        self.assertEqual(self.limiter.limited, 0)
        self.assertEqual(status(await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH)), 200)
        # Another source still redeems; the flooded one gets one token per 12 s.
        self.assertEqual(status(await self.options(code, identity=OTHER_LOGIN)), 200)
        self.redemption_clock.value += REDEMPTION_PER_SOURCE_REFILL_SECONDS
        self.assertEqual(status(await self.options(code)), 200)
        self.assertEqual(await self.options(code), expected)

    async def test_global_cap_bounds_many_sources(self):
        expected = await self.denial()
        for index in range(REDEMPTION_GLOBAL_CAPACITY):
            self.assertEqual(await self.options("x", identity=f"synthetic-{index}@example.invalid"), expected)
        limited = self.access.redemption_limiter.limited
        _, code = self.invite()
        self.assertEqual(await self.options(code, identity="synthetic-new@example.invalid"), expected)
        self.assertEqual(self.access.redemption_limiter.limited, limited + 1)
        self.assertLessEqual(self.access.redemption_limiter.sources(), 256)

    async def test_sign_in_flood_does_not_spend_redemption(self):
        for _ in range(self.limiter.per_source_capacity + 3):
            await call(self.surface, "POST", AUTHENTICATION_OPTIONS_PATH)
        self.assertGreater(self.limiter.limited, 0)
        _, code = self.invite()
        self.assertEqual(status(await self.options(code)), 200)


class CompositionTests(RedemptionFixture):
    def test_one_limiter_object_cannot_serve_both(self):
        fresh = HumanAccess(HumanAccessConfiguration(enabled=True), store=self.store,
                            ceremonies=PasskeyCeremonies(self.store, self.rp, session_gate=self.check,
                                                         clock=self.ceremony_clock),
                            reservation=self.check)
        limiter = fresh.redemption_limiter
        self.assertIsNot(limiter, fresh.rate_limiter)
        self.assertEqual((limiter.per_source_capacity, limiter.per_source_refill_seconds,
                          limiter.global_capacity), (5, 12.0, REDEMPTION_GLOBAL_CAPACITY))
        shared = SourceRateLimiter()
        ceremonies = PasskeyCeremonies(self.store, self.rp, session_gate=self.check,
                                       clock=self.ceremony_clock)
        with self.assertRaises(HumanAccessUnavailable):
            HumanAccess(HumanAccessConfiguration(enabled=True), store=self.store, ceremonies=ceremonies,
                        reservation=self.check, rate_limiter=shared, redemption_limiter=shared)
        with self.assertRaises(HumanAccessUnavailable):
            HumanAccess(HumanAccessConfiguration(enabled=True), store=self.store, ceremonies=ceremonies,
                        reservation=self.check, redemption_limiter=object())


if __name__ == "__main__":
    unittest.main()
