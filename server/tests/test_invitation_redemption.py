"""Issue #10 phase 2 S2: invitation redemption routes and the code format.

Synthetic only: software authenticators (``webauthn_fakes``), synthetic
``/proc/net`` rows, a temporary SQLite database and the in-process ASGI
driver of ``test_human_surface``. Every identity is an invented ``.invalid``
value and every code is generated in the test process. Mock only: no
browser, Tailscale, proxy or real authenticator is involved.
"""

import asyncio
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
import json
import logging
import secrets
import unittest
from unittest.mock import patch

from app.auth.boot_clock import CLOCK_ROLLBACK_TOLERANCE, BootInstant, invitation_clock_valid
from app.auth.bootstrap_cli import bootstrap_owner
from app.auth.human_surface import (
    AUTHENTICATION_OPTIONS_PATH, REGISTRATION_OPTIONS_PATH, REGISTRATION_PATH, SESSION_PATH,
    HumanAccess, HumanAccessConfiguration, HumanAccessUnavailable,
)
from app.auth.invitation_code import (
    ALPHABET, CODE_BYTES, DISPLAY_LENGTH, INVITATION_LIFETIME, MAX_INVITATION_LIFETIME, InvalidInvitationCode,
    format_invitation_code, invitation_lifetime, new_invitation_code, parse_invitation_code,
)
from app.auth.model import Permission
from app.auth import webauthn
from app.auth.passkeys import PasskeyCeremonies
from app.auth.rate_limit import (
    REDEMPTION_PER_SOURCE_CAPACITY, REDEMPTION_PER_SOURCE_REFILL_SECONDS,
    SourceRateLimiter, redemption_rate_limiter,
)
from app.auth.store import MAX_REDEMPTION_ATTEMPTS, AccessStore, InvitationClockUnavailable
from app.auth.model import AccessValidationError

from tests.test_hostname_reservation import Clock
from tests.test_human_surface import (
    HOST, ORIGIN, OTHER_LOGIN, VIEWER, HumanSurfaceFixture, call, header, payload, status,
)
from tests.test_webauthn_ceremonies import waiting
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


BOOT = "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"
OTHER_BOOT = "1f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"


class BootClock:
    """A synthetic boot id and ``CLOCK_BOOTTIME`` (microseconds)."""

    def __init__(self):
        self.boot_id = BOOT
        self.us = 5_000_000_000
        self.available = True

    def __call__(self):
        return BootInstant(self.boot_id, self.us) if self.available else None

    def advance(self, **delta):
        self.us += timedelta(**delta) // timedelta(microseconds=1)


class RedemptionFixture(HumanSurfaceFixture):
    def setUp(self):
        super().setUp()
        # A roomy limiter unless a test exercises the D4 values themselves.
        self.access.redemption_limiter = SourceRateLimiter(
            per_source_capacity=1000, global_capacity=None, monotonic=self.limit_clock)
        self.boot = BootClock()
        self.store._boot_clock = self.boot

    def elapse(self, **delta):
        """Both clocks move together, as on a host whose wall clock is not stepped."""
        self.ceremony_clock.advance(**delta)
        self.boot.advance(**delta)

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
        self.elapse(minutes=2)
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

    async def test_no_global_bucket_lets_one_source_stop_another(self):
        # Owner decision 2026-10-11 (Codex P1 on PR #234): only the per-source
        # bucket. Many sources each spending their whole burst never refuse a
        # fresh source, the Owner redeeming a recovery code included.
        expected = await self.denial()
        limiter = self.access.redemption_limiter
        self.assertIsNone(limiter.global_capacity)
        for index in range(40):
            for _ in range(REDEMPTION_PER_SOURCE_CAPACITY):
                self.assertEqual(await self.options("x", identity=f"synthetic-{index}@example.invalid"),
                                 expected)
        self.assertEqual(limiter.limited, 0)
        _, code = self.invite()
        self.assertEqual(status(await self.options(code, identity="synthetic-new@example.invalid")), 200)
        self.assertEqual(limiter.limited, 0)
        self.assertLessEqual(limiter.sources(), 256)
        # Each source is still bounded by its own bucket.
        self.assertEqual(await self.options(code, identity="synthetic-0@example.invalid"), expected)
        self.assertEqual(limiter.limited, 1)

    async def test_the_limiter_is_charged_before_either_body_is_parsed(self):
        # A request whose body would be refused anyway still spends a token,
        # so the limiter cannot be moved behind the body checks unnoticed.
        expected = await self.denial()
        limiter = self.access.redemption_limiter
        for path in (REGISTRATION_PATH, REGISTRATION_OPTIONS_PATH):
            with self.subTest(path=path):
                self.redemption_clock.value += 10 * REDEMPTION_PER_SOURCE_REFILL_SECONDS
                for _ in range(REDEMPTION_PER_SOURCE_CAPACITY):
                    self.assertEqual(await call(self.surface, "POST", path, body=b"{"), expected)
                before = limiter.limited
                _, code = self.invite()
                self.assertEqual(await self.options(code), expected)
                self.assertEqual(limiter.limited, before + 1)

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
                          limiter.global_capacity), (5, 12.0, None))
        # Sign-in keeps its global bucket.
        self.assertEqual(fresh.rate_limiter.global_capacity, 120)
        shared = SourceRateLimiter()
        ceremonies = PasskeyCeremonies(self.store, self.rp, session_gate=self.check,
                                       clock=self.ceremony_clock)
        with self.assertRaises(HumanAccessUnavailable):
            HumanAccess(HumanAccessConfiguration(enabled=True), store=self.store, ceremonies=ceremonies,
                        reservation=self.check, rate_limiter=shared, redemption_limiter=shared)
        with self.assertRaises(HumanAccessUnavailable):
            HumanAccess(HumanAccessConfiguration(enabled=True), store=self.store, ceremonies=ceremonies,
                        reservation=self.check, redemption_limiter=object())


class InvitationClockTests(RedemptionFixture):
    """Owner decision 2026-10-11 (Codex P1 on PR #234): a wall clock stepped
    back after issuance must not extend a code."""

    async def test_a_consistent_clock_redeems(self):
        _, code = self.invite()
        self.elapse(hours=23, minutes=59)
        self.assertEqual(status((await self.redeem(code))[1]), 204)

    async def test_a_wall_clock_rollback_on_the_same_boot_refuses(self):
        expected = await self.denial()
        _, code = self.invite()
        # 25 hours really passed (monotonic), but the wall clock was stepped
        # back so it reads only 23 hours later: still "inside" the wall window.
        self.boot.advance(hours=25)
        self.ceremony_clock.advance(hours=23)
        self.assertEqual(await self.options(code), expected)
        # A rollback inside the lifetime is refused as well (detected rollback).
        principal, code = self.invite()
        self.boot.advance(hours=2)
        self.ceremony_clock.advance(hours=1)
        self.assertEqual(await self.options(code), expected)
        self.assertEqual(self.count(
            f"SELECT attempt_count FROM access_invitations WHERE principal_id='{principal.id}'"), 0)

    async def test_finish_rechecks_the_clock(self):
        expected = await self.denial()
        _, code = self.invite()
        begun = await self.options(code)
        self.assertEqual(status(begun), 200)
        credential = SyntheticAuthenticator().register(payload(begun), origin=ORIGIN, rp_id=HOST)
        self.boot.advance(minutes=2)  # the wall clock does not move: stepped back by 2 minutes
        self.assertEqual(await self.finish(code, credential), expected)
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)

    async def test_a_long_wait_before_the_commit_is_not_a_rollback(self):
        """Codex P2 on PR #234: the finish path captured its wall-clock time
        before ``session_gate.admit()`` and read the boot clock after it, so
        a wait over 30 s (e.g. behind storage admission) looked like a wall
        clock stepped back and refused a valid code. Both clocks are now read
        as one pair inside the redemption transaction."""
        principal, code = self.invite()
        begun = await self.options(code)
        self.assertEqual(status(begun), 200)
        credential = SyntheticAuthenticator().register(payload(begun), origin=ORIGIN, rp_id=HOST)
        admit = self.check.admit

        def slow_admit(epoch):
            # Real time passes while waiting: both clocks move together, by
            # far more than the rollback tolerance.
            self.elapse(minutes=5)
            return admit(epoch)

        with patch.object(self.check, "admit", slow_admit):
            response = await self.finish(code, credential)
        self.assertEqual(status(response), 204)
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 1)
        # The stored time is the in-transaction reading, not the early one.
        self.assertEqual(self.count("SELECT enrolled_at_us FROM access_credentials"),
                         self.count(f"SELECT redeemed_at_us FROM access_invitations "
                                    f"WHERE principal_id='{principal.id}'"))
        self.assertEqual(self.count(f"SELECT attempt_count FROM access_invitations "
                                    f"WHERE principal_id='{principal.id}'"), 1)

    async def test_a_rollback_during_the_wait_is_still_refused(self):
        expected = await self.denial()
        _, code = self.invite()
        begun = await self.options(code)
        self.assertEqual(status(begun), 200)
        credential = SyntheticAuthenticator().register(payload(begun), origin=ORIGIN, rp_id=HOST)
        admit = self.check.admit

        def slow_admit_with_step(epoch):
            # Five minutes pass, and the wall clock is also stepped back by
            # them: it reads the same time while the boot clock moved on.
            self.boot.advance(minutes=5)
            return admit(epoch)

        with patch.object(self.check, "admit", slow_admit_with_step):
            self.assertEqual(await self.finish(code, credential), expected)
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)
        self.assertEqual(self.count(REDEEMED), 0)

    async def registered(self, code):
        begun = await self.options(code)
        self.assertEqual(status(begun), 200)
        return SyntheticAuthenticator().register(payload(begun), origin=ORIGIN, rp_id=HOST)

    async def test_finish_reads_the_clock_pair_after_the_storage_admission_wait(self):
        """Issue #235 item 1: the wait is injected into the redemption's own
        storage admission (``_audited_transaction``), not only the gate, so
        ``enroll_credential`` reading its wall/boot pair before that wait
        (a regression) would refuse this valid code after a five-minute wait."""
        principal, code = self.invite()
        credential = await self.registered(code)
        with waiting(self.store, "_audited_transaction", lambda: self.elapse(minutes=5)):
            response = await self.finish(code, credential)
        self.assertEqual(status(response), 204)
        after_wait = (self.ceremony_clock() - datetime(1970, 1, 1, tzinfo=timezone.utc)) // timedelta(microseconds=1)
        self.assertEqual(self.count("SELECT enrolled_at_us FROM access_credentials"), after_wait)
        self.assertEqual(self.count(f"SELECT redeemed_at_us FROM access_invitations "
                                    f"WHERE principal_id='{principal.id}'"), after_wait)

    async def test_finish_refuses_an_expiry_or_rollback_during_the_storage_admission_wait(self):
        expected = await self.denial()
        # The invitation expires while the redemption waits for admission.
        _, code = self.invite(lifetime=timedelta(hours=1))
        self.elapse(minutes=58)
        credential = await self.registered(code)
        with waiting(self.store, "_audited_transaction", lambda: self.elapse(minutes=3)):
            self.assertEqual(await self.finish(code, credential), expected)
        # The wall clock is stepped back by the five minutes the wait took.
        _, code = self.invite()
        credential = await self.registered(code)
        with waiting(self.store, "_audited_transaction", lambda: self.boot.advance(minutes=5)):
            self.assertEqual(await self.finish(code, credential), expected)
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)
        self.assertEqual(self.count(REDEEMED), 0)

    def waiting_store(self, wait):
        """The next store write transaction is entered only after ``wait()``:
        a storage-admission or SQLite lock wait (Codex P2 on PR #234)."""
        original = self.store._transaction
        pending = [wait]

        @contextmanager
        def slow(write=False):
            if write and pending:
                pending.pop()()
            with original(write=write) as connection:
                yield connection

        return patch.object(self.store, "_transaction", slow)

    def options_state(self, principal):
        return (self.count(f"SELECT attempt_count FROM access_invitations WHERE principal_id='{principal.id}'"),
                self.count("SELECT count(*) FROM access_webauthn_challenges"))

    async def test_options_refuse_an_invitation_that_expired_during_the_wait(self):
        """Codex P2 on PR #234: the options step read its wall and boot clocks
        before storage admission and ``BEGIN IMMEDIATE``, so an invitation
        that expired during that wait was still accepted, counted an attempt,
        stored a challenge and returned the invitee's display name."""
        expected = await self.denial()
        principal, code = self.invite()
        self.elapse(hours=23, minutes=58)
        with self.waiting_store(lambda: self.elapse(minutes=5)):
            response = await self.options(code)
        self.assertEqual(response, expected)
        self.assertNotIn("Synthetic invitee", repr(response))
        self.assertEqual(self.options_state(principal), (0, 0))

    async def test_options_refuse_a_rollback_during_the_wait(self):
        expected = await self.denial()
        principal, code = self.invite()
        # Five minutes pass during the wait, and the wall clock is stepped
        # back by them: it reads the same time while the boot clock moved on.
        with self.waiting_store(lambda: self.boot.advance(minutes=5)):
            response = await self.options(code)
        self.assertEqual(response, expected)
        self.assertNotIn("Synthetic invitee", repr(response))
        self.assertEqual(self.options_state(principal), (0, 0))

    async def test_options_accept_a_long_wait_while_the_code_stays_valid(self):
        principal, code = self.invite()
        self.elapse(hours=23, minutes=50)
        with self.waiting_store(lambda: self.elapse(minutes=5)):
            begun = await self.options(code)
        self.assertEqual(status(begun), 200)
        self.assertEqual(payload(begun)["user"]["displayName"], "Synthetic invitee")
        self.assertEqual(self.options_state(principal), (1, 1))
        # The challenge carries the in-transaction (post-wait) time.
        after_wait = (self.ceremony_clock() - datetime(1970, 1, 1, tzinfo=timezone.utc)) // timedelta(microseconds=1)
        self.assertEqual(self.count("SELECT issued_at_us FROM access_webauthn_challenges"), after_wait)
        credential = SyntheticAuthenticator().register(payload(begun), origin=ORIGIN, rp_id=HOST)
        self.assertEqual(status(await self.finish(code, credential)), 204)

    async def test_monotonic_elapsed_beyond_the_lifetime_or_negative_refuses(self):
        expected = await self.denial()
        _, code = self.invite(lifetime=timedelta(hours=2))
        self.boot.advance(hours=2)
        self.ceremony_clock.advance(hours=1, minutes=59)
        self.assertEqual(await self.options(code), expected)
        _, code = self.invite()
        self.boot.us -= 1  # same boot, monotonic reading before issuance
        self.assertEqual(await self.options(code), expected)

    async def test_after_a_reboot_the_wall_clock_window_decides(self):
        expected = await self.denial()
        _, code = self.invite()
        _, late = self.invite()
        self.boot.boot_id, self.boot.us = OTHER_BOOT, 1_000_000
        self.ceremony_clock.advance(hours=1)
        self.assertEqual(status((await self.redeem(code))[1]), 204)
        self.ceremony_clock.advance(hours=23)
        self.assertEqual(await self.options(late), expected)

    async def test_an_unverifiable_clock_refuses(self):
        expected = await self.denial()
        principal, code = self.invite()
        self.boot.available = False
        self.assertEqual(await self.options(code), expected)
        self.boot.available = True
        # A row issued before the boot pair existed (NULL) is unverifiable.
        with closing(self.database.connect()) as connection:
            connection.execute("UPDATE access_invitations SET issued_boot_id=NULL, issued_boottime_us=NULL")
            connection.commit()
        self.assertEqual(await self.options(code), expected)
        self.assertEqual(self.count(
            f"SELECT attempt_count FROM access_invitations WHERE principal_id='{principal.id}'"), 0)
        # Without the boot clock nothing is issued at all.
        self.boot.available = False
        invitee = self.store.invite("Synthetic invitee", (Permission.LIVE_VIEW,))
        with self.assertRaises(InvitationClockUnavailable):
            self.store.issue_enrollment(invitee.id, secrets.token_bytes(20),
                                        self.ceremony_clock() + timedelta(hours=1))
        self.assertEqual(self.count(
            f"SELECT count(*) FROM access_invitations WHERE principal_id='{invitee.id}'"), 0)

    def test_the_clock_rule_itself(self):
        hour = 3_600_000_000
        base = dict(issued_us=0, expires_us=24 * hour, issued_boot_id=BOOT, issued_boottime_us=10 * hour,
                    max_lifetime_us=MAX_INVITATION_LIFETIME // timedelta(microseconds=1))
        tolerance = CLOCK_ROLLBACK_TOLERANCE // timedelta(microseconds=1)

        def same(us):
            return BootInstant(BOOT, us)

        self.assertTrue(invitation_clock_valid(**base, now_us=hour, now=same(11 * hour)))
        self.assertTrue(invitation_clock_valid(**base, now_us=hour - tolerance, now=same(11 * hour)))
        self.assertFalse(invitation_clock_valid(**base, now_us=hour - tolerance - 1, now=same(11 * hour)))
        # A wall clock stepped forward only ends the code earlier.
        self.assertTrue(invitation_clock_valid(**base, now_us=20 * hour, now=same(11 * hour)))
        self.assertFalse(invitation_clock_valid(**base, now_us=24 * hour, now=same(11 * hour)))
        self.assertFalse(invitation_clock_valid(**base, now_us=23 * hour, now=same(34 * hour)))
        self.assertFalse(invitation_clock_valid(**base, now_us=hour, now=same(10 * hour - 1)))
        # Inside the 30 s tolerance only the monotonic lifetime ends the code
        # (PR #234 review): a 2-hour code, the boot clock 2 hours on, the
        # wall clock 10 s short of its expiry, is refused; 1 us earlier it holds.
        short = dict(base, expires_us=2 * hour)
        wall = 2 * hour - 10_000_000
        self.assertLess(2 * hour - wall, tolerance)
        self.assertFalse(invitation_clock_valid(**short, now_us=wall, now=same(12 * hour)))
        self.assertTrue(invitation_clock_valid(**short, now_us=wall, now=same(12 * hour - 1)))
        self.assertTrue(invitation_clock_valid(**base, now_us=hour, now=BootInstant(OTHER_BOOT, 0)))
        self.assertFalse(invitation_clock_valid(**base, now_us=-1, now=BootInstant(OTHER_BOOT, 0)))
        self.assertFalse(invitation_clock_valid(**base, now_us=hour, now=None))
        self.assertFalse(invitation_clock_valid(**dict(base, issued_boot_id=None), now_us=hour,
                                                now=same(11 * hour)))
        self.assertFalse(invitation_clock_valid(**dict(base, issued_boottime_us=True), now_us=hour,
                                                now=same(11 * hour)))
        self.assertFalse(invitation_clock_valid(**dict(base, expires_us=8 * 24 * hour), now_us=hour,
                                                now=BootInstant(OTHER_BOOT, 0)))


class InvitationLifetimeTests(RedemptionFixture):
    def test_the_lifetime_is_validated_and_bounds_issuance(self):
        self.assertEqual(invitation_lifetime(1), timedelta(hours=1))
        self.assertEqual(invitation_lifetime(168), MAX_INVITATION_LIFETIME)
        for value in (0, 169, -1, 24.0, "24", True, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                invitation_lifetime(value)
        for value in (timedelta(0), timedelta(days=7, microseconds=1), 24):
            with self.subTest(value=value), self.assertRaises(AccessValidationError):
                AccessStore(self.database, invitation_lifetime=value)
        short = AccessStore(self.database, clock=self.ceremony_clock, unaudited_writes=True,
                            invitation_lifetime=timedelta(hours=2), boot_clock=self.boot)
        self.assertEqual(short.invitation_expiry(self.ceremony_clock()), self.ceremony_clock() + timedelta(hours=2))
        invitee = short.invite("Synthetic invitee", (Permission.LIVE_VIEW,))
        with self.assertRaises(AccessValidationError):
            short.issue_enrollment(invitee.id, secrets.token_bytes(20),
                                   self.ceremony_clock() + timedelta(hours=2, seconds=1))
        short.issue_enrollment(invitee.id, secrets.token_bytes(20), self.ceremony_clock() + timedelta(hours=2))
        # The default store never issues beyond 24 hours.
        with self.assertRaises(AccessValidationError):
            self.store.issue_enrollment(invitee.id, secrets.token_bytes(20),
                                        self.ceremony_clock() + timedelta(hours=24, seconds=1))


class ConstantTimeLookupTests(RedemptionFixture):
    """AUTH-013 (Codex P2 on PR #234): the stored digest is compared with
    ``hmac.compare_digest``; SQLite only ever compares the lookup key."""

    async def test_the_digest_is_compared_in_constant_time(self):
        expected = await self.denial()
        _, code = self.invite()
        with patch("app.auth.store.hmac.compare_digest", side_effect=lambda a, b: a == b) as compared:
            self.assertEqual(status(await self.options(code)), 200)
        self.assertEqual(compared.call_count, 1)
        # A row found by its lookup key whose digest differs is refused.
        principal, code = self.invite()
        with closing(self.database.connect()) as connection:
            connection.execute("UPDATE access_invitations SET secret_digest=zeroblob(32) WHERE principal_id=?",
                               (str(principal.id),))
            connection.commit()
        self.assertEqual(await self.options(code), expected)
        # A row without a lookup key (issued before it existed) is never found.
        principal, code = self.invite()
        with closing(self.database.connect()) as connection:
            connection.execute("UPDATE access_invitations SET lookup_key=NULL WHERE principal_id=?",
                               (str(principal.id),))
            connection.commit()
        self.assertEqual(await self.options(code), expected)
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)

    def test_neither_redemption_query_compares_the_secret_digest_in_sql(self):
        statements = []
        original = type(self.database).connect

        def tracing(database, *args, **kwargs):
            connection = original(database, *args, **kwargs)
            connection.set_trace_callback(statements.append)
            return connection

        _, code = self.invite()
        secret = parse_invitation_code(code)
        with patch.object(type(self.database), "connect", tracing):
            with self.assertRaises(AccessValidationError):
                self.store.enroll_credential(secrets.token_bytes(20), VIEWER, b"c" * 16, b"k", -7, 0)
            self.store.begin_registration(secret, VIEWER, b"d" * 32, at=self.ceremony_clock(),
                                          lifetime=timedelta(minutes=5))
        self.assertTrue(statements)
        self.assertFalse([item for item in statements if "secret_digest=" in item.replace(" ", "")])
        self.assertTrue([item for item in statements if "lookup_key=" in item.replace(" ", "")])


class RefusalRecordTests(RedemptionFixture):
    """AUTH-013 (Codex P2 on PR #234): refused attempts are recorded value-free."""

    async def test_refusals_are_counted_and_logged_without_values(self):
        expected = await self.denial()
        _, code = self.invite()
        unknown = new_invitation_code()[1]
        with self.assertLogs("app.auth.human_surface", "WARNING") as logs:
            for body in ({"code": unknown}, {"code": unknown.lower()}, {}, {"code": code, "extra": 1}):
                self.assertEqual(await call(self.surface, "POST", REGISTRATION_OPTIONS_PATH,
                                            body=json.dumps(body).encode()), expected)
            self.assertEqual(await self.finish(unknown, {"id": "x"}), expected)
        self.assertEqual(self.access.refused_redemptions, 5)
        # Power-of-two throttled: the 1st and 2nd and 4th refusals log.
        self.assertEqual([record.getMessage() for record in logs.records],
                         ["invitation_redemption_refused"] * 3)
        text = repr([record.__dict__ for record in logs.records])
        for value in (code, unknown, unknown.lower(), VIEWER):
            self.assertNotIn(value, text)
        # The extra member was refused before the ceremony: no attempt counted.
        self.assertEqual(self.count("SELECT attempt_count FROM access_invitations"), 0)
        # A success is not a refusal.
        self.assertEqual(status((await self.redeem(code))[1]), 204)
        self.assertEqual(self.access.refused_redemptions, 5)

    async def test_the_device_bound_409_is_counted_and_logged_without_values(self):
        # Codex P2 on PR #234: the fixed 409 is a refused redemption too.
        self.ceremonies.require_device_bound = True
        _, code = self.invite()
        with self.assertLogs("app.auth.human_surface", "WARNING") as logs:
            _, refused = await self.redeem(code, SyntheticAuthenticator(backup_eligible=True))
        self.assertEqual(status(refused), 409)
        self.assertEqual(self.access.refused_redemptions, 1)
        self.assertEqual([record.getMessage() for record in logs.records],
                         ["invitation_redemption_refused"])
        text = repr([record.__dict__ for record in logs.records])
        for value in (code, VIEWER):
            self.assertNotIn(value, text)
        # A device-bound authenticator then redeems; no further refusal.
        self.assertEqual(status((await self.redeem(code))[1]), 204)
        self.assertEqual(self.access.refused_redemptions, 1)


class ExcludedCredentialTests(RedemptionFixture):
    """PR #234 review: excludeCredentials lists only the usable credentials."""

    async def test_only_the_active_credential_is_excluded(self):
        principal, code = self.invite()
        self.assertEqual(status((await self.redeem(code))[1]), 204)
        for _ in range(2):
            self.elapse(seconds=1)
            secret, code = new_invitation_code()
            self.store.issue_enrollment(principal.id, secret, self.ceremony_clock() + INVITATION_LIFETIME)
            self.assertEqual(status((await self.redeem(code))[1]), 204)
        with closing(self.database.connect()) as connection:
            active, revoked, inconsistent = [bytes(row[0]) for row in connection.execute(
                "SELECT credential_id FROM access_credentials WHERE principal_id=? ORDER BY enrolled_at_us",
                (str(principal.id),))]
        with self.store._transaction(write=True) as connection:
            handle = connection.execute("SELECT handle FROM access_credentials WHERE credential_id=?",
                                        (revoked,)).fetchone()[0]
            self.store.revoke_credential_on(connection, principal.id, handle, at=self.ceremony_clock())
        self.store.mark_credential_inconsistent(inconsistent, principal.id, at=self.ceremony_clock())
        secret, code = new_invitation_code()
        self.store.issue_enrollment(principal.id, secret, self.ceremony_clock() + INVITATION_LIFETIME)
        begun = await self.options(code)
        self.assertEqual(status(begun), 200)
        self.assertEqual(payload(begun)["excludeCredentials"],
                         [{"type": "public-key", "id": webauthn.b64url_encode(active)}])


class DeviceBoundOrderTests(RedemptionFixture):
    """PR #234 review: the 409 only after the invitation is re-validated."""

    async def test_the_409_needs_a_still_valid_invitation_bound_to_the_challenge(self):
        self.ceremonies.require_device_bound = True
        expected = await self.denial()
        _, first = self.invite()
        _, second = self.invite()
        begun = await self.options(first)
        credential = SyntheticAuthenticator(backup_eligible=True).register(payload(begun), origin=ORIGIN,
                                                                           rp_id=HOST)
        # Another valid code than the one the challenge was bound to.
        self.assertEqual(await self.finish(second, credential), expected)
        # The invitation expired between the two steps.
        _, code = self.invite(lifetime=timedelta(minutes=3))
        begun = await self.options(code)
        credential = SyntheticAuthenticator(backup_eligible=True).register(payload(begun), origin=ORIGIN,
                                                                           rp_id=HOST)
        self.elapse(minutes=4)
        self.assertEqual(await self.finish(code, credential), expected)
        self.assertEqual(self.count("SELECT count(*) FROM access_credentials"), 0)


if __name__ == "__main__":
    unittest.main()
