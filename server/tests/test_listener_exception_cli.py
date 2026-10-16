"""Issue #10 (Owner decision D3, 2026-10-16): the local listener-exception command.

``python -m app.auth.reservation_cli show|set``. Synthetic only: a temporary
SQLite database, a pseudo-terminal from ``os.openpty`` standing in for the
controlling terminal, synthetic ``/proc/net`` rows and socket creators, and a
replaced deployment loader. No sudo, real terminal, tailscaled, socket or
deployment database; mock only.
"""

from contextlib import closing, redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from app.audit.store import AuditStore
from app.auth import reservation_cli
from app.auth.access_config import parse_human_access
from app.auth.reservation import (
    AddressFamily, BindScope, CheckKind, ListenerException, MAX_LISTENER_EXCEPTIONS, MAX_UID, TransportProtocol,
)
from app.auth.reservation_store import (
    RESERVATION_LISTENER_EXCEPTIONS_ID, STORE_KEY, ListenerExceptionStore, decode,
)
from app.local_admin import CliRefused
from app.storage.database import Database
from app.storage.migrations import migrate
from app.storage.schema import APPLICATION_MIGRATIONS

from tests.test_bootstrap_cli import AUDIT, NOW, Console
from tests.test_hostname_reservation import (
    HOST, HUMAN, TAILSCALED_CREATOR, FakeRevoker, Files, Owners, Sink, checker, config, proc, V4, V6,
)


SSH_ARG = "protocol=tcp,port=22,unit=ssh.socket,uid=0"
WG_ARG = "protocol=udp,port=41641,unit=tailscaled.service,uid=0"
PEER_ARG = "scope=reserved_address,protocol=tcp,port=43210,family=ipv4,unit=tailscaled.service,uid=0"
SSH = ListenerException(22, unit="ssh.socket", uid=0)
WG = ListenerException(41641, TransportProtocol.UDP, unit="tailscaled.service", uid=0)
PEER = ListenerException(43210, family=AddressFamily.IPV4, scope=BindScope.RESERVED_ADDRESS,
                         unit="tailscaled.service", uid=0)
SSH_LINE = "scope=wildcard,protocol=tcp,port=22,family=any,unit=ssh.socket,uid=0"
WG_LINE = "scope=wildcard,protocol=udp,port=41641,family=any,unit=tailscaled.service,uid=0"
PEER_LINE = "scope=reserved_address,protocol=tcp,port=43210,family=ipv4,unit=tailscaled.service,uid=0"
CHANGE = (reservation_cli.CHANGE_WORD,)
# The ``human_access`` section stating ``config()``'s reservation, with the
# upstream ``Deployment.load`` sets from ``human_host`` / ``human_port``.
SECTION = {"enabled": True, "hostname": HOST, "reserved_addresses": [str(V4), str(V6)],
           "isolation": "single_purpose_node", "tailscale_executable": "/usr/bin/tailscale"}


def human_access(**changes):
    return replace(parse_human_access({**SECTION, **changes}),
                   upstream_host=str(HUMAN.address), upstream_port=HUMAN.port)


class ListenerExceptionCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(os.path.realpath(temporary.name))
        self.path = self.root / "state.sqlite3"
        self.database = Database(self.path)
        with closing(self.database.connect()) as connection:
            migrate(connection, APPLICATION_MIGRATIONS)
        self.clock = lambda: NOW
        self.config = self.root / "deployment.json"
        self.service_uid = os.geteuid()
        self.human_access = human_access()
        self.loaded = []

    def deployment(self, path):
        def load(config_path):
            self.loaded.append(config_path)
            return SimpleNamespace(service_uid=self.service_uid, human_access=self.human_access,
                                   settings=SimpleNamespace(database_path=path))
        return load

    def run_cli(self, command, *arguments, lines=(), console=None, path=None, terminal_factory=None):
        console = console or Console(self)
        console.type(*lines)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr), \
                patch.object(reservation_cli, "_load_deployment", self.deployment(path or self.path)):
            code = reservation_cli.main([command, "--config", str(self.config), *arguments],
                                        terminal_factory=terminal_factory or console.factory, clock=self.clock)
        self.console = console
        return code, stdout.getvalue(), stderr.getvalue(), console.output().replace("\r\n", "\n")

    def rows(self, sql, *parameters):
        with closing(self.database.connect()) as connection:
            return [tuple(row) for row in connection.execute(sql, parameters)]

    def stored(self):
        rows = self.rows("SELECT value FROM application_metadata WHERE key=?", STORE_KEY)
        return rows[0][0] if rows else None

    def store_raw(self, value):
        with closing(self.database.connect()) as connection:
            connection.execute("INSERT OR REPLACE INTO application_metadata VALUES (?, ?)", (STORE_KEY, value))
            connection.commit()

    def assert_refused(self, result, reason):
        code, stdout, stderr, _ = result
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn(f"refused: {reason}\n", stderr)

    def assert_unchanged(self, stored=None):
        self.assertEqual(self.stored(), stored)
        self.assertEqual(self.rows(AUDIT), [])

    # -- set ------------------------------------------------------------------

    def test_set_stores_the_set_and_its_owner_audit_record_together(self):
        code, stdout, stderr, terminal = self.run_cli("set", SSH_ARG, WG_ARG, PEER_ARG, lines=CHANGE)
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(decode(self.stored()), frozenset({SSH, WG, PEER}))
        self.assertEqual(self.rows(AUDIT), [("owner", "change_security_setting", "security_settings",
                                            str(RESERVATION_LISTENER_EXCEPTIONS_ID), "succeeded")])
        # Standard output is value-free: the count and the restart reminder.
        self.assertEqual(stdout.splitlines(), ["listener exceptions stored: 3",
                                               "note: " + reservation_cli.RESTART_NOTE])
        # The terminal showed the stored and the new set before asking.
        self.assertIn("Stored listener exceptions:\n  (none)\n", terminal)
        for line in (SSH_LINE, WG_LINE, PEER_LINE):
            self.assertIn("  " + line + "\n", terminal)
        self.assertIn("restart server-sentinel.service", terminal)
        self.assertIn("Type CHANGE to confirm: ", terminal)
        self.assertEqual(self.console.opened, 1)
        self.assertEqual(self.loaded, [self.config])

    def test_the_audit_record_carries_no_port_unit_or_address(self):
        self.run_cli("set", SSH_ARG, PEER_ARG, lines=CHANGE)
        with closing(self.database.connect()) as connection:
            dump = "\n".join(connection.iterdump())
        audit_rows = "\n".join(str(row) for row in self.rows("SELECT * FROM security_admin_audit_records"))
        for value in ("43210", "ssh.socket", "tailscaled", "reserved_address", str(V6)):
            self.assertNotIn(value, audit_rows)
        self.assertIn("ssh.socket", dump)  # only in the stored set itself

    def test_show_prints_the_stored_set_in_argument_form(self):
        code, stdout, stderr, _ = self.run_cli("show")
        self.assertEqual((code, stdout, stderr), (0, "no listener exceptions\n", ""))
        self.run_cli("set", PEER_ARG, WG_ARG, SSH_ARG, lines=CHANGE)
        code, stdout, stderr, _ = self.run_cli("show")
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(stdout.splitlines(), sorted([SSH_LINE, WG_LINE, PEER_LINE]))
        # What show prints is accepted by set unchanged.
        for line in stdout.splitlines():
            self.assertIn(reservation_cli.parse_exception(line), {SSH, WG, PEER})
        # show writes and audits nothing.
        self.assertEqual(len(self.rows(AUDIT)), 1)

    def test_the_service_applies_the_stored_set_at_its_next_startup(self):
        # The command stores; a check starting afterwards (a restart) loads it.
        files = Files(tcp=proc(("127.0.0.1", 8080, "0A"), ("100.64.0.10", 43210, "0A")))
        store = ListenerExceptionStore(self.database)
        running, *_ = checker(files=Files(**files.raw), exception_store=store,
                              socket_owners=Owners(TAILSCALED_CREATOR), session_revoker=FakeRevoker())
        self.assertFalse(running.startup().open)
        self.assertEqual(self.run_cli("set", PEER_ARG, lines=CHANGE)[0], 0)
        # The running check keeps the set it loaded at startup.
        self.assertEqual(running.listener_exceptions, frozenset())
        self.assertFalse(running._check(CheckKind.RETRY).open)
        restarted, *_ = checker(files=Files(**files.raw), exception_store=store,
                                socket_owners=Owners(TAILSCALED_CREATOR), session_revoker=FakeRevoker(),
                                sink=Sink())
        self.assertTrue(restarted.startup().open)
        self.assertEqual(restarted.listener_exceptions, frozenset({PEER}))

    def test_clear_stores_the_empty_set(self):
        self.run_cli("set", SSH_ARG, lines=CHANGE)
        code, stdout, _, terminal = self.run_cli("set", "--clear", lines=CHANGE)
        self.assertEqual(code, 0)
        self.assertEqual(decode(self.stored()), frozenset())
        self.assertEqual(json.loads(self.stored()), {"version": 3, "exceptions": []})
        self.assertEqual(stdout.splitlines()[0], "listener exceptions stored: 0")
        self.assertIn("New listener exceptions (replacing the whole set):\n  (none)\n", terminal)
        self.assertEqual(len(self.rows(AUDIT)), 2)

    def test_a_declined_confirmation_changes_and_records_nothing(self):
        for answer in ("", "change", "CHANGE now", "yes"):
            with self.subTest(answer=answer):
                self.assert_refused(self.run_cli("set", SSH_ARG, lines=(answer,)), "owner_confirmation_declined")
                self.assert_unchanged()

    def test_rejected_exceptions_refuse_before_the_terminal_opens(self):
        cases = {
            "unknown field": "protocol=tcp,port=22,unit=ssh.socket,uid=0,executable=/usr/sbin/sshd",
            "repeated field": "protocol=tcp,port=22,port=23,unit=ssh.socket,uid=0",
            "missing unit": "protocol=tcp,port=22,uid=0",
            "missing uid": "protocol=tcp,port=22,unit=ssh.socket",
            "empty value": "protocol=tcp,port=,unit=ssh.socket,uid=0",
            "no separator": "protocol=tcp,port=22,unit=ssh.socket,uid",
            "leading zero port": "protocol=tcp,port=022,unit=ssh.socket,uid=0",
            "signed port": "protocol=tcp,port=+22,unit=ssh.socket,uid=0",
            "negative uid": "protocol=tcp,port=22,unit=ssh.socket,uid=-1",
            "unknown protocol": "protocol=sctp,port=22,unit=ssh.socket,uid=0",
            "unknown family": "protocol=tcp,port=22,family=inet,unit=ssh.socket,uid=0",
            "ipv6 wildcard": "protocol=tcp,port=22,family=ipv6,unit=ssh.socket,uid=0",
            "unknown scope": "scope=reserved,protocol=tcp,port=22,unit=ssh.socket,uid=0",
            "scope unit": "protocol=tcp,port=22,unit=ssh.target,uid=0",
            "served port": "protocol=tcp,port=443,unit=ssh.socket,uid=0",
            "served port udp": "protocol=udp,port=443,unit=tailscaled.service,uid=0",
            "upstream port": "protocol=tcp,port=8080,unit=ssh.socket,uid=0",
            "reserved served port": "scope=reserved_address,protocol=tcp,port=443,unit=tailscaled.service,uid=0",
            "reserved udp": "scope=reserved_address,protocol=udp,port=43210,unit=tailscaled.service,uid=0",
            "reserved other unit": "scope=reserved_address,protocol=tcp,port=43210,unit=ssh.socket,uid=0",
            "reserved other uid": "scope=reserved_address,protocol=tcp,port=43210,unit=tailscaled.service,uid=1",
            "too long": "protocol=tcp,port=22,unit=" + "a" * 300 + ".service,uid=0",
            "spaces": "protocol=tcp, port=22,unit=ssh.socket,uid=0",
        }
        for name, argument in cases.items():
            with self.subTest(name):
                factory_calls = []
                result = self.run_cli("set", argument, terminal_factory=lambda: factory_calls.append(1))
                self.assert_refused(result, "listener_exception_rejected")
                self.assertEqual(factory_calls, [])
                self.assert_unchanged()
        sets = {"repeated exception": (SSH_ARG, SSH_ARG),
                "too many": tuple(f"protocol=tcp,port={port},unit=ssh.socket,uid=0"
                                  for port in range(1000, 1001 + MAX_LISTENER_EXCEPTIONS)),
                "clear and a set": ("--clear", SSH_ARG),
                # Issue #278: one reserved-address exception per family.
                "second peer port": (PEER_ARG, PEER_ARG.replace("port=43210", "port=43211")),
                "peer port for both and ipv4": (PEER_ARG, PEER_ARG.replace(",family=ipv4", "").replace(
                    "port=43210", "port=43211")),
                "neither": ()}
        for name, arguments in sets.items():
            with self.subTest(name):
                self.assert_refused(self.run_cli("set", *arguments), "listener_exception_rejected")
                self.assert_unchanged()

    def test_set_needs_the_deployment_reservation(self):
        self.human_access = None
        self.assert_refused(self.run_cli("set", SSH_ARG, lines=CHANGE), "human_access_not_configured")
        self.assert_unchanged()
        # show does not: it only reads the stored set.
        self.assertEqual(self.run_cli("show")[0], 0)
        # Anything but the parsed section is refused.
        for broken in (SimpleNamespace(), SimpleNamespace(reservation_config=config)):
            with self.subTest(broken=broken):
                self.human_access = broken
                self.assert_refused(self.run_cli("set", SSH_ARG, lines=CHANGE), "deployment_configuration_rejected")
                self.assert_unchanged()
        # A section that states no usable reservation (its upstream unset,
        # so not loaded through ``Deployment.load``): refused, value-free.
        self.human_access = parse_human_access(SECTION)
        result = self.run_cli("set", SSH_ARG, lines=CHANGE)
        self.assert_refused(result, "human_access_configuration_rejected")
        self.assert_unchanged()
        for value in (HOST, str(V4), str(V6), "tailscale", str(HUMAN.port)):
            self.assertNotIn(value, result[2])

    def test_set_reads_the_reservation_the_section_states(self):
        self.assertEqual(self.human_access.reservation_config(), config())
        # A disabled section states the same reservation; the CLI accepts it.
        self.human_access = human_access(enabled=False)
        self.assertEqual(self.run_cli("set", SSH_ARG, lines=CHANGE)[0], 0)
        self.assertEqual(decode(self.stored()), frozenset({SSH}))
        # The section's port is the reservation's: an exception for it is refused.
        self.human_access = human_access(port=8443)
        self.assert_refused(self.run_cli("set", "protocol=tcp,port=8443,unit=ssh.socket,uid=0", lines=CHANGE),
                            "listener_exception_rejected")
        self.assertEqual(self.run_cli("set", "protocol=tcp,port=443,unit=ssh.socket,uid=0", lines=CHANGE)[0], 0)

    def test_the_stored_value_is_compared_again_inside_the_transaction(self):
        self.run_cli("set", SSH_ARG, lines=CHANGE)
        before = self.stored()
        console = Console(self)

        def factory():
            terminal = console.factory()
            original = terminal.read_line

            def read_line():
                answer = original()
                # Another change lands after the set was shown, before the commit.
                self.store_raw('{"version":3,"exceptions":[]}')
                return answer
            terminal.read_line = read_line
            return terminal

        result = self.run_cli("set", WG_ARG, lines=CHANGE, console=console, terminal_factory=factory)
        self.assert_refused(result, "listener_exceptions_changed")
        self.assertNotEqual(self.stored(), before)
        self.assertEqual(decode(self.stored()), frozenset())
        self.assertEqual(len(self.rows(AUDIT)), 1)

    def test_unreadable_or_outdated_stored_sets_are_not_shown_but_can_be_replaced(self):
        outdated = '{"version":2,"exceptions":[{"protocol":"tcp","port":22,"family":null,"scope":"wildcard",' \
                   '"executable":"/usr/sbin/sshd","unit":null}]}'
        for raw, reason in (("{corrupt", "stored_exceptions_unreadable"),
                            ('{"version":3,"exceptions":[{"protocol":"udp","port":43210,"family":null,'
                             '"scope":"reserved_address","unit":"tailscaled.service","uid":0}]}',
                             "stored_exceptions_unreadable"),
                            (outdated, "stored_exceptions_outdated")):
            with self.subTest(reason=reason, raw=raw[:20]):
                records = len(self.rows(AUDIT))
                self.store_raw(raw)
                code, stdout, stderr, _ = self.run_cli("show")
                self.assert_refused((code, stdout, stderr, None), reason)
                self.assertNotIn("sshd", stderr)
                code, _, _, terminal = self.run_cli("set", SSH_ARG, lines=CHANGE)
                self.assertEqual(code, 0)
                self.assertIn("(the stored set cannot be read; it is replaced)", terminal)
                self.assertNotIn("sshd", terminal)
                self.assertEqual(decode(self.stored()), frozenset({SSH}))
                self.assertEqual(len(self.rows(AUDIT)), records + 1)

    def test_account_terminal_and_database_refusals_change_nothing(self):
        with patch.object(reservation_cli.os, "geteuid", return_value=0):
            self.assert_refused(self.run_cli("set", SSH_ARG, lines=CHANGE), "run_as_service_account")
        self.service_uid = os.geteuid() + 1
        self.assert_refused(self.run_cli("set", SSH_ARG, lines=CHANGE), "run_as_service_account")
        self.assert_refused(self.run_cli("show"), "run_as_service_account")
        self.service_uid = os.geteuid()

        def no_terminal():
            raise CliRefused("controlling_terminal_required")
        for command in (("show",), ("set", SSH_ARG)):
            with self.subTest(command=command):
                self.assert_refused(self.run_cli(*command, terminal_factory=no_terminal),
                                    "controlling_terminal_required")
        self.assert_refused(self.run_cli("set", SSH_ARG, lines=CHANGE, path=self.root / "missing.sqlite3"),
                            "database_not_found")
        self.assertFalse((self.root / "missing.sqlite3").exists())
        self.assert_refused(self.run_cli("show", path=Path("relative.sqlite3")), "database_path_rejected")

        def failing_load(config_path):
            raise OSError("synthetic")
        with patch.object(reservation_cli, "_load_deployment", failing_load), \
                redirect_stderr(io.StringIO()) as stderr, redirect_stdout(io.StringIO()):
            self.assertEqual(reservation_cli.main(["show", "--config", str(self.config)]), 2)
        self.assertIn("refused: deployment_configuration_rejected", stderr.getvalue())
        self.assert_unchanged()

    def test_a_database_of_another_schema_is_refused(self):
        with closing(self.database.connect()) as connection:
            connection.execute("DELETE FROM schema_migrations WHERE version=(SELECT max(version) FROM schema_migrations)")
            connection.commit()
        self.assert_refused(self.run_cli("set", SSH_ARG, lines=CHANGE), "database_schema_outdated")
        self.assert_unchanged()

    def test_a_failed_write_rolls_back_with_its_audit_record(self):
        def failing_write(store, connection, exceptions):
            connection.execute("INSERT INTO application_metadata(key, value) VALUES (?, ?)", (STORE_KEY, "partial"))
            raise sqlite3.OperationalError("synthetic write failure")
        with patch.object(ListenerExceptionStore, "write_on", failing_write):
            self.assert_refused(self.run_cli("set", SSH_ARG, lines=CHANGE), "database_unavailable")
        self.assert_unchanged()

        def failing_append(audit, connection, **kwargs):
            raise sqlite3.OperationalError("synthetic append failure")
        with patch.object(AuditStore, "append_on", failing_append):
            self.assert_refused(self.run_cli("set", SSH_ARG, lines=CHANGE), "database_unavailable")
        self.assert_unchanged()

    def test_a_failed_check_after_the_commit_is_reported(self):
        calls = []

        def verify(database):
            calls.append(database)
            raise CliRefused("database_rejected")
        with patch.object(reservation_cli, "_verify_pinned", verify):
            code, stdout, stderr, _ = self.run_cli("set", SSH_ARG, lines=CHANGE)
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("refused: committed_verification_failed\n", stderr)
        self.assertIn("run 'show'", stderr)
        self.assertEqual(len(calls), 1)
        # Committed: the set and its audit record are both there.
        self.assertEqual(decode(self.stored()), frozenset({SSH}))
        self.assertEqual(len(self.rows(AUDIT)), 1)


class ParseTests(unittest.TestCase):
    def test_argument_form_round_trips(self):
        for item in (SSH, WG, PEER, ListenerException(5353, TransportProtocol.UDP, AddressFamily.IPV4,
                                                      unit="avahi-daemon.service", uid=103)):
            with self.subTest(item=item):
                self.assertEqual(reservation_cli.parse_exception(reservation_cli.format_exception(item)), item)
        self.assertEqual(reservation_cli.parse_exception(SSH_ARG), SSH)
        self.assertEqual(reservation_cli.parse_exception("uid=0,unit=ssh.socket,port=22,protocol=tcp"), SSH)
        self.assertEqual(reservation_cli.parse_exception(SSH_ARG + ",family=any,scope=wildcard"), SSH)
        # The longest valid exception (250-character unit stem, largest uid)
        # round-trips too: what ``show`` prints, ``set`` accepts.
        longest = ListenerException(65535, TransportProtocol.UDP, AddressFamily.IPV4,
                                    unit="u" * 250 + ".service", uid=MAX_UID)
        text = reservation_cli.format_exception(longest)
        self.assertLessEqual(len(text), reservation_cli.MAX_ARGUMENT_LENGTH)
        self.assertEqual(reservation_cli.parse_exception(text), longest)

    def test_non_string_or_empty_is_refused(self):
        for value in (None, 22, "", ",", "="):
            with self.subTest(value=value), self.assertRaises(CliRefused):
                reservation_cli.parse_exception(value)


if __name__ == "__main__":
    unittest.main()
