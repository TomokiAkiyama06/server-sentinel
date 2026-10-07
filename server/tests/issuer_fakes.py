"""Test-only seams for the pairing CLI's privilege separation (Issue #109).

Unit tests run unprivileged and in one process, so they replace the two
seams of ``pairing_cli``: the root start and account drops
(``SameAccountPrivileges``) and the forked CA child (``InProcessIssuer``,
which runs the real ``CaIssuer`` handler in this process and passes every
message through JSON exactly as the pipe does). The real fork, the real drops
and two real accounts are covered by ``test_issuer_process`` (fork, same
account) and ``test_ca_privilege_separation_root`` (root only).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

from app.cameras.remote_agent import pairing_cli
from app.cameras.remote_agent.issuer_process import Account, CaIssuer, IssuerUnavailable
from app.cameras.remote_agent.node_ca import PrivateDirectory


class SameAccountPrivileges:
    """No root start and no account change: both "accounts" are this process's."""

    def __init__(self):
        self.events: list[str] = []

    def require_start(self) -> None:
        self.events.append("start")

    def account(self, name: str) -> Account:
        return Account(os.getuid(), os.getgid())

    def check_accounts(self, ca: Account, service: Account) -> None:
        self.events.append("accounts")

    def drop(self, account: Account) -> None:
        self.events.append("drop")

    def harden_child(self) -> None:
        self.events.append("harden")

    def require_ca_directory_closed(self, path: Path) -> None:
        self.events.append("ca_closed")


class InProcessIssuer:
    """The CA child's handler in this process, behind the same JSON boundary."""

    instances: list["InProcessIssuer"] = []

    def __init__(self, authority_path: Path, events: list[str]):
        self.handler = CaIssuer(PrivateDirectory(Path(authority_path)))
        self.operations: list[str] = []
        self.events = events
        self.closed = False
        self.finished = False
        InProcessIssuer.instances.append(self)

    def request(self, message: dict) -> dict:
        if self.closed:
            raise IssuerUnavailable("issuer channel is closed")
        message = json.loads(json.dumps(message))
        self.operations.append(message.get("op"))
        self.events.append("issuer:" + str(message.get("op")))
        return json.loads(json.dumps(self.handler.handle(message)))

    def finish(self) -> None:
        self.close()
        self.finished = True
        self.events.append("issuer:exited")

    def close(self) -> None:
        if not self.closed:
            self.handler.close()
            self.closed = True


def install(test_case) -> SameAccountPrivileges:
    """Patch ``pairing_cli`` for the rest of ``test_case``; returns the event recorder."""
    privileges = SameAccountPrivileges()
    InProcessIssuer.instances = []

    def start(authority_path, ca, chosen):
        privileges.events.append("fork")
        return InProcessIssuer(authority_path, privileges.events)

    for target, value in (("_PRIVILEGES", privileges), ("_start_issuer", start)):
        patcher = patch.object(pairing_cli, target, value)
        patcher.start()
        test_case.addCleanup(patcher.stop)
    return privileges
