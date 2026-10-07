"""Test-only launcher for the Main pairing CLI on an unprivileged CI runner.

Runs the real ``pairing_cli.main`` with the real forked CA child, pipes and
issuer, replacing only the root start and the two account drops
(``issuer_process.OsPrivileges``) with no-ops, because CI runs as one
unprivileged account (Issue #109). The two-account behaviour itself is
covered by ``server/tests/test_ca_privilege_separation_root.py`` (root only).
Production has no switch that selects this; it exists only under tests/.
"""
from __future__ import annotations

import os
from pathlib import Path

from app.cameras.remote_agent import pairing_cli
from app.cameras.remote_agent.issuer_process import Account


class SameAccountPrivileges:
    def require_start(self) -> None:
        pass

    def account(self, name: str) -> Account:
        return Account(os.getuid(), os.getgid())

    def check_accounts(self, ca: Account, service: Account) -> None:
        pass

    def drop(self, account: Account) -> None:
        # The real drop's own invariants that hold without root still hold.
        if os.geteuid() == 0:
            raise SystemExit("this launcher refuses to run as root")

    def harden_child(self) -> None:
        pass

    def require_ca_directory_closed(self, path: Path, *, missing_ok: bool = False) -> None:
        pass


if __name__ == "__main__":
    pairing_cli._PRIVILEGES = SameAccountPrivileges()
    raise SystemExit(pairing_cli.main())
