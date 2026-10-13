"""Explicit deployment settings, with value-free validation errors."""

from dataclasses import InitVar, dataclass, field
from datetime import timedelta
from ipaddress import ip_address
import os
from pathlib import Path
from typing import Mapping


# Invitation code lifetime (Owner decisions D5 and 2026-10-11): a deployment
# setting, default 24 hours, at most 7 days, in whole hours from 1. Defined
# here (standard library only) so the standalone installer, which bundles
# this module, validates the key too; ``app.auth.invitation_code`` re-exports.
INVITATION_LIFETIME = timedelta(hours=24)
MAX_INVITATION_LIFETIME = timedelta(days=7)


def invitation_lifetime(hours: object) -> timedelta:
    """The validated deployment invitation lifetime for a whole number of hours.

    ``1`` to ``168`` (7 days); anything else (a bool, a float, a string, out of
    range) raises ``ValueError`` with a fixed message that carries no value.
    """
    if type(hours) is not int or not 1 <= hours <= MAX_INVITATION_LIFETIME // timedelta(hours=1):
        raise ValueError("invitation lifetime is invalid")
    return timedelta(hours=hours)


def valid_invitation_lifetime(value: object) -> bool:
    """Whether ``value`` is a usable lifetime: a ``timedelta`` in (0, 7 days]."""
    return isinstance(value, timedelta) and timedelta(0) < value <= MAX_INVITATION_LIFETIME


class ConfigurationError(ValueError):
    """Invalid configuration; the message never contains supplied values."""


def _source_root() -> Path:
    module = Path(__file__).resolve()
    # A source checkout has a .git directory/file. The minimal container copies
    # only server/ into /app, so its protected code root is /app, never '/'.
    return next((parent for parent in module.parents if (parent / ".git").exists()),
                module.parents[1])


@dataclass(frozen=True)
class Settings:
    data_directory: Path = field(repr=False)
    human_host: str = "127.0.0.1"
    human_port: int = 8000
    log_level: str = "INFO"
    # Owner decision 2026-10-11: how long an invitation code stays valid,
    # default 24 hours, at most 7 days (deployment key
    # ``invitation_lifetime_hours``, whole hours 1-168).
    invitation_lifetime: timedelta = INVITATION_LIFETIME
    # Issue #10 phase 2 S5b: the verified Web build (``manifest.json``,
    # ``shell/``, ``app/``) the human surface serves, loaded once by
    # ``app.auth.web_assets.WebAssets.load``. ``None`` means no human
    # composition can be mounted (``create_app`` refuses one). Issue #10 S5c
    # points it at the release's own build directory.
    web_assets_dir: Path | None = field(default=None, repr=False)
    source_root: InitVar[Path | None] = None

    def __post_init__(self, source_root: Path | None) -> None:
        if not isinstance(self.data_directory, Path) or not self.data_directory.is_absolute():
            raise ConfigurationError("data_directory must be an absolute directory")
        try:
            directory = self.data_directory.resolve(strict=True)
            root = (source_root or _source_root()).resolve(strict=True)
            valid = directory.is_dir() and not directory.is_relative_to(root)
        except (OSError, RuntimeError, ValueError):
            raise ConfigurationError("data_directory is unavailable") from None
        if not valid:
            raise ConfigurationError("data_directory must exist outside the source tree")
        object.__setattr__(self, "data_directory", directory)
        try:
            loopback = isinstance(self.human_host, str) and ip_address(self.human_host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise ConfigurationError("human_host must be a loopback IP address")
        if type(self.human_port) is not int or not 1 <= self.human_port <= 65535:
            raise ConfigurationError("human_port must be an integer from 1 to 65535")
        if not isinstance(self.log_level, str) or self.log_level not in {"INFO", "WARNING", "ERROR"}:
            raise ConfigurationError("log_level must be INFO, WARNING or ERROR")
        if not valid_invitation_lifetime(self.invitation_lifetime):
            raise ConfigurationError("invitation_lifetime_hours must be an integer from 1 to 168")
        if self.web_assets_dir is not None and (not isinstance(self.web_assets_dir, Path)
                                                or not self.web_assets_dir.is_absolute()):
            raise ConfigurationError("web_assets_dir must be an absolute directory")

    @property
    def database_path(self) -> Path:
        return self.data_directory / "state.sqlite3"

    @property
    def session_binding_key_path(self) -> Path:
        """Deployment-local HMAC key for proxy-identity session bindings.

        Kept outside the database (ADR-0003/ADR-0004) and loaded or created
        with mode 0600 by ``app.auth.session_binding.SessionBindingKey``.
        """
        return self.data_directory / "session-binding.key"

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None, *,
                 source_root: Path | None = None) -> "Settings":
        values = os.environ if environ is None else environ
        prefix = "SERVERSENTINEL_"
        # CI markers are runner metadata only; they do not alter runtime policy.
        allowed = {"DATA_DIRECTORY", "HUMAN_HOST", "HUMAN_PORT", "LOG_LEVEL",
                   "CI_SYNTHETIC_ONLY", "CI_SCENARIO"}
        if any(key.startswith(prefix) and key[len(prefix):] not in allowed for key in values):
            raise ConfigurationError("unknown application setting")
        raw_directory = values.get(prefix + "DATA_DIRECTORY")
        if not raw_directory:
            raise ConfigurationError("data_directory is required")
        raw_port = values.get(prefix + "HUMAN_PORT", "8000")
        if not isinstance(raw_port, str) or not raw_port.isascii() or not raw_port.isdecimal():
            raise ConfigurationError("human_port must be an integer from 1 to 65535")
        try:
            return cls(
                data_directory=Path(raw_directory),
                human_host=values.get(prefix + "HUMAN_HOST", "127.0.0.1"),
                human_port=int(raw_port),
                log_level=values.get(prefix + "LOG_LEVEL", "INFO"),
                source_root=source_root,
            )
        except (TypeError, ValueError) as exc:
            if isinstance(exc, ConfigurationError):
                raise
            raise ConfigurationError("invalid application setting") from None
