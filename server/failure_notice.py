# server-sentinel-failure-notice: placed by the ServerSentinel Main installer (Issue #321)
"""Send one fixed Slack message when ``server-sentinel.service`` has failed.

Issue #321 item 2 (Owner decision 2026-11-05): the monitoring runtime runs
inside the service, so a service that cannot start (its ``--check`` refuses,
or the release is broken) could not tell anyone. systemd starts
``server-sentinel-failure-notice.service`` through ``OnFailure=`` when the
service enters the failed state, and that unit runs this file.

The installer copies this file unchanged to the installation root (outside
every release) and runs it with the host interpreter, isolated
(``python3 -I -S``), so it neither imports the application nor depends on the
release, its virtual environment or the runtime filesystem. It uses the
standard library only.

It reads only ``monitoring.slack_webhook_url`` from the deployment
configuration and accepts it only under the rules of
``app/notifications/slack.py`` (``SlackEndpoint``). It sends one fixed text
that holds no value (``MESSAGE``), through no proxy and no redirect, with a
bounded timeout and at most ``ATTEMPTS`` attempts. It prints one fixed line
of its own on stderr (the journal); no URL, path, configuration value,
response or exception text ever leaves it.

At most one notice per failure episode: the time of the last notice sent is
kept in the unit's ``RuntimeDirectory=`` (``/run``, independent of the
runtime root), and a further failure less than ``COOLDOWN_SECONDS`` later in
the same boot is suppressed. ``/run`` starts empty at every boot, so the
first failure of every boot is reported.

With ``--unless-active`` (``server-sentinel-start-watch.service``, started
once per boot by its timer; PR #392 review P1) it first asks systemd whether
the service is active and sends nothing when it is. That covers a start that
never ran because a dependency failed (the runtime mount of
``RequiresMountsFor=``): such a start job fails without putting the service
into the failed state, so ``OnFailure=`` never fires. A state that cannot be
read counts as not active: a spurious notice rather than a silent outage.
"""

import fcntl
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


MESSAGE = "ServerSentinel critical alert: service_start_failed"
# The deployment loader's own bound (app/deployment.py MAX_CONFIGURATION_BYTES).
MAX_CONFIGURATION_BYTES = 16 * 1024
TIMEOUT_SECONDS = 10
# Three attempts, 15 s apart: at most 3 * 10 + 2 * 15 = 60 s of delivery.
# Only a failure that a later attempt can fix (no answer, 429, 5xx) is retried.
ATTEMPTS = 3
RETRY_SECONDS = 15
COOLDOWN_SECONDS = 3600
STATE_FILE = "last-notice"
LOCK_FILE = "lock"
# The other unit holds the lock for at most one delivery (DELIVERY_SECONDS,
# 60 s); past this the notice is tried without it rather than not at all.
LOCK_WAIT_SECONDS = 65
LOCK_POLL_SECONDS = 0.5
MAX_STATE_BYTES = 32
PREFIX = "ServerSentinel failure notice: "
SERVICE = "server-sentinel.service"
SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMCTL_TIMEOUT_SECONDS = 10
# The longest one run can take (PR #392 review): the watch's state query, the
# wait for the other unit's lock, and a whole delivery. The installer derives
# both units' TimeoutStartSec= from it (plus a margin for name resolution and
# the configuration read, which the socket timeout does not bound), so
# systemd never stops a run that would still have sent the notice.
DELIVERY_SECONDS = ATTEMPTS * TIMEOUT_SECONDS + (ATTEMPTS - 1) * RETRY_SECONDS
WORST_CASE_SECONDS = SYSTEMCTL_TIMEOUT_SECONDS + LOCK_WAIT_SECONDS + DELIVERY_SECONDS
SLACK_PATH = re.compile(r"/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def valid_endpoint(url: object) -> bool:
    """The rules of ``SlackEndpoint`` (app/notifications/slack.py), standard library only."""
    try:
        if not isinstance(url, str) or any(ord(character) <= 32 for character in url):
            return False
        parsed = urlsplit(url)
        return (parsed.scheme == "https" and parsed.hostname == "hooks.slack.com"
                and parsed.port in (None, 443) and not parsed.username and not parsed.password
                and not parsed.query and not parsed.fragment
                and bool(SLACK_PATH.fullmatch(parsed.path)) and len(url) <= 2048)
    except (ValueError, TypeError, AttributeError):
        return False


def read_webhook(path: str) -> tuple[str, str | None]:
    """``("configured", url)``, ``("not_configured", None)`` or ``("unavailable", None)``.

    Only ``monitoring.slack_webhook_url`` is read; nothing else in the file is
    validated, so a configuration that the release refuses for another
    reason still yields its webhook.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return "unavailable", None
            content = stream.read(MAX_CONFIGURATION_BYTES + 1)
        if len(content) > MAX_CONFIGURATION_BYTES:
            return "unavailable", None
        value = json.loads(content)
    except Exception:
        return "unavailable", None
    if not isinstance(value, dict):
        return "unavailable", None
    monitoring = value.get("monitoring")
    if monitoring is None or isinstance(monitoring, dict) and "slack_webhook_url" not in monitoring:
        return "not_configured", None
    if not isinstance(monitoring, dict) or not valid_endpoint(monitoring["slack_webhook_url"]):
        return "unavailable", None
    return "configured", monitoring["slack_webhook_url"]


def send(url: str, *, opener=None, timeout=TIMEOUT_SECONDS) -> str:
    """One bounded HTTPS POST: ``"sent"``, ``"rejected"`` (final) or ``"failed"`` (retryable)."""
    try:
        opener = opener or build_opener(
            ProxyHandler({}), NoRedirect(), HTTPSHandler(context=ssl.create_default_context()),
        )
        request = Request(url, data=json.dumps({"text": MESSAGE}, ensure_ascii=True).encode("ascii"),
                          headers={"Content-Type": "application/json"}, method="POST")
        with opener.open(request, timeout=timeout) as response:
            body = response.read(33)
            if response.status == 200 and len(body) <= 32 and body.strip() == b"ok":
                return "sent"
            return "rejected"
    except HTTPError as error:
        code = getattr(error, "code", None)
        # The error owns a response stream; close it so no cleanup warning can
        # later print its URL.
        try:
            error.close()
        except Exception:
            pass
        if isinstance(code, int) and (code == 429 or code >= 500):
            return "failed"
        return "rejected"
    except Exception:
        # No URL, response, exception text or cause leaves here.
        return "failed"


def service_active(runner=subprocess.run) -> bool:
    """Whether systemd reports ``server-sentinel.service`` as active; unknown is False."""
    try:
        result = runner([SYSTEMCTL, "show", "--property=ActiveState", "--value", SERVICE],
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, timeout=SYSTEMCTL_TIMEOUT_SECONDS,
                        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SYSTEMD_PAGER": "",
                             "SYSTEMD_COLORS": "0"}, check=False)
        return result.returncode == 0 and result.stdout.strip() == b"active"
    except Exception:
        return False


def _state_path(environ) -> str | None:
    directory = environ.get("RUNTIME_DIRECTORY")
    # systemd sets one absolute directory for one RuntimeDirectory= entry.
    if not isinstance(directory, str) or not directory.startswith("/") or ":" in directory:
        return None
    return os.path.join(directory, STATE_FILE)


def recently_notified(path: str | None, now: float) -> bool:
    if path is None:
        return False
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            content = stream.read(MAX_STATE_BYTES + 1)
        text = content.decode("ascii").strip()
        if len(content) > MAX_STATE_BYTES or not re.fullmatch(r"[0-9]{1,15}", text):
            return False
        last = int(text)
    except Exception:
        return False
    # A time in the future cannot come from this boot's clock: not trusted.
    return 0 <= now - last < COOLDOWN_SECONDS


def record_notice(path: str | None, now: float) -> None:
    if path is None:
        return
    temporary = path + ".new"
    try:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                             | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(str(int(now)).encode("ascii"))
        os.replace(temporary, path)
    except Exception:
        # A notice that cannot be remembered may be repeated; never lost.
        pass


def _lock(directory: str | None, *, monotonic=time.monotonic, sleep=time.sleep):
    """Hold an exclusive lock in the runtime directory, or ``None``.

    The notice unit and the start watch share the directory; holding the lock
    over check, delivery and record keeps one failure seen by both from being
    sent twice (PR #392 review). A lock that cannot be opened or is not
    released within ``LOCK_WAIT_SECONDS`` is given up: a duplicate is better
    than a lost notice.
    """
    if directory is None:
        return None
    try:
        descriptor = os.open(os.path.join(directory, LOCK_FILE),
                             os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    except Exception:
        return None
    deadline = monotonic() + LOCK_WAIT_SECONDS
    while True:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor
        except BlockingIOError:
            if monotonic() >= deadline:
                break
            sleep(LOCK_POLL_SECONDS)
        except Exception:
            break
    os.close(descriptor)
    return None


def _unlock(descriptor) -> None:
    if descriptor is not None:
        try:
            os.close(descriptor)
        except Exception:
            pass


def _boot_clock() -> float:
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def _say(stream, words: str) -> None:
    try:
        stream.write(PREFIX + words + "\n")
        stream.flush()
    except Exception:
        pass


def run(config: str, *, environ=None, opener=None, clock=_boot_clock, sleep=time.sleep,
        stderr=None, unless_active=False, runner=subprocess.run) -> int:
    environ = os.environ if environ is None else environ
    stderr = sys.stderr if stderr is None else stderr
    if unless_active and service_active(runner):
        _say(stderr, "not sent (reason=service_active)")
        return 0
    state = _state_path(environ)
    lock = _lock(os.path.dirname(state) if state else None, sleep=sleep)
    try:
        return _notify(config, state, opener=opener, clock=clock, sleep=sleep, stderr=stderr)
    finally:
        _unlock(lock)


def _notify(config, state, *, opener, clock, sleep, stderr) -> int:
    now = clock()
    if recently_notified(state, now):
        _say(stderr, "suppressed (reason=recent_notice)")
        return 0
    status, url = read_webhook(config)
    if status == "not_configured":
        _say(stderr, "not sent (reason=slack_not_configured)")
        return 0
    if status != "configured":
        _say(stderr, "not sent (reason=webhook_unavailable)")
        return 1
    result = "failed"
    for attempt in range(ATTEMPTS):
        if attempt:
            sleep(RETRY_SECONDS)
        result = send(url, opener=opener)
        if result != "failed":
            break
    if result == "sent":
        record_notice(state, clock())
        _say(stderr, "sent")
        return 0
    _say(stderr, "not sent (reason=delivery_" + ("rejected" if result == "rejected" else "failed")
         + ")")
    return 1


def main(arguments=None) -> int:
    arguments = sys.argv[1:] if arguments is None else arguments
    unless_active = arguments[2:] == ["--unless-active"]
    if (len(arguments) != 2 + unless_active or arguments[0] != "--config"
            or not arguments[1].startswith("/")):
        _say(sys.stderr, "not sent (reason=usage)")
        return 2
    return run(arguments[1], unless_active=unless_active)


if __name__ == "__main__":
    raise SystemExit(main())
