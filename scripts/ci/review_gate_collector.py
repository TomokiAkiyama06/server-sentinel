"""Trusted provider review collector for the dedicated-App review gate (#4).

This module converts authenticated Codex / Claude GitHub pull-request reviews
into the fixed success Check Run request from ``review_gate_policy``.  It runs
only inside the Owner-controlled publisher deployment.  It never reads a PR
checkout, never executes a provider, never posts a review trigger, and never
publishes a check itself.

Provider reviews on GitHub carry only ``commit_id``; they do not name the base
branch commit, merge base, diff digest or the request that triggered them.  The
collector therefore binds a review to an exact ``Context`` indirectly:

* before a trigger is posted, it durably records a *review request* holding the
  complete live ``Context``, the highest review ID then visible on the PR (the
  watermark) and the request time;
* a review counts only when it comes from the exact Owner-configured provider
  bot identity, targets the recorded HEAD, has an ID above the watermark, and
  was submitted at least the configured maximum provider runtime (plus a clock
  skew allowance) after the request, so a review started under an older base
  cannot be attributed to the new context;
* the complete live context is re-read before and after the reviews are read.
  Any HEAD / base / merge-base / diff / test-merge difference from the request
  permanently invalidates that request, so no receipt can be produced until a
  new request is recorded and a new review arrives;
* every qualifying trusted review of the HEAD must be a clean pass.  An early
  (ambiguous) failing review, a blocking finding, a missing pass marker or an
  unreadable review blocks.  Nothing here maps an error to success.

Every decision reason is a fixed code.  Neither review text, source, tokens nor
key material is logged or placed in an exception message.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import fcntl
import json
import logging
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any, Callable, Iterator, Mapping, Protocol

from scripts.ci.review_gate_policy import (CHECK_NAMES, Context, PolicyFailure,
                                           successful_check_run_request)
from scripts.ci import review_gate_publisher
from scripts.ci.review_gate_publisher import (AppCredentials, CachingGitHubTransport,
                                              GitHubTransport, GitObjectCache,
                                              PublisherFailure, _secure_private_bytes,
                                              publish_revocation, publish_success,
                                              success_is_latest_attempt)


LOG = logging.getLogger("server_sentinel.review_gate.collector")
COLLECTOR_CONFIG_ENV = "SERVER_SENTINEL_REVIEW_COLLECTOR_CONFIG"
LEDGER_SCHEMA_VERSION = 2
MAX_REVIEWS = 1000
MAX_REVIEW_COMMENTS = 300
# Trusted same-HEAD reviews above one watermark; each costs comment API pages.
MAX_CANDIDATE_REVIEWS = 20
LOCK_TIMEOUT_SECONDS = 30.0
MAX_TEXT_CHARS = 65536
MAX_LEDGER_BYTES = 16384
MAX_MARKERS = 32
MAX_MARKER_CHARS = 200
CLOCK_SKEW_ALLOWANCE_SECONDS = 300
MIN_PROVIDER_RUNTIME_SECONDS = 60
MAX_PROVIDER_RUNTIME_SECONDS = 86400
# Identities that any same-repository PR workflow can act as through its
# ordinary GITHUB_TOKEN.  They can never be configured as a review provider.
GITHUB_ACTIONS_USER_ID = 41898282
GITHUB_ACTIONS_APP_ID = 15368
_FORBIDDEN_LOGINS = frozenset({"github-actions[bot]", "dependabot[bot]"})
_BOT_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\[bot\]")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_SHA = re.compile(r"[0-9a-f]{40}")
_REQUEST_ID = re.compile(r"[0-9a-f]{32}")
_PASS_STATES = frozenset({"COMMENTED", "APPROVED"})
_PUBLICATION_STATES = frozenset({"publishing", "success", "revoking"})


class CollectorFailure(RuntimeError):
    """Fail-closed collector error; messages never include evidence contents."""


@dataclass(frozen=True)
class ProviderIdentity:
    """Owner-verified provider bot identity and result classification policy.

    ``user_id`` is GitHub's immutable numeric account ID of the provider's App
    bot user.  A login alone is display data; both must match.  The marker sets
    come from the trusted deployment configuration, never from a PR.
    """

    reviewer: str
    user_id: int
    user_login: str
    max_review_runtime_seconds: int
    pass_markers: tuple[str, ...]
    blocking_markers: tuple[str, ...]
    non_blocking_markers: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.reviewer, str) or self.reviewer not in CHECK_NAMES:
            raise CollectorFailure("unsupported reviewer")
        if (type(self.user_id) is not int or self.user_id <= 0
                or self.user_id == GITHUB_ACTIONS_USER_ID
                or not isinstance(self.user_login, str)
                or not _BOT_LOGIN.fullmatch(self.user_login)
                or self.user_login.lower() in _FORBIDDEN_LOGINS):
            raise CollectorFailure("a dedicated, Owner-verified provider bot is required")
        runtime = self.max_review_runtime_seconds
        if (type(runtime) is not int or runtime < MIN_PROVIDER_RUNTIME_SECONDS
                or runtime > MAX_PROVIDER_RUNTIME_SECONDS):
            raise CollectorFailure("invalid provider runtime bound")
        for markers, required in ((self.pass_markers, True),
                                  (self.blocking_markers, True),
                                  (self.non_blocking_markers, False)):
            if (not isinstance(markers, tuple) or len(markers) > MAX_MARKERS
                    or (required and not markers)
                    or any(not isinstance(marker, str) or not marker.strip()
                           or len(marker) > MAX_MARKER_CHARS for marker in markers)):
                raise CollectorFailure("invalid provider marker policy")
        if set(self.blocking_markers) & (set(self.pass_markers)
                                         | set(self.non_blocking_markers)):
            raise CollectorFailure("provider marker sets overlap")


@dataclass(frozen=True)
class Publication:
    """The success Check Run this collector posted, or may have posted.

    ``state == "publishing"`` is written *before* the success is sent, so a
    lost or malformed response, a crash, or a ledger write failure after
    GitHub accepted the post still leaves a record that later outcomes revoke.
    ``state == "revoking"`` is written *before* a superseding failure attempt
    is posted, so an interrupted revocation is retried and never read as the
    current success.  ``check_run_id`` is known only once GitHub confirmed the
    success (it may be absent while publishing or revoking).
    """

    request_id: str
    test_merge_sha: str
    check_run_id: int | None
    state: str

    def __post_init__(self) -> None:
        if (not isinstance(self.request_id, str)
                or not _REQUEST_ID.fullmatch(self.request_id)
                or not isinstance(self.test_merge_sha, str)
                or not _SHA.fullmatch(self.test_merge_sha)
                or self.state not in _PUBLICATION_STATES
                or not ((self.check_run_id is None and self.state != "success")
                        or (type(self.check_run_id) is int and self.check_run_id > 0))):
            raise CollectorFailure("invalid publication record")


@dataclass(frozen=True)
class ReviewRequest:
    reviewer: str
    request_id: str
    state: str
    context: Context
    review_watermark: int
    requested_at: int
    # Carried across superseding requests until the success is revoked.
    published: Publication | None = None

    def __post_init__(self) -> None:
        if (not isinstance(self.reviewer, str) or self.reviewer not in CHECK_NAMES
                or not isinstance(self.request_id, str)
                or not _REQUEST_ID.fullmatch(self.request_id)
                or self.state not in {"active", "invalidated"}
                or not isinstance(self.context, Context)
                or type(self.review_watermark) is not int or self.review_watermark < 0
                or type(self.requested_at) is not int or self.requested_at <= 0
                or not (self.published is None
                        or isinstance(self.published, Publication))):
            raise CollectorFailure("invalid review request record")


@dataclass(frozen=True)
class RequestOutcome:
    request: ReviewRequest
    created: bool


@dataclass(frozen=True)
class CollectorDecision:
    """``check_run_request`` is present only for ``status == "pass"``."""

    status: str
    reason: str
    reviewer: str
    request_id: str | None = None
    check_run_request: dict[str, Any] | None = None
    ignored_untrusted_reviews: int = 0
    context: Context | None = None


class ReviewSource(Protocol):
    """Authenticated, completely paginated provider review evidence.

    ``repository`` names the ``owner/name`` repository whose reviews the
    source reads; ``collect_and_publish`` refuses a source that does not name
    the configured repository.
    """

    repository: str

    def list_reviews(self, pr_number: int) -> list[dict[str, Any]]:
        ...

    def list_review_comments(self, pr_number: int,
                             review_id: int) -> list[dict[str, Any]]:
        ...


class ListTransport(Protocol):
    def get_list(self, path: str, token: str) -> list[Any]:
        ...


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CollectorFailure("duplicate field")
        result[key] = value
    return result


def _parse_timestamp(value: Any) -> int:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise CollectorFailure("invalid provider review timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise CollectorFailure("invalid provider review timestamp") from None
    return int(parsed.replace(tzinfo=timezone.utc).timestamp())


def _checked_reviews(reviews: Any) -> list[dict[str, Any]]:
    if not isinstance(reviews, list) or len(reviews) > MAX_REVIEWS:
        raise CollectorFailure("provider review listing is unavailable or too large")
    seen: set[int] = set()
    for review in reviews:
        if (not isinstance(review, dict) or type(review.get("id")) is not int
                or review["id"] <= 0 or review["id"] in seen):
            raise CollectorFailure("invalid provider review listing")
        seen.add(review["id"])
    return reviews


def _is_trusted(review: Mapping[str, Any], identity: ProviderIdentity) -> bool:
    """Return whether the review author is exactly the configured provider.

    Malformed author data fails closed.  A lookalike login, a matching login
    with another account ID, a non-bot account, and anything GitHub reports as
    performed via the shared Actions App are merely untrusted and ignored.
    """
    user = review.get("user")
    if user is None:
        return False  # GitHub reports deleted ("ghost") authors as null.
    if (not isinstance(user, dict) or type(user.get("id")) is not int
            or not isinstance(user.get("login"), str)):
        raise CollectorFailure("invalid provider review author")
    via = review.get("performed_via_github_app")
    if via is not None and (not isinstance(via, dict)
                            or via.get("id") == GITHUB_ACTIONS_APP_ID):
        return False
    return (user["id"] == identity.user_id
            and user["login"] == identity.user_login
            and user.get("type") == "Bot")


def _text(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > MAX_TEXT_CHARS:
        raise CollectorFailure("provider review text is invalid or too large")
    return value


def _review_passes(review: Mapping[str, Any], comments: Any,
                   identity: ProviderIdentity) -> bool:
    """Classify one trusted review; only explicit clean evidence passes."""
    body = _text(review.get("body"))
    if review.get("state") not in _PASS_STATES:
        return False
    if (not any(marker in body for marker in identity.pass_markers)
            or any(marker in body for marker in identity.blocking_markers)):
        return False
    if not isinstance(comments, list) or len(comments) > MAX_REVIEW_COMMENTS:
        raise CollectorFailure("provider review comments are unavailable or too large")
    for comment in comments:
        if (not isinstance(comment, dict)
                or comment.get("pull_request_review_id") != review["id"]):
            raise CollectorFailure("invalid provider review comment listing")
        text = _text(comment.get("body"))
        if (any(marker in text for marker in identity.blocking_markers)
                or not any(marker in text for marker in identity.non_blocking_markers)):
            return False
    return True


class LedgerStore:
    """Durable, private review-request records outside every checkout.

    Records survive publisher restarts; writes are atomic replace + fsync.  A
    corrupt or foreign record fails closed and needs an Owner decision; it is
    never silently discarded.
    """

    def __init__(self, state_dir: Path, checkout_root: Path) -> None:
        if not isinstance(state_dir, Path) or not state_dir.is_absolute():
            raise CollectorFailure("collector state directory must be absolute")
        try:
            info = os.lstat(state_dir)
            resolved = state_dir.resolve(strict=True)
            root = checkout_root.resolve(strict=True)
        except OSError:
            raise CollectorFailure("collector state directory is unavailable") from None
        if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077
                or info.st_uid != os.geteuid()):
            raise CollectorFailure("collector state directory must be a private directory")
        if resolved.is_relative_to(root):
            raise CollectorFailure("collector state must stay outside the checkout")
        self._dir = resolved

    def _name(self, repository_id: int, pr_number: int, reviewer: str) -> str:
        if (type(repository_id) is not int or repository_id <= 0
                or type(pr_number) is not int or pr_number <= 0
                or reviewer not in CHECK_NAMES):
            raise CollectorFailure("invalid review request key")
        return f"{repository_id}-{pr_number}-{reviewer}.json"

    @contextmanager
    def lock(self, repository_id: int, pr_number: int) -> Iterator[None]:
        """Serialize request / collection per PR across processes."""
        self._name(repository_id, pr_number, "codex")  # validates the key
        name = f"{repository_id}-{pr_number}"
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._dir / f"{name}.lock", flags, 0o600)
        except OSError:
            raise CollectorFailure("collector lock is unavailable") from None
        try:
            deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise CollectorFailure("collector lock is busy") from None
                    time.sleep(0.05)
                except OSError:
                    raise CollectorFailure("collector lock is unavailable") from None
            yield
        finally:
            os.close(descriptor)

    def load(self, repository_id: int, pr_number: int,
             reviewer: str) -> ReviewRequest | None:
        path = self._dir / self._name(repository_id, pr_number, reviewer)
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return None
        except OSError:
            raise CollectorFailure("review request ledger is unavailable") from None
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                    or info.st_uid != os.geteuid()
                    or info.st_size > MAX_LEDGER_BYTES):
                raise CollectorFailure("review request ledger is not a private record")
            raw = os.read(descriptor, MAX_LEDGER_BYTES + 1)
        except OSError:
            raise CollectorFailure("review request ledger is unavailable") from None
        finally:
            os.close(descriptor)
        if len(raw) > MAX_LEDGER_BYTES:
            raise CollectorFailure("review request ledger is not a private record")
        try:
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
            if (not isinstance(data, dict) or set(data) != {
                    "schema_version", "reviewer", "request_id", "state",
                    "context", "review_watermark", "requested_at", "published"}
                    or data["schema_version"] != LEDGER_SCHEMA_VERSION
                    or type(data["schema_version"]) is not int
                    or not isinstance(data["context"], dict)):
                raise CollectorFailure("review request ledger is corrupt")
            published = data["published"]
            if published is not None:
                if not isinstance(published, dict) or set(published) != {
                        "request_id", "test_merge_sha", "check_run_id", "state"}:
                    raise CollectorFailure("review request ledger is corrupt")
                published = Publication(**published)
            request = ReviewRequest(
                reviewer=data["reviewer"], request_id=data["request_id"],
                state=data["state"], context=Context(**data["context"]),
                review_watermark=data["review_watermark"],
                requested_at=data["requested_at"], published=published)
        except (UnicodeDecodeError, ValueError, TypeError, RecursionError,
                PolicyFailure, CollectorFailure):
            raise CollectorFailure("review request ledger is corrupt") from None
        if (request.reviewer != reviewer
                or request.context.repository_id != repository_id
                or request.context.pr_number != pr_number):
            raise CollectorFailure("review request ledger is corrupt")
        return request

    def save(self, request: ReviewRequest) -> None:
        name = self._name(request.context.repository_id,
                          request.context.pr_number, request.reviewer)
        payload = json.dumps({
            "schema_version": LEDGER_SCHEMA_VERSION,
            "reviewer": request.reviewer, "request_id": request.request_id,
            "state": request.state, "context": asdict(request.context),
            "review_watermark": request.review_watermark,
            "requested_at": request.requested_at,
            "published": (None if request.published is None
                          else asdict(request.published)),
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(payload) > MAX_LEDGER_BYTES:
            raise CollectorFailure("review request record exceeds size limit")
        temporary = self._dir / f".{name}.{secrets.token_hex(8)}.tmp"
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                 | getattr(os, "O_NOFOLLOW", 0))
        try:
            descriptor = os.open(temporary, flags, 0o600)
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, self._dir / name)
            directory = os.open(self._dir, os.O_RDONLY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise CollectorFailure("review request ledger write failed") from None


class ReviewCollector:
    """Record review requests and convert trusted results into receipts."""

    def __init__(self, store: LedgerStore,
                 identities: Mapping[str, ProviderIdentity],
                 clock: Callable[[], float] = time.time) -> None:
        if (not isinstance(identities, Mapping)
                or any(not isinstance(identity, ProviderIdentity)
                       or identity.reviewer != reviewer
                       for reviewer, identity in identities.items())):
            raise CollectorFailure("invalid provider identity policy")
        ids = [identity.user_id for identity in identities.values()]
        if len(set(ids)) != len(ids):
            raise CollectorFailure("providers must have distinct identities")
        self._store = store
        self._identities = dict(identities)
        self._clock = clock
        # Ledger keys whose superseding failure attempt may have been posted
        # without the ledger recording it (the ``revoking`` write failed).
        # Their standing publication is never reused as the current success.
        self._unrecorded_revocations: set[tuple[int, int, str]] = set()
        # Immutable commit/tree responses shared by every live-context read
        # of every reconciliation pass (mutable PR state is always re-read).
        self._git_objects = GitObjectCache()

    def _identity(self, reviewer: str) -> ProviderIdentity:
        identity = self._identities.get(reviewer) if isinstance(reviewer, str) else None
        if identity is None:
            raise CollectorFailure("reviewer is not configured")
        return identity

    def _now(self) -> int:
        now = self._clock()
        if not isinstance(now, (int, float)) or now <= 0:
            raise CollectorFailure("clock is unavailable")
        return int(now)

    def request_review(self, reviewer: str, live: Context, source: ReviewSource,
                       *, force_new: bool = False) -> RequestOutcome:
        """Durably record a request before the caller posts its trigger.

        Repeating the call for an unchanged active context returns the same
        request (``created=False``) so a retried trigger delivery does not
        create a second request.  ``force_new`` supersedes it, for example to
        re-review the same context after a failed provider run.  It is refused
        while a success this collector published still stands, because that
        success would keep satisfying the required check during the rerun;
        call ``revoke_published`` first.
        """
        self._identity(reviewer)
        if not isinstance(live, Context):
            raise CollectorFailure("invalid live context")
        with self._store.lock(live.repository_id, live.pr_number):
            existing = self._store.load(live.repository_id, live.pr_number, reviewer)
            if (existing is not None and existing.state == "active"
                    and existing.context == live and not force_new):
                return RequestOutcome(existing, False)
            if force_new and existing is not None and existing.published is not None:
                raise CollectorFailure("revoke the published success before a rerun")
            reviews = _checked_reviews(source.list_reviews(live.pr_number))
            watermark = max((review["id"] for review in reviews), default=0)
            if existing is not None and watermark < existing.review_watermark:
                raise CollectorFailure("provider review listing regressed")
            request = ReviewRequest(reviewer, secrets.token_hex(16), "active", live,
                                    watermark, self._now(),
                                    existing.published if existing is not None else None)
            self._store.save(request)
        LOG.info("review request recorded reviewer=%s pr=%d request=%s superseded=%s",
                 reviewer, live.pr_number, request.request_id,
                 existing.request_id if existing is not None else "none")
        return RequestOutcome(request, True)

    def _invalidate(self, request: ReviewRequest, reason: str) -> CollectorDecision:
        self._store.save(replace(request, state="invalidated"))
        LOG.warning("review request invalidated reviewer=%s pr=%d request=%s reason=%s",
                    request.reviewer, request.context.pr_number,
                    request.request_id, reason)
        return CollectorDecision("invalidated", reason, request.reviewer,
                                 request.request_id)

    def collect(self, reviewer: str, read_live_context: Callable[[], Context],
                source: ReviewSource) -> CollectorDecision:
        """Return a receipt request only for a clean review of the live context.

        ``read_live_context`` must re-read GitHub (for example
        ``review_gate_publisher.collect_live_context``).  It is called before
        and after the provider evidence is read.  Exceptions propagate so the
        required check stays absent; they are never converted into a decision
        that could pass.
        """
        identity = self._identity(reviewer)
        before = read_live_context()
        if not isinstance(before, Context):
            raise CollectorFailure("invalid live context")
        with self._store.lock(before.repository_id, before.pr_number):
            request, decision = self._decide_locked(identity, before,
                                                    read_live_context, source)
        if decision is None:
            again = read_live_context()
            if not isinstance(again, Context):
                raise CollectorFailure("invalid live context")
            context = request.context
            with self._store.lock(context.repository_id, context.pr_number):
                decision = self._confirm_mismatch_locked(reviewer, request, again)
        return self._logged(decision, before)

    def _collect_held(self, reviewer: str, read_live_context: Callable[[], Context],
                      source: ReviewSource) -> CollectorDecision:
        """``collect`` for a caller that already holds the PR's ledger lock."""
        identity = self._identity(reviewer)
        before = read_live_context()
        if not isinstance(before, Context):
            raise CollectorFailure("invalid live context")
        request, decision = self._decide_locked(identity, before,
                                                read_live_context, source)
        if decision is None:
            again = read_live_context()
            if not isinstance(again, Context):
                raise CollectorFailure("invalid live context")
            decision = self._confirm_mismatch_locked(reviewer, request, again)
        return self._logged(decision, before)

    @staticmethod
    def _logged(decision: CollectorDecision, before: Context) -> CollectorDecision:
        log = LOG.info if decision.status == "pass" else LOG.warning
        log("review collection reviewer=%s pr=%d status=%s reason=%s untrusted=%d",
            decision.reviewer, before.pr_number, decision.status, decision.reason,
            decision.ignored_untrusted_reviews)
        return decision

    def _decide_locked(self, identity: ProviderIdentity, before: Context,
                       read_live_context: Callable[[], Context], source: ReviewSource
                       ) -> tuple[ReviewRequest | None, CollectorDecision | None]:
        reviewer = identity.reviewer
        request = self._store.load(before.repository_id, before.pr_number, reviewer)
        if request is None:
            return None, CollectorDecision("pending", "no_review_request", reviewer)
        if request.state != "active":
            return request, CollectorDecision("invalidated", "review_request_invalidated",
                                              reviewer, request.request_id)
        if request.context != before:
            return request, None  # Ordering is unknown; confirm with a fresh read.
        return request, self._evaluate(identity, request, before,
                                       read_live_context, source)

    def _confirm_mismatch_locked(self, reviewer: str, seen: ReviewRequest,
                                 again: Context) -> CollectorDecision:
        """Invalidate only on a mismatch that is proven not older than the request.

        The first live read may have started before a concurrent
        ``request_review`` for a newer context recorded ``seen`` -- possibly
        within the same clock second, so timestamps cannot order them.
        ``seen`` was observed under the lock, hence the requester's own live
        read had already finished; ``again`` was read after that observation
        and is not older than the request.  If the request was replaced
        meanwhile, ordering is again unknown and the decision stays pending.
        """
        context = seen.context
        request = self._store.load(context.repository_id, context.pr_number, reviewer)
        if request is None or request.request_id != seen.request_id:
            return CollectorDecision("pending", "live_context_read_predates_request",
                                     reviewer,
                                     None if request is None else request.request_id)
        if request.state != "active":
            return CollectorDecision("invalidated", "review_request_invalidated",
                                     reviewer, request.request_id)
        if request.context != again:
            return self._invalidate(request, "context_changed_since_request")
        return CollectorDecision("pending", "live_context_read_predates_request",
                                 reviewer, seen.request_id)

    def _checked_decision(self, credentials: AppCredentials,
                          decision: CollectorDecision) -> Context:
        if (not isinstance(decision, CollectorDecision) or decision.status != "pass"
                or not isinstance(decision.context, Context)
                or decision.check_run_request
                != successful_check_run_request(decision.context, decision.reviewer)):
            raise CollectorFailure("only a passing collector decision can be published")
        self._identity(decision.reviewer)
        context = decision.context
        if context.repository_id != credentials.config.repository_id:
            raise CollectorFailure("decision targets another repository")
        return context

    def publish(self, client: GitHubTransport, credentials: AppCredentials,
                decision: CollectorDecision) -> dict[str, Any]:
        """Post the success for a ``pass`` decision exactly once.

        The success is posted only while the decision's request is still the
        ledger's active request for the same context.  An already recorded
        success for that request and test merge is reused while GitHub still
        lists it as the App's latest attempt, so polling and restart recovery
        do not create further runs.  Any other standing
        success (an older request, or one being revoked) is first superseded.
        The publisher re-reads the live context before posting.  A
        ``publishing`` record is saved first; if the outcome is then ambiguous
        (error, lost response, crash, failed ledger write) the next outcome
        revokes it, and a later pass revokes it before posting a new success.
        """
        context = self._checked_decision(credentials, decision)
        with self._store.lock(context.repository_id, context.pr_number):
            return self._publish_locked(client, credentials, decision)

    def _load_publication_locked(self, repository_id: int, pr_number: int,
                                 reviewer: str) -> ReviewRequest | None:
        """Load a record, marking an unrecorded revocation as ``revoking``."""
        request = self._store.load(repository_id, pr_number, reviewer)
        key = (repository_id, pr_number, reviewer)
        if key not in self._unrecorded_revocations:
            return request
        standing = None if request is None else request.published
        if standing is None:
            self._unrecorded_revocations.discard(key)
            return request
        if standing.state == "revoking":
            return request
        return replace(request, published=replace(standing, state="revoking"))

    def _publish_locked(self, client: GitHubTransport, credentials: AppCredentials,
                        decision: CollectorDecision) -> dict[str, Any]:
        context = self._checked_decision(credentials, decision)
        request = self._load_publication_locked(context.repository_id,
                                                context.pr_number, decision.reviewer)
        if request is None:
            raise CollectorFailure("review request ledger is missing")
        current = (request.state == "active"
                   and request.request_id == decision.request_id
                   and request.context == context)
        standing = request.published
        if (current and standing is not None and standing.state == "success"
                and standing.request_id == request.request_id
                and standing.test_merge_sha == context.test_merge_sha):
            # A failure attempt may have superseded this success without the
            # ledger recording it (unwritable state_dir, possibly in another
            # worker or before a restart): reuse it only while GitHub still
            # lists it as the latest attempt; otherwise supersede and republish.
            if success_is_latest_attempt(client, credentials, standing.test_merge_sha,
                                         decision.reviewer, standing.check_run_id):
                return {"published": False, "check_run_id": standing.check_run_id}
            LOG.warning("review success is not the latest attempt reviewer=%s pr=%d "
                        "request=%s", decision.reviewer, context.pr_number,
                        standing.request_id)
        request = self._revoke_locked(client, credentials, request)
        if not current:
            return {"published": False, "check_run_id": None}
        request = replace(request, published=Publication(
            request.request_id, context.test_merge_sha, None, "publishing"))
        self._store.save(request)
        response = publish_success(client, credentials, context, decision.reviewer)
        run_id = response.get("id")
        if type(run_id) is not int or run_id <= 0:
            raise CollectorFailure("GitHub did not identify the published check")
        self._store.save(replace(request, published=Publication(
            request.request_id, context.test_merge_sha, run_id, "success")))
        LOG.info("review success published reviewer=%s pr=%d request=%s",
                 decision.reviewer, context.pr_number, decision.request_id)
        return {"published": True, "check_run_id": run_id}

    def revoke_published(self, client: GitHubTransport, credentials: AppCredentials,
                         reviewer: str, pr_number: int) -> bool:
        """Supersede a standing success with a newer failure attempt.

        Needed before ``force_new`` and after a collection error left the
        current evidence unverifiable (``collect_and_publish`` already does
        this for every non-passing outcome).  Returns whether a success had to
        be superseded.
        """
        self._identity(reviewer)
        repository_id = credentials.config.repository_id
        with self._store.lock(repository_id, pr_number):
            return self._revoke_standing_locked(client, credentials, reviewer,
                                                repository_id, pr_number)

    def _revoke_standing_locked(self, client: GitHubTransport,
                                credentials: AppCredentials, reviewer: str,
                                repository_id: int, pr_number: int) -> bool:
        request = self._load_publication_locked(repository_id, pr_number, reviewer)
        if request is None or request.published is None:
            return False
        self._revoke_locked(client, credentials, request)
        return True

    def _revoke_locked(self, client: GitHubTransport, credentials: AppCredentials,
                       request: ReviewRequest) -> ReviewRequest:
        """Post a failure attempt over the standing success; fail closed.

        ``revoking`` is recorded first so an interrupted revocation is retried.
        If that ledger write fails (read-only or full state directory) the
        failure attempt is still posted, best effort, before the write error is
        raised: an unwritable ledger must never leave the old success as
        GitHub's latest attempt.  The ledger then still names the standing
        success, so this collector remembers the key and never reuses that
        record as the current success: the next pass (once the ledger is
        writable) revokes it again, clears it and, on a clean review, posts a
        new success.  A restart or another worker lacks that memory; there a
        clean pass still verifies on GitHub that the recorded success is the
        latest attempt before reusing it (see ``_publish_locked``).
        """
        standing = request.published
        if standing is None:
            return request
        key = (request.context.repository_id, request.context.pr_number,
               request.reviewer)
        if standing.state != "revoking":
            revoking = replace(request, published=replace(standing, state="revoking"))
            try:
                self._store.save(revoking)
            except CollectorFailure:
                self._unrecorded_revocations.add(key)
                try:
                    publish_revocation(client, credentials, standing.test_merge_sha,
                                       request.reviewer)
                    posted = True
                except Exception:
                    posted = False
                LOG.error("review success revocation not recorded reviewer=%s pr=%d "
                          "request=%s failure_posted=%s", request.reviewer,
                          request.context.pr_number, standing.request_id, posted)
                raise
            request = revoking
        publish_revocation(client, credentials, standing.test_merge_sha, request.reviewer)
        request = replace(request, published=None)
        self._store.save(request)
        self._unrecorded_revocations.discard(key)
        LOG.warning("review success superseded reviewer=%s pr=%d request=%s",
                    request.reviewer, request.context.pr_number, standing.request_id)
        return request

    def collect_and_publish(self, reviewer: str, pr_number: int,
                            read_live_context: Callable[[], Context] | None,
                            source: ReviewSource, client: GitHubTransport,
                            credentials: AppCredentials) -> CollectorDecision:
        """One reconciliation pass: collect, then publish or supersede.

        Every outcome other than ``pass`` -- including a collection error,
        which means the current evidence cannot be verified -- supersedes a
        standing success, so GitHub's latest attempt never reads successful
        while the collector cannot currently confirm a clean review.

        The PR's ledger lock is held for the whole pass, so its publication or
        revocation always acts on the ledger state its own collection
        observed: an overlapping pass can neither revoke a success published
        from newer evidence nor publish from evidence that a newer
        non-passing collection has already superseded.  If the lock cannot be
        taken, another pass is running and nothing is changed.

        Collection is bound to ``pr_number`` and the configured repository:
        every live read that names another pull request or repository fails
        before any ledger is read or written, so a miswired reader can never
        produce, for another PR, an outcome whose revocation lands here.  The
        review ``source`` must name the same repository: a source built for
        another repository (whose same-numbered PR may share the head commit,
        e.g. a fork) is refused as a collection error, which revokes any
        standing success instead of accepting reviews of another diff.

        With ``read_live_context=None`` (the production composition) every
        live read -- before, after, a mismatch confirmation and the re-read in
        ``publish_success`` -- is ``collect_live_context`` over ``client``
        wrapped in this collector's ``GitObjectCache``: immutable commit and
        tree objects (the complete merge-base ancestry walk) are fetched once
        and reused across rechecks and later passes, while the PR, merge ref
        and check runs are read fresh every time.
        """
        if type(pr_number) is not int or pr_number <= 0:
            raise CollectorFailure("invalid pull request number")
        self._identity(reviewer)
        repository_id = credentials.config.repository_id
        client = CachingGitHubTransport(client, self._git_objects)
        if read_live_context is None:
            def read_live_context() -> Context:
                return review_gate_publisher.collect_live_context(
                    client, credentials.config, credentials.installation_token, pr_number)

        def bound_read() -> Context:
            live = read_live_context()
            if (not isinstance(live, Context) or live.pr_number != pr_number
                    or live.repository_id != repository_id):
                raise CollectorFailure("live context names another pull request")
            return live
        with self._store.lock(repository_id, pr_number):
            try:
                _require_source_repository(source, credentials.config.repository)
                decision = self._collect_held(reviewer, bound_read, source)
                if decision.status == "pass":
                    self._publish_locked(client, credentials, decision)
                    return decision
            except Exception:
                try:
                    self._revoke_standing_locked(client, credentials, reviewer,
                                                 repository_id, pr_number)
                except Exception:
                    raise CollectorFailure(
                        "collection failed and the published success could not be "
                        "revoked") from None
                raise
            self._revoke_standing_locked(client, credentials, reviewer,
                                         repository_id, pr_number)
        return decision

    def _evaluate(self, identity: ProviderIdentity, request: ReviewRequest,
                  before: Context, read_live_context: Callable[[], Context],
                  source: ReviewSource) -> CollectorDecision:
        reviews = _checked_reviews(source.list_reviews(before.pr_number))
        if request.review_watermark and not any(
                review["id"] == request.review_watermark for review in reviews):
            # Submitted reviews are not deletable, so the review the watermark
            # was derived from must still be listed; a truncated or empty
            # listing fails closed instead of hiding a newer failing review.
            raise CollectorFailure("provider review listing is incomplete")
        earliest = (request.requested_at + identity.max_review_runtime_seconds
                    + CLOCK_SKEW_ALLOWANCE_SECONDS)
        untrusted = 0
        passes = 0
        candidates = 0
        blocked = False
        for review in reviews:
            if review["id"] <= request.review_watermark:
                continue
            if not _is_trusted(review, identity):
                untrusted += 1
                continue
            commit = review.get("commit_id")
            if not isinstance(commit, str) or not _SHA.fullmatch(commit):
                raise CollectorFailure("invalid provider review commit")
            if commit != before.head_sha:
                continue  # A review of an older HEAD is irrelevant here.
            candidates += 1
            if candidates > MAX_CANDIDATE_REVIEWS:
                raise CollectorFailure("too many provider reviews for one request")
            submitted = _parse_timestamp(review.get("submitted_at"))
            comments = source.list_review_comments(before.pr_number, review["id"])
            if not _review_passes(review, comments, identity):
                blocked = True
            elif submitted >= earliest:
                passes += 1
            # A passing review submitted too soon may have been started under
            # an older base; it proves nothing and is not counted.
        after = read_live_context()
        if not isinstance(after, Context):
            raise CollectorFailure("invalid live context")
        if after != before:
            return self._invalidate(request, "context_changed_during_collection")
        if blocked:
            return CollectorDecision("blocked", "provider_result_not_clean",
                                     identity.reviewer, request.request_id,
                                     ignored_untrusted_reviews=untrusted)
        if passes == 0:
            return CollectorDecision("pending", "awaiting_unambiguous_review",
                                     identity.reviewer, request.request_id,
                                     ignored_untrusted_reviews=untrusted)
        try:
            check_run = successful_check_run_request(before, identity.reviewer)
        except PolicyFailure:
            raise CollectorFailure("receipt could not be produced") from None
        return CollectorDecision("pass", "trusted_clean_review", identity.reviewer,
                                 request.request_id, check_run, untrusted, before)


def _require_source_repository(source: ReviewSource, repository: str) -> None:
    # GitHub owner and repository names are case-insensitive.
    named = getattr(source, "repository", None)
    if (not isinstance(named, str) or not isinstance(repository, str)
            or named.casefold() != repository.casefold()):
        raise CollectorFailure("review source targets another repository")


class GitHubReviewSource:
    """Completely paginated PR reviews and review comments via the App client."""

    PAGE_SIZE = 100
    MAX_PAGES = MAX_REVIEWS // PAGE_SIZE

    def __init__(self, client: ListTransport, repository: str, token: str) -> None:
        if (not isinstance(repository, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)):
            raise CollectorFailure("invalid target repository")
        self._client = client
        self._repository = repository
        self._repo = "/repos/" + repository
        self._token = token

    @classmethod
    def for_credentials(cls, client: ListTransport,
                        credentials: AppCredentials) -> "GitHubReviewSource":
        """The source for the configured repository, read with its App token."""
        return cls(client, credentials.config.repository,
                   credentials.installation_token)

    @property
    def repository(self) -> str:
        return self._repository

    def __repr__(self) -> str:
        return f"GitHubReviewSource({self._repo!r})"

    def _all(self, path: str, limit: int) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for page in range(1, self.MAX_PAGES + 1):
            batch = self._client.get_list(
                f"{path}?per_page={self.PAGE_SIZE}&page={page}", self._token)
            if not isinstance(batch, list) or len(batch) > self.PAGE_SIZE:
                raise CollectorFailure("invalid GitHub list response")
            items.extend(batch)
            if len(items) > limit:
                raise CollectorFailure("provider evidence exceeds verification limit")
            if len(batch) < self.PAGE_SIZE:
                return items
        # Every permitted page was full: completeness cannot be proven.
        raise CollectorFailure("provider evidence exceeds verification limit")

    def list_reviews(self, pr_number: int) -> list[dict[str, Any]]:
        if type(pr_number) is not int or pr_number <= 0:
            raise CollectorFailure("invalid pull request number")
        return self._all(f"{self._repo}/pulls/{pr_number}/reviews", MAX_REVIEWS)

    def list_review_comments(self, pr_number: int,
                             review_id: int) -> list[dict[str, Any]]:
        if (type(pr_number) is not int or pr_number <= 0
                or type(review_id) is not int or review_id <= 0):
            raise CollectorFailure("invalid review identity")
        return self._all(f"{self._repo}/pulls/{pr_number}/reviews/{review_id}/comments",
                         MAX_REVIEW_COMMENTS)


def load_collector(environ: Mapping[str, str], checkout_root: Path,
                   clock: Callable[[], float] = time.time) -> ReviewCollector:
    """Load provider policy from an external private JSON file.

    The file contains only public identities, bounds and markers, for example::

        {"state_dir": "/var/lib/server-sentinel-review-gate",
         "providers": {"codex": {"user_id": 1, "user_login": "example[bot]",
                                 "max_review_runtime_seconds": 1800,
                                 "pass_markers": ["..."],
                                 "blocking_markers": ["..."],
                                 "non_blocking_markers": ["..."]}}}
    """
    raw_path = environ.get(COLLECTOR_CONFIG_ENV)
    if not isinstance(raw_path, str) or not raw_path:
        raise CollectorFailure("review collector configuration is not configured")
    try:
        _, raw = _secure_private_bytes(Path(raw_path), checkout_root)
    except PublisherFailure:
        raise CollectorFailure("review collector configuration is unavailable") from None
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        if (not isinstance(data, dict) or set(data) != {"state_dir", "providers"}
                or not isinstance(data["state_dir"], str)
                or not isinstance(data["providers"], dict) or not data["providers"]):
            raise CollectorFailure("invalid review collector configuration")
        identities = {}
        for reviewer, entry in data["providers"].items():
            if not isinstance(entry, dict) or set(entry) != {
                    "user_id", "user_login", "max_review_runtime_seconds",
                    "pass_markers", "blocking_markers", "non_blocking_markers"}:
                raise CollectorFailure("invalid review collector configuration")
            markers = {}
            for key in ("pass_markers", "blocking_markers", "non_blocking_markers"):
                if not isinstance(entry[key], list):
                    raise CollectorFailure("invalid review collector configuration")
                markers[key] = tuple(entry[key])
            identities[reviewer] = ProviderIdentity(
                reviewer=reviewer, user_id=entry["user_id"],
                user_login=entry["user_login"],
                max_review_runtime_seconds=entry["max_review_runtime_seconds"],
                **markers)
        store = LedgerStore(Path(data["state_dir"]), checkout_root)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError, CollectorFailure):
        raise CollectorFailure("invalid review collector configuration") from None
    return ReviewCollector(store, identities, clock)
