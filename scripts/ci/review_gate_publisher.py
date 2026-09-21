"""Self-hosted delivery adapter for the dedicated-App review gate (#4).

This module runs only from an Owner-controlled deployment.  It never reads a
PR checkout, executes git hooks, creates credentials, creates an App, or edits
repository rules.  It obtains its App material at runtime from an external
root/current-user-owned 0600 configuration and key path, re-reads GitHub's live
PR state, and posts a policy-produced Check Run only when that entire state is
unchanged.  Provider review collection and App-JWT token exchange deliberately
remain separate deployment adapters.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import (HTTPRedirectHandler, HTTPSHandler, ProxyHandler,
                            Request, build_opener)
import ssl

from scripts.ci.review_gate_policy import (Context, Issuer, PolicyFailure,
                                           successful_check_run_request)


CONFIG_ENV = "SERVER_SENTINEL_REVIEW_GATE_CONFIG"
TOKEN_ENV = "SERVER_SENTINEL_REVIEW_GATE_INSTALLATION_TOKEN"
GITHUB_API = "https://api.github.com"
_HEX = re.compile(r"[0-9a-f]{40}")
_MAX_ANCESTRY_COMMITS = 4096
_MAX_COMMIT_PARENTS = 64


class PublisherFailure(RuntimeError):
    """A fail-closed adapter error that never includes credential contents."""


@dataclass(frozen=True)
class RuntimeConfig:
    repository: str
    repository_id: int
    issuer: Issuer
    installation_id: int
    private_key_path: Path

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository):
            raise PublisherFailure("invalid target repository")
        if type(self.repository_id) is not int or self.repository_id <= 0:
            raise PublisherFailure("invalid target repository identity")
        if type(self.installation_id) is not int or self.installation_id <= 0:
            raise PublisherFailure("invalid installation identity")
        if not self.private_key_path.is_absolute():
            raise PublisherFailure("private key path must be absolute")


@dataclass(frozen=True)
class AppCredentials:
    """App key material from the trusted runtime boundary, never a checkout."""

    config: RuntimeConfig
    private_key_pem: bytes
    installation_token: str


class GitHubTransport(Protocol):
    def get_json(self, path: str, token: str) -> dict[str, Any]:
        ...

    def get_bytes(self, path: str, token: str, accept: str) -> bytes:
        ...

    def post_json(self, path: str, token: str,
                  payload: dict[str, Any]) -> dict[str, Any]:
        ...


def _outside_checkout(path: Path, checkout_root: Path) -> Path:
    if not path.is_absolute():
        raise PublisherFailure("runtime path must be absolute")
    try:
        resolved = path.resolve(strict=True)
        root = checkout_root.resolve(strict=True)
    except OSError as exc:
        raise PublisherFailure("runtime path is unavailable") from exc
    if resolved.is_relative_to(root):
        raise PublisherFailure("runtime material must stay outside the checkout")
    return resolved


def _secure_private_bytes(path: Path, checkout_root: Path) -> tuple[Path, bytes]:
    """Open first, then validate the actual descriptor to avoid check/read races."""
    if not path.is_absolute():
        raise PublisherFailure("runtime path must be absolute")
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PublisherFailure("runtime material is unavailable") from exc
    try:
        info = os.fstat(descriptor)
        descriptor_path = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
        resolved = _outside_checkout(descriptor_path, checkout_root)
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077
                or info.st_uid not in {0, os.geteuid()}):
            raise PublisherFailure("runtime material must be a private regular file")
        chunks = []
        remaining = 65_537
        while remaining:
            chunk = os.read(descriptor, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining == 0 and os.read(descriptor, 1):
            raise PublisherFailure("runtime material exceeds size limit")
        return resolved, b"".join(chunks)
    except OSError as exc:
        raise PublisherFailure("runtime material is unavailable") from exc
    finally:
        os.close(descriptor)


def load_runtime_config(environ: Mapping[str, str], checkout_root: Path) -> RuntimeConfig:
    """Load public App routing configuration from an external private JSON file."""
    raw_path = environ.get(CONFIG_ENV)
    if not isinstance(raw_path, str) or not raw_path:
        raise PublisherFailure("review gate configuration is not configured")
    _, config_bytes = _secure_private_bytes(Path(raw_path), checkout_root)
    try:
        raw = json.loads(config_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublisherFailure("invalid review gate configuration") from exc
    if not isinstance(raw, dict) or set(raw) != {
            "repository", "repository_id", "app_id", "app_slug",
            "installation_id", "private_key_path"}:
        raise PublisherFailure("unexpected review gate configuration fields")
    try:
        return RuntimeConfig(
            repository=raw["repository"], repository_id=raw["repository_id"],
            issuer=Issuer(raw["app_id"], raw["app_slug"]),
            installation_id=raw["installation_id"],
            private_key_path=Path(raw["private_key_path"]),
        )
    except (KeyError, TypeError, PolicyFailure) as exc:
        raise PublisherFailure("invalid review gate configuration") from exc


def load_app_credentials(config: RuntimeConfig, environ: Mapping[str, str],
                         checkout_root: Path) -> AppCredentials:
    """Load a private App key and short-lived installation token at runtime.

    The key is loaded only to validate this trusted deployment boundary here.
    A separately reviewed App-JWT exchange adapter may consume it to refresh the
    installation token; this module never writes either value or returns it in
    an error.  The token is intentionally an environment-only runtime input.
    """
    _, key = _secure_private_bytes(config.private_key_path, checkout_root)
    pem_markers = (
        (b"-----BEGIN PRIVATE KEY-----", b"-----END PRIVATE KEY-----"),
        (b"-----BEGIN RSA PRIVATE KEY-----",
         b"-----END RSA PRIVATE KEY-----"),
    )
    if not (64 <= len(key) <= 65536
            and any(key.startswith(begin) and key.rstrip().endswith(end)
                    for begin, end in pem_markers)):
        raise PublisherFailure("invalid App private key material")
    token = environ.get(TOKEN_ENV)
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,512}", token):
        raise PublisherFailure("installation token is unavailable")
    return AppCredentials(config, key, token)


class _RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class UrllibGitHubTransport:
    """Narrow GitHub.com client: HTTPS, no proxy, no redirect, bounded JSON."""

    def __init__(self) -> None:
        self._opener = build_opener(ProxyHandler({}), _RejectRedirect(),
                                    HTTPSHandler(context=ssl.create_default_context()))

    @staticmethod
    def _url(path: str) -> str:
        if (not isinstance(path, str) or not path.startswith("/")
                or ("?" in path and not path.endswith("?recursive=1"))):
            raise PublisherFailure("invalid GitHub API path")
        return GITHUB_API + path

    def _request(self, method: str, path: str, token: str, body: bytes | None,
                 accept: str) -> bytes:
        request = Request(self._url(path), data=body, method=method, headers={
            "Accept": accept, "Authorization": "Bearer " + token,
            "User-Agent": "ServerSentinel-review-gate/1",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        if body is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with self._opener.open(request, timeout=20) as response:
                data = response.read(1_048_577)
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise PublisherFailure("GitHub API request failed") from exc
        if len(data) > 1_048_576:
            raise PublisherFailure("GitHub API response exceeds limit")
        return data

    def get_json(self, path: str, token: str) -> dict[str, Any]:
        return _json_object(self._request("GET", path, token, None,
                                          "application/vnd.github+json"))

    def get_bytes(self, path: str, token: str, accept: str) -> bytes:
        return self._request("GET", path, token, None, accept)

    def post_json(self, path: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return _json_object(self._request("POST", path, token, body,
                                          "application/vnd.github+json"))


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublisherFailure("invalid GitHub API JSON") from exc
    if not isinstance(value, dict):
        raise PublisherFailure("unexpected GitHub API response")
    return value


def _sha(value: Any) -> str:
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        raise PublisherFailure("invalid GitHub commit identity")
    return value


def _path_part(value: str) -> str:
    return quote(value, safe="")


def _commit_parents(client: GitHubTransport, repo: str, token: str,
                    sha: str) -> tuple[str, ...]:
    commit = client.get_json(f"{repo}/git/commits/{sha}", token)
    try:
        if _sha(commit["sha"]) != sha:
            raise PublisherFailure("commit response identity mismatch")
        parents = tuple(_sha(parent["sha"]) for parent in commit["parents"])
    except (KeyError, TypeError) as exc:
        raise PublisherFailure("invalid commit ancestry response") from exc
    # Bound hostile/malformed API fan-out as well as total graph size.  GitHub
    # permits octopus merges, so fail closed instead of assuming two parents.
    if (len(parents) > _MAX_COMMIT_PARENTS
            or len(set(parents)) != len(parents) or sha in parents):
        raise PublisherFailure("invalid commit ancestry response")
    return parents


def _ancestor_graph(client: GitHubTransport, repo: str, token: str,
                    starts: tuple[str, ...], max_commits: int,
                    graph: dict[str, tuple[str, ...]]) -> None:
    """Populate complete parent graphs, refusing an incomplete bounded proof."""
    pending = list(starts)
    while pending:
        sha = pending.pop()
        if sha in graph:
            continue
        if len(graph) >= max_commits:
            raise PublisherFailure("commit ancestry exceeds verification limit")
        parents = _commit_parents(client, repo, token, sha)
        graph[sha] = parents
        pending.extend(parent for parent in parents if parent not in graph)


def _reachable(graph: Mapping[str, tuple[str, ...]], start: str) -> set[str]:
    result: set[str] = set()
    pending = [start]
    while pending:
        sha = pending.pop()
        if sha in result:
            continue
        result.add(sha)
        pending.extend(graph[sha])
    return result


def unique_merge_base(client: GitHubTransport, repo: str, token: str,
                      base_sha: str, head_sha: str,
                      max_commits: int = _MAX_ANCESTRY_COMMITS) -> str:
    """Prove a single best common ancestor from a complete bounded DAG.

    GitHub's compare response selects one merge base and cannot prove that a
    criss-cross history has only one.  Walking parent objects to their roots is
    more expensive, but makes ambiguity and an exhausted verification budget
    fail closed.
    """
    if (type(max_commits) is not int or max_commits <= 0
            or max_commits > _MAX_ANCESTRY_COMMITS):
        raise PublisherFailure("invalid ancestry verification limit")
    graph: dict[str, tuple[str, ...]] = {}
    _ancestor_graph(client, repo, token, (base_sha, head_sha), max_commits, graph)
    common = _reachable(graph, base_sha) & _reachable(graph, head_sha)
    if not common:
        raise PublisherFailure("commits have no common ancestor")

    # Common ancestors are closed under ancestry.  A common commit is a best
    # common ancestor exactly when no immediate child in the common subgraph
    # descends from it.
    shadowed: set[str] = set()
    for child in common:
        shadowed.update(parent for parent in graph[child] if parent in common)
    best = common - shadowed
    if len(best) != 1:
        raise PublisherFailure("commit history has multiple merge bases")
    return best.pop()


def canonical_no_rename_diff(base_tree: dict[str, Any],
                             head_tree: dict[str, Any]) -> bytes:
    """Encode changed Git tree entries with paths, never rename detection."""
    def entries(tree: dict[str, Any]) -> dict[str, tuple[str, str]]:
        if tree.get("truncated") is True or not isinstance(tree.get("tree"), list):
            raise PublisherFailure("Git tree response is incomplete")
        result: dict[str, tuple[str, str]] = {}
        for item in tree["tree"]:
            if not isinstance(item, dict) or item.get("type") not in {"blob", "commit"}:
                continue
            path, mode, sha = item.get("path"), item.get("mode"), item.get("sha")
            if (not isinstance(path, str) or not path or "\x00" in path
                    or not isinstance(mode, str) or not re.fullmatch(r"[0-7]{6}", mode)
                    or path in result):
                raise PublisherFailure("invalid Git tree entry")
            result[path] = (mode, _sha(sha))
        return result
    before, after = entries(base_tree), entries(head_tree)
    rows = [b"server-sentinel-no-renames-tree-diff-v1\n"]
    for path in sorted(set(before) | set(after)):
        if before.get(path) != after.get(path):
            old = before.get(path, ("-", "-"))
            new = after.get(path, ("-", "-"))
            rows.append((path + "\x00" + old[0] + "\x00" + old[1] + "\x00"
                         + new[0] + "\x00" + new[1] + "\n").encode("utf-8"))
    return b"".join(rows)


def collect_live_context(client: GitHubTransport, config: RuntimeConfig,
                         token: str, pr_number: int) -> Context:
    """Build a Context from authenticated GitHub responses without git execution."""
    if type(pr_number) is not int or pr_number <= 0:
        raise PublisherFailure("invalid pull request number")
    repo = "/repos/" + "/".join(_path_part(part) for part in config.repository.split("/"))
    pr = client.get_json(f"{repo}/pulls/{pr_number}", token)
    try:
        base = pr["base"]
        head = pr["head"]
        if (type(pr.get("number")) is not int or pr["number"] != pr_number
                or not isinstance(base, dict) or not isinstance(head, dict)
                or not isinstance(base.get("repo"), dict)
                or base["repo"].get("id") != config.repository_id):
            raise PublisherFailure("pull request does not target configured repository")
        base_ref, base_sha, head_sha = base["ref"], _sha(base["sha"]), _sha(head["sha"])
        if base_ref != "main":
            raise PublisherFailure("pull request base is not main")
    except (KeyError, TypeError) as exc:
        raise PublisherFailure("invalid pull request response") from exc
    merge_base = unique_merge_base(client, repo, token, base_sha, head_sha)
    merge_ref = client.get_json(f"{repo}/git/ref/pull/{pr_number}/merge", token)
    try:
        test_merge = _sha(merge_ref["object"]["sha"])
    except (KeyError, TypeError) as exc:
        raise PublisherFailure("test merge ref is unavailable") from exc
    merge_commit = client.get_json(f"{repo}/git/commits/{test_merge}", token)
    try:
        parents = merge_commit["parents"]
        parent_shas = [_sha(parent["sha"]) for parent in parents]
    except (KeyError, TypeError) as exc:
        raise PublisherFailure("invalid test merge commit") from exc
    if len(parent_shas) != 2 or set(parent_shas) != {base_sha, head_sha}:
        raise PublisherFailure("test merge does not bind current base and head")
    base_tree = client.get_json(f"{repo}/git/trees/{base_sha}?recursive=1", token)
    head_tree = client.get_json(f"{repo}/git/trees/{head_sha}?recursive=1", token)
    diff = canonical_no_rename_diff(base_tree, head_tree)
    return Context(config.repository_id, pr_number, "refs/heads/main", head_sha,
                   base_sha, merge_base, hashlib.sha256(diff).hexdigest(), test_merge)


def _validate_published_run(run: dict[str, Any], config: RuntimeConfig,
                            request: dict[str, Any]) -> None:
    app = run.get("app")
    output = run.get("output")
    if (not isinstance(app, dict) or app.get("id") != config.issuer.app_id
            or app.get("slug") != config.issuer.app_slug
            or run.get("name") != request["name"]
            or run.get("head_sha") != request["head_sha"]
            or run.get("status") != "completed" or run.get("conclusion") != "success"
            or not isinstance(output, dict)
            or output.get("summary") != request["output"]["summary"]):
        raise PublisherFailure("GitHub did not confirm the expected dedicated-App check")


def publish_success(client: GitHubTransport, credentials: AppCredentials,
                    expected: Context, reviewer: str) -> dict[str, Any]:
    """Revalidate live state, then post exactly one fixed success Check Run."""
    live = collect_live_context(client, credentials.config,
                                credentials.installation_token, expected.pr_number)
    if live != expected:
        raise PublisherFailure("review context changed before publication")
    request = successful_check_run_request(expected, reviewer)
    repo = "/repos/" + "/".join(_path_part(part) for part in credentials.config.repository.split("/"))
    response = client.post_json(f"{repo}/check-runs", credentials.installation_token, request)
    _validate_published_run(response, credentials.config, request)
    return response
