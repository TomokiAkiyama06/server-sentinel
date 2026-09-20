#!/usr/bin/env python3
"""Conservative, offline guards. Findings never print paths or matched content.

This checks known secret/reporting signatures, not arbitrary obfuscation or the
contents of ordinary UI images. New media recipes require a reviewed change to
this generator; a manifest claim or a hash alone never proves provenance.
"""

import argparse
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_FILES = 20000
SYNTHETIC = "tests/fixtures/synthetic/"
MANIFEST = SYNTHETIC + "manifest.json"
RUNTIME_ROOTS = {"server", "agent", "web", "infra"}
SECRET_PATTERNS = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    rb"-{5}BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|CERTIFICATE)-{5}",
    rb"https://hooks\.slack\.com/services/[A-Z0-9]{8,}/[A-Z0-9]{8,}/[A-Z0-9]{16,}",
    rb"\bxox[baprs]-[A-Za-z0-9-]{10,}",
    rb"\btskey-(?:auth|api|client|oauth)-[A-Za-z0-9_-]{10,}",
    rb"\bgh[pousr]_[A-Za-z0-9]{30,}",
    rb"\bgithub_pat_[A-Za-z0-9_]{40,}",
    rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    rb"\bAIza[A-Za-z0-9_-]{30,}",
    rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}",
))
SDK_PATTERN = re.compile(
    rb"(?<![a-z0-9])(?:@sentry(?:/|\b)|sentry[_/-]sdk|sentry\.io|sentry\.init|"
    rb"posthog|mixpanel|amplitude(?:-js|/analytics|_analytics)?|"
    rb"@segment/|analytics[-_]node|analytics[-_]python|"
    rb"google[-_]analytics|google[-_]tag[-_]manager|googletagmanager\.com|"
    rb"google-analytics\.com|gtag\s*\(|"
    rb"(?:@?firebase[/-])(?:analytics|crashlytics)|firebase_crashlytics|"
    rb"bugsnag|rollbar|newrelic|new_relic|ddtrace|@datadog/|datadog[-_]rum|"
    rb"applicationinsights|application_insights|logrocket|hotjar|fullstory|"
    rb"heap-js|clarity-js|plausible-tracker|@vercel/(?:analytics|speed-insights)|"
    rb"opentelemetry[-_/](?:sdk|exporter))",
    re.IGNORECASE,
)
REPORT_PATTERN = re.compile(
    rb"(?:[\"']?\b(?:telemetry|analytics|crash[-_]?report(?:ing)?|"
    rb"crash[-_]?upload|sentry[-_]?dsn)"
    rb"(?:[-_]?(?:enabled|disabled|opt[-_]?in|endpoint|url|key|token|dsn))?"
    rb"[\"']?\s*[:=])|"
    rb"[\"']?\btracking[-_]?(?:opt[-_]?in|endpoint|url|key|token|dsn)[\"']?\s*[:=]|"
    rb"\b(?:enable|disable)[-_]?(?:telemetry|analytics)\b\s*[:=]",
    re.IGNORECASE,
)
SECRET_DIRS = {
    ".secrets", "secrets", "credentials", "keys", "private-keys", "private_keys",
    "certs", "certificates", ".ssh",
}
RUNTIME_DIRS = {
    "buffer", "incidents", "runtime", "local-state", "real-media", "real-footage",
    "camera-footage", "logs",
}
ROOT_DATA_DIRS = {
    "recordings", "data", "diagnostics", "media", "captures", "snapshots", "uploads",
}
SECRET_SUFFIXES = {
    ".pem", ".key", ".p8", ".p12", ".pfx", ".mobileprovision", ".cer", ".der",
    ".crt", ".csr", ".provisionprofile",
}
IMAGE_SUFFIXES = {
    ".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tif", ".tiff", ".ppm",
    ".pgm", ".pbm", ".svg", ".avif",
}
CAPTURE_SUFFIXES = {
    ".mp4", ".mov", ".m4v", ".mkv", ".avi", ".webm", ".m2ts", ".h264",
    ".h265", ".hevc", ".mjpeg", ".mjpg", ".yuv", ".m4a", ".aac", ".wav",
    ".mp3", ".flac", ".ogg", ".opus", ".heic", ".heif", ".dng",
}
INVENTORY_PATTERN = re.compile(
    r"^(?:hardware|device)[-_](?:inventory|baseline|serials|uuids).*\.(?:json|ya?ml|csv|txt)$"
)
ROOT_MANIFEST_PATTERN = re.compile(
    r"^(?:package(?:-lock)?\.json|(?:npm-shrinkwrap|composer)\.json|"
    r"(?:yarn|pnpm-lock|bun|uv|poetry|pdm|Cargo|composer)\.(?:lock|lockb|yaml)|"
    r"pyproject\.toml|requirements.*\.(?:txt|in)|Pipfile(?:\.lock)?|"
    r"setup\.(?:py|cfg)|go\.(?:mod|sum)|Dockerfile(?:\..*)?|"
    r"(?:docker-)?compose(?:\.[^.]+)?\.ya?ml)$", re.IGNORECASE,
)


@dataclass(frozen=True, order=True)
class Finding:
    category: str
    ordinal: int
    line: int = 0


def generated_fixture(recipe: str) -> bytes:
    """Fixed geometry only: no input pixels, arbitrary text, or generator code."""
    if recipe != "checkerboard-8x8-v1":
        raise ValueError("unsupported recipe")
    pixels = ["240 240 240" if (x // 2 + y // 2) % 2 else "16 32 48"
              for y in range(8) for x in range(8)]
    return ("P3\n8 8\n255\n" + "\n".join(pixels) + "\n").encode("ascii")


def secret_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    lower = tuple(part.lower() for part in parts)
    name = lower[-1]
    return bool(
        set(lower[:-1]) & SECRET_DIRS
        or any(part == ".env" or part.startswith(".env.") for part in lower[:-1])
        or (name == ".env" or name.startswith(".env.")) and parts[-1] != ".env.example"
        or name in {".envrc", ".credentials", ".netrc"}
        or re.match(r"id_(?:rsa|dsa|ecdsa|ed25519)", name)
        or name.startswith("credentials") and PurePosixPath(name).suffix
        in {".json", ".yaml", ".yml", ".toml"}
        or PurePosixPath(name).suffix in SECRET_SUFFIXES
    )


def runtime_data_path(path: str) -> bool:
    parts = tuple(part.lower() for part in PurePosixPath(path).parts)
    name = parts[-1]
    return bool(
        set(parts[:-1]) & RUNTIME_DIRS or parts[0] in ROOT_DATA_DIRS
        or re.search(r"\.(?:sqlite3?|db)(?:-.*)?$", name)
        or name.endswith(".log") or INVENTORY_PATTERN.match(name)
        or len(parts) == 1 and re.match(r"(?:serials|uuids)\.(?:json|ya?ml|csv|txt)$", name)
        or re.match(r"(?:owner|face|biometric)[-_].*(?:embedding|template)", name)
    )


def media_kind(data: bytes) -> str | None:
    if data.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a",
                        b"BM", b"II*\0", b"MM\0*")):
        return "image"
    if re.match(rb"P[1-6]\s", data):
        return "image"
    if data.startswith(b"RIFF"):
        return "image" if data[8:12] == b"WEBP" else "capture"
    if len(data) > 12 and data[4:8] == b"ftyp":
        return "capture"
    if data.startswith((b"\x1aE\xdf\xa3", b"OggS", b"fLaC", b"ID3")):
        return "capture"
    return None


def runtime_file(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if PurePosixPath(path).suffix.lower() in {".md", ".rst"}:
        return False  # Documentation prose is not a runtime import or setting.
    return (parts[0] in RUNTIME_ROOTS | {"dist", "build"}
            or path == ".env.example"
            or len(parts) == 1 and bool(ROOT_MANIFEST_PATTERN.fullmatch(parts[0])))


def regular_bytes(root: Path, path: str) -> bytes:
    """Reject links in every path component before reading any bytes."""
    current = root
    parts = PurePosixPath(path).parts
    if not parts or any(part in {".", ".."} for part in parts) or path.startswith("/"):
        raise ValueError("unsafe path")
    for index, part in enumerate(parts):
        current /= part
        mode = current.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) if index < len(parts) - 1
                                    else stat.S_ISREG(mode)):
            raise ValueError("unsafe file type")
    if current.stat().st_size > MAX_BYTES:
        raise ValueError("scan size exceeded")
    data = current.read_bytes()
    if len(data) > MAX_BYTES:
        raise ValueError("scan size exceeded")
    return data


def tracked_files(root: Path) -> dict[str, str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--stage", "-z"],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    entries = {}
    for entry in result.stdout.split(b"\0"):
        if not entry:
            continue
        metadata, path = entry.split(b"\t", 1)
        mode, _object, stage = metadata.split()
        if stage != b"0":
            raise ValueError("unmerged index")
        entries[os.fsdecode(path)] = mode.decode("ascii")
    return entries


def bundle_files(root: Path) -> set[str]:
    """Include ignored build outputs, without following symlinks or node_modules."""
    found = set()
    for directory in sorted(RUNTIME_ROOTS | {"build", "dist"}):
        start = root / directory
        if start.is_symlink():
            found.add(directory)
            continue
        if not start.is_dir():
            continue
        def walk_error(error):
            raise error

        for current, directories, filenames in os.walk(start, followlinks=False, onerror=walk_error):
            relative = Path(current).relative_to(root)
            in_bundle = bool(set(relative.parts) & {"build", "dist"})
            for name in list(directories):
                candidate = Path(current) / name
                if candidate.is_symlink():
                    found.add(candidate.relative_to(root).as_posix())
                    directories.remove(name)
                elif name in {".git", "node_modules", ".venv", "venv", "__pycache__"}:
                    directories.remove(name)
            if in_bundle:
                found.update((relative / name).as_posix() for name in filenames)
            if len(found) > MAX_FILES:
                raise ValueError("scan count exceeded")
    return found


def unique_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest key")
        result[key] = value
    return result


def provenance(contents: dict[str, bytes]) -> tuple[dict[str, bytes], bool]:
    if MANIFEST not in contents:
        return {}, False
    try:
        manifest = json.loads(contents[MANIFEST], object_pairs_hook=unique_keys)
        if (not isinstance(manifest, dict) or set(manifest) != {"schema", "fixtures"}
                or type(manifest["schema"]) is not int or manifest["schema"] != 1
                or not isinstance(manifest["fixtures"], list)):
            raise ValueError("invalid manifest")
        expected = {}
        for entry in manifest["fixtures"]:
            if not isinstance(entry, dict) or set(entry) != {"path", "recipe"}:
                raise ValueError("invalid entry")
            path = entry["path"]
            if (not isinstance(path, str) or not path.startswith(SYNTHETIC)
                    or not path.endswith(".ppm") or path not in contents
                    or path in expected or str(PurePosixPath(path)) != path
                    or ".." in PurePosixPath(path).parts):
                raise ValueError("invalid fixture path")
            expected[path] = generated_fixture(entry["recipe"])
        return expected, True
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        return {}, False


def audit(root: Path) -> list[Finding]:
    tracked = tracked_files(root)
    paths = sorted(set(tracked) | bundle_files(root))
    if len(paths) > MAX_FILES:
        return [Finding("scan-limit", 0)]
    findings = set()
    contents = {}
    total_bytes = 0
    ordinals = {path: index for index, path in enumerate(paths, 1)}
    for path in paths:
        ordinal = ordinals[path]
        if path in tracked and tracked[path] not in {"100644", "100755"}:
            findings.add(Finding("unsafe-file-type", ordinal))
            continue
        try:
            contents[path] = regular_bytes(root, path)
        except (OSError, ValueError):
            findings.add(Finding("unreadable-or-unsafe-file", ordinal))
            continue
        total_bytes += len(contents[path])
        if total_bytes > MAX_TOTAL_BYTES:
            return [Finding("scan-limit", ordinal)]
        if secret_path(path):
            findings.add(Finding("sensitive-path", ordinal))
        if runtime_data_path(path):
            findings.add(Finding("runtime-data-path", ordinal))
        data = contents[path]
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(data):
                findings.add(Finding("secret-format", ordinal, data.count(b"\n", 0, match.start()) + 1))
        if data.startswith(b"SQLite format 3\0"):
            findings.add(Finding("runtime-data-content", ordinal))
        if runtime_file(path):
            for pattern in (SDK_PATTERN, REPORT_PATTERN):
                for match in pattern.finditer(data):
                    findings.add(Finding("prohibited-reporting", ordinal,
                                         data.count(b"\n", 0, match.start()) + 1))
            if data.startswith((b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c")):
                findings.add(Finding("opaque-runtime-package", ordinal))

    expected, valid = provenance(contents)
    if MANIFEST in tracked and not valid:
        findings.add(Finding("invalid-fixture-manifest", ordinals[MANIFEST]))
    for path, data in contents.items():
        ordinal = ordinals[path]
        suffix = PurePosixPath(path).suffix.lower()
        kind = media_kind(data)
        fixture_path = any(part.lower() in {"fixture", "fixtures"}
                           for part in PurePosixPath(path).parts[:-1])
        is_media = kind is not None or suffix in IMAGE_SUFFIXES | CAPTURE_SUFFIXES
        if is_media and (fixture_path or suffix in CAPTURE_SUFFIXES or kind == "capture"):
            if path not in expected:
                findings.add(Finding("unproven-media", ordinal))
            elif data != expected[path]:
                findings.add(Finding("fixture-content-mismatch", ordinal))
        elif kind == "image" and suffix not in IMAGE_SUFFIXES:
            findings.add(Finding("misnamed-media", ordinal))
        if path in expected and data != expected[path]:
            findings.add(Finding("fixture-content-mismatch", ordinal))
    return sorted(findings)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    try:
        findings = audit(args.root.resolve())
    except (OSError, ValueError, subprocess.SubprocessError):
        findings = [Finding("repository-scan-failed", 0)]
    for finding in findings:
        print(f"{finding.category} file={finding.ordinal} line={finding.line}")
    if not findings:
        print("repository-guards-passed")
    return int(bool(findings))


if __name__ == "__main__":
    raise SystemExit(main())
