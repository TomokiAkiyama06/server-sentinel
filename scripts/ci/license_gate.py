#!/usr/bin/env python3
"""Offline dependency and model-license release gate.

The reviewed inventory is intentionally hand-authored. Lockfiles establish what
would be installed; they are not accepted as independent license evidence.

Immutable pin evidence lives in the same reviewed record as the license
evidence: every dependency location carries its lockfile digests or resolved
artifact digest, every model weight carries its artifact digest, and every
container base image carries its image digest. A component therefore cannot be
license-reviewed without a pin, and a later digest substitution never inherits
the earlier review even when the exact version string is unchanged.
"""

import argparse
import base64
import binascii
import datetime
import hashlib
import json
import os
import posixpath
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import unquote


INVENTORY = "license/components.json"
APPROVALS = "license/owner-approvals.json"
SCHEMA = 2
MODEL_DIRECTORIES = {"models", "weights", "checkpoints", "model-artifacts"}
MODEL_ASSET_PATHS = {("assets", "ml"), ("assets", "ai")}
BUILD_OUTPUT_DIRECTORIES = {"build", "dist"}
SCAN_EXCLUDED_DIRECTORIES = {".git", ".venv", "node_modules", "__pycache__"}
RECOGNIZED_STATIC_OUTPUT_SUFFIXES = {
    ".avif", ".cjs", ".css", ".gif", ".html", ".ico", ".jpeg", ".jpg",
    ".js", ".json", ".license", ".map", ".md", ".mjs", ".otf", ".png",
    ".svg", ".ttf", ".txt", ".wasm", ".webp", ".woff", ".woff2", ".xml",
}
# Binary formats that are reviewed as media or Web runtime assets. Any other
# opaque file is treated as a model artifact until it has its own record.
RECOGNIZED_BINARY_SUFFIXES = {
    ".avif", ".bmp", ".gif", ".ico", ".jpeg", ".jpg", ".mkv", ".mp3", ".mp4",
    ".oga", ".ogg", ".otf", ".pbm", ".pgm", ".png", ".pnm", ".ppm", ".ttf",
    ".wasm", ".wav", ".webm", ".webp", ".woff", ".woff2",
}
MODEL_SUFFIXES = {
    ".bin", ".caffemodel", ".ckpt", ".dlc", ".engine", ".ggml", ".gguf",
    ".h5", ".joblib", ".keras", ".mar", ".mlmodel", ".mlpackage", ".msgpack",
    ".nemo", ".npy", ".npz", ".onnx", ".params", ".pb", ".pdmodel",
    ".pdparams", ".pickle", ".pkl", ".plan", ".pt", ".pth", ".rknn",
    ".safetensors", ".tflite", ".torchscript", ".trt", ".weights", ".xmodel",
}
REQUIRED_SCOPE_REVIEWS = {"transport", "model_code", "model_weight"}
PERMISSIVE_LICENSES = {
    "0BSD", "Apache-2.0", "Apache-2.0 OR BSD-2-Clause", "BSD-2-Clause",
    "BSD-3-Clause", "ISC", "MIT", "PSF-2.0", "Python-2.0", "Unicode-3.0",
    "Unicode-DFS-2016", "Zlib",
}
IMAGE_OBLIGATIONS = {
    "preserve-license-and-copyright", "preserve-notice",
    "fulfill-image-redistribution-obligations",
}
# The committed base-image review (server/docs/DEPENDENCIES.md,
# agent/docs/DEPENDENCIES.md, web/THIRD_PARTY_NOTICES.md) covers unmodified,
# digest-pinned CI execution images that ServerSentinel does not republish.
# Any other distribution intent needs a new Owner decision.
CI_ONLY_DISTRIBUTION = "ci-only-not-redistributed"
REQUIREMENT_NAME = re.compile(r"([A-Za-z0-9_.-]+)==(\S+)")
HASH_OPTION = re.compile(r"--hash=sha256:([0-9a-f]{64})")
SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# PEP 440 public versions only: prefix wildcards, ranges, and environment
# markers are not exact pins and must not inherit a component's review.
PYTHON_VERSION = re.compile(r"""
    ^(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*
    (?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?
    (?:-[0-9]+|[-_.]?(?:post|rev|r)[-_.]?[0-9]*)?
    (?:[-_.]?dev[-_.]?[0-9]*)?
    (?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$
""", re.VERBOSE | re.IGNORECASE)
SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
IMAGE_REFERENCE = re.compile(
    r"^(?P<repository>[a-z0-9]+(?:[._-][a-z0-9]+)*"
    r"(?:(?::[0-9]+)?/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)"
    r"(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9._-]*))?"
    r"(?:@(?P<digest>sha256:[0-9a-f]{64}))?$")
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._@/+:-]*")
KINDS = {"source", "model_code", "model_weight"}
SCOPES = {"backend", "frontend", "transport", "tooling"}
LOCK_ECOSYSTEMS = {"python-requirements", "npm-lock"}
PROJECT_ECOSYSTEMS = {"python-project": "python-requirements",
                      "npm-project": "npm-lock"}
INPUT_ECOSYSTEMS = (LOCK_ECOSYSTEMS | set(PROJECT_ECOSYSTEMS)
                    | {"container-image"})
ECOSYSTEM_PREFIXES = {
    "python-requirements": "pypi", "python-project": "pypi",
    "npm-lock": "npm", "npm-project": "npm", "model-artifact": "model",
}
SUPPORTED_MANIFESTS = {"package-lock.json", "npm-shrinkwrap.json",
                       "package.json", "pyproject.toml"}
# Manifests that can install or resolve dependencies without a reviewed parser.
UNSUPPORTED_MANIFESTS = {
    "Cargo.lock", "Gemfile.lock", "Pipfile", "Pipfile.lock", "bun.lock",
    "bun.lockb", "composer.lock", "deno.lock", "go.mod", "go.sum",
    "pnpm-lock.yaml", "poetry.lock", "setup.cfg", "setup.py", "uv.lock",
    "yarn.lock",
}


# Container build commands are allowlisted: an unrecognized installer, option
# or subcommand fails closed instead of being skipped as "some other flag".
PIP_BINARY = re.compile(r"pip[0-9.]*")
PIP_REQUIREMENT_FLAGS = {"--requirement", "--constraint"}
ALLOWED_PIP_FLAGS = {
    "--disable-pip-version-check", "--no-build-isolation", "--no-cache-dir",
    "--no-compile", "--no-deps", "--no-input", "--no-warn-script-location",
    "--prefer-binary", "--quiet", "--require-hashes", "--upgrade", "-q", "-U",
}
ALLOWED_PIP_VALUE_FLAGS = {
    "--only-binary", "--progress-bar", "--retries", "--root-user-action",
    "--timeout",
}
# npm resolves installs from the lock only for the `ci` family; every other
# command, including its documented `install` aliases, is rejected.
REVIEWED_NPM_COMMANDS = {
    "ci", "clean-install", "ic", "install-clean", "isntall-clean",
    "run", "run-script", "start", "test",
}
REJECTED_PACKAGE_MANAGERS = {"bun", "npx", "pnpm", "yarn"}
SOURCE_SCAN_SUFFIXES = {".py", ".pyi"}


class GateError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class Pin:
    """Immutable pin evidence recorded next to a component's license."""

    type: str
    digests: tuple[str, ...] = ()
    resolved: str = ""


@dataclass(frozen=True, order=True)
class LockedComponent:
    path: str
    ecosystem: str
    scope: str
    name: str
    version: str
    pin: Pin


@dataclass(frozen=True, order=True)
class ImageUse:
    path: str
    scope: str
    repository: str
    tag: str
    digest: str


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GateError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_python_name(value):
    return re.sub(r"[-_.]+", "-", value).lower()


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError, GateError) as error:
        raise GateError(f"cannot read {path.name}: {error}") from error


def read_text(path: Path, relative: str):
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise GateError(f"cannot read {relative}") from error


def relative_path(value, *, field):
    if not isinstance(value, str) or not value or "\\" in value:
        raise GateError(f"{field} must be a repository-relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value:
        raise GateError(f"unsafe {field}")
    return value


def nonempty_string(value, field):
    if not isinstance(value, str) or not value.strip():
        raise GateError(f"{field} must be a nonempty string")
    return value


def evidence(root: Path, values, field):
    if not isinstance(values, list) or not values:
        raise GateError(f"{field} must contain evidence")
    for value in values:
        nonempty_string(value, field)
        if value.startswith("https://"):
            continue
        path = relative_path(value, field=field)
        if not (root / path).is_file():
            raise GateError(f"{field} references a missing file")


def obligation_list(values, field):
    if not isinstance(values, list) or not values:
        raise GateError(f"{field} must be explicit")
    if any(not isinstance(value, str) or not value for value in values):
        raise GateError(f"invalid {field}")
    return set(values)


def valid_sri(value):
    if not isinstance(value, str) or "-" not in value:
        return False
    algorithm, encoded = value.split("-", 1)
    sizes = {"sha256": 32, "sha384": 48, "sha512": 64}
    if algorithm not in sizes or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", encoded):
        return False
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return False
    canonical = base64.b64encode(decoded).decode("ascii")
    return len(decoded) == sizes[algorithm] and encoded == canonical


def digest_tuple(values, ecosystem, *, field="pin digests"):
    if not isinstance(values, list) or not values or values != sorted(set(values)):
        raise GateError(f"{field} must be a sorted nonempty unique list")
    if ecosystem == "npm-lock":
        valid = all(valid_sri(value) for value in values)
    else:
        valid = all(isinstance(value, str) and SHA256_DIGEST.fullmatch(value)
                    for value in values)
    if not valid:
        raise GateError(f"invalid {field}")
    return tuple(values)


def reserved_model_path(value):
    return bool(set(PurePosixPath(value).parts[:-1]) & MODEL_DIRECTORIES)


def model_like_path(value):
    parts = PurePosixPath(value).parts[:-1]
    return reserved_model_path(value) or any(
        parts[index:index + 2] in MODEL_ASSET_PATHS
        for index in range(max(0, len(parts) - 1))
    )


def opaque_build_output(value):
    path = PurePosixPath(value)
    return (bool(set(path.parts[:-1]) & BUILD_OUTPUT_DIRECTORIES)
            and path.suffix.lower() not in RECOGNIZED_STATIC_OUTPUT_SUFFIXES)


def opaque_bytes(path: Path):
    """Report whether a file is opaque rather than reviewable UTF-8 text."""
    try:
        with path.open("rb") as handle:
            chunk = handle.read(65536)
    except OSError as error:
        raise GateError(f"cannot inspect {path.name}") from error
    if b"\x00" in chunk:
        return True
    for trim in range(4):
        try:
            chunk[:len(chunk) - trim].decode("utf-8")
        except UnicodeDecodeError:
            continue
        return False
    return True


def scan_paths(root: Path):
    """Yield repository files, skipping tool caches and nested checkouts."""
    for directory, names, files in os.walk(root):
        current = Path(directory)
        names[:] = sorted(
            name for name in names
            if name not in SCAN_EXCLUDED_DIRECTORIES
            and not (current != root and (current / name / ".git").exists())
        )
        for name in sorted(files):
            yield current / name


def python_lock(path: Path, relative: str, scope: str):
    logical = read_text(path, relative).replace("\\\n", " ").splitlines()
    found = []
    includes = []
    for line in logical:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        directive = re.fullmatch(r"(?:-r|--requirement|-c|--constraint)\s+(\S+)", line)
        if directive:
            raw_target = directive.group(1)
            if "://" in raw_target or "\\" in raw_target or PurePosixPath(raw_target).is_absolute():
                raise GateError(f"unsafe requirement include in {relative}")
            target = posixpath.normpath(str(PurePosixPath(relative).parent / raw_target))
            relative_path(target, field="requirement include")
            includes.append(target)
            continue
        if line.startswith(("-r", "--requirement", "-c", "--constraint")):
            raise GateError(f"invalid requirement include in {relative}")
        match = REQUIREMENT_NAME.match(line)
        if not match:
            raise GateError(f"unparsed or unpinned requirement in {relative}")
        version = match.group(2)
        if not PYTHON_VERSION.fullmatch(version):
            raise GateError(f"requirement version is not an exact pin in {relative}")
        hashes = []
        for token in line[match.end():].split():
            digest = HASH_OPTION.fullmatch(token)
            if not digest:
                raise GateError(f"unsupported requirement option in {relative}")
            hashes.append("sha256:" + digest.group(1))
        if not hashes:
            raise GateError(f"requirement has no SHA256 evidence in {relative}")
        pin = Pin("lockfile-entry", tuple(sorted(set(hashes))))
        found.append(LockedComponent(relative, "python-requirements", scope,
                                     canonical_python_name(match.group(1)), version, pin))
    return found, includes


def npm_lock(path: Path, relative: str, scope: str):
    data = load_json(path)
    if data.get("lockfileVersion") != 3 or not isinstance(data.get("packages"), dict):
        raise GateError(f"unsupported npm lock in {relative}")
    found = []
    for location, package in data["packages"].items():
        if not location:
            continue
        prefix = "node_modules/"
        if not location.startswith(prefix) or not isinstance(package, dict):
            raise GateError(f"invalid npm package entry in {relative}")
        name = location.rsplit(prefix, 1)[-1]
        version = nonempty_string(package.get("version"), "npm version")
        if not SEMVER.fullmatch(version):
            raise GateError(f"npm lock version is not an exact pin in {relative}")
        resolved = nonempty_string(package.get("resolved"), "npm resolved artifact")
        integrity = nonempty_string(package.get("integrity"), "npm integrity")
        digests = tuple(sorted(set(integrity.split())))
        if not digests or any(not valid_sri(value) for value in digests):
            raise GateError(f"invalid npm integrity in {relative}")
        pin = Pin("lockfile-entry", digests, unquote(resolved))
        found.append(LockedComponent(relative, "npm-lock", scope, name, version, pin))
    return found


def python_project(path: Path, relative: str, scope: str):
    try:
        data = tomllib.loads(read_text(path, relative))
    except tomllib.TOMLDecodeError as error:
        raise GateError(f"cannot parse {relative}") from error
    project = data.get("project", {})
    if not isinstance(project, dict):
        raise GateError(f"invalid project table in {relative}")
    dependencies = project.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise GateError(f"invalid project dependencies in {relative}")
    dynamic = project.get("dynamic", [])
    optional_dependencies = project.get("optional-dependencies", {})
    build_system = data.get("build-system", {})
    tool = data.get("tool", {})
    if (not isinstance(dynamic, list)
            or any(not isinstance(value, str) for value in dynamic)
            or not isinstance(optional_dependencies, dict)
            or not isinstance(build_system, dict)
            or not isinstance(tool, dict)):
        raise GateError(f"invalid unsupported dependency section in {relative}")
    build_requires = build_system.get("requires", [])
    if not isinstance(build_requires, list):
        raise GateError(f"invalid unsupported dependency section in {relative}")
    setuptools = tool.get("setuptools", {})
    if not isinstance(setuptools, dict):
        raise GateError(f"invalid unsupported dependency section in {relative}")
    setuptools_dynamic = setuptools.get("dynamic", {})
    if not isinstance(setuptools_dynamic, dict):
        raise GateError(f"invalid unsupported dependency section in {relative}")
    dependency_fields = {"dependencies", "optional-dependencies"}
    if (optional_dependencies
            or build_requires
            or dependency_fields & set(dynamic)
            or dependency_fields & set(setuptools_dynamic)):
        raise GateError(f"unsupported project dependency section in {relative}")
    found = []
    for dependency in dependencies:
        match = REQUIREMENT_NAME.fullmatch(dependency) if isinstance(dependency, str) else None
        if not match or not PYTHON_VERSION.fullmatch(match.group(2)):
            raise GateError(f"project dependency is not exact in {relative}")
        found.append(LockedComponent(relative, "python-project", scope,
                                     canonical_python_name(match.group(1)),
                                     match.group(2), Pin("lock-correspondence")))
    return found


def npm_project(path: Path, relative: str, scope: str):
    data = load_json(path)
    found = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        dependencies = data.get(section, {})
        if not isinstance(dependencies, dict):
            raise GateError(f"invalid {section} in {relative}")
        for name, version in dependencies.items():
            if not isinstance(name, str) or not isinstance(version, str):
                raise GateError(f"invalid package declaration in {relative}")
            if not SEMVER.fullmatch(version):
                raise GateError(f"npm dependency is not exact in {relative}")
            found.append(LockedComponent(relative, "npm-project", scope, name, version,
                                         Pin("lock-correspondence")))
    return found


def dockerfile_words(path: Path, relative: str):
    """Yield the token list of each Dockerfile instruction."""
    logical = read_text(path, relative).replace("\\\n", " ").splitlines()
    for line in logical:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        yield line.split()


def image_use(reference, path, scope, relative):
    if "$" in reference:
        raise GateError(f"container base image must not be a variable in {relative}")
    match = IMAGE_REFERENCE.fullmatch(reference)
    if not match or not match.group("digest"):
        raise GateError(f"container base image must be digest-pinned in {relative}")
    if not match.group("tag"):
        raise GateError(f"container base image must record its tag in {relative}")
    return ImageUse(path, scope, match.group("repository"), match.group("tag"),
                    match.group("digest"))


def container_file(path: Path, relative: str, scope: str):
    """Audit base images and install commands of a reviewed Dockerfile."""
    images = []
    requirements = []
    stages = set()
    for words in dockerfile_words(path, relative):
        instruction = words[0].upper()
        arguments = words[1:]
        if instruction == "FROM":
            positional = [word for word in arguments if not word.startswith("--")]
            if len(positional) not in (1, 3) or (
                    len(positional) == 3 and positional[1].upper() != "AS"):
                raise GateError(f"unsupported FROM instruction in {relative}")
            reference = positional[0]
            if reference.lower() not in stages:
                images.append(image_use(reference, relative, scope, relative))
            if len(positional) == 3:
                stages.add(positional[2].lower())
        elif instruction in {"COPY", "ADD"}:
            for word in arguments:
                if not word.startswith("--from="):
                    continue
                source = word.split("=", 1)[1]
                if source.lower() in stages or source.isdigit():
                    continue
                images.append(image_use(source, relative, scope, relative))
        elif instruction == "RUN":
            requirements.extend(run_commands(arguments, relative))
    if not images:
        raise GateError(f"no reviewed base image in {relative}")
    return images, requirements


def shell_tokens(command):
    """Split one shell command, ignoring JSON-exec quoting and separators."""
    return [token.strip("[]\",'") for token in command.split() if token.strip("[]\",'")]


def requirement_targets(target, relative):
    """Repository paths a Dockerfile requirement option can refer to."""
    if (not target or "://" in target or "\\" in target
            or PurePosixPath(target).is_absolute()):
        raise GateError(f"pip install uses an unreviewed source in {relative}")
    parent = PurePosixPath(relative).parent
    candidates = []
    for option in (target, PurePosixPath(target).name):
        resolved = posixpath.normpath(str(parent / option))
        if resolved.startswith(("..", "/")):
            raise GateError(f"pip install uses an unreviewed source in {relative}")
        candidates.append(relative_path(resolved, field="pip requirement file"))
    return tuple(dict.fromkeys(candidates))


def pip_command(words, index, relative):
    """Audit one pip invocation and report the requirement files it installs."""
    subcommand = None
    requirements = []
    while index < len(words):
        word = words[index]
        index += 1
        target = None
        if word.startswith("--"):
            name, separator, value = word.partition("=")
            if name in PIP_REQUIREMENT_FLAGS:
                target = value if separator else None
            elif separator and name in ALLOWED_PIP_VALUE_FLAGS:
                continue
            elif not separator and name in ALLOWED_PIP_FLAGS:
                continue
            else:
                raise GateError(f"unreviewed pip install option in {relative}")
        elif word.startswith("-") and word != "-":
            if word[:2] in {"-r", "-c"}:
                target = word[2:] or None
            elif word in ALLOWED_PIP_FLAGS:
                continue
            else:
                raise GateError(f"unreviewed pip install option in {relative}")
        elif subcommand is None and word == "install":
            subcommand = word
            continue
        else:
            raise GateError(f"pip install must use a reviewed requirement file in {relative}")
        if target is None:
            if index >= len(words):
                raise GateError(f"pip install requirement file is missing in {relative}")
            target = words[index]
            index += 1
        requirements.append(requirement_targets(target, relative))
    if subcommand is None:
        raise GateError(f"unclassified pip command in {relative}")
    if "--require-hashes" not in words:
        raise GateError(f"pip install must use --require-hashes in {relative}")
    if not requirements:
        raise GateError(f"pip install must use a reviewed requirement file in {relative}")
    return requirements


def npm_command(words, index, relative):
    """Accept only lock-driven npm commands, whatever alias or option order."""
    while index < len(words):
        word = words[index]
        index += 1
        if word.startswith("-"):
            raise GateError(f"unreviewed npm option before the command in {relative}")
        if word not in REVIEWED_NPM_COMMANDS:
            raise GateError(f"unclassified npm command in {relative}")
        return
    raise GateError(f"unclassified npm command in {relative}")


def run_commands(arguments, relative):
    """Reject unpinned installs and report requirement files a build installs."""
    requirements = []
    for command in re.split(r"&&|;|\|+", " ".join(arguments)):
        words = shell_tokens(command)
        for index, word in enumerate(words):
            name = PurePosixPath(word).name
            if name in REJECTED_PACKAGE_MANAGERS:
                raise GateError(f"unreviewed package manager in {relative}")
            if name == "npm":
                npm_command(words, index + 1, relative)
                break
            if PIP_BINARY.fullmatch(name):
                requirements.extend(pip_command(words, index + 1, relative))
                break
    return requirements


def exempt_source_file(relative, suffix, exemptions):
    """Reviewed source packages that merely share a reserved directory name."""
    path = PurePosixPath(relative)
    return (suffix in SOURCE_SCAN_SUFFIXES
            and any(exemption in path.parents for exemption in exemptions))


def model_files(root: Path, exemptions=()):
    exempted = {PurePosixPath(value) for value in exemptions}
    used = set()
    found = set()
    for path in scan_paths(root):
        relative = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        classified = (model_like_path(relative) or opaque_build_output(relative)
                      or suffix in MODEL_SUFFIXES)
        reviewable = suffix in RECOGNIZED_BINARY_SUFFIXES
        if path.is_symlink():
            if classified or (not reviewable and path.is_file() and opaque_bytes(path)):
                raise GateError("model artifacts must be regular files")
            continue
        if not path.is_file():
            continue
        if not classified and not reviewable and opaque_bytes(path):
            classified = True
        if (classified and suffix not in MODEL_SUFFIXES
                and exempt_source_file(relative, suffix, exempted)
                and not opaque_bytes(path)):
            # A reviewed, text-only source package never silently covers an
            # opaque or model-suffixed file stored next to it.
            used.add(str(PurePosixPath(relative).parent))
            continue
        if classified:
            found.add(relative)
    stale = {str(value) for value in exempted} - {
        parent for value in used
        for parent in [value] + [str(item) for item in PurePosixPath(value).parents]
    }
    if stale:
        raise GateError("stale model scan exemption")
    return sorted(found)


def approvals_by_id(root: Path):
    data = load_json(root / APPROVALS)
    if set(data) != {"schema", "approvals"} or data["schema"] != 1 or not isinstance(data["approvals"], list):
        raise GateError("invalid owner approval registry")
    result = {}
    required = {"component_id", "name", "version", "kind", "license", "upstream",
                "approved_by", "approved_on", "decision"}
    for record in data["approvals"]:
        if not isinstance(record, dict) or set(record) != required:
            raise GateError("invalid owner approval record")
        component_id = nonempty_string(record["component_id"], "approval component_id")
        if component_id in result or record["approved_by"] != "repository-owner":
            raise GateError("invalid or duplicate owner approval")
        approved_on = nonempty_string(record["approved_on"], "approved_on")
        try:
            datetime.date.fromisoformat(approved_on)
        except ValueError as error:
            raise GateError("invalid approval date") from error
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", approved_on):
            raise GateError("invalid approval date")
        decision = relative_path(record["decision"], field="approval decision")
        if not decision.startswith("docs/decisions/") or not (root / decision).is_file():
            raise GateError("approval must reference a committed owner decision")
        result[component_id] = record
    return result


def component_prefix(component_id):
    return component_id.split(":", 1)[0] if ":" in component_id else ""


def declared_pin(value, ecosystem, upstream):
    """Validate the immutable pin evidence stored with a component record."""
    if not isinstance(value, dict) or not isinstance(value.get("type"), str):
        raise GateError("location requires immutable pin evidence")
    kind = value["type"]
    if ecosystem == "python-requirements":
        if set(value) != {"type", "digests"} or kind != "lockfile-entry":
            raise GateError("invalid lockfile pin evidence")
        return Pin(kind, digest_tuple(value["digests"], ecosystem)), ""
    if ecosystem == "npm-lock":
        if set(value) != {"type", "digests", "resolved"} or kind != "lockfile-entry":
            raise GateError("invalid lockfile pin evidence")
        resolved = nonempty_string(value["resolved"], "resolved artifact")
        if not resolved.startswith("https://"):
            raise GateError("resolved artifact must use https")
        if unquote(resolved) != unquote(upstream):
            raise GateError("resolved artifact differs from the reviewed upstream")
        return Pin(kind, digest_tuple(value["digests"], ecosystem), unquote(resolved)), ""
    if ecosystem in PROJECT_ECOSYSTEMS:
        if set(value) != {"type", "lock"} or kind != "lock-correspondence":
            raise GateError("invalid project pin evidence")
        return Pin(kind), relative_path(value["lock"], field="pin lock")
    if set(value) != {"type", "digests"} or kind != "artifact-digest":
        raise GateError("invalid model weight pin evidence")
    digests = digest_tuple(value["digests"], "model-artifact")
    if len(digests) != 1:
        raise GateError("model weight requires exactly one artifact digest")
    return Pin(kind, digests), ""


def model_scan_exemptions(root: Path, data):
    """Reviewed source directories that only share a reserved model name."""
    records = data["model_scan_exemptions"]
    if not isinstance(records, list):
        raise GateError("invalid model scan exemption inventory")
    paths = []
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "reason", "evidence"}:
            raise GateError("invalid model scan exemption record")
        value = relative_path(record["path"], field="model scan exemption path")
        if not (root / value).is_dir():
            raise GateError("model scan exemption must name a committed directory")
        if not set(PurePosixPath(value).parts) & MODEL_DIRECTORIES:
            raise GateError("model scan exemption does not cover a reserved directory")
        if value in paths:
            raise GateError("duplicate model scan exemption")
        nonempty_string(record["reason"], "model scan exemption reason")
        evidence(root, record["evidence"], "model scan exemption evidence")
        paths.append(value)
    return tuple(paths)


def container_images(root: Path, data, discovered_images):
    """Check every reviewed base image record against its Dockerfile uses."""
    records = data["container_images"]
    if not isinstance(records, list):
        raise GateError("invalid container image inventory")
    declared = set()
    identifiers = set()
    required = {"id", "repository", "tag", "digest", "distribution", "upstream",
                "license_summary", "license_evidence", "transitive_evidence",
                "obligations", "notice_files", "locations"}
    for record in records:
        if not isinstance(record, dict) or set(record) != required:
            raise GateError("invalid container image record")
        repository = nonempty_string(record["repository"], "image repository")
        tag = nonempty_string(record["tag"], "image tag")
        digest = record["digest"]
        if not isinstance(digest, str) or not SHA256_DIGEST.fullmatch(digest):
            raise GateError("container base image requires a sha256 digest pin")
        identifier = nonempty_string(record["id"], "image id")
        if identifier != f"image:{repository}@{tag}" or identifier in identifiers:
            raise GateError("invalid or duplicate container image id")
        identifiers.add(identifier)
        if record["distribution"] != CI_ONLY_DISTRIBUTION:
            raise GateError("container base image redistribution requires an owner decision")
        upstream = nonempty_string(record["upstream"], "image upstream")
        if not upstream.startswith("https://"):
            raise GateError("upstream must use https")
        nonempty_string(record["license_summary"], "image license summary")
        evidence(root, record["license_evidence"], "image license evidence")
        evidence(root, record["transitive_evidence"], "image transitive evidence")
        evidence(root, record["notice_files"], "image notice files")
        obligations = obligation_list(record["obligations"], "image obligations")
        if not IMAGE_OBLIGATIONS <= obligations:
            raise GateError("container base image notice obligations are required")
        locations = record["locations"]
        if not isinstance(locations, list) or not locations:
            raise GateError("container image record needs a Dockerfile location")
        for location in locations:
            if not isinstance(location, dict) or set(location) != {"path", "scope"}:
                raise GateError("invalid container image location")
            path = relative_path(location["path"], field="container image path")
            if location["scope"] not in SCOPES:
                raise GateError("invalid container image scope")
            use = ImageUse(path, location["scope"], repository, tag, digest)
            if use in declared:
                raise GateError("duplicate container image location")
            declared.add(use)
    if declared != set(discovered_images):
        raise GateError("container base images differ from reviewed image records")
    return len(records)


def audit(root: Path, inventory_path=INVENTORY):
    data = load_json(root / inventory_path)
    required_root = {"schema", "inputs", "scope_reviews", "components",
                     "container_images", "model_scan_exemptions"}
    if not isinstance(data, dict) or set(data) != required_root or data["schema"] != SCHEMA:
        raise GateError("invalid component inventory schema")

    inputs = data["inputs"]
    if not isinstance(inputs, list) or not inputs:
        raise GateError("inputs must be nonempty")
    discovered = []
    discovered_images = []
    build_requirements = set()
    include_graph = {}
    input_paths = set()
    input_ecosystems = {}
    for item in inputs:
        if not isinstance(item, dict) or set(item) != {"path", "ecosystem", "scope"}:
            raise GateError("invalid inventory input")
        relative = relative_path(item["path"], field="input path")
        ecosystem = item["ecosystem"]
        scope = item["scope"]
        if ecosystem not in INPUT_ECOSYSTEMS or scope not in SCOPES:
            raise GateError("unsupported input ecosystem or scope")
        if relative in input_paths or not (root / relative).is_file():
            raise GateError("duplicate or missing inventory input")
        input_paths.add(relative)
        input_ecosystems[relative] = ecosystem
        if ecosystem == "python-requirements":
            components, includes = python_lock(root / relative, relative, scope)
            discovered.extend(components)
            include_graph[relative] = includes
        elif ecosystem == "python-project":
            discovered.extend(python_project(root / relative, relative, scope))
        elif ecosystem == "npm-project":
            discovered.extend(npm_project(root / relative, relative, scope))
        elif ecosystem == "npm-lock":
            discovered.extend(npm_lock(root / relative, relative, scope))
        else:
            images, requirements = container_file(root / relative, relative, scope)
            discovered_images.extend(images)
            build_requirements.update(requirements)

    tracked_inputs = set()
    unsupported = []
    shrinkwrapped = set()
    locked_directories = set()
    for path in scan_paths(root):
        relative = path.relative_to(root)
        name = relative.name
        if name in UNSUPPORTED_MANIFESTS:
            unsupported.append(relative.as_posix())
        elif (name.startswith(("requirements", "Dockerfile"))
              or name in SUPPORTED_MANIFESTS):
            tracked_inputs.add(relative.as_posix())
        if name == "npm-shrinkwrap.json":
            shrinkwrapped.add(relative.parent.as_posix())
        elif name == "package-lock.json":
            locked_directories.add(relative.parent.as_posix())
    if unsupported:
        raise GateError("unsupported dependency manifest requires a reviewed parser")
    if shrinkwrapped & locked_directories:
        raise GateError("npm-shrinkwrap.json and package-lock.json are ambiguous")
    if tracked_inputs != input_paths:
        raise GateError("dependency input set differs from reviewed inventory")
    for candidates in sorted(build_requirements):
        if not any(input_ecosystems.get(target) == "python-requirements"
                   for target in candidates):
            raise GateError(
                f"container build installs an unreviewed requirement file: {candidates[0]}")
    for source, targets in include_graph.items():
        for target in targets:
            if target not in input_paths or input_ecosystems[target] != "python-requirements":
                raise GateError(f"requirement include is not a reviewed input: {source}")
    visiting = set()
    visited = set()

    def visit(path):
        if path in visiting:
            raise GateError("requirement include cycle")
        if path in visited:
            return
        visiting.add(path)
        for target in include_graph.get(path, []):
            visit(target)
        visiting.remove(path)
        visited.add(path)

    for path in include_graph:
        visit(path)

    reviews = data["scope_reviews"]
    if not isinstance(reviews, list):
        raise GateError("invalid scope reviews")
    review_names = set()
    for review in reviews:
        if not isinstance(review, dict) or set(review) != {"scope", "status", "evidence"}:
            raise GateError("invalid scope review")
        scope = review["scope"]
        if scope in review_names or scope not in REQUIRED_SCOPE_REVIEWS or review["status"] != "reviewed-empty":
            raise GateError("invalid or duplicate empty scope review")
        review_names.add(scope)
        evidence(root, review["evidence"], "scope review evidence")

    approvals = approvals_by_id(root)
    declared = []
    correspondence = []
    artifacts = set()
    ids = set()
    required_component = {
        "id", "name", "version", "kind", "upstream", "license", "license_evidence",
        "transitive_evidence", "obligations", "notice_files", "locations",
    }
    for component in data["components"]:
        if not isinstance(component, dict) or set(component) != required_component:
            raise GateError("invalid component record")
        component_id = nonempty_string(component["id"], "component id")
        if not SAFE_ID.fullmatch(component_id) or component_id in ids:
            raise GateError("invalid or duplicate component id")
        ids.add(component_id)
        name = nonempty_string(component["name"], "component name")
        version = nonempty_string(component["version"], "component version")
        kind = component["kind"]
        if kind not in KINDS:
            raise GateError("invalid component kind")
        upstream = nonempty_string(component["upstream"], "upstream")
        if not upstream.startswith("https://"):
            raise GateError("upstream must use https")
        license_name = nonempty_string(component["license"], "license")
        evidence(root, component["license_evidence"], "license evidence")
        evidence(root, component["transitive_evidence"], "transitive evidence")
        obligations = obligation_list(component["obligations"], "redistribution obligations")
        if "preserve-license-and-copyright" not in obligations:
            raise GateError("license preservation obligation is required")
        if "Apache-" in license_name and "preserve-notice" not in obligations:
            raise GateError("Apache notice obligation is required")
        evidence(root, component["notice_files"], "notice files")

        locations = component["locations"]
        if kind == "model_weight":
            if not isinstance(locations, list) or len(locations) != 1:
                raise GateError("model weight must identify exactly one artifact")
        elif not isinstance(locations, list) or not locations:
            raise GateError("component record needs at least one location")
        ecosystems = set()
        for location in locations:
            if not isinstance(location, dict) or set(location) != {"path", "ecosystem", "scope", "pin"}:
                raise GateError("invalid dependency location")
            path = relative_path(location["path"], field="location path")
            ecosystem = location["ecosystem"]
            scope = location["scope"]
            if kind == "model_weight":
                if ecosystem != "model-artifact" or scope != "model_weight":
                    raise GateError("invalid model artifact classification")
                if not reserved_model_path(path):
                    raise GateError("model weight must be stored in a reserved model artifact directory")
            elif ecosystem not in INPUT_ECOSYSTEMS - {"container-image"} or scope not in SCOPES:
                raise GateError("invalid dependency location")
            ecosystems.add(ecosystem)
            pin, lock = declared_pin(location["pin"], ecosystem, upstream)
            if kind == "model_weight":
                artifact = root / path
                if not artifact.is_file():
                    raise GateError("missing model artifact")
                if "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest() != pin.digests[0]:
                    raise GateError("model artifact digest mismatch")
                artifacts.add(path)
                continue
            if ecosystem in PROJECT_ECOSYSTEMS:
                correspondence.append((PROJECT_ECOSYSTEMS[ecosystem], lock, scope, name, version))
            declared.append(LockedComponent(path, ecosystem, scope, name, version, pin))

        prefixes = {ECOSYSTEM_PREFIXES[value] for value in ecosystems}
        if len(prefixes) != 1:
            raise GateError("component mixes dependency ecosystems")
        prefix = prefixes.pop()
        if prefix == "pypi" and name != canonical_python_name(name):
            raise GateError("Python component name must be PEP 503 canonical")
        if component_id != f"{prefix}:{name}@{version}":
            raise GateError(f"component id is not its dependency coordinate: {component_id}")
        if license_name not in PERMISSIVE_LICENSES:
            approval = approvals.get(component_id)
            identity = (name, version, kind, license_name, upstream)
            if approval is None or tuple(
                    approval[field] for field in
                    ("name", "version", "kind", "license", "upstream")) != identity:
                raise GateError(f"blocked license lacks exact owner approval: {component_id}")
            if re.search(r"(?:^|[^A-Z])A?GPL(?:[^A-Z]|$)", license_name, re.IGNORECASE):
                if "provide-corresponding-source" not in obligations:
                    raise GateError("GPL-family corresponding-source obligation is required")

    if sorted(discovered) != sorted(declared):
        raise GateError("locked dependencies differ from reviewed component records")
    locked_index = {
        (component.ecosystem, component.path, component.scope,
         component.name, component.version)
        for component in discovered
        if component.ecosystem in LOCK_ECOSYSTEMS
    }
    for ecosystem, lock, scope, name, version in correspondence:
        if input_ecosystems.get(lock) != ecosystem:
            raise GateError("project pin references an unreviewed lock input")
        if (ecosystem, lock, scope, name, version) not in locked_index:
            raise GateError("project dependency lacks matching reviewed lock entry")
    if set(model_files(root, model_scan_exemptions(root, data))) != artifacts:
        raise GateError("model artifact set differs from reviewed component records")
    images = container_images(root, data, discovered_images)
    coverage = {
        "model_code": any(component["kind"] == "model_code" for component in data["components"]),
        "model_weight": any(component["kind"] == "model_weight" for component in data["components"]),
        "transport": any(location["scope"] == "transport"
                         for component in data["components"]
                         for location in component["locations"]),
    }
    for required in REQUIRED_SCOPE_REVIEWS:
        if required not in review_names and not coverage[required]:
            raise GateError(f"missing review coverage: {required}")
        if required in review_names and coverage[required]:
            raise GateError(f"stale reviewed-empty scope: {required}")
    unused = set(approvals) - ids
    if unused:
        raise GateError("owner approval references an absent component")
    return len(data["components"]), len(discovered), len(artifacts), images


def reviewed_lock_pins(root: Path, input_path, ecosystem, inventory_path=INVENTORY):
    """Collect the reviewed pins recorded for one lock input."""
    data = load_json(root / inventory_path)
    if not isinstance(data, dict) or not isinstance(data.get("components"), list):
        raise GateError("invalid component inventory schema")
    pins = {}
    for component in data["components"]:
        if not isinstance(component, dict) or not isinstance(component.get("locations"), list):
            raise GateError("invalid component record")
        for location in component["locations"]:
            if not isinstance(location, dict):
                raise GateError("invalid dependency location")
            if location.get("path") != input_path or location.get("ecosystem") != ecosystem:
                continue
            pin, _ = declared_pin(location.get("pin"), ecosystem,
                                  nonempty_string(component.get("upstream"), "upstream"))
            key = (nonempty_string(component.get("name"), "component name"),
                   nonempty_string(component.get("version"), "component version"))
            if key in pins:
                raise GateError("duplicate reviewed pin for a lock input")
            pins[key] = pin
    if not pins:
        raise GateError(f"no reviewed pins recorded for {input_path}")
    return pins


def verify_resolved_python(root: Path, report_path: Path, input_path: str):
    """Compare a pip installation report against the reviewed pins."""
    report = load_json(report_path)
    if not isinstance(report, dict) or str(report.get("version", "")).split(".")[0] != "1":
        raise GateError("unsupported pip installation report")
    installed = report.get("install")
    if not isinstance(installed, list) or not installed:
        raise GateError("pip installation report resolved no distribution")
    pins = reviewed_lock_pins(root, input_path, "python-requirements")
    seen = set()
    for entry in installed:
        metadata = entry.get("metadata") if isinstance(entry, dict) else None
        download = entry.get("download_info") if isinstance(entry, dict) else None
        if not isinstance(metadata, dict) or not isinstance(download, dict):
            raise GateError("invalid pip installation report entry")
        archive = download.get("archive_info")
        hashes = archive.get("hashes") if isinstance(archive, dict) else None
        digest = hashes.get("sha256") if isinstance(hashes, dict) else None
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise GateError("resolved distribution has no sha256 pin evidence")
        key = (canonical_python_name(nonempty_string(metadata.get("name"), "resolved name")),
               nonempty_string(metadata.get("version"), "resolved version"))
        pin = pins.get(key)
        if pin is None or "sha256:" + digest not in pin.digests:
            raise GateError(f"resolved pin differs from reviewed evidence: {key[0]} {key[1]}")
        seen.add(key)
    missing = set(pins) - seen
    if missing:
        raise GateError("pip installation report is missing reviewed pins")
    return len(seen)


def verify_resolved_npm(root: Path, installed_path: Path, input_path: str):
    """Compare the packages npm actually installed against the reviewed pins."""
    pins = reviewed_lock_pins(root, input_path, "npm-lock")
    resolved = npm_lock(installed_path, installed_path.name, "frontend")
    if not resolved:
        raise GateError("npm installation resolved no package")
    for component in resolved:
        pin = pins.get((component.name, component.version))
        if pin is None or pin != component.pin:
            raise GateError(
                f"resolved pin differs from reviewed evidence: {component.name} {component.version}")
    return len(resolved)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--resolved-python", type=Path,
                        help="pip installation report (--report) to verify against reviewed pins")
    parser.add_argument("--resolved-npm", type=Path,
                        help="node_modules/.package-lock.json to verify against reviewed pins")
    parser.add_argument("--input", help="reviewed lock input the resolved report belongs to")
    args = parser.parse_args(argv)
    if (args.resolved_python or args.resolved_npm) and not args.input:
        parser.error("--input is required with a resolved report")
    root = args.root.resolve()
    try:
        if args.resolved_python or args.resolved_npm:
            # Build-time check of what the installer actually resolved. The
            # inventory audit itself runs as its own step on the same commit,
            # before any dependency is installed.
            resolved = 0
            if args.resolved_python:
                resolved += verify_resolved_python(root, args.resolved_python, args.input)
            if args.resolved_npm:
                resolved += verify_resolved_npm(root, args.resolved_npm, args.input)
            print(f"resolved pins match reviewed evidence: {resolved} entries "
                  f"for {args.input}")
            return 0
        components, locked, artifacts, images = audit(root)
    except GateError as error:
        print(f"license gate failed: {error}", file=sys.stderr)
        return 1
    print(f"license gate passed: {components} components, {locked} locked entries, "
          f"{artifacts} model artifacts, {images} base images")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
