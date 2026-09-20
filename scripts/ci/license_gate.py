#!/usr/bin/env python3
"""Offline dependency and model-license release gate.

The reviewed inventory is intentionally hand-authored. Lockfiles establish what
would be installed; they are not accepted as independent license evidence.
"""

import argparse
import base64
import binascii
import datetime
import hashlib
import json
import posixpath
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import unquote


INVENTORY = "license/components.json"
APPROVALS = "license/owner-approvals.json"
PINS = "license/pins.json"
MODEL_DIRECTORIES = {"models", "weights", "checkpoints", "model-artifacts"}
MODEL_ASSET_PATHS = {("assets", "ml"), ("assets", "ai")}
BUILD_OUTPUT_DIRECTORIES = {"build", "dist"}
RECOGNIZED_STATIC_OUTPUT_SUFFIXES = {
    ".avif", ".cjs", ".css", ".gif", ".html", ".ico", ".jpeg", ".jpg",
    ".js", ".json", ".license", ".map", ".md", ".mjs", ".otf", ".png",
    ".svg", ".ttf", ".txt", ".wasm", ".webp", ".woff", ".woff2", ".xml",
}
MODEL_SUFFIXES = {
    ".bin", ".ckpt", ".engine", ".h5", ".mlmodel", ".onnx", ".pb", ".pt",
    ".pth", ".safetensors", ".tflite", ".weights",
}
REQUIRED_SCOPE_REVIEWS = {"transport", "model_code", "model_weight"}
PERMISSIVE_LICENSES = {
    "0BSD", "Apache-2.0", "Apache-2.0 OR BSD-2-Clause", "BSD-2-Clause",
    "BSD-3-Clause", "ISC", "MIT", "PSF-2.0", "Python-2.0", "Unicode-3.0",
    "Unicode-DFS-2016", "Zlib",
}
PACKAGE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)")
HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._@/+:-]*")
KINDS = {"source", "model_code", "model_weight"}
SCOPES = {"backend", "frontend", "transport", "tooling"}
ECOSYSTEMS = {
    "python-project", "python-requirements", "npm-project", "npm-lock",
    "model-artifact",
}


class GateError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class LockedComponent:
    path: str
    ecosystem: str
    scope: str
    name: str
    version: str
    artifact: str = ""


@dataclass(frozen=True, order=True)
class LockedPin:
    path: str
    ecosystem: str
    name: str
    version: str
    digests: tuple[str, ...]


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GateError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError, GateError) as error:
        raise GateError(f"cannot read {path.name}: {error}") from error


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


def python_lock(path: Path, relative: str, scope: str):
    text = path.read_text(encoding="utf-8")
    logical = text.replace("\\\n", " ").splitlines()
    found = []
    pins = []
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
        match = PACKAGE.match(line)
        if not match:
            raise GateError(f"unparsed or unpinned requirement in {relative}")
        hashes = HASH.findall(line)
        if not hashes:
            raise GateError(f"requirement has no SHA256 evidence in {relative}")
        found.append(LockedComponent(relative, "python-requirements", scope,
                                     match.group(1).lower().replace("_", "-"), match.group(2)))
        pins.append(LockedPin(relative, "python-requirements",
                              match.group(1).lower().replace("_", "-"), match.group(2),
                              tuple(sorted("sha256:" + value for value in hashes))))
    return found, pins, includes


def npm_lock(path: Path, relative: str, scope: str):
    data = load_json(path)
    if data.get("lockfileVersion") != 3 or not isinstance(data.get("packages"), dict):
        raise GateError(f"unsupported npm lock in {relative}")
    found = []
    pins = []
    for location, package in data["packages"].items():
        if not location:
            continue
        prefix = "node_modules/"
        if not location.startswith(prefix) or not isinstance(package, dict):
            raise GateError(f"invalid npm package entry in {relative}")
        name = location.rsplit(prefix, 1)[-1]
        version = nonempty_string(package.get("version"), "npm version")
        nonempty_string(package.get("resolved"), "npm resolved artifact")
        integrity = nonempty_string(package.get("integrity"), "npm integrity")
        digests = tuple(sorted(integrity.split()))
        if not digests or any(not valid_sri(value) for value in digests):
            raise GateError(f"invalid npm integrity in {relative}")
        found.append(LockedComponent(relative, "npm-lock", scope, name, version,
                                     unquote(package["resolved"])))
        pins.append(LockedPin(relative, "npm-lock", name, version, digests))
    return found, pins


def python_project(path: Path, relative: str, scope: str):
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise GateError(f"cannot parse {relative}") from error
    dependencies = data.get("project", {}).get("dependencies", [])
    if not isinstance(dependencies, list):
        raise GateError(f"invalid project dependencies in {relative}")
    found = []
    for dependency in dependencies:
        match = PACKAGE.fullmatch(dependency) if isinstance(dependency, str) else None
        if not match:
            raise GateError(f"project dependency is not exact in {relative}")
        found.append(LockedComponent(relative, "python-project", scope,
                                     match.group(1).lower().replace("_", "-"), match.group(2)))
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
            if not re.fullmatch(r"[0-9]+(?:\.[0-9A-Za-z-]+)+", version):
                raise GateError(f"npm dependency is not exact in {relative}")
            found.append(LockedComponent(relative, "npm-project", scope, name, version))
    return found


def model_files(root: Path):
    found = set()
    excluded = {".git", ".venv", "node_modules", "__pycache__"}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if set(relative.parts) & excluded:
            continue
        in_model_directory = model_like_path(relative.as_posix())
        opaque_output = opaque_build_output(relative.as_posix())
        has_model_suffix = path.suffix.lower() in MODEL_SUFFIXES
        if path.is_symlink() and (in_model_directory or opaque_output or has_model_suffix):
            raise GateError("model artifacts must be regular files")
        if path.is_file() and (in_model_directory or opaque_output or has_model_suffix):
            found.add(relative.as_posix())
    return sorted(found)


def reviewed_pins(root: Path):
    data = load_json(root / PINS)
    if set(data) != {"schema", "pins"} or data["schema"] != 1 or not isinstance(data["pins"], list):
        raise GateError("invalid pinning evidence registry")
    result = []
    required = {"path", "ecosystem", "name", "version", "digests"}
    for pin in data["pins"]:
        if not isinstance(pin, dict) or set(pin) != required:
            raise GateError("invalid pinning evidence record")
        path = relative_path(pin["path"], field="pin path")
        ecosystem = pin["ecosystem"]
        if ecosystem not in {"python-requirements", "npm-lock"}:
            raise GateError("invalid pin ecosystem")
        name = nonempty_string(pin["name"], "pin name")
        version = nonempty_string(pin["version"], "pin version")
        digests = pin["digests"]
        if not isinstance(digests, list) or not digests or digests != sorted(set(digests)):
            raise GateError("pin digests must be a sorted nonempty unique list")
        if ecosystem == "python-requirements":
            valid = all(isinstance(value, str)
                        and re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in digests)
        else:
            valid = all(valid_sri(value) for value in digests)
        if not valid:
            raise GateError("invalid reviewed digest")
        result.append(LockedPin(path, ecosystem, name, version, tuple(digests)))
    if len(result) != len(set(result)):
        raise GateError("duplicate pinning evidence record")
    return result


def approvals_by_id(root: Path):
    data = load_json(root / APPROVALS)
    if set(data) != {"schema", "approvals"} or data["schema"] != 1 or not isinstance(data["approvals"], list):
        raise GateError("invalid owner approval registry")
    result = {}
    required = {"component_id", "version", "license", "approved_by", "approved_on", "decision"}
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


def audit(root: Path, inventory_path=INVENTORY):
    data = load_json(root / inventory_path)
    required_root = {"schema", "inputs", "scope_reviews", "components"}
    if not isinstance(data, dict) or set(data) != required_root or data["schema"] != 1:
        raise GateError("invalid component inventory schema")

    inputs = data["inputs"]
    if not isinstance(inputs, list) or not inputs:
        raise GateError("inputs must be nonempty")
    discovered = []
    discovered_pins = []
    include_graph = {}
    input_paths = set()
    input_ecosystems = {}
    for item in inputs:
        if not isinstance(item, dict) or set(item) != {"path", "ecosystem", "scope"}:
            raise GateError("invalid inventory input")
        relative = relative_path(item["path"], field="input path")
        ecosystem = item["ecosystem"]
        scope = item["scope"]
        if ecosystem not in ECOSYSTEMS - {"model-artifact"} or scope not in SCOPES:
            raise GateError("unsupported input ecosystem or scope")
        if relative in input_paths or not (root / relative).is_file():
            raise GateError("duplicate or missing inventory input")
        input_paths.add(relative)
        input_ecosystems[relative] = ecosystem
        if ecosystem == "python-requirements":
            components, pins, includes = python_lock(root / relative, relative, scope)
            discovered.extend(components)
            discovered_pins.extend(pins)
            include_graph[relative] = includes
        elif ecosystem == "python-project":
            discovered.extend(python_project(root / relative, relative, scope))
        elif ecosystem == "npm-project":
            discovered.extend(npm_project(root / relative, relative, scope))
        else:
            components, pins = npm_lock(root / relative, relative, scope)
            discovered.extend(components)
            discovered_pins.extend(pins)

    tracked_inputs = set()
    for pattern in ("**/requirements*.lock", "**/requirements*.txt", "**/package-lock.json",
                    "**/package.json", "**/pyproject.toml"):
        for path in root.glob(pattern):
            if path.is_file() and not set(path.relative_to(root).parts) & {"node_modules", ".venv"}:
                tracked_inputs.add(path.relative_to(root).as_posix())
    unsupported = []
    for pattern in ("**/Cargo.lock", "**/go.mod", "**/pnpm-lock.yaml", "**/yarn.lock",
                    "**/Pipfile.lock", "**/poetry.lock", "**/uv.lock"):
        for path in root.glob(pattern):
            if path.is_file() and not set(path.relative_to(root).parts) & {"node_modules", ".venv"}:
                unsupported.append(path.relative_to(root).as_posix())
    if unsupported:
        raise GateError("unsupported dependency manifest requires a reviewed parser")
    if tracked_inputs != input_paths:
        raise GateError("dependency input set differs from reviewed inventory")
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
    if sorted(discovered_pins) != sorted(reviewed_pins(root)):
        raise GateError("lock digests differ from reviewed pinning evidence")
    locked_python = {
        (component.scope, component.name, component.version)
        for component in discovered
        if component.ecosystem == "python-requirements"
    }
    for component in discovered:
        if (component.ecosystem == "python-project"
                and (component.scope, component.name, component.version) not in locked_python):
            raise GateError("python project dependency lacks matching reviewed lock entry")

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
    artifacts = set()
    ids = set()
    required_component = {
        "id", "name", "version", "kind", "upstream", "license", "license_evidence",
        "transitive_evidence", "obligations", "notice_files", "locations", "sha256",
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
        if not isinstance(component["obligations"], list) or not component["obligations"]:
            raise GateError("redistribution obligations must be explicit")
        if any(not isinstance(value, str) or not value for value in component["obligations"]):
            raise GateError("invalid redistribution obligation")
        obligations = set(component["obligations"])
        if "preserve-license-and-copyright" not in obligations:
            raise GateError("license preservation obligation is required")
        if "Apache-" in license_name and "preserve-notice" not in obligations:
            raise GateError("Apache notice obligation is required")
        evidence(root, component["notice_files"], "notice files")
        if license_name not in PERMISSIVE_LICENSES:
            approval = approvals.get(component_id)
            expected = (version, license_name)
            if approval is None or (approval["version"], approval["license"]) != expected:
                raise GateError(f"blocked license lacks exact owner approval: {component_id}")
            if re.search(r"(?:^|[^A-Z])A?GPL(?:[^A-Z]|$)", license_name, re.IGNORECASE):
                if "provide-corresponding-source" not in obligations:
                    raise GateError("GPL-family corresponding-source obligation is required")

        locations = component["locations"]
        sha256 = component["sha256"]
        if kind == "model_weight":
            if not isinstance(locations, list) or len(locations) != 1:
                raise GateError("model weight must identify exactly one artifact")
            location = locations[0]
            if not isinstance(location, dict) or set(location) != {"path", "ecosystem", "scope"}:
                raise GateError("invalid model artifact location")
            path = relative_path(location["path"], field="model artifact path")
            if location != {"path": path, "ecosystem": "model-artifact", "scope": "model_weight"}:
                raise GateError("invalid model artifact classification")
            if not reserved_model_path(path):
                raise GateError("model weight must be stored in a reserved model artifact directory")
            artifact = root / path
            if not artifact.is_file() or not re.fullmatch(r"[0-9a-f]{64}", str(sha256)):
                raise GateError("missing model artifact or SHA256")
            if hashlib.sha256(artifact.read_bytes()).hexdigest() != sha256:
                raise GateError("model artifact SHA256 mismatch")
            artifacts.add(path)
        else:
            if sha256 is not None or not isinstance(locations, list) or not locations:
                raise GateError("source/model code must use dependency locations and null sha256")
            for location in locations:
                if not isinstance(location, dict) or set(location) != {"path", "ecosystem", "scope"}:
                    raise GateError("invalid dependency location")
                artifact = unquote(upstream) if location["ecosystem"] == "npm-lock" else ""
                locked = LockedComponent(location["path"], location["ecosystem"],
                                         location["scope"], name, version, artifact)
                declared.append(locked)

    if sorted(discovered) != sorted(declared):
        raise GateError("locked dependencies differ from reviewed component records")
    if set(model_files(root)) != artifacts:
        raise GateError("model artifact set differs from reviewed component records")
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
    return len(data["components"]), len(discovered), len(artifacts)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)
    try:
        components, locked, artifacts = audit(args.root.resolve())
    except GateError as error:
        print(f"license gate failed: {error}", file=sys.stderr)
        return 1
    print(f"license gate passed: {components} components, {locked} locked entries, {artifacts} model artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
