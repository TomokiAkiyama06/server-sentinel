#!/usr/bin/env python3
"""Run fail-closed checks for implemented components; no runtime is fabricated.

See docs/CI.md for the version 1 component ci.toml contract. Docker smoke tests
block external egress; that does not prove the absence of attempted telemetry.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import tomllib
import uuid


COMPONENTS = ("server", "agent", "web")
PYTHON_SUFFIXES = {".py", ".pyi"}
NODE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"}
OTHER_SOURCE_SUFFIXES = {".go", ".rs", ".c", ".cpp", ".java", ".sh", ".bash"}
IGNORED_DIRS = {".git", ".venv", ".venv-ci", "node_modules", "__pycache__"}
COMMAND_TIMEOUT = 600
SMOKE_TIMEOUT = 120


class CheckFailure(Exception):
    """A component is incomplete or a required check failed."""


def files_under(root: Path) -> list[Path]:
    """Inspect source directories, excluding generated dependency trees."""
    if root.is_symlink():
        raise CheckFailure(f"CI source directory must not be a symlink: {root}")

    def inaccessible(error: OSError) -> None:
        raise CheckFailure(f"cannot inspect CI source directory: {error.filename}") from error

    result = []
    for current, directories, filenames in os.walk(root, onerror=inaccessible):
        directories[:] = [name for name in directories if name not in IGNORED_DIRS]
        for name in directories + filenames:
            path = Path(current) / name
            if path.is_symlink():
                raise CheckFailure(f"CI source tree must not contain symlinks: {path}")
        result.extend(Path(current) / name for name in filenames)
    return sorted(result)


def run(command: list[str], cwd: Path, *, env: dict[str, str] | None = None,
        timeout: int = COMMAND_TIMEOUT) -> None:
    print(f"[{cwd.name}] {shlex.join(command)}", flush=True)
    try:
        subprocess.run(command, cwd=cwd, env=env, check=True, timeout=timeout)
    except subprocess.CalledProcessError as exc:
        raise CheckFailure(f"{cwd.name}: command failed (exit {exc.returncode})") from exc
    except subprocess.TimeoutExpired as exc:
        raise CheckFailure(f"{cwd.name}: command exceeded {timeout}s") from exc
    except OSError as exc:
        raise CheckFailure(f"{cwd.name}: cannot execute {command[0]}") from exc


def read_toml(path: Path) -> dict:
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise CheckFailure(f"{path}: missing or invalid TOML") from exc


def argv(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value or any(
        not isinstance(item, str) or not item.strip() or "\0" in item for item in value
    ):
        raise CheckFailure(f"{label} must be a nonempty argv array of strings")
    return value


def require_file(path: Path) -> None:
    if not path.is_file():
        raise CheckFailure(f"required component file is missing: {path}")


def smoke_config(component: Path, config: dict) -> dict:
    smoke = config.get("smoke")
    if not isinstance(smoke, dict) or set(smoke) != {"dockerfile", "normal", "error"}:
        raise CheckFailure(f"{component.name}: smoke requires dockerfile, normal and error")
    dockerfile = smoke["dockerfile"]
    if not isinstance(dockerfile, str) or not dockerfile or Path(dockerfile).is_absolute():
        raise CheckFailure(f"{component.name}: smoke.dockerfile must be a relative path")
    path = (component / dockerfile).resolve()
    if not path.is_relative_to(component.resolve()):
        raise CheckFailure(f"{component.name}: smoke.dockerfile escapes the component")
    require_file(path)
    return {
        "dockerfile": path,
        "normal": argv(smoke["normal"], f"{component.name}: smoke.normal"),
        "error": argv(smoke["error"], f"{component.name}: smoke.error"),
    }


def component_config(component: Path, files: list[Path]) -> dict | None:
    python = (component / "pyproject.toml").exists() or any(
        path.suffix in PYTHON_SUFFIXES
        or path.name in {"pyproject.toml", "setup.cfg", "uv.lock", "poetry.lock"}
        or path.name.startswith("requirements") and path.suffix in {".txt", ".lock"}
        for path in files
    )
    node = (component / "package.json").exists() or any(
        path.suffix in NODE_SUFFIXES
        or path.name in {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
        for path in files
    )
    other = any(path.suffix in OTHER_SOURCE_SUFFIXES for path in files)
    container = any(path.name.startswith("Dockerfile") for path in files)
    if not (python or node or other or container):
        if (component / "ci.toml").exists():
            raise CheckFailure(f"{component.name}: ci.toml exists without a component")
        print(f"{component.name}: not implemented (no runtime source or manifest)")
        return None
    if other or (not python and not node):
        raise CheckFailure(f"{component.name}: unsupported runtime requires explicit CI onboarding")

    config = read_toml(component / "ci.toml")
    if type(config.get("version")) is not int or config["version"] != 1:
        raise CheckFailure(f"{component.name}: ci.toml requires version = 1")
    if set(config) - {"version", "checks", "smoke"}:
        raise CheckFailure(f"{component.name}: unknown ci.toml sections")
    result = {"python": python, "node": node, "smoke": smoke_config(component, config)}
    if python:
        read_toml(component / "pyproject.toml")
        require_file(component / "requirements-ci.lock")
        checks = config.get("checks")
        if not isinstance(checks, dict) or set(checks) != {"lint", "test"}:
            raise CheckFailure(f"{component.name}: Python requires checks.lint and checks.test")
        result["checks"] = {
            key: argv(checks[key], f"{component.name}: checks.{key}") for key in ("lint", "test")
        }
    elif "checks" in config:
        raise CheckFailure(f"{component.name}: Node checks use package.json lint/test scripts")
    if node:
        require_file(component / "package-lock.json")
        try:
            package = json.loads((component / "package.json").read_text())
        except (OSError, ValueError) as exc:
            raise CheckFailure(f"{component.name}: missing or invalid package.json") from exc
        scripts = package.get("scripts") if isinstance(package, dict) else None
        if not isinstance(scripts, dict) or any(
            not isinstance(scripts.get(name), str) or not scripts[name].strip()
            for name in ("lint", "test")
        ):
            raise CheckFailure(f"{component.name}: package.json requires lint and test scripts")
    return result


def python_checks(component: Path, config: dict) -> None:
    with tempfile.TemporaryDirectory(prefix="server-sentinel-ci-") as temporary:
        venv = Path(temporary) / "venv"
        run([sys.executable, "-m", "venv", str(venv)], component)
        env = os.environ.copy()
        env.update({
            "PATH": str(venv / "bin") + os.pathsep + env.get("PATH", ""),
            "VIRTUAL_ENV": str(venv),
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        run([
            str(venv / "bin/python"), "-m", "pip", "install", "--require-hashes",
            "--only-binary=:all:", "--requirement", "requirements-ci.lock",
        ], component, env=env)
        for name in ("lint", "test"):
            run(config["checks"][name], component, env=env)


def node_checks(component: Path) -> None:
    run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], component)
    run(["npm", "run", "lint"], component)
    run(["npm", "run", "test"], component)


def docker_check(dockerfile: Path, context: Path) -> None:
    run(["docker", "build", "--check", "--file", str(dockerfile), str(context)], context)


def smoke_checks(component: Path, config: dict) -> None:
    """Execute synthetic normal/error assertions with no external runtime network.

    Commands must start the actual component and assert their respective scenario.
    Dependency downloads during image construction are outside the smoke phase.
    No host environment, credentials, volumes, ports or deployment data are passed.
    """
    smoke = config["smoke"]
    image = "server-sentinel-ci:" + uuid.uuid4().hex
    run([
        "docker", "build", "--file", str(smoke["dockerfile"]), "--tag", image, str(component),
    ], component)
    try:
        for scenario in ("normal", "error"):
            name = "server-sentinel-ci-" + uuid.uuid4().hex
            command = smoke[scenario]
            try:
                run([
                    "docker", "run", "--name", name, "--pull=never", "--network=none",
                    "--read-only", "--user=65534:65534", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=512m",
                    "--cpus=1", "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
                    "--env=SERVERSENTINEL_CI_SYNTHETIC_ONLY=1",
                    f"--env=SERVERSENTINEL_CI_SCENARIO={scenario}",
                    "--entrypoint", command[0], image, *command[1:],
                ], component, timeout=SMOKE_TIMEOUT)
            finally:
                # Killing a timed-out docker CLI does not stop its container.
                run(["docker", "container", "rm", "--force", name], component, timeout=30)
    finally:
        run(["docker", "image", "rm", "--force", image], component, timeout=30)
    print(f"{component.name}: isolated synthetic normal/error smoke passed; "
          "outbound attempts were not inspected")


def is_compose(path: Path) -> bool:
    return path.suffix in {".yaml", ".yml"} and (
        path.stem == "compose" or path.stem.startswith("compose.")
        or path.stem == "docker-compose" or path.stem.startswith("docker-compose.")
    )


def run_checks(root: Path) -> None:
    root = root.resolve()
    discovered = {}
    # Validate every onboarding contract before installing or executing anything.
    for name in COMPONENTS:
        component = root / name
        config = component_config(component, files_under(component))
        if config is not None:
            discovered[component] = config

    files = files_under(root)
    smoke_contexts = {
        config["smoke"]["dockerfile"]: component for component, config in discovered.items()
    }
    dockerfiles = {path.resolve() for path in files if path.name.startswith("Dockerfile")}
    dockerfiles.update(smoke_contexts)
    for path in sorted(dockerfiles):
        docker_check(path, smoke_contexts.get(path, root))
    if not dockerfiles:
        print("Docker: not implemented (no Dockerfiles)")
    compose_files = [path for path in files if is_compose(path)]
    for path in compose_files:
        run([
            "docker", "compose", "--env-file", "/dev/null", "--file", str(path),
            "config", "--quiet", "--no-interpolate", "--no-env-resolution",
        ], root)
    if not compose_files:
        print("Compose: not implemented (no Compose configurations)")

    for component, config in discovered.items():
        if config["python"]:
            python_checks(component, config)
        if config["node"]:
            node_checks(component)
        smoke_checks(component, config)
    if not discovered:
        print("Runtime startup/egress smoke: not applicable; no runtime components exist")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    try:
        run_checks(args.root)
    except CheckFailure as exc:
        print(f"Component CI failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
