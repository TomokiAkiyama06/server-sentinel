"""Exercise conditional CI using synthetic projects and mocked external tools."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.ci import component_checks as ci


class ComponentChecksTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ci.COMPONENTS:
            self.write(f"{name}/README.md", "Future component.\n")
        self.process = patch.object(ci.subprocess, "run").start()
        self.addCleanup(patch.stopall)
        self.output = io.StringIO()
        self.redirect = redirect_stdout(self.output)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def config(self, name="server", python=True, smoke=True):
        text = "version = 1\n"
        if python:
            text += ('[checks]\nlint = ["python", "-m", "pyflakes", "."]\n'
                     'test = ["python", "-m", "unittest", "discover"]\n')
        if smoke:
            text += ('[smoke]\ndockerfile = "Dockerfile.ci"\n'
                     'normal = ["python", "smoke.py", "normal"]\n'
                     'error = ["python", "smoke.py", "error"]\n')
        self.write(f"{name}/ci.toml", text)
        self.write(f"{name}/Dockerfile.ci", "FROM scratch\n")

    def python_component(self, name="server"):
        self.config(name)
        self.write(f"{name}/pyproject.toml", '[project]\nname = "synthetic"\nversion = "0.0.0"\n')
        self.write(f"{name}/requirements-ci.lock", "# Synthetic test: no dependencies.\n")
        self.write(f"{name}/app.py", "print('synthetic')\n")

    def node_component(self, name="web"):
        self.config(name, python=False)
        self.write(f"{name}/package.json", json.dumps({
            "name": "synthetic",
            "scripts": {"lint": "node lint.mjs", "test": "node test.mjs"},
        }))
        self.write(f"{name}/package-lock.json", '{"lockfileVersion": 3}\n')

    def commands(self):
        return [call.args[0] for call in self.process.call_args_list]

    def test_readme_only_and_root_tooling_are_explicitly_not_implemented(self):
        self.write("scripts/ci/tool.py", "pass\n")
        self.write("pyproject.toml", "[tool.synthetic]\n")
        ci.run_checks(self.root)
        self.process.assert_not_called()
        for name in ci.COMPONENTS:
            self.assertIn(f"{name}: not implemented", self.output.getvalue())
        self.assertIn("no runtime components exist", self.output.getvalue())

    def test_source_without_onboarding_fails_instead_of_skipping(self):
        for suffix in ("py", "tsx", "mjs"):
            with self.subTest(suffix=suffix):
                source = self.write(f"server/app.{suffix}", "synthetic\n")
                with self.assertRaisesRegex(ci.CheckFailure, "ci.toml"):
                    ci.run_checks(self.root)
                source.unlink()
        self.process.assert_not_called()

    def test_dependency_and_cache_directories_are_pruned_before_traversal(self):
        for directory in ci.IGNORED_DIRS:
            self.write(f"server/{directory}/hidden/app.py", "not component source\n")
        walked = []
        real_walk = ci.os.walk

        def record_walk(root, **kwargs):
            for current, directories, files in real_walk(root, **kwargs):
                walked.append(Path(current))
                yield current, directories, files

        with patch.object(ci.os, "walk", side_effect=record_walk):
            ci.run_checks(self.root)
        self.assertFalse(any(
            part in ci.IGNORED_DIRS for path in walked
            for part in path.relative_to(self.root).parts
        ))
        self.process.assert_not_called()

    def test_source_symlinks_fail_without_following_external_files(self):
        for directory in (False, True):
            with self.subTest(directory=directory):
                with tempfile.TemporaryDirectory() as outside:
                    target = Path(outside)
                    if not directory:
                        target = target / "external.py"
                        target.write_text("synthetic external source\n")
                    link = self.root / "server/link"
                    link.symlink_to(target, target_is_directory=directory)
                    with self.assertRaisesRegex(ci.CheckFailure, "symlink"):
                        ci.run_checks(self.root)
                    link.unlink()
        self.process.assert_not_called()

    def test_nested_manifest_alone_cannot_hide_implementation(self):
        self.write("server/nested/package.json", '{"name":"synthetic"}')
        with self.assertRaises(ci.CheckFailure):
            ci.run_checks(self.root)

    def test_python_requires_manifest_lock_and_both_commands(self):
        self.python_component()
        for filename in ("pyproject.toml", "requirements-ci.lock"):
            with self.subTest(filename=filename):
                path = self.root / "server" / filename
                previous = path.read_text()
                path.unlink()
                with self.assertRaises(ci.CheckFailure):
                    ci.run_checks(self.root)
                path.write_text(previous)
        path = self.root / "server/ci.toml"
        path.write_text(path.read_text().replace(
            'test = ["python", "-m", "unittest", "discover"]', 'test = []',
        ))
        with self.assertRaisesRegex(ci.CheckFailure, "argv"):
            ci.run_checks(self.root)
        self.process.assert_not_called()

    def test_python_install_is_hashed_isolated_and_commands_are_checked(self):
        self.python_component()
        ci.run_checks(self.root)
        calls = self.process.call_args_list
        pip_call = next(call for call in calls if "pip" in call.args[0])
        self.assertIn("--require-hashes", pip_call.args[0])
        self.assertIn("requirements-ci.lock", pip_call.args[0])
        self.assertIn("VIRTUAL_ENV", pip_call.kwargs["env"])
        self.assertIn(["python", "-m", "pyflakes", "."], self.commands())
        self.assertIn(["python", "-m", "unittest", "discover"], self.commands())
        for call in calls:
            self.assertTrue(call.kwargs["check"])
            self.assertGreater(call.kwargs["timeout"], 0)

    def test_node_requires_lock_and_nonempty_lint_test_scripts(self):
        self.node_component()
        (self.root / "web/package-lock.json").unlink()
        with self.assertRaisesRegex(ci.CheckFailure, "package-lock"):
            ci.run_checks(self.root)
        self.write("web/package-lock.json", "{}")
        self.write("web/package.json", '{"scripts":{"lint":"lint"}}')
        with self.assertRaisesRegex(ci.CheckFailure, "lint and test"):
            ci.run_checks(self.root)
        self.process.assert_not_called()

    def test_node_install_and_both_package_scripts_run(self):
        self.node_component()
        ci.run_checks(self.root)
        self.assertIn(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], self.commands())
        self.assertIn(["npm", "run", "lint"], self.commands())
        self.assertIn(["npm", "run", "test"], self.commands())

    def test_missing_smoke_is_a_failure_before_any_install(self):
        self.python_component()
        self.config(smoke=False)
        with self.assertRaisesRegex(ci.CheckFailure, "smoke requires"):
            ci.run_checks(self.root)
        self.process.assert_not_called()

    def test_smoke_cannot_use_dockerfile_outside_component(self):
        self.python_component()
        self.write("Dockerfile", "FROM scratch\n")
        path = self.root / "server/ci.toml"
        path.write_text(path.read_text().replace('"Dockerfile.ci"', '"../Dockerfile"'))
        with self.assertRaisesRegex(ci.CheckFailure, "escapes"):
            ci.run_checks(self.root)
        self.process.assert_not_called()

    def test_unknown_version_and_sections_fail(self):
        self.python_component()
        path = self.root / "server/ci.toml"
        original = path.read_text()
        for content in (original.replace("version = 1", "version = true"),
                        original.replace("version = 1", "version = 2"),
                        original + "\n[ignored]\nenabled = false\n"):
            path.write_text(content)
            with self.assertRaises(ci.CheckFailure):
                ci.run_checks(self.root)

    def test_smoke_runs_both_scenarios_with_restrictions_and_cleanup(self):
        self.node_component()
        with patch.dict(ci.os.environ, {"SYNTHETIC_CI_SECRET": "must-not-enter-container"}):
            ci.run_checks(self.root)
        commands = self.commands()
        runs = [command for command in commands if command[:2] == ["docker", "run"]]
        self.assertEqual(len(runs), 2)
        for scenario, command in zip(("normal", "error"), runs):
            for required in ("--network=none", "--read-only", "--user=65534:65534",
                             "--cap-drop=ALL", "--security-opt=no-new-privileges",
                             "--pids-limit=128", "--memory=512m", "--cpus=1",
                             "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
                             "--env=SERVERSENTINEL_CI_SYNTHETIC_ONLY=1",
                             f"--env=SERVERSENTINEL_CI_SCENARIO={scenario}"):
                self.assertIn(required, command)
            self.assertNotIn("must-not-enter-container", " ".join(command))
            self.assertFalse(any(
                arg.startswith(("--volume", "--mount", "--publish")) for arg in command
            ))
            name = command[command.index("--name") + 1]
            self.assertIn(["docker", "container", "rm", "--force", name], commands)
        self.assertTrue(any(
            command[:4] == ["docker", "image", "rm", "--force"] for command in commands
        ))
        self.assertIn("outbound attempts were not inspected", self.output.getvalue())

    def test_command_failure_and_timeout_propagate_and_clean_up_smoke(self):
        self.python_component()
        for exception in (subprocess.CalledProcessError(7, ["docker"]),
                          subprocess.TimeoutExpired(["docker"], ci.SMOKE_TIMEOUT)):
            with self.subTest(exception=exception):
                self.process.reset_mock()

                def execute(command, **kwargs):
                    if command[:2] == ["docker", "run"]:
                        raise exception

                self.process.side_effect = execute
                with self.assertRaises(ci.CheckFailure):
                    ci.run_checks(self.root)
                self.assertTrue(any(command[:4] == ["docker", "container", "rm", "--force"]
                                    for command in self.commands()))
                self.assertTrue(any(command[:4] == ["docker", "image", "rm", "--force"]
                                    for command in self.commands()))

    def test_lint_failure_prevents_smoke(self):
        self.node_component()

        def execute(command, **kwargs):
            if command == ["npm", "run", "lint"]:
                raise subprocess.CalledProcessError(2, command)

        self.process.side_effect = execute
        with self.assertRaisesRegex(ci.CheckFailure, "exit 2"):
            ci.run_checks(self.root)
        self.assertFalse(any(command[:2] == ["docker", "run"] for command in self.commands()))

    def test_all_contracts_validated_before_running_any_component(self):
        self.python_component()
        self.write("web/src/app.tsx", "synthetic\n")
        with self.assertRaises(ci.CheckFailure):
            ci.run_checks(self.root)
        self.process.assert_not_called()

    def test_docker_and_compose_are_validated_without_starting_services(self):
        dockerfile = self.write("infra/docker/Dockerfile.server", "FROM scratch\n")
        compose = self.write("infra/docker/compose.ci.yaml", "services: {}\n")
        ci.run_checks(self.root)
        self.assertIn([
            "docker", "build", "--check", "--file", str(dockerfile), str(self.root),
        ], self.commands())
        self.assertIn([
            "docker", "compose", "--env-file", "/dev/null", "--file", str(compose),
            "config", "--quiet", "--no-interpolate", "--no-env-resolution",
        ], self.commands())
        self.assertFalse(any("up" in command or "run" in command for command in self.commands()))

    def test_compose_failure_is_not_ignored(self):
        self.write("compose.yaml", "invalid synthetic configuration\n")
        self.process.side_effect = subprocess.CalledProcessError(1, ["docker", "compose"])
        with self.assertRaisesRegex(ci.CheckFailure, "exit 1"):
            ci.run_checks(self.root)


if __name__ == "__main__":
    unittest.main()
