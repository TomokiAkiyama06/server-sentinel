"""License gate regressions use synthetic manifests and artifacts only."""

import contextlib
import hashlib
import io
import base64
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.ci import license_gate
from scripts.ci import repository_guard


DIGEST = "sha256:" + "a" * 64
IMAGE_DIGEST = "sha256:" + "d" * 64


class GateFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.write("docs/evidence.md", "synthetic review evidence\n")
        self.write("docs/decisions/0001-synthetic.md", "synthetic owner decision\n")
        self.write("requirements.lock", "demo==1.2.3 --hash=" + DIGEST + "\n")
        self.inputs = [{
            "path": "requirements.lock",
            "ecosystem": "python-requirements",
            "scope": "backend",
        }]
        self.reviews = [
            self.review("transport"), self.review("model_code"), self.review("model_weight"),
        ]
        self.components = [self.component()]
        self.images = []
        self.exemptions = []
        self.build_scripts = []
        self.approvals = []
        self.save()

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content if isinstance(content, bytes) else content.encode())

    def review(self, scope):
        return {"scope": scope, "status": "reviewed-empty", "evidence": ["docs/evidence.md"]}

    def location(self, **changes):
        value = {
            "path": "requirements.lock",
            "ecosystem": "python-requirements",
            "scope": "backend",
            "pin": {"type": "lockfile-entry", "digests": [DIGEST]},
        }
        value.update(changes)
        return value

    def component(self, **changes):
        value = {
            "id": "pypi:demo@1.2.3",
            "name": "demo",
            "version": "1.2.3",
            "kind": "source",
            "upstream": "https://example.test/demo/1.2.3",
            "license": "MIT",
            "license_evidence": ["docs/evidence.md"],
            "transitive_evidence": ["docs/evidence.md"],
            "obligations": ["preserve-license-and-copyright"],
            "notice_files": ["docs/evidence.md"],
            "locations": [self.location()],
        }
        value.update(changes)
        return value

    def approval(self, **changes):
        value = {
            "component_id": "pypi:demo@1.2.3",
            "name": "demo",
            "version": "1.2.3",
            "kind": "source",
            "license": "GPL-3.0-only",
            "upstream": "https://example.test/demo/1.2.3",
            "approved_by": "repository-owner",
            "approved_on": "2026-09-21",
            "decision": "docs/decisions/0001-synthetic.md",
        }
        value.update(changes)
        return value

    def image(self, **changes):
        value = {
            "id": "image:demo/base@1.0",
            "repository": "demo/base",
            "tag": "1.0",
            "digest": IMAGE_DIGEST,
            "distribution": "ci-only-not-redistributed",
            "upstream": "https://example.test/demo/base",
            "license_summary": "synthetic unmodified aggregate execution image",
            "license_evidence": ["docs/evidence.md"],
            "transitive_evidence": ["docs/evidence.md"],
            "obligations": [
                "preserve-license-and-copyright",
                "preserve-notice",
                "fulfill-image-redistribution-obligations",
            ],
            "notice_files": ["docs/evidence.md"],
            "locations": [{"path": "Dockerfile.ci", "scope": "tooling"}],
        }
        value.update(changes)
        return value

    def weight(self, artifact, path="models/demo.onnx", **changes):
        value = {
            "id": "model:demo-weight@1",
            "name": "demo-weight",
            "version": "1",
            "kind": "model_weight",
            "upstream": "https://example.test/models/demo/1",
            "license": "Apache-2.0",
            "license_evidence": ["docs/evidence.md"],
            "transitive_evidence": ["docs/evidence.md"],
            "obligations": ["preserve-license-and-copyright", "preserve-notice"],
            "notice_files": ["docs/evidence.md"],
            "locations": [{
                "path": path,
                "ecosystem": "model-artifact",
                "scope": "model_weight",
                "pin": {
                    "type": "artifact-digest",
                    "digests": ["sha256:" + hashlib.sha256(artifact).hexdigest()],
                },
            }],
        }
        value.update(changes)
        return value

    def add_npm_project(self, scripts=None):
        scripts = scripts if scripts is not None else {"build": "node scripts/build.mjs"}
        self.write("package.json", json.dumps({
            "dependencies": {},
            "scripts": scripts,
        }))
        self.add_build_script("scripts/build.mjs")
        if any("tests/*.test.mjs" in body for body in scripts.values()):
            self.add_build_script("tests/core.test.mjs")
        self.inputs.append({
            "path": "package.json", "ecosystem": "npm-project", "scope": "frontend",
        })
        self.save()

    def add_build_script(self, path, content="// synthetic reviewed script\n"):
        self.write(path, content)
        digest = "sha256:" + hashlib.sha256(content.encode()).hexdigest()
        self.build_scripts = [record for record in self.build_scripts
                              if record["path"] != path]
        self.build_scripts.append({"path": path, "sha256": digest})

    def add_container(self, content="FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"):
        self.write("Dockerfile.ci", content)
        self.inputs.append({
            "path": "Dockerfile.ci", "ecosystem": "container-image", "scope": "tooling",
        })
        self.images.append(self.image())
        self.save()

    def npm_lock(self, integrity, resolved="https://example.test/transitive-4.5.6.tgz",
                 path="frontend/package-lock.json"):
        self.write(path, json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/transitive": {
                    "version": "4.5.6", "resolved": resolved, "integrity": integrity,
                },
            },
        }))
        return {
            "path": path, "ecosystem": "npm-lock", "scope": "frontend",
            "pin": {"type": "lockfile-entry", "resolved": resolved, "digests": [integrity]},
        }

    def sri(self, byte, algorithm="sha512"):
        sizes = {"sha256": 32, "sha384": 48, "sha512": 64}
        encoded = base64.b64encode(bytes([byte]) * sizes[algorithm]).decode("ascii")
        return algorithm + "-" + encoded

    def save(self):
        self.write(license_gate.INVENTORY, json.dumps({
            "schema": 3,
            "build_scripts": self.build_scripts,
            "inputs": self.inputs,
            "scope_reviews": self.reviews,
            "model_scan_exemptions": self.exemptions,
            "components": self.components,
            "container_images": self.images,
        }))
        self.write(license_gate.APPROVALS, json.dumps({
            "schema": 1, "approvals": self.approvals,
        }))

    def assert_dynamic_python_dependency_rejected(self, project):
        self.write("deps.in", "unreviewed-package==9.8.7\n")
        self.write("pyproject.toml", project)
        self.inputs.append({
            "path": "pyproject.toml", "ecosystem": "python-project", "scope": "backend",
        })
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "unsupported project dependency section"):
            license_gate.audit(self.root)


class LicenseGateTests(GateFixture):
    def test_permissive_exact_component_passes(self):
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 0))

    def test_locked_dependency_missing_from_inventory_fails(self):
        self.components = []
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "locked dependencies differ"):
            license_gate.audit(self.root)

    def test_python_project_dependency_requires_matching_hashed_lock_entry(self):
        self.write("pyproject.toml", '[project]\ndependencies = ["direct==9.8.7"]\n')
        self.inputs.append({
            "path": "pyproject.toml", "ecosystem": "python-project", "scope": "backend",
        })
        self.components.append(self.component(
            id="pypi:direct@9.8.7",
            name="direct",
            version="9.8.7",
            upstream="https://example.test/direct/9.8.7",
            locations=[self.location(
                path="pyproject.toml", ecosystem="python-project",
                pin={"type": "lock-correspondence", "lock": "requirements.lock"},
            )],
        ))
        self.save()
        with self.assertRaisesRegex(
                license_gate.GateError, "project dependency lacks matching reviewed lock entry"):
            license_gate.audit(self.root)

    def test_python_project_lock_correspondence_includes_scope(self):
        self.write("pyproject.toml", '[project]\ndependencies = ["demo==1.2.3"]\n')
        project_location = self.location(
            path="pyproject.toml", ecosystem="python-project", scope="frontend",
            pin={"type": "lock-correspondence", "lock": "requirements.lock"},
        )
        self.inputs.append({
            "path": "pyproject.toml", "ecosystem": "python-project", "scope": "frontend",
        })
        self.components[0]["locations"].append(project_location)
        self.save()
        with self.assertRaisesRegex(
                license_gate.GateError, "project dependency lacks matching reviewed lock entry"):
            license_gate.audit(self.root)

        project_location["scope"] = "backend"
        self.inputs[-1]["scope"] = "backend"
        self.save()
        self.assertEqual(license_gate.audit(self.root), (1, 2, 0, 0))

    def test_project_pin_must_name_a_reviewed_lock_input(self):
        self.write("pyproject.toml", '[project]\ndependencies = ["demo==1.2.3"]\n')
        self.inputs.append({
            "path": "pyproject.toml", "ecosystem": "python-project", "scope": "backend",
        })
        self.components[0]["locations"].append(self.location(
            path="pyproject.toml", ecosystem="python-project",
            pin={"type": "lock-correspondence", "lock": "unreviewed.lock"},
        ))
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "unreviewed lock input"):
            license_gate.audit(self.root)

    def test_python_names_use_pep503_canonicalization_for_lock_correspondence(self):
        self.write("requirements.lock", "zope...interface==1.2.3 --hash=" + DIGEST + "\n")
        self.write("pyproject.toml", '[project]\ndependencies = ["Zope.Interface==1.2.3"]\n')
        self.inputs.append({
            "path": "pyproject.toml", "ecosystem": "python-project", "scope": "backend",
        })
        self.components = [self.component(
            id="pypi:zope-interface@1.2.3",
            name="zope-interface",
            upstream="https://example.test/zope-interface/1.2.3",
            locations=[self.location(), self.location(
                path="pyproject.toml", ecosystem="python-project",
                pin={"type": "lock-correspondence", "lock": "requirements.lock"},
            )],
        )]
        self.save()
        self.assertEqual(license_gate.audit(self.root), (1, 2, 0, 0))

    def test_missing_license_transitive_notice_and_upstream_evidence_fail(self):
        mutations = [
            {"license_evidence": []},
            {"transitive_evidence": []},
            {"notice_files": []},
            {"upstream": "http://example.test/demo"},
            {"version": ""},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.components = [self.component(**mutation)]
                self.save()
                with self.assertRaises(license_gate.GateError):
                    license_gate.audit(self.root)

    def test_blocked_families_require_exact_owner_approval(self):
        for blocked in ("AGPL-3.0-only", "GPL-3.0-only", "SSPL-1.0", "BUSL-1.1",
                        "source-available-custom", "unclear", "Proprietary", "Elastic-2.0",
                        "Commons-Clause", "Custom-Permissive-Sounding"):
            with self.subTest(license=blocked):
                self.components = [self.component(license=blocked)]
                self.approvals = []
                self.save()
                with self.assertRaisesRegex(license_gate.GateError, "lacks exact owner approval"):
                    license_gate.audit(self.root)

    def test_exact_recorded_owner_approval_allows_blocked_component(self):
        self.components = [self.component(
            license="GPL-3.0-only",
            obligations=["preserve-license-and-copyright", "provide-corresponding-source"],
        )]
        self.approvals = [self.approval()]
        self.save()
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 0))
        self.approvals[0]["version"] = "1.2.2"
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "lacks exact owner approval"):
            license_gate.audit(self.root)

    def test_owner_approval_is_bound_to_the_actual_dependency_identity(self):
        """An approval must not survive swapping the package behind its id."""
        self.components = [self.component(
            license="GPL-3.0-only",
            obligations=["preserve-license-and-copyright", "provide-corresponding-source"],
        )]
        self.approvals = [self.approval()]
        self.save()
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 0))

        self.write("requirements.lock", "replacement==1.2.3 --hash=" + DIGEST + "\n")
        self.components[0].update(name="replacement",
                                  upstream="https://example.test/replacement/1.2.3")
        self.save()
        with self.assertRaisesRegex(
                license_gate.GateError, "component id is not its dependency coordinate"):
            license_gate.audit(self.root)

        self.components[0]["id"] = "pypi:replacement@1.2.3"
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "lacks exact owner approval"):
            license_gate.audit(self.root)

        self.approvals[0].update(component_id="pypi:replacement@1.2.3", name="replacement",
                                 upstream="https://example.test/replacement/1.2.3")
        self.save()
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 0))

    def test_component_id_must_state_the_dependency_coordinate(self):
        self.components = [self.component(id="pypi:demo@9.9.9")]
        self.save()
        with self.assertRaisesRegex(
                license_gate.GateError, "component id is not its dependency coordinate"):
            license_gate.audit(self.root)

    def test_material_license_obligations_are_enforced(self):
        self.components = [self.component(
            license="Apache-2.0",
            obligations=["preserve-license-and-copyright"],
        )]
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "Apache notice"):
            license_gate.audit(self.root)

        self.components = [self.component(license="GPL-3.0-only")]
        self.approvals = [self.approval()]
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "corresponding-source"):
            license_gate.audit(self.root)

    def test_model_code_does_not_approve_weight_artifact(self):
        self.components = [self.component(kind="model_code")]
        self.reviews = [self.review("transport"), self.review("model_weight")]
        artifact = b"synthetic model bytes only"
        self.write("models/demo.onnx", artifact)
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "model artifact set differs"):
            license_gate.audit(self.root)

        self.components.append(self.weight(artifact))
        self.reviews = [self.review("transport")]
        self.save()
        self.assertEqual(license_gate.audit(self.root), (2, 1, 1, 0))

    def test_model_weight_digest_substitution_is_rejected(self):
        artifact = b"synthetic model bytes only"
        self.components = [self.component(kind="model_code"), self.weight(artifact)]
        self.reviews = [self.review("transport")]
        self.write("models/demo.onnx", artifact)
        self.save()
        self.assertEqual(license_gate.audit(self.root), (2, 1, 1, 0))

        self.write("models/demo.onnx", b"substituted synthetic model bytes")
        with self.assertRaisesRegex(license_gate.GateError, "model artifact digest mismatch"):
            license_gate.audit(self.root)

    def test_model_weight_requires_pin_evidence(self):
        artifact = b"synthetic model bytes only"
        weight = self.weight(artifact)
        weight["locations"][0].pop("pin")
        self.components = [self.component(kind="model_code"), weight]
        self.reviews = [self.review("transport")]
        self.write("models/demo.onnx", artifact)
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "invalid dependency location"):
            license_gate.audit(self.root)

    def test_unreviewed_lockfile_and_npm_transitive_are_detected(self):
        pin = self.npm_lock(self.sri(1))
        with self.assertRaisesRegex(license_gate.GateError, "input set differs"):
            license_gate.audit(self.root)
        self.inputs.append({
            "path": "frontend/package-lock.json", "ecosystem": "npm-lock", "scope": "frontend",
        })
        self.save()
        self.assertEqual(pin["ecosystem"], "npm-lock")
        with self.assertRaisesRegex(license_gate.GateError, "locked dependencies differ"):
            license_gate.audit(self.root)

    def test_requirement_must_be_exact_and_hash_pinned(self):
        for requirement in ("demo>=1.2.3\n", "demo==1.2.3\n"):
            with self.subTest(requirement=requirement.strip()):
                self.write("requirements.lock", requirement)
                with self.assertRaises(license_gate.GateError):
                    license_gate.audit(self.root)

    def test_wildcard_and_conditional_requirements_are_not_exact_pins(self):
        """`demo==1.*` selects several releases behind one reviewed record."""
        unpinned = {
            "demo==1.*": "not an exact pin",
            "demo==1.2.*": "not an exact pin",
            'demo==1.2.3;python_version<"3.13"': "not an exact pin",
            "demo===1.2.3": "not an exact pin",
        }
        for requirement, message in unpinned.items():
            with self.subTest(requirement=requirement):
                self.write("requirements.lock", requirement + " --hash=" + DIGEST + "\n")
                with self.assertRaisesRegex(license_gate.GateError, message):
                    license_gate.audit(self.root)

        self.write("requirements.lock",
                   'demo==1.2.3 --hash=' + DIGEST + ' ; python_version<"3.13"\n')
        with self.assertRaisesRegex(license_gate.GateError, "unsupported requirement option"):
            license_gate.audit(self.root)

        self.write("requirements.lock", "demo[extra]==1.2.3 --hash=" + DIGEST + "\n")
        with self.assertRaisesRegex(license_gate.GateError, "unparsed or unpinned requirement"):
            license_gate.audit(self.root)

    def test_npm_ranges_and_wildcards_are_not_exact_pins(self):
        for version in ("1.x", "1.2.x", "^1.2.3", "~1.2.3", ">=1.2.3", "latest", "*"):
            with self.subTest(version=version):
                self.write("frontend/package.json",
                           json.dumps({"dependencies": {"transitive": version}}))
                self.inputs = self.inputs[:1] + [{
                    "path": "frontend/package.json",
                    "ecosystem": "npm-project",
                    "scope": "frontend",
                }]
                self.save()
                with self.assertRaisesRegex(license_gate.GateError, "not exact"):
                    license_gate.audit(self.root)

    def test_unknown_dependency_ecosystem_fails_closed(self):
        self.write("transport/Cargo.lock", "# synthetic lock\n")
        with self.assertRaisesRegex(license_gate.GateError, "reviewed parser"):
            license_gate.audit(self.root)

    def test_setuptools_backend_dependency_sources_fail_closed(self):
        """setup.py / setup.cfg can declare install requirements the gate cannot parse."""
        for manifest in ("setup.py", "setup.cfg", "Pipfile", "uv.lock"):
            with self.subTest(manifest=manifest):
                target = self.root / manifest
                target.write_text("# synthetic backend dependency source\n")
                with self.assertRaisesRegex(license_gate.GateError, "reviewed parser"):
                    license_gate.audit(self.root)
                target.unlink()

    def test_unregistered_pip_requirement_manifest_fails_closed(self):
        self.write("server/requirements-prod.in", "demo==1.2.3 --hash=" + DIGEST + "\n")
        with self.assertRaisesRegex(license_gate.GateError, "input set differs"):
            license_gate.audit(self.root)

    def test_python_optional_and_build_dependencies_require_reviewed_parser(self):
        self.write("pyproject.toml", """\
[project]
dependencies = []

[project.optional-dependencies]
detector = ["detector==1.2.3"]
""")
        self.inputs.append({
            "path": "pyproject.toml", "ecosystem": "python-project", "scope": "backend",
        })
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "unsupported project dependency section"):
            license_gate.audit(self.root)

        self.write("pyproject.toml", """\
[project]
dependencies = []

[build-system]
requires = ["build-backend==1.2.3"]
""")
        with self.assertRaisesRegex(license_gate.GateError, "unsupported project dependency section"):
            license_gate.audit(self.root)

    def test_pep621_dynamic_dependencies_require_reviewed_parser(self):
        self.assert_dynamic_python_dependency_rejected("""\
[project]
dependencies = []
dynamic = ["dependencies"]
""")

    def test_pep621_dynamic_optional_dependencies_require_reviewed_parser(self):
        self.assert_dynamic_python_dependency_rejected("""\
[project]
dependencies = []
dynamic = ["optional-dependencies"]
""")

    def test_setuptools_dynamic_dependencies_require_reviewed_parser(self):
        self.assert_dynamic_python_dependency_rejected("""\
[project]
dependencies = []

[tool.setuptools.dynamic]
dependencies = {file = ["deps.in"]}
""")

    def test_setuptools_dynamic_optional_dependencies_require_reviewed_parser(self):
        self.assert_dynamic_python_dependency_rejected("""\
[project]
dependencies = []

[tool.setuptools.dynamic]
optional-dependencies = {test = {file = ["deps.in"]}}
""")

    def test_empty_and_non_dependency_dynamic_metadata_are_allowed(self):
        self.write("pyproject.toml", """\
[project]
dependencies = []
dynamic = ["version"]

[project.optional-dependencies]

[build-system]
requires = []

[tool.setuptools.dynamic]
version = {attr = "package.__version__"}
""")
        self.inputs.append({
            "path": "pyproject.toml", "ecosystem": "python-project", "scope": "backend",
        })
        self.save()
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 0))

    def test_npm_shrinkwrap_is_reviewed_and_never_shadows_the_lock(self):
        """npm prefers npm-shrinkwrap.json, so it cannot stay unreviewed."""
        integrity = self.sri(5)
        pin = self.npm_lock(integrity, path="frontend/npm-shrinkwrap.json")
        with self.assertRaisesRegex(license_gate.GateError, "input set differs"):
            license_gate.audit(self.root)

        self.inputs.append({
            "path": "frontend/npm-shrinkwrap.json", "ecosystem": "npm-lock", "scope": "frontend",
        })
        self.components.append(self.component(
            id="npm:transitive@4.5.6", name="transitive", version="4.5.6",
            upstream="https://example.test/transitive-4.5.6.tgz", locations=[pin],
        ))
        self.save()
        self.assertEqual(license_gate.audit(self.root), (2, 2, 0, 0))

        self.npm_lock(integrity, path="frontend/package-lock.json")
        with self.assertRaisesRegex(license_gate.GateError, "ambiguous"):
            license_gate.audit(self.root)

    def test_nested_requirement_dependency_is_recursively_audited(self):
        self.write("requirements.lock", "-r requirements-nested.lock\n")
        self.write("requirements-nested.lock", "nested==9.8.7 --hash=sha256:" + "c" * 64 + "\n")
        self.inputs.append({
            "path": "requirements-nested.lock",
            "ecosystem": "python-requirements",
            "scope": "backend",
        })
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "locked dependencies differ"):
            license_gate.audit(self.root)

    def test_remote_unreviewed_and_cyclic_requirement_includes_fail(self):
        for directive in ("-r https://example.test/requirements.txt\n", "-r ../outside.lock\n"):
            with self.subTest(directive=directive.strip()):
                self.write("requirements.lock", directive)
                with self.assertRaises(license_gate.GateError):
                    license_gate.audit(self.root)

        self.write("requirements.lock", "-r requirements-other.lock\n")
        self.write("requirements-other.lock", "-r requirements.lock\n")
        self.inputs.append({
            "path": "requirements-other.lock",
            "ecosystem": "python-requirements",
            "scope": "backend",
        })
        self.components = []
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "include cycle"):
            license_gate.audit(self.root)

    def test_model_roots_scan_zip_h5_and_extensionless_files(self):
        paths = {
            "server/assets/models/archive.zip",
            "server/assets/models/manifest.json",
            "agent/runtime/weights/owner.h5",
            "checkpoints/person-v1",
        }
        for path in paths:
            self.write(path, b"synthetic artifact")
        self.assertLessEqual(paths, set(license_gate.model_files(self.root)))
        with self.assertRaisesRegex(license_gate.GateError, "model artifact set differs"):
            license_gate.audit(self.root)

    def test_serialized_estimators_outside_reserved_roots_are_detected(self):
        """A committed .pkl/.joblib estimator still needs its own weight record."""
        for path in ("server/app/detector/person.pkl", "server/app/detector/person.joblib",
                     "agent/runtime/person.safetensors", "web/src/person.npz"):
            with self.subTest(path=path):
                target = self.root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("synthetic serialized estimator\n")
                self.assertIn(path, license_gate.model_files(self.root))
                with self.assertRaisesRegex(license_gate.GateError, "model artifact set differs"):
                    license_gate.audit(self.root)
                target.unlink()

    def test_opaque_files_with_unknown_suffixes_require_weight_review(self):
        """Renaming a model does not turn it into a reviewed text asset."""
        self.write("server/app/detector/person.dat", b"\x80\x04\x95synthetic pickle bytes\x00")
        self.assertIn("server/app/detector/person.dat", license_gate.model_files(self.root))
        with self.assertRaisesRegex(license_gate.GateError, "model artifact set differs"):
            license_gate.audit(self.root)

    def test_reviewable_text_and_media_assets_are_not_model_artifacts(self):
        self.write("web/src/app.tsx", "export const App = () => null;\n")
        self.write("web/src/icon.png", b"\x89PNG\r\n\x1a\n synthetic image bytes")
        self.write("docs/notes.md", "synthetic note\n")
        self.assertEqual(license_gate.model_files(self.root), [])
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 0))

    def test_media_suffix_without_its_format_is_not_a_reviewed_asset(self):
        """A weight renamed to .png or .wasm stays an unreviewed artifact."""
        self.write("web/src/icon.png", b"\x89PNG\r\n\x1a\n synthetic image bytes")
        self.write("web/src/person.png", b"\x80\x04\x95synthetic weight bytes\x00")
        self.write("web/dist/person.wasm", b"\x80\x04\x95synthetic weight bytes\x00")
        self.write("web/src/glyph.woff2", b"wOF2 synthetic font bytes\x00")
        found = license_gate.model_files(self.root)
        self.assertNotIn("web/src/icon.png", found)
        self.assertNotIn("web/src/glyph.woff2", found)
        self.assertIn("web/src/person.png", found)
        self.assertIn("web/dist/person.wasm", found)
        with self.assertRaisesRegex(license_gate.GateError, "model artifact set differs"):
            license_gate.audit(self.root)

    def test_text_prefix_does_not_hide_a_trailing_artifact(self):
        """The whole file is decoded, not only its first scan chunk."""
        path = self.root / "server/app/detector/person.dat"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic readable prefix\n" * 4096
                         + b"\x80\x04\x95synthetic weight bytes")
        self.assertGreater(path.stat().st_size, 65536)
        self.assertTrue(license_gate.opaque_bytes(path))
        self.assertIn("server/app/detector/person.dat",
                      license_gate.model_files(self.root))
        with self.assertRaisesRegex(license_gate.GateError, "model artifact set differs"):
            license_gate.audit(self.root)

    def test_tracked_artifacts_inside_dependency_caches_are_scanned(self):
        """A force-added weight below node_modules is still a tracked artifact."""
        self.write("node_modules/models/person.onnx", b"synthetic weight bytes")
        self.write("node_modules/left-pad/index.js", "module.exports = 1;\n")
        subprocess.run(["git", "-C", str(self.root), "init", "--quiet"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "-f",
                        "node_modules/models/person.onnx"], check=True)
        found = license_gate.model_files(self.root)
        self.assertIn("node_modules/models/person.onnx", found)
        self.assertNotIn("node_modules/left-pad/index.js", found)
        with self.assertRaisesRegex(license_gate.GateError, "model artifact set differs"):
            license_gate.audit(self.root)

    def test_dependency_cache_without_tracked_file_evidence_fails_closed(self):
        """Skipping a cache is only safe while its tracked files are knowable."""
        self.write("node_modules/left-pad/index.js", "module.exports = 1;\n")
        with self.assertRaisesRegex(
                license_gate.GateError, "cannot determine tracked files"):
            license_gate.model_files(self.root)
        with self.assertRaisesRegex(
                license_gate.GateError, "cannot determine tracked files"):
            license_gate.audit(self.root)

        subprocess.run(["git", "-C", str(self.root), "init", "--quiet"], check=True)
        self.assertEqual(license_gate.model_files(self.root), [])
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 0))

    def test_tracked_build_and_dist_model_artifacts_are_not_excluded(self):
        paths = {"build/opaque-model.zip", "dist/opaque-weight.binpack"}
        for path in paths:
            self.write(path, b"synthetic committed model output")
        self.write("build/app.js", "console.log('synthetic reviewed static output');\n")
        self.write("dist/worker.wasm", b"\x00asm synthetic web worker")
        subprocess.run(["git", "-C", str(self.root), "init", "--quiet"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", *sorted(paths)], check=True)
        tracked = subprocess.run(
            ["git", "-C", str(self.root), "ls-files"], check=True,
            stdout=subprocess.PIPE, text=True,
        ).stdout.splitlines()
        self.assertEqual(set(tracked), paths)
        self.assertEqual(set(license_gate.model_files(self.root)), paths)
        self.assertNotIn("dist/worker.wasm", license_gate.model_files(self.root))
        self.assertEqual(repository_guard.audit(self.root), [])
        with self.assertRaisesRegex(license_gate.GateError, "model artifact set differs"):
            license_gate.audit(self.root)

    def test_python_hash_change_is_rejected_for_same_name_and_version(self):
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 0))
        self.write("requirements.lock", "demo==1.2.3 --hash=sha256:" + "b" * 64 + "\n")
        with self.assertRaisesRegex(license_gate.GateError, "locked dependencies differ"):
            license_gate.audit(self.root)

    def test_component_location_without_pin_evidence_is_rejected(self):
        location = self.location()
        location.pop("pin")
        self.components = [self.component(locations=[location])]
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "invalid dependency location"):
            license_gate.audit(self.root)

        self.components = [self.component(locations=[self.location(pin={"type": "lockfile-entry"})])]
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "invalid lockfile pin evidence"):
            license_gate.audit(self.root)

        self.components = [self.component(locations=[self.location(
            pin={"type": "lockfile-entry", "digests": ["sha256:" + "z" * 64]})])]
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "invalid pin digests"):
            license_gate.audit(self.root)

    def test_npm_sri_change_is_rejected_for_same_name_version_and_resolved(self):
        approved = self.sri(2)
        pin = self.npm_lock(approved)
        self.inputs.append({
            "path": "frontend/package-lock.json", "ecosystem": "npm-lock", "scope": "frontend",
        })
        self.components.append(self.component(
            id="npm:transitive@4.5.6",
            name="transitive",
            version="4.5.6",
            upstream="https://example.test/transitive-4.5.6.tgz",
            locations=[pin],
        ))
        self.save()
        self.assertEqual(license_gate.audit(self.root), (2, 2, 0, 0))

        self.npm_lock(self.sri(3))
        with self.assertRaisesRegex(license_gate.GateError, "locked dependencies differ"):
            license_gate.audit(self.root)

        self.npm_lock("sha512-synthetic")
        with self.assertRaisesRegex(license_gate.GateError, "invalid npm integrity"):
            license_gate.audit(self.root)

        self.npm_lock(approved, resolved="https://example.test/substituted-4.5.6.tgz")
        with self.assertRaisesRegex(license_gate.GateError, "locked dependencies differ"):
            license_gate.audit(self.root)

    def test_npm_resolved_artifact_must_match_the_reviewed_upstream(self):
        pin = self.npm_lock(self.sri(2))
        self.inputs.append({
            "path": "frontend/package-lock.json", "ecosystem": "npm-lock", "scope": "frontend",
        })
        self.components.append(self.component(
            id="npm:transitive@4.5.6", name="transitive", version="4.5.6",
            upstream="https://example.test/other-4.5.6.tgz", locations=[pin],
        ))
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "differs from the reviewed upstream"):
            license_gate.audit(self.root)

    def test_model_weight_location_outside_reserved_directory_is_rejected(self):
        artifact = b"synthetic opaque model archive"
        self.write("server/assets/ml/model.zip", artifact)
        self.components.append(self.weight(artifact, path="server/assets/ml/model.zip"))
        self.reviews = [self.review("transport"), self.review("model_code")]
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "reserved model artifact directory"):
            license_gate.audit(self.root)

    def test_ci_rejects_unregistered_opaque_artifact_in_model_like_asset_path(self):
        path = "assets/ml/opaque-weight.zip"
        self.write(path, b"synthetic opaque model archive without ZIP magic")
        ordinary = "assets/downloads/ordinary-archive.zip"
        self.write(ordinary, b"synthetic unrelated archive bytes")
        subprocess.run(["git", "-C", str(self.root), "init", "--quiet"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)

        # The general repository guard does not ban arbitrary non-runtime ZIP
        # bytes. The following license gate in the CI sequence must fail based
        # on the narrowly model-like assets/ml path.
        self.assertEqual(repository_guard.audit(self.root), [])
        self.assertIn(path, license_gate.model_files(self.root))
        self.assertNotIn(ordinary, license_gate.model_files(self.root))
        with self.assertRaisesRegex(license_gate.GateError, "model artifact set differs"):
            license_gate.audit(self.root)

    def test_reviewed_model_scan_exemption_covers_only_text_source_files(self):
        """A source package may share the reserved name; artifacts still fail."""
        self.write("tests/models/__init__.py", "\"\"\"synthetic design models.\"\"\"\n")
        self.write("tests/models/contract.py", "VALUE = 1\n")
        with self.assertRaisesRegex(license_gate.GateError, "model artifact set differs"):
            license_gate.audit(self.root)

        self.exemptions = [{
            "path": "tests/models",
            "reason": "synthetic design model package, no ML artifact",
            "evidence": ["docs/evidence.md"],
        }]
        self.save()
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 0))

        for path, content in (("tests/models/person.onnx", b"synthetic weight bytes"),
                              ("tests/models/person.py", b"\x80\x04\x95opaque\x00"),
                              ("tests/models/person.bin", "text but a model suffix\n")):
            with self.subTest(path=path):
                self.write(path, content)
                self.assertIn(path, license_gate.model_files(
                    self.root, ["tests/models"]))
                with self.assertRaisesRegex(license_gate.GateError, "model artifact set differs"):
                    license_gate.audit(self.root)
                (self.root / path).unlink()

    def test_model_scan_exemption_must_be_reviewed_and_used(self):
        self.exemptions = [{
            "path": "tests/models",
            "reason": "synthetic design model package, no ML artifact",
            "evidence": ["docs/evidence.md"],
        }]
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "committed directory"):
            license_gate.audit(self.root)

        self.write("tests/models/__init__.py", "VALUE = 1\n")
        self.save()
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 0))

        self.write("docs/notes/__init__.py", "VALUE = 1\n")
        self.exemptions[0]["path"] = "docs/notes"
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "reserved directory"):
            license_gate.audit(self.root)

        self.exemptions[0].update(path="tests/models", evidence=[])
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "exemption evidence"):
            license_gate.audit(self.root)

    def test_stale_model_scan_exemption_is_rejected(self):
        self.write("tests/models/person.onnx", b"synthetic weight bytes")
        self.exemptions = [{
            "path": "tests/models",
            "reason": "synthetic design model package, no ML artifact",
            "evidence": ["docs/evidence.md"],
        }]
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "stale model scan exemption"):
            license_gate.audit(self.root)

    def test_npm_sri_requires_canonical_base64_and_algorithm_digest_length(self):
        for invalid in (
            "sha512-synthetic",
            "sha512-YWJj",
            "sha512-YWJj====",
            "sha256-" + base64.b64encode(bytes(31)).decode("ascii"),
        ):
            with self.subTest(integrity=invalid):
                self.assertFalse(license_gate.valid_sri(invalid))
        for algorithm in ("sha256", "sha384", "sha512"):
            self.assertTrue(license_gate.valid_sri(self.sri(4, algorithm)))


class ContainerImageGateTests(GateFixture):
    def test_digest_pinned_base_image_passes(self):
        self.add_container()
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 1))

    def test_unregistered_dockerfile_fails_closed(self):
        self.write("Dockerfile.ci", "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n")
        with self.assertRaisesRegex(license_gate.GateError, "input set differs"):
            license_gate.audit(self.root)

    def test_floating_tag_and_variable_base_images_are_rejected(self):
        for reference in ("demo/base:latest", "demo/base:1.0", "demo/base", "$BASE_IMAGE"):
            with self.subTest(reference=reference):
                self.images = []
                self.inputs = self.inputs[:1]
                self.add_container("FROM " + reference + "\n")
                with self.assertRaisesRegex(
                        license_gate.GateError, "digest-pinned|must not be a variable"):
                    license_gate.audit(self.root)

    def test_base_image_digest_substitution_is_rejected(self):
        self.add_container()
        self.write("Dockerfile.ci", "FROM demo/base:1.0@sha256:" + "e" * 64 + "\n")
        with self.assertRaisesRegex(
                license_gate.GateError, "container base images differ from reviewed image records"):
            license_gate.audit(self.root)

    def test_unregistered_copy_stage_image_is_rejected(self):
        self.add_container(
            "FROM demo/base:1.0@" + IMAGE_DIGEST + " AS build\n"
            "COPY --from=build /app /app\n"
            "COPY --from=other/base:2.0@sha256:" + "f" * 64 + " /opt /opt\n")
        with self.assertRaisesRegex(
                license_gate.GateError, "container base images differ from reviewed image records"):
            license_gate.audit(self.root)

    def test_multi_stage_reference_reuses_the_reviewed_image(self):
        self.add_container(
            "FROM demo/base:1.0@" + IMAGE_DIGEST + " AS build\n"
            "COPY --from=build /app /app\n"
            "FROM build\n")
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 1))

    def test_container_build_rejects_remote_add_sources(self):
        """ADD must not fetch an untracked dependency or model at build time."""
        self.add_container()
        for source in (
                "https://example.test/person.onnx",
                "git://example.test/repository.git",
                "git@example.test:owner/repository.git",
                "$REMOTE_URL",
                "${REMOTE_URL}/artifact"):
            with self.subTest(source=source):
                self.write(
                    "Dockerfile.ci",
                    "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
                    f"ADD {source} /app/artifact\n")
                with self.assertRaisesRegex(
                        license_gate.GateError, "remote ADD source is not reviewed"):
                    license_gate.audit(self.root)

        self.write(
            "Dockerfile.ci",
            "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
            "ADD local-artifact.txt /app/artifact.txt\n")
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 1))

    def test_image_redistribution_requires_an_owner_decision(self):
        self.add_container()
        self.images[0]["distribution"] = "redistributed"
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "requires an owner decision"):
            license_gate.audit(self.root)

    def test_image_record_requires_notice_and_redistribution_obligations(self):
        self.add_container()
        self.images[0]["obligations"] = ["preserve-license-and-copyright"]
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "notice obligations are required"):
            license_gate.audit(self.root)

        self.images[0]["obligations"] = [
            "preserve-license-and-copyright", "preserve-notice",
            "fulfill-image-redistribution-obligations",
        ]
        self.images[0]["license_evidence"] = []
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "image license evidence"):
            license_gate.audit(self.root)

    def test_container_build_must_install_reviewed_hash_pinned_requirements(self):
        self.write("requirements.lock", "demo==1.2.3 --hash=" + DIGEST + "\n")
        self.add_container(
            "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
            "RUN python -m pip install --require-hashes -r requirements.lock\n")
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 1))

        self.write("Dockerfile.ci",
                   "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
                   "RUN python -m pip install -r requirements.lock\n")
        with self.assertRaisesRegex(license_gate.GateError, "--require-hashes"):
            license_gate.audit(self.root)

        self.write("Dockerfile.ci",
                   "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
                   "RUN python -m pip install --require-hashes unreviewed-package\n")
        with self.assertRaisesRegex(license_gate.GateError, "reviewed requirement file"):
            license_gate.audit(self.root)

        self.write("Dockerfile.ci",
                   "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
                   "RUN python -m pip install --require-hashes -r requirements-prod.in\n")
        self.write("requirements-prod.in", "unreviewed==9.9.9 --hash=" + DIGEST + "\n")
        with self.assertRaisesRegex(license_gate.GateError, "input set differs"):
            license_gate.audit(self.root)

    def test_container_build_rejects_commands_outside_the_allowlist(self):
        """A package manager cannot bypass review by using an unknown name."""
        self.add_container(
            "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
            "RUN apt-get install curl\n")
        with self.assertRaisesRegex(license_gate.GateError, "unreviewed build command"):
            license_gate.audit(self.root)

        self.write("Dockerfile.ci",
                   "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
                   "RUN node scripts/build.mjs\n"
                   "RUN tsc --noEmit\n")
        with self.assertRaisesRegex(license_gate.GateError, "unreviewed build command"):
            license_gate.audit(self.root)

        self.write("Dockerfile.ci",
                   "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
                   "RUN tsc --noEmit\n")
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 1))

    def test_container_build_rejects_installer_names_in_wrapper_arguments(self):
        """An argv argument named npm or pip is not the process executable."""
        self.add_container()
        for command in (
                "RUN sh /tmp/npm ci --ignore-scripts\n",
                "RUN env npm ci --ignore-scripts\n",
                "RUN node npm install unreviewed-package\n"):
            with self.subTest(command=command.strip()):
                self.write("Dockerfile.ci",
                           "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n" + command)
                with self.assertRaisesRegex(license_gate.GateError, "unreviewed build command"):
                    license_gate.audit(self.root)

    def test_container_build_rejects_onbuild_instructions(self):
        self.add_container()
        for command in (
                "ONBUILD ADD https://example.test/person.onnx /app/person.onnx\n",
                "ONBUILD RUN npm install unreviewed-package\n"):
            with self.subTest(command=command.strip()):
                self.write("Dockerfile.ci",
                           "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n" + command)
                with self.assertRaisesRegex(license_gate.GateError, "ONBUILD instruction"):
                    license_gate.audit(self.root)

    def test_container_build_must_use_a_lock_driven_npm_command(self):
        """npm install aliases and option-first forms must not slip through."""
        self.add_npm_project()
        self.add_container(
            "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
            "RUN npm ci --ignore-scripts\n"
            "RUN npm run build\n")
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 1))

        self.write("Dockerfile.ci",
                   "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
                   "RUN npm ci\n")
        with self.assertRaisesRegex(license_gate.GateError, "--ignore-scripts"):
            license_gate.audit(self.root)

        rejected = {
            "RUN npm install --ignore-scripts\n": "unclassified npm command",
            "RUN npm i unreviewed-package\n": "unclassified npm command",
            "RUN npm in unreviewed-package\n": "unclassified npm command",
            "RUN npm ins unreviewed-package\n": "unclassified npm command",
            "RUN npm insta unreviewed-package\n": "unclassified npm command",
            "RUN npm isntall unreviewed-package\n": "unclassified npm command",
            "RUN npm add unreviewed-package\n": "unclassified npm command",
            "RUN npm update\n": "unclassified npm command",
            "RUN npm exec unreviewed-package\n": "unclassified npm command",
            "RUN /usr/local/bin/npm install unreviewed-package\n": "unclassified npm command",
            "RUN npm --prefix /tmp install unreviewed-package\n":
                "unreviewed npm option before the command",
            "RUN npx unreviewed-package\n": "unreviewed package manager",
            "RUN pnpm install\n": "unreviewed package manager",
            "RUN yarn add unreviewed-package\n": "unreviewed package manager",
            'RUN ["npm", "install", "unreviewed-package"]\n': "unclassified npm command",
        }
        for command, message in rejected.items():
            with self.subTest(command=command.strip()):
                self.write("Dockerfile.ci",
                           "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n" + command)
                with self.assertRaisesRegex(license_gate.GateError, message):
                    license_gate.audit(self.root)

    def test_container_build_rejects_path_changing_npm_options(self):
        """`npm ci --prefix /tmp` would install an undiscovered dependency tree."""
        self.add_npm_project()
        self.add_container(
            "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
            "RUN npm ci --ignore-scripts --no-audit --no-fund --omit=dev\n"
            "RUN npm run build\n")
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 1))

        rejected = {
            "RUN npm ci --ignore-scripts --prefix /tmp\n": "unreviewed npm option",
            "RUN npm ci --ignore-scripts -C /tmp\n": "unreviewed npm option",
            "RUN npm ci --ignore-scripts --registry=https://example.test\n":
                "unreviewed npm option",
            "RUN npm ci --ignore-scripts --global\n": "unreviewed npm option",
            "RUN npm ci --ignore-scripts --userconfig=/tmp/npmrc\n":
                "unreviewed npm option",
            "RUN npm ci --ignore-scripts unreviewed-package\n": "unreviewed npm argument",
        }
        for command, message in rejected.items():
            with self.subTest(command=command.strip()):
                self.write("Dockerfile.ci",
                           "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n" + command)
                with self.assertRaisesRegex(license_gate.GateError, message):
                    license_gate.audit(self.root)

    def test_package_scripts_behind_npm_run_are_audited(self):
        """`npm run build` executes a package script, so the body is reviewed."""
        self.add_npm_project({"build": "node scripts/build.mjs",
                              "test": "node --test tests/*.test.mjs"})
        self.add_container(
            "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
            "RUN npm ci --ignore-scripts\n"
            "RUN npm run build\n")
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 1))

        rejected = {
            "npm install unreviewed-package": "unclassified npm command",
            "npm run build && npm i unreviewed-package": "unclassified npm command",
            "pip install unreviewed-package": "reviewed requirement file",
            "p${EMPTY}ip install unreviewed-package": "unreviewed shell syntax",
            "npx unreviewed-package": "unreviewed package manager",
        }
        for body, message in rejected.items():
            with self.subTest(script=body):
                self.write("package.json", json.dumps({
                    "dependencies": {}, "scripts": {"build": body},
                }))
                with self.assertRaisesRegex(license_gate.GateError, message):
                    license_gate.audit(self.root)

    def test_package_node_scripts_require_reviewed_content_hashes(self):
        self.add_npm_project()
        self.add_container(
            "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
            "RUN npm ci --ignore-scripts\n"
            "RUN npm run build\n")
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 1))

        self.write("scripts/build.mjs", "await fetch('https://example.test/model.onnx');\n")
        with self.assertRaisesRegex(license_gate.GateError, "build script digest mismatch"):
            license_gate.audit(self.root)

        self.add_build_script("scripts/build.mjs")
        self.add_build_script("scripts/download.mjs")
        self.write("package.json", json.dumps({
            "dependencies": {}, "scripts": {"build": "node scripts/missing.mjs"},
        }))
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "unreviewed repository script"):
            license_gate.audit(self.root)

        self.write("package.json", json.dumps({
            "dependencies": {}, "scripts": {"build": "node ../scripts/build.mjs"},
        }))
        with self.assertRaisesRegex(license_gate.GateError, "unreviewed repository script"):
            license_gate.audit(self.root)

    def test_container_running_package_scripts_needs_a_reviewed_manifest(self):
        self.add_container(
            "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
            "RUN npm run build\n")
        with self.assertRaisesRegex(
                license_gate.GateError, "runs unreviewed package scripts"):
            license_gate.audit(self.root)

    def test_container_build_rejects_shell_expanded_installer_names(self):
        """The default shell resolves escaping and expansion before the command."""
        self.write("requirements.lock", "demo==1.2.3 --hash=" + DIGEST + "\n")
        self.add_container()
        for command in ("RUN pi\\p install unreviewed-package\n",
                        "RUN p${EMPTY}ip install unreviewed-package\n",
                        "RUN $PIP install unreviewed-package\n",
                        "RUN python -m pip install --require-hashes -r $LOCK\n"):
            with self.subTest(command=command.strip()):
                self.write("Dockerfile.ci",
                           "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n" + command)
                with self.assertRaisesRegex(license_gate.GateError, "unreviewed shell syntax"):
                    license_gate.audit(self.root)

        # Quoting does not hide a direct installer executable.
        self.write("Dockerfile.ci",
                   "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
                   "RUN 'pip' install unreviewed-package\n")
        with self.assertRaisesRegex(license_gate.GateError, "reviewed requirement file"):
            license_gate.audit(self.root)

        # A shell wrapper is never trusted merely because an argument names pip.
        self.write("Dockerfile.ci",
                   "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
                   "RUN eval \"pip install unreviewed-package\"\n")
        with self.assertRaisesRegex(license_gate.GateError, "unreviewed build command"):
            license_gate.audit(self.root)

    def test_container_build_parses_attached_pip_requirement_options(self):
        """`-rvendor.lock` and `--requirement=vendor.lock` install real files."""
        self.write("requirements.lock", "demo==1.2.3 --hash=" + DIGEST + "\n")
        self.write("vendor.lock", "unreviewed==9.9.9 --hash=sha256:" + "e" * 64 + "\n")
        self.add_container(
            "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
            "RUN python -m pip install --require-hashes -rrequirements.lock\n")
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 1))

        self.write("Dockerfile.ci",
                   "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n"
                   "RUN python -m pip install --require-hashes --requirement=requirements.lock\n")
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0, 1))

        for command in ("RUN python -m pip install --require-hashes -rvendor.lock\n",
                        "RUN python -m pip install --require-hashes --requirement=vendor.lock\n",
                        "RUN python -m pip install --require-hashes -cvendor.lock "
                        "-r requirements.lock\n",
                        "RUN python -m pip install --require-hashes "
                        "--constraint=vendor.lock -r requirements.lock\n"):
            with self.subTest(command=command.strip()):
                self.write("Dockerfile.ci",
                           "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n" + command)
                with self.assertRaisesRegex(
                        license_gate.GateError, "installs an unreviewed requirement file"):
                    license_gate.audit(self.root)

    def test_container_build_rejects_unreviewed_pip_options_and_commands(self):
        self.write("requirements.lock", "demo==1.2.3 --hash=" + DIGEST + "\n")
        self.add_container()
        rejected = {
            "RUN python -m pip install --require-hashes --index-url=https://example.test/simple "
            "-r requirements.lock\n": "unreviewed pip install option",
            "RUN python -m pip install --require-hashes -e .\n":
                "unreviewed pip install option",
            "RUN python -m pip install --require-hashes -qr requirements.lock\n":
                "unreviewed pip install option",
            "RUN python -m pip download --require-hashes -r requirements.lock\n":
                "reviewed requirement file",
            "RUN python -m pip install -r requirements.lock\n": "--require-hashes",
            "RUN python -m pip install --require-hashes\n": "reviewed requirement file",
            'RUN ["python", "-m", "pip", "install", "unreviewed-package"]\n':
                "reviewed requirement file",
            "RUN python -m pip install --require-hashes -r /etc/requirements.lock\n":
                "unreviewed source",
            "RUN python -m pip install --require-hashes "
            "-r https://example.test/requirements.lock\n": "unreviewed source",
            "RUN python -m pip install --require-hashes -r ../requirements.lock\n":
                "unreviewed source",
            "RUN python -m pip install --require-hashes -r req*.lock\n":
                "unreviewed source",
        }
        for command, message in rejected.items():
            with self.subTest(command=command.strip()):
                self.write("Dockerfile.ci",
                           "FROM demo/base:1.0@" + IMAGE_DIGEST + "\n" + command)
                with self.assertRaisesRegex(license_gate.GateError, message):
                    license_gate.audit(self.root)


class ResolvedPinTests(GateFixture):
    def pip_report(self, name="demo", version="1.2.3", digest="a" * 64):
        return {
            "version": "1",
            "install": [{
                "metadata": {"name": name, "version": version},
                "download_info": {
                    "url": "https://example.test/demo-1.2.3-py3-none-any.whl",
                    "archive_info": {"hashes": {"sha256": digest}},
                },
            }],
        }

    def report_path(self, report):
        path = self.root / "pip-report.json"
        path.write_text(json.dumps(report))
        return path

    def test_resolved_python_installation_matches_reviewed_pins(self):
        path = self.report_path(self.pip_report())
        self.assertEqual(
            license_gate.verify_resolved_python(self.root, path, "requirements.lock"), 1)

    def test_resolved_python_digest_mismatch_is_rejected(self):
        path = self.report_path(self.pip_report(digest="b" * 64))
        with self.assertRaisesRegex(license_gate.GateError, "resolved pin differs"):
            license_gate.verify_resolved_python(self.root, path, "requirements.lock")

    def test_resolved_python_version_substitution_is_rejected(self):
        path = self.report_path(self.pip_report(version="1.2.4"))
        with self.assertRaisesRegex(license_gate.GateError, "resolved pin differs"):
            license_gate.verify_resolved_python(self.root, path, "requirements.lock")

    def test_resolved_python_without_digest_evidence_is_rejected(self):
        report = self.pip_report()
        report["install"][0]["download_info"] = {"url": "https://example.test/demo.whl"}
        path = self.report_path(report)
        with self.assertRaisesRegex(license_gate.GateError, "no sha256 pin evidence"):
            license_gate.verify_resolved_python(self.root, path, "requirements.lock")

    def test_resolved_python_must_cover_every_reviewed_pin(self):
        self.write("requirements.lock",
                   "demo==1.2.3 --hash=" + DIGEST + "\n"
                   "second==2.0.0 --hash=sha256:" + "c" * 64 + "\n")
        self.components.append(self.component(
            id="pypi:second@2.0.0", name="second", version="2.0.0",
            upstream="https://example.test/second/2.0.0",
            locations=[self.location(pin={
                "type": "lockfile-entry", "digests": ["sha256:" + "c" * 64],
            })],
        ))
        self.save()
        self.assertEqual(license_gate.audit(self.root), (2, 2, 0, 0))
        path = self.report_path(self.pip_report())
        with self.assertRaisesRegex(license_gate.GateError, "missing reviewed pins"):
            license_gate.verify_resolved_python(self.root, path, "requirements.lock")

    def test_resolved_npm_installation_matches_reviewed_pins(self):
        integrity = self.sri(2)
        pin = self.npm_lock(integrity)
        self.inputs.append({
            "path": "frontend/package-lock.json", "ecosystem": "npm-lock", "scope": "frontend",
        })
        self.components.append(self.component(
            id="npm:transitive@4.5.6", name="transitive", version="4.5.6",
            upstream="https://example.test/transitive-4.5.6.tgz", locations=[pin],
        ))
        self.save()
        installed = self.root / "frontend/node_modules/.package-lock.json"
        installed.parent.mkdir(parents=True, exist_ok=True)
        installed.write_text((self.root / "frontend/package-lock.json").read_text())
        self.assertEqual(license_gate.verify_resolved_npm(
            self.root, installed, "frontend/package-lock.json"), 1)

        installed.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {"node_modules/transitive": {
                "version": "4.5.6",
                "resolved": "https://example.test/transitive-4.5.6.tgz",
                "integrity": self.sri(9),
            }},
        }))
        with self.assertRaisesRegex(license_gate.GateError, "resolved pin differs"):
            license_gate.verify_resolved_npm(
                self.root, installed, "frontend/package-lock.json")

    def test_command_line_resolved_verification_reports_mismatch(self):
        matching = self.report_path(self.pip_report())
        arguments = ["--root", str(self.root), "--resolved-python", str(matching),
                     "--input", "requirements.lock"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(license_gate.main(arguments), 0)
        arguments[3] = str(self.report_path(self.pip_report(digest="b" * 64)))
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(license_gate.main(arguments), 1)
        self.assertIn("resolved pin differs", errors.getvalue())

    def test_resolved_report_requires_reviewed_pins_for_the_named_input(self):
        path = self.report_path(self.pip_report())
        with self.assertRaisesRegex(license_gate.GateError, "no reviewed pins recorded"):
            license_gate.verify_resolved_python(self.root, path, "other.lock")


if __name__ == "__main__":
    unittest.main()
