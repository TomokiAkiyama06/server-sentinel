"""License gate regressions use synthetic manifests and artifacts only."""

import hashlib
import base64
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.ci import license_gate
from scripts.ci import repository_guard


class LicenseGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.write("docs/evidence.md", "synthetic review evidence\n")
        self.write("docs/decisions/0001-synthetic.md", "synthetic owner decision\n")
        self.write("requirements.lock", "demo==1.2.3 --hash=sha256:" + "a" * 64 + "\n")
        self.inputs = [{
            "path": "requirements.lock",
            "ecosystem": "python-requirements",
            "scope": "backend",
        }]
        self.reviews = [
            self.review("transport"), self.review("model_code"), self.review("model_weight"),
        ]
        self.components = [self.component()]
        self.pins = [{
            "path": "requirements.lock",
            "ecosystem": "python-requirements",
            "name": "demo",
            "version": "1.2.3",
            "digests": ["sha256:" + "a" * 64],
        }]
        self.approvals = []
        self.save()

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content if isinstance(content, bytes) else content.encode())

    def review(self, scope):
        return {"scope": scope, "status": "reviewed-empty", "evidence": ["docs/evidence.md"]}

    def location(self):
        return {"path": "requirements.lock", "ecosystem": "python-requirements", "scope": "backend"}

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
            "sha256": None,
        }
        value.update(changes)
        return value

    def sri(self, byte, algorithm="sha512"):
        sizes = {"sha256": 32, "sha384": 48, "sha512": 64}
        encoded = base64.b64encode(bytes([byte]) * sizes[algorithm]).decode("ascii")
        return algorithm + "-" + encoded

    def save(self):
        self.write(license_gate.INVENTORY, json.dumps({
            "schema": 1,
            "inputs": self.inputs,
            "scope_reviews": self.reviews,
            "components": self.components,
        }))
        self.write(license_gate.APPROVALS, json.dumps({
            "schema": 1, "approvals": self.approvals,
        }))
        self.write(license_gate.PINS, json.dumps({
            "schema": 1, "pins": self.pins,
        }))

    def test_permissive_exact_component_passes(self):
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0))

    def test_locked_dependency_missing_from_inventory_fails(self):
        self.components = []
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "locked dependencies differ"):
            license_gate.audit(self.root)

    def test_python_project_dependency_requires_matching_hashed_lock_entry(self):
        self.write("pyproject.toml", '[project]\ndependencies = ["direct==9.8.7"]\n')
        project_location = {
            "path": "pyproject.toml", "ecosystem": "python-project", "scope": "backend",
        }
        self.inputs.append(project_location)
        self.components.append(self.component(
            id="pypi:direct@9.8.7",
            name="direct",
            version="9.8.7",
            upstream="https://example.test/direct/9.8.7",
            locations=[project_location],
        ))
        self.save()
        with self.assertRaisesRegex(
                license_gate.GateError, "python project dependency lacks matching reviewed lock entry"):
            license_gate.audit(self.root)

    def test_python_project_lock_correspondence_includes_scope(self):
        self.write("pyproject.toml", '[project]\ndependencies = ["demo==1.2.3"]\n')
        project_location = {
            "path": "pyproject.toml", "ecosystem": "python-project", "scope": "frontend",
        }
        self.inputs.append(project_location)
        self.components[0]["locations"].append(project_location)
        self.save()
        with self.assertRaisesRegex(
                license_gate.GateError, "python project dependency lacks matching reviewed lock entry"):
            license_gate.audit(self.root)

        project_location["scope"] = "backend"
        self.save()
        self.assertEqual(license_gate.audit(self.root), (1, 2, 0))

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
        self.approvals = [{
            "component_id": "pypi:demo@1.2.3",
            "version": "1.2.3",
            "license": "GPL-3.0-only",
            "approved_by": "repository-owner",
            "approved_on": "2026-09-21",
            "decision": "docs/decisions/0001-synthetic.md",
        }]
        self.save()
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0))
        self.approvals[0]["version"] = "1.2.2"
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "lacks exact owner approval"):
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
        self.approvals = [{
            "component_id": "pypi:demo@1.2.3",
            "version": "1.2.3",
            "license": "GPL-3.0-only",
            "approved_by": "repository-owner",
            "approved_on": "2026-09-21",
            "decision": "docs/decisions/0001-synthetic.md",
        }]
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

        self.components.append({
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
                "path": "models/demo.onnx",
                "ecosystem": "model-artifact",
                "scope": "model_weight",
            }],
            "sha256": hashlib.sha256(artifact).hexdigest(),
        })
        self.reviews = [self.review("transport")]
        self.save()
        self.assertEqual(license_gate.audit(self.root), (2, 1, 1))

    def test_unreviewed_lockfile_and_npm_transitive_are_detected(self):
        integrity = self.sri(1)
        self.write("frontend/package-lock.json", json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/transitive": {
                    "version": "4.5.6",
                    "resolved": "https://example.test/transitive.tgz",
                    "integrity": integrity,
                },
            },
        }))
        with self.assertRaisesRegex(license_gate.GateError, "input set differs"):
            license_gate.audit(self.root)
        self.inputs.append({
            "path": "frontend/package-lock.json", "ecosystem": "npm-lock", "scope": "frontend",
        })
        self.pins.append({
            "path": "frontend/package-lock.json",
            "ecosystem": "npm-lock",
            "name": "transitive",
            "version": "4.5.6",
            "digests": [integrity],
        })
        self.save()
        with self.assertRaisesRegex(license_gate.GateError, "locked dependencies differ"):
            license_gate.audit(self.root)

    def test_requirement_must_be_exact_and_hash_pinned(self):
        for requirement in ("demo>=1.2.3\n", "demo==1.2.3\n"):
            with self.subTest(requirement=requirement.strip()):
                self.write("requirements.lock", requirement)
                with self.assertRaises(license_gate.GateError):
                    license_gate.audit(self.root)

    def test_unknown_dependency_ecosystem_fails_closed(self):
        self.write("transport/Cargo.lock", "# synthetic lock\n")
        with self.assertRaisesRegex(license_gate.GateError, "reviewed parser"):
            license_gate.audit(self.root)

    def test_nested_requirement_dependency_is_recursively_audited(self):
        self.write("requirements.lock", "-r requirements-nested.lock\n")
        self.write("requirements-nested.lock", "nested==9.8.7 --hash=sha256:" + "c" * 64 + "\n")
        self.inputs.append({
            "path": "requirements-nested.lock",
            "ecosystem": "python-requirements",
            "scope": "backend",
        })
        self.pins = [{
            "path": "requirements-nested.lock",
            "ecosystem": "python-requirements",
            "name": "nested",
            "version": "9.8.7",
            "digests": ["sha256:" + "c" * 64],
        }]
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
        self.pins = []
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
        self.assertEqual(set(license_gate.model_files(self.root)), paths)
        with self.assertRaisesRegex(license_gate.GateError, "model artifact set differs"):
            license_gate.audit(self.root)

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
        self.assertEqual(license_gate.audit(self.root), (1, 1, 0))
        self.write("requirements.lock", "demo==1.2.3 --hash=sha256:" + "b" * 64 + "\n")
        with self.assertRaisesRegex(license_gate.GateError, "lock digests differ"):
            license_gate.audit(self.root)

    def test_npm_sri_change_is_rejected_for_same_name_version_and_resolved(self):
        resolved = "https://example.test/transitive-4.5.6.tgz"
        approved_sri = self.sri(2)
        package = {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/transitive": {
                    "version": "4.5.6", "resolved": resolved, "integrity": approved_sri,
                },
            },
        }
        self.write("frontend/package-lock.json", json.dumps(package))
        self.inputs.append({
            "path": "frontend/package-lock.json", "ecosystem": "npm-lock", "scope": "frontend",
        })
        self.components.append(self.component(
            id="npm:transitive@4.5.6",
            name="transitive",
            version="4.5.6",
            upstream=resolved,
            locations=[{
                "path": "frontend/package-lock.json",
                "ecosystem": "npm-lock",
                "scope": "frontend",
            }],
        ))
        self.pins.append({
            "path": "frontend/package-lock.json",
            "ecosystem": "npm-lock",
            "name": "transitive",
            "version": "4.5.6",
            "digests": [approved_sri],
        })
        self.save()
        self.assertEqual(license_gate.audit(self.root), (2, 2, 0))
        package["packages"]["node_modules/transitive"]["integrity"] = self.sri(3)
        self.write("frontend/package-lock.json", json.dumps(package))
        with self.assertRaisesRegex(license_gate.GateError, "lock digests differ"):
            license_gate.audit(self.root)
        package["packages"]["node_modules/transitive"]["integrity"] = "sha512-synthetic"
        self.write("frontend/package-lock.json", json.dumps(package))
        with self.assertRaisesRegex(license_gate.GateError, "invalid npm integrity"):
            license_gate.audit(self.root)

    def test_model_weight_location_outside_reserved_directory_is_rejected(self):
        artifact = b"synthetic opaque model archive"
        self.write("server/assets/ml/model.zip", artifact)
        self.components.append({
            "id": "model:opaque-weight@1",
            "name": "opaque-weight",
            "version": "1",
            "kind": "model_weight",
            "upstream": "https://example.test/models/opaque/1",
            "license": "Apache-2.0",
            "license_evidence": ["docs/evidence.md"],
            "transitive_evidence": ["docs/evidence.md"],
            "obligations": ["preserve-license-and-copyright", "preserve-notice"],
            "notice_files": ["docs/evidence.md"],
            "locations": [{
                "path": "server/assets/ml/model.zip",
                "ecosystem": "model-artifact",
                "scope": "model_weight",
            }],
            "sha256": hashlib.sha256(artifact).hexdigest(),
        })
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


if __name__ == "__main__":
    unittest.main()
