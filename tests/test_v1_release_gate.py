from __future__ import annotations

import json
import tomllib
import unittest
from copy import deepcopy
from pathlib import Path

import finredops
from finredops.reference_deployment import (
    ReferenceDeploymentError,
    validate_reference_deployment,
)
from finredops.v1_release import (
    STABLE_CLI_COMMANDS,
    STABLE_SCHEMA_FILES,
    v1_release_manifest,
)

ROOT = Path(__file__).resolve().parents[1]


class V1ReleaseGateTests(unittest.TestCase):
    def test_release_manifest_is_stable_and_non_autonomous(self) -> None:
        manifest = v1_release_manifest()
        self.assertEqual(manifest["release_version"], "1.0.0")
        self.assertEqual(manifest["supported_upgrade_from"], ["0.9.3"])
        self.assertTrue(manifest["breaking_change_requires_major_version"])
        self.assertFalse(manifest["automatic_destructive_downgrade_supported"])
        self.assertFalse(manifest["autonomous_penetration_testing_claimed"])
        self.assertFalse(manifest["compliance_certification_claimed"])
        self.assertFalse(manifest["independent_external_human_security_audit_claimed"])
        self.assertGreaterEqual(len(STABLE_CLI_COMMANDS), 12)
        self.assertEqual(len(STABLE_CLI_COMMANDS), len(set(STABLE_CLI_COMMANDS)))

    def test_stable_schema_files_keep_exact_v1_discriminators(self) -> None:
        for name, (relative_path, expected_version) in STABLE_SCHEMA_FILES.items():
            document = json.loads((ROOT / relative_path).read_text(encoding="utf-8"))
            properties = document.get("properties", {})
            schema_version = properties.get("schema_version", {})
            self.assertEqual(schema_version.get("const"), expected_version, name)
            self.assertFalse(document.get("additionalProperties", True), name)

    def test_production_reference_profile_validates_and_is_secret_free(self) -> None:
        path = ROOT / "deploy/reference/production-reference.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        validated = validate_reference_deployment(document)
        self.assertRegex(validated["deployment_digest"], r"^[a-f0-9]{64}$")
        self.assertFalse(validated["production_active_testing_allowed"])
        self.assertEqual(
            validated["components"]["institution_cryptography"]["provider"],
            "aws_kms",
        )
        self.assertTrue(validated["components"]["postgresql_rls"]["force_rls"])

    def test_reference_profile_rejects_secret_bearing_fields(self) -> None:
        document = json.loads(
            (ROOT / "deploy/reference/production-reference.json").read_text(encoding="utf-8")
        )
        tampered = deepcopy(document)
        tampered["components"]["external_identity"]["client_secret"] = "not-allowed"
        with self.assertRaises(ReferenceDeploymentError):
            validate_reference_deployment(tampered)

    def test_reference_profile_rejects_boundary_weakening(self) -> None:
        document = json.loads(
            (ROOT / "deploy/reference/production-reference.json").read_text(encoding="utf-8")
        )
        for mutator in (
            lambda d: d.__setitem__("production_active_testing_allowed", True),
            lambda d: d["components"]["postgresql_rls"].__setitem__("force_rls", False),
            lambda d: d["components"]["isolated_worker"].__setitem__("non_production_only", False),
        ):
            tampered = deepcopy(document)
            mutator(tampered)
            with self.assertRaises(ReferenceDeploymentError):
                validate_reference_deployment(tampered)

    def test_package_and_module_versions_are_v1(self) -> None:
        with (ROOT / "pyproject.toml").open("rb") as source:
            project = tomllib.load(source)["project"]
        self.assertEqual(project["version"], "1.0.0")
        self.assertEqual(finredops.__version__, "1.0.0")

    def test_required_v1_documents_are_present(self) -> None:
        required = (
            "docs/API_COMPATIBILITY.md",
            "docs/PRODUCTION_REFERENCE_DEPLOYMENT.md",
            "docs/RELEASE_VERIFICATION.md",
            "docs/UPGRADE_TO_V1.md",
            "docs/SECURITY_REVIEW_V1.md",
            "docs/LEGAL_ACCESSIBILITY_SCOPE.md",
            "docs/V1_NON_CLAIMS.md",
        )
        for name in required:
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertGreater(len(text.strip()), 900, name)

    def test_release_and_codeql_workflows_preserve_v1_security_gates(self) -> None:
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("actions/attest@v4", release)
        self.assertIn("CHECKSUMS.sha256", release)
        self.assertIn("verify-release-checksums", release)
        self.assertIn("v1-release-contract.json", release)
        self.assertIn("production-reference.json", release)
        codeql = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
        self.assertIn("github/codeql-action/init@v4", codeql)
        self.assertIn("github/codeql-action/analyze@v4", codeql)
        self.assertIn("security-extended", codeql)

    def test_roadmap_marks_all_v1_release_gates_complete(self) -> None:
        roadmap = (ROOT / "docs/ROADMAP.md").read_text(encoding="utf-8")
        marker = "### v1.0.0 — production-ready reference release gate"
        section = roadmap.split(marker, 1)[1].split("## Platform hardening", 1)[0]
        self.assertNotIn("- [ ]", section)
        self.assertGreaterEqual(section.count("- [x]"), 7)

    def test_v1_non_claims_keep_production_active_testing_disabled(self) -> None:
        text = (ROOT / "docs/V1_NON_CLAIMS.md").read_text(encoding="utf-8").lower()
        self.assertIn("production-target active-testing", text)
        self.assertIn("autonomous target discovery", text)
        self.assertIn("external-human penetration-test", text)


if __name__ == "__main__":
    unittest.main()
