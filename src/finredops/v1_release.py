"""FinRedOps v1 public release contract and compatibility manifest."""

from __future__ import annotations

from typing import Any, Mapping

V1_RELEASE_VERSION = "1.0.0"
PUBLIC_CONTRACT_VERSION = "finredops.public-contract.v1"
SUPPORTED_UPGRADE_FROM = ("0.9.3",)

# These CLI commands form the stable v1 operator surface. New commands may be
# added compatibly in v1.x, but these commands are not removed or repurposed
# without a major-version change.
STABLE_CLI_COMMANDS = (
    "import-sarif",
    "validate-intake",
    "promote-trusted-reviewed-report",
    "verify-review-trust",
    "approve-trusted-report",
    "verify-oidc-id-token",
    "verify-oidc-workflow-bindings",
    "resolve-change-control",
    "verify-change-control",
    "authorize-tenant-route",
    "verify-tenant-authorization",
    "verify-postgres-runtime",
    "verify-audit-anchor-receipt",
    "verify-audit-anchor-chain",
    "verify-release-checksums",
)

# Versioned JSON artifacts that are explicitly part of the v1 compatibility
# contract. Their schema_version discriminator is the compatibility boundary.
STABLE_SCHEMA_VERSIONS = {
    "tenant_authorization": "finredops.tenant-authorization.v1",
    "institution_context": "finredops.institution-security-context.v1",
    "approved_change_package": "finredops.approved-change-package.v1",
    "audit_anchor_receipt": "finredops.audit-anchor-receipt.v1",
    "evidence_vault_record": "finredops.evidence-vault-record.v1",
    "workload_execution_lease": "finredops.workload-execution-lease.v1",
}


def v1_release_manifest() -> Mapping[str, Any]:
    """Return the deterministic repository-level v1 release contract."""

    return {
        "schema_version": PUBLIC_CONTRACT_VERSION,
        "release_version": V1_RELEASE_VERSION,
        "supported_upgrade_from": list(SUPPORTED_UPGRADE_FROM),
        "stable_cli_commands": list(STABLE_CLI_COMMANDS),
        "stable_schema_versions": dict(sorted(STABLE_SCHEMA_VERSIONS.items())),
        "python_import_surface_stable": False,
        "cli_backward_compatibility_required_within_v1": True,
        "schema_discriminator_backward_compatibility_required_within_v1": True,
        "breaking_change_requires_major_version": True,
        "automatic_destructive_downgrade_supported": False,
        "reference_deployment_profile_required": True,
        "release_provenance_required": True,
        "independent_external_human_security_audit_claimed": False,
        "compliance_certification_claimed": False,
        "autonomous_penetration_testing_claimed": False,
    }
