"""Release-candidate compatibility contract for persisted FinRedOps state.

The manifest is descriptive and fail-closed. It does not perform destructive
schema downgrade or rewrite unknown future artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import sha256_digest, to_primitive

RELEASE_VERSION = "0.9.3"


@dataclass(frozen=True, slots=True)
class PersistenceCompatibility:
    name: str
    current_schema: int
    readable_schemas: tuple[int, ...]
    auto_upgrade_from: tuple[int, ...]
    downgrade_write_supported: bool = False
    future_schema_open_supported: bool = False

    def __post_init__(self) -> None:
        if not self.name or self.current_schema < 1:
            raise ValueError("Persistence compatibility entry is invalid.")
        if self.current_schema not in self.readable_schemas:
            raise ValueError("Current persistence schema must be readable.")
        if any(value < 1 or value >= self.current_schema for value in self.auto_upgrade_from):
            raise ValueError("Auto-upgrade sources must be older positive schema versions.")
        if self.downgrade_write_supported or self.future_schema_open_supported:
            raise ValueError("Release candidate persistence policy must remain fail-closed.")

    def classify(self, version: int) -> str:
        if isinstance(version, bool) or not isinstance(version, int) or version < 0:
            raise ValueError("Schema version must be a non-negative integer.")
        if version == 0:
            return "uninitialized"
        if version == self.current_schema:
            return "current"
        if version in self.auto_upgrade_from:
            return "upgradeable"
        if version > self.current_schema:
            return "future_unsupported"
        return "legacy_unsupported"


PERSISTENCE_COMPATIBILITY = (
    PersistenceCompatibility(
        name="sqlite-governance-store",
        current_schema=3,
        readable_schemas=(3,),
        auto_upgrade_from=(1, 2),
    ),
    PersistenceCompatibility(
        name="sqlite-evidence-vault",
        current_schema=1,
        readable_schemas=(1,),
        auto_upgrade_from=(),
    ),
    PersistenceCompatibility(
        name="reference-audit-anchor",
        current_schema=1,
        readable_schemas=(1,),
        auto_upgrade_from=(),
    ),
    PersistenceCompatibility(
        name="one-time-grant-ledger",
        current_schema=1,
        readable_schemas=(1,),
        auto_upgrade_from=(),
    ),
)

SECURITY_ARTIFACT_SCHEMAS = (
    "finredops.snapshot.v2",
    "finredops.envelope-encrypted-artifact.v1",
    "finredops.key-backed-signature.v1",
    "finredops.workload-identity-attestation.v1",
    "finredops.one-time-test-account-grant.v1",
    "finredops.emergency-stop-state.v1",
    "finredops.workload-execution-lease.v1",
    "finredops.worker-execution-envelope.v1",
    "finredops.worker-receipt-signature.v1",
    "finredops.cyclonedx-intake.v1",
    "finredops.cvss40-validation.v1",
    "finredops.asvs-requirement-catalog.v1",
)


def release_compatibility_manifest() -> dict[str, Any]:
    core = {
        "schema_version": "finredops.release-compatibility-manifest.v1",
        "release_version": RELEASE_VERSION,
        "persistence": [to_primitive(item) for item in PERSISTENCE_COMPATIBILITY],
        "security_artifact_schemas": list(SECURITY_ARTIFACT_SCHEMAS),
        "automatic_downgrade_supported": False,
        "unknown_future_schema_open_supported": False,
        "backup_before_migration_required": True,
        "rollback_uses_backup_or_previous_environment": True,
    }
    return {**core, "manifest_digest": sha256_digest(core)}
