"""Strict, secret-free v1 production-reference deployment profile validation."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .models import canonical_json, sha256_digest

_SCHEMA_VERSION = "finredops.production-reference-deployment.v1"
_ALLOWED_CRYPTO_PROVIDER = "aws_kms"
_REQUIRED_COMPONENTS = (
    "external_identity",
    "tenant_authorization",
    "postgresql_rls",
    "institution_cryptography",
    "configuration_change_control",
    "external_audit_anchor",
    "evidence_vault",
    "isolated_worker",
)
_SECRET_NAME = re.compile(
    r"(^|_)(password|passwd|secret|token|private_key|client_secret|credential|api_key)($|_)",
    re.IGNORECASE,
)


class ReferenceDeploymentError(ValueError):
    """Raised when a v1 reference-deployment profile is unsafe or incomplete."""


def _reject_secrets(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ReferenceDeploymentError(f"{path} contains a non-string key.")
            if _SECRET_NAME.search(key):
                raise ReferenceDeploymentError(
                    f"{path}.{key} is secret-bearing and must not be stored in the deployment profile."
                )
            _reject_secrets(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_secrets(nested, f"{path}[{index}]")


def validate_reference_deployment(document: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate the v1 production-reference profile without contacting providers."""

    if not isinstance(document, Mapping):
        raise ReferenceDeploymentError("Reference deployment must be a JSON object.")
    _reject_secrets(document)
    if document.get("schema_version") != _SCHEMA_VERSION:
        raise ReferenceDeploymentError("Unsupported production-reference schema version.")
    if document.get("release_version") != "1.0.0":
        raise ReferenceDeploymentError("Reference deployment must target FinRedOps 1.0.0.")
    if document.get("production_active_testing_allowed") is not False:
        raise ReferenceDeploymentError("Production active testing must remain disabled.")
    if document.get("autonomous_target_discovery_allowed") is not False:
        raise ReferenceDeploymentError("Autonomous target discovery must remain disabled.")

    components = document.get("components")
    if not isinstance(components, Mapping):
        raise ReferenceDeploymentError("components must be an object.")
    if tuple(sorted(components)) != tuple(sorted(_REQUIRED_COMPONENTS)):
        raise ReferenceDeploymentError("Reference deployment component set is incomplete or unexpected.")

    identity = components["external_identity"]
    if not isinstance(identity, Mapping) or identity.get("protocol") != "oidc_jwks":
        raise ReferenceDeploymentError("External identity must use the pinned OIDC/JWKS boundary.")
    if identity.get("network_discovery") is not False:
        raise ReferenceDeploymentError("OIDC discovery must remain external to the verifier.")

    tenant = components["tenant_authorization"]
    if not isinstance(tenant, Mapping) or tenant.get("exact_subject_grants") is not True:
        raise ReferenceDeploymentError("Tenant routing must require exact subject grants.")

    postgres = components["postgresql_rls"]
    if not isinstance(postgres, Mapping):
        raise ReferenceDeploymentError("PostgreSQL RLS configuration is required.")
    if postgres.get("major_version") != 17:
        raise ReferenceDeploymentError("The v1 reference profile pins PostgreSQL 17.")
    if postgres.get("force_rls") is not True or postgres.get("session_user_tenant_source") is not True:
        raise ReferenceDeploymentError("PostgreSQL FORCE RLS and session_user tenant resolution are required.")

    crypto = components["institution_cryptography"]
    if not isinstance(crypto, Mapping) or crypto.get("provider") != _ALLOWED_CRYPTO_PROVIDER:
        raise ReferenceDeploymentError("The v1 reference deployment uses the built-in AWS KMS adapter.")
    purposes = crypto.get("required_key_purposes")
    if sorted(purposes or []) != ["audit_signing", "data_encryption", "workload_identity"]:
        raise ReferenceDeploymentError("All three institution key purposes are required.")

    change = components["configuration_change_control"]
    if not isinstance(change, Mapping) or change.get("independent_governors") != 2:
        raise ReferenceDeploymentError("Two independent configuration governors are required.")

    anchor = components["external_audit_anchor"]
    if not isinstance(anchor, Mapping) or anchor.get("separate_trust_root") is not True:
        raise ReferenceDeploymentError("External audit anchoring requires a separate trust root.")

    vault = components["evidence_vault"]
    if not isinstance(vault, Mapping):
        raise ReferenceDeploymentError("Evidence-vault configuration is required.")
    if vault.get("envelope_encryption") is not True or vault.get("legal_hold") is not True:
        raise ReferenceDeploymentError("Encrypted evidence and legal-hold lifecycle are required.")

    worker = components["isolated_worker"]
    if not isinstance(worker, Mapping):
        raise ReferenceDeploymentError("Isolated-worker configuration is required.")
    if worker.get("non_production_only") is not True or worker.get("single_use_test_account") is not True:
        raise ReferenceDeploymentError("Worker execution must remain non-production and single-use-account bound.")

    normalized = dict(document)
    normalized["deployment_digest"] = sha256_digest(
        {key: value for key, value in document.items() if key != "deployment_digest"}
    )
    if document.get("deployment_digest") not in (None, normalized["deployment_digest"]):
        raise ReferenceDeploymentError("deployment_digest does not match the canonical profile.")
    canonical_json(normalized)
    return normalized
