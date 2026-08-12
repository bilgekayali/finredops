"""Closed action catalog for simulation and bounded active validation."""

from __future__ import annotations

from dataclasses import dataclass

from .models import RiskLevel


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    action_id: str
    name: str
    description: str
    risk_level: RiskLevel
    allowed_parameter_keys: frozenset[str]
    required_parameter_keys: frozenset[str] = frozenset()
    supported_in_mvp: bool = True


def _action(
    action_id: str,
    name: str,
    description: str,
    risk_level: RiskLevel,
    *parameter_keys: str,
    required: tuple[str, ...] = (),
    supported: bool = True,
) -> ActionDefinition:
    return ActionDefinition(
        action_id=action_id,
        name=name,
        description=description,
        risk_level=risk_level,
        allowed_parameter_keys=frozenset(parameter_keys),
        required_parameter_keys=frozenset(required),
        supported_in_mvp=supported,
    )


ACTION_CATALOG: dict[str, ActionDefinition] = {
    item.action_id: item
    for item in (
        _action(
            "http.response_headers.inspect",
            "HTTP response header review",
            "Review synthetic response-header evidence against a declared baseline.",
            RiskLevel.PASSIVE,
            "expected_control",
            "evidence_reference",
        ),
        _action(
            "tls.certificate_metadata.inspect",
            "TLS certificate metadata review",
            "Review synthetic certificate metadata without opening a network connection.",
            RiskLevel.PASSIVE,
            "expected_control",
            "evidence_reference",
        ),
        _action(
            "dns.metadata.inspect",
            "DNS metadata review",
            "Review a synthetic DNS metadata record supplied with the engagement.",
            RiskLevel.PASSIVE,
            "record_type",
            "evidence_reference",
        ),
        _action(
            "identity.configuration.review",
            "Identity control evidence review",
            "Review a synthetic identity-control evidence package.",
            RiskLevel.EVIDENCE_ONLY,
            "control_family",
            "evidence_reference",
        ),
        _action(
            "cloud.configuration.review",
            "Cloud control evidence review",
            "Review synthetic cloud configuration evidence against an approved control.",
            RiskLevel.EVIDENCE_ONLY,
            "control_family",
            "evidence_reference",
        ),
        _action(
            "transaction.workflow.review",
            "Transaction workflow evidence review",
            "Review a synthetic transaction-control narrative and evidence reference.",
            RiskLevel.EVIDENCE_ONLY,
            "control_family",
            "evidence_reference",
        ),
        _action(
            "http.security_posture.validate",
            "Bounded HTTP security posture validation",
            "Make one approved TLS HEAD request without redirects or response-body collection and produce reviewable finding metadata.",
            RiskLevel.CONTROLLED,
            "port",
            "path",
            "timeout_seconds",
            "change_reference",
            "methodology_profile",
            required=("change_reference",),
        ),
        _action(
            "vulnerability.validation.controlled",
            "Controlled vulnerability validation",
            "Reserved catalog entry for separately reviewed institution-specific validation modules.",
            RiskLevel.CONTROLLED,
            "finding_reference",
            supported=False,
        ),
    )
}


def get_action(action_id: str) -> ActionDefinition | None:
    """Return a catalog entry without accepting aliases or free-form commands."""

    return ACTION_CATALOG.get(action_id)
