"""Institution policy profiles and engagement preflight checks."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from .catalog import ACTION_CATALOG
from .models import (
    AssetKind,
    DataClassification,
    Engagement,
    Environment,
    RiskLevel,
    ScopeAsset,
    StringEnum,
    sha256_digest,
    to_primitive,
)


class FindingSeverity(StringEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class PreflightFinding:
    severity: FindingSeverity
    code: str
    message: str
    path: str
    blocking: bool


@dataclass(frozen=True, slots=True)
class PreflightReport:
    profile_id: str
    profile_digest: str
    engagement_digest: str
    findings: tuple[PreflightFinding, ...]

    @property
    def allowed(self) -> bool:
        return not any(item.blocking for item in self.findings)

    @property
    def blocking_count(self) -> int:
        return sum(1 for item in self.findings if item.blocking)

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "profile_digest": self.profile_digest,
            "engagement_digest": self.engagement_digest,
            "allowed": self.allowed,
            "blocking_count": self.blocking_count,
            "findings": to_primitive(self.findings),
        }


@dataclass(frozen=True, slots=True)
class PolicyProfile:
    profile_id: str
    name: str
    version: str
    allowed_environments: tuple[Environment, ...]
    production_allowed_risks: tuple[RiskLevel, ...]
    max_approval_ttl_minutes: int
    max_requests_per_minute: int
    minimum_emergency_contacts: int
    minimum_production_contacts: int
    minimum_ipv4_prefix: int
    minimum_ipv6_prefix: int

    def digest(self) -> str:
        return sha256_digest(self)

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self), "digest": self.digest()}

    def lint(self, engagement: Engagement) -> PreflightReport:
        findings: list[PreflightFinding] = []

        def add(
            severity: FindingSeverity,
            code: str,
            message: str,
            path: str,
            *,
            blocking: bool | None = None,
        ) -> None:
            findings.append(
                PreflightFinding(
                    severity=severity,
                    code=code,
                    message=message,
                    path=path,
                    blocking=severity == FindingSeverity.ERROR if blocking is None else blocking,
                )
            )

        all_assets = (*engagement.assets, *engagement.excluded_assets)
        asset_ids = [asset.asset_id for asset in all_assets]
        if len(asset_ids) != len(set(asset_ids)):
            add(
                FindingSeverity.ERROR,
                "PROFILE_DUPLICATE_ASSET_ID",
                "Asset identifiers must be unique across scope and exclusions.",
                "assets",
            )

        scope_values = [(asset.kind, asset.value) for asset in engagement.assets]
        if len(scope_values) != len(set(scope_values)):
            add(
                FindingSeverity.ERROR,
                "PROFILE_DUPLICATE_SCOPE",
                "The approved scope contains duplicate canonical assets.",
                "assets",
            )

        for index, asset in enumerate(all_assets):
            path = (
                f"assets[{index}]"
                if index < len(engagement.assets)
                else f"excluded_assets[{index - len(engagement.assets)}]"
            )
            if asset.environment not in self.allowed_environments:
                add(
                    FindingSeverity.ERROR,
                    "PROFILE_ENVIRONMENT_DENIED",
                    f"Environment {asset.environment.value!r} is not permitted by the profile.",
                    f"{path}.environment",
                )
            if asset.kind == AssetKind.CIDR:
                network = ipaddress.ip_network(asset.value, strict=False)
                minimum = (
                    self.minimum_ipv4_prefix
                    if network.version == 4
                    else self.minimum_ipv6_prefix
                )
                if network.prefixlen < minimum:
                    add(
                        FindingSeverity.ERROR,
                        "PROFILE_SCOPE_TOO_BROAD",
                        f"Network scope {asset.value} is broader than /{minimum}.",
                        f"{path}.value",
                    )

        for included in engagement.assets:
            for excluded in engagement.excluded_assets:
                if _assets_overlap(included, excluded):
                    add(
                        FindingSeverity.ERROR,
                        "PROFILE_SCOPE_EXCLUSION_OVERLAP",
                        "An in-scope asset overlaps an explicit exclusion.",
                        "excluded_assets",
                    )
                    break

        mapped_functions = {asset.critical_function.casefold() for asset in engagement.assets}
        for index, critical_function in enumerate(engagement.critical_functions):
            if critical_function.casefold() not in mapped_functions:
                add(
                    FindingSeverity.ERROR,
                    "PROFILE_UNMAPPED_CRITICAL_FUNCTION",
                    f"Critical function {critical_function!r} has no in-scope asset.",
                    f"critical_functions[{index}]",
                )

        for index, action_id in enumerate(engagement.allowed_actions):
            action = ACTION_CATALOG.get(action_id)
            if action is None:
                add(
                    FindingSeverity.ERROR,
                    "PROFILE_UNKNOWN_ACTION",
                    f"Action {action_id!r} is not present in the closed catalog.",
                    f"allowed_actions[{index}]",
                )
                continue
            if not action.supported_in_mvp:
                add(
                    FindingSeverity.WARNING,
                    "PROFILE_ACTION_NOT_IMPLEMENTED",
                    f"Action {action_id!r} will remain policy-denied in this release.",
                    f"allowed_actions[{index}]",
                    blocking=False,
                )

        production_assets = [
            asset for asset in engagement.assets if asset.environment == Environment.PRODUCTION
        ]
        if production_assets:
            for index, action_id in enumerate(engagement.allowed_actions):
                action = ACTION_CATALOG.get(action_id)
                if action and action.risk_level not in self.production_allowed_risks:
                    add(
                        FindingSeverity.ERROR,
                        "PROFILE_PRODUCTION_ACTION_DENIED",
                        f"Action risk {action.risk_level.value!r} is not allowed for production scope.",
                        f"allowed_actions[{index}]",
                    )
            if len(set(engagement.emergency_contacts)) < self.minimum_production_contacts:
                add(
                    FindingSeverity.ERROR,
                    "PROFILE_PRODUCTION_CONTACTS",
                    "Production scope requires additional distinct emergency contacts.",
                    "emergency_contacts",
                )
            if any(
                asset.data_classification == DataClassification.RESTRICTED
                for asset in production_assets
            ):
                add(
                    FindingSeverity.INFO,
                    "PROFILE_RESTRICTED_DATA",
                    "Restricted-data scope requires institution-owned evidence handling controls.",
                    "assets",
                    blocking=False,
                )

        contacts = engagement.emergency_contacts
        if len(set(contacts)) < self.minimum_emergency_contacts:
            add(
                FindingSeverity.ERROR,
                "PROFILE_EMERGENCY_CONTACTS",
                "The profile requires more distinct emergency contacts.",
                "emergency_contacts",
            )
        for index, contact in enumerate(contacts):
            if not _EMAIL.fullmatch(contact):
                add(
                    FindingSeverity.ERROR,
                    "PROFILE_INVALID_CONTACT",
                    "Emergency contacts must be syntactically valid email addresses.",
                    f"emergency_contacts[{index}]",
                )

        if engagement.approval_ttl_minutes > self.max_approval_ttl_minutes:
            add(
                FindingSeverity.ERROR,
                "PROFILE_APPROVAL_TTL",
                "Approval TTL exceeds the institution profile maximum.",
                "approval_ttl_minutes",
            )
        if engagement.max_requests_per_minute > self.max_requests_per_minute:
            add(
                FindingSeverity.ERROR,
                "PROFILE_RATE_LIMIT",
                "Request-rate ceiling exceeds the institution profile maximum.",
                "max_requests_per_minute",
            )

        if not findings:
            add(
                FindingSeverity.INFO,
                "PROFILE_PREFLIGHT_CLEAR",
                "Engagement satisfies all automated profile checks.",
                "$",
                blocking=False,
            )
        return PreflightReport(
            profile_id=self.profile_id,
            profile_digest=self.digest(),
            engagement_digest=engagement.digest(),
            findings=tuple(findings),
        )


_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _assets_overlap(left: ScopeAsset, right: ScopeAsset) -> bool:
    if left.kind == AssetKind.HOSTNAME or right.kind == AssetKind.HOSTNAME:
        return left.kind == right.kind and left.value == right.value
    left_network = (
        ipaddress.ip_network(left.value, strict=False)
        if left.kind == AssetKind.CIDR
        else ipaddress.ip_network(f"{left.value}/32" if ":" not in left.value else f"{left.value}/128")
    )
    right_network = (
        ipaddress.ip_network(right.value, strict=False)
        if right.kind == AssetKind.CIDR
        else ipaddress.ip_network(f"{right.value}/32" if ":" not in right.value else f"{right.value}/128")
    )
    return left_network.version == right_network.version and left_network.overlaps(right_network)


def regulated_financial_profile() -> PolicyProfile:
    """Return the built-in high-assurance financial-institution profile."""

    return PolicyProfile(
        profile_id="regulated-financial-v1",
        name="Regulated financial institution baseline",
        version="1.0.0",
        allowed_environments=(
            Environment.LAB,
            Environment.DEVELOPMENT,
            Environment.TEST,
            Environment.PRODUCTION,
        ),
        production_allowed_risks=(RiskLevel.EVIDENCE_ONLY,),
        max_approval_ttl_minutes=120,
        max_requests_per_minute=30,
        minimum_emergency_contacts=1,
        minimum_production_contacts=2,
        minimum_ipv4_prefix=28,
        minimum_ipv6_prefix=120,
    )
