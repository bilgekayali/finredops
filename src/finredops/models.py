"""Domain models used by the FinRedOps control plane."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, fields, replace
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


class StringEnum(str, Enum):
    """Enum that serializes cleanly to JSON."""


class AssetKind(StringEnum):
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    CIDR = "cidr"


class DataClassification(StringEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Environment(StringEnum):
    LAB = "lab"
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class RiskLevel(StringEnum):
    EVIDENCE_ONLY = "evidence_only"
    PASSIVE = "passive"
    CONTROLLED = "controlled"
    IMPACTING = "impacting"


class EngagementStatus(StringEnum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    PAUSED = "paused"
    COMPLETED = "completed"
    REVOKED = "revoked"


class Role(StringEnum):
    REQUESTER = "requester"
    BUSINESS_OWNER = "business_owner"
    CONTROL_TEAM = "control_team"
    EXECUTION_APPROVER = "execution_approver"
    OPERATOR = "operator"
    AUDITOR = "auditor"


class ApprovalDecision(StringEnum):
    APPROVED = "approved"
    DENIED = "denied"


class SubjectKind(StringEnum):
    ENGAGEMENT = "engagement"
    PROPOSAL = "proposal"


class ExecutionStatus(StringEnum):
    SIMULATED = "simulated"
    VALIDATED = "validated"
    FAILED = "failed"
    DENIED = "denied"
    CANCELLED = "cancelled"


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Datetime values must include a timezone.")
    return value.astimezone(timezone.utc)


def parse_datetime(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    return ensure_aware(datetime.fromisoformat(normalized))


def canonical_hostname(value: str) -> str:
    hostname = value.strip().casefold().rstrip(".")
    if not hostname or len(hostname) > 253:
        raise ValueError("Hostname must contain 1 to 253 characters.")
    if "*" in hostname:
        raise ValueError("Wildcard hostnames are intentionally unsupported.")
    labels = hostname.split(".")
    if len(labels) < 2 or any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError(f"Invalid fully qualified hostname: {value!r}")
    return hostname


def canonical_target(value: str) -> str:
    candidate = value.strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return canonical_hostname(candidate)


def to_primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return ensure_aware(value).isoformat().replace("+00:00", "Z")
    if hasattr(value, "__dataclass_fields__"):
        return {
            field.name: to_primitive(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, Mapping):
        return {
            str(key): to_primitive(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [to_primitive(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(to_primitive(item) for item in value)
    return value


def freeze_value(value: Any) -> Any:
    """Recursively freeze JSON-like values used in approved or audited records."""

    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Mapping keys must be strings.")
            frozen[key] = freeze_value(item)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(freeze_value(item) for item in value)
    if value is None or isinstance(value, (str, int, float, bool, Enum, datetime)):
        return value
    raise ValueError(f"Unsupported immutable value type: {type(value).__name__}.")


def canonical_json(value: Any) -> str:
    return json.dumps(
        to_primitive(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def sha256_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ScopeAsset:
    asset_id: str
    kind: AssetKind
    value: str
    environment: Environment
    data_classification: DataClassification
    critical_function: str

    def __post_init__(self) -> None:
        if not self.asset_id.strip():
            raise ValueError("asset_id cannot be empty.")
        if not self.critical_function.strip():
            raise ValueError("critical_function cannot be empty.")
        if self.kind == AssetKind.HOSTNAME:
            normalized = canonical_hostname(self.value)
        elif self.kind == AssetKind.IP_ADDRESS:
            normalized = str(ipaddress.ip_address(self.value.strip()))
        elif self.kind == AssetKind.CIDR:
            normalized = str(ipaddress.ip_network(self.value.strip(), strict=False))
        else:  # pragma: no cover - defensive for future enum expansion
            raise ValueError(f"Unsupported asset kind: {self.kind}")
        object.__setattr__(self, "value", normalized)

    def contains(self, target: str) -> bool:
        normalized = canonical_target(target)
        if self.kind == AssetKind.HOSTNAME:
            return normalized == self.value
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            return False
        if self.kind == AssetKind.IP_ADDRESS:
            return address == ipaddress.ip_address(self.value)
        return address in ipaddress.ip_network(self.value, strict=False)


@dataclass(frozen=True, slots=True)
class Engagement:
    engagement_id: str
    name: str
    requester_id: str
    critical_functions: tuple[str, ...]
    assets: tuple[ScopeAsset, ...]
    excluded_assets: tuple[ScopeAsset, ...]
    allowed_actions: tuple[str, ...]
    window_start: datetime
    window_end: datetime
    emergency_contacts: tuple[str, ...]
    max_requests_per_minute: int = 10
    approval_ttl_minutes: int = 60
    status: EngagementStatus = EngagementStatus.DRAFT

    def __post_init__(self) -> None:
        if not self.engagement_id.strip() or not self.name.strip():
            raise ValueError("Engagement ID and name are required.")
        if not self.requester_id.strip():
            raise ValueError("requester_id is required.")
        if not self.assets:
            raise ValueError("At least one in-scope asset is required.")
        if not self.allowed_actions:
            raise ValueError("At least one allowed action is required.")
        start = ensure_aware(self.window_start)
        end = ensure_aware(self.window_end)
        if end <= start:
            raise ValueError("window_end must be after window_start.")
        if not 1 <= self.max_requests_per_minute <= 60:
            raise ValueError("max_requests_per_minute must be between 1 and 60.")
        if not 5 <= self.approval_ttl_minutes <= 1440:
            raise ValueError("approval_ttl_minutes must be between 5 and 1440.")
        if not self.critical_functions:
            raise ValueError("At least one critical function is required.")
        if not self.emergency_contacts:
            raise ValueError("At least one emergency contact is required.")
        object.__setattr__(self, "window_start", start)
        object.__setattr__(self, "window_end", end)
        object.__setattr__(self, "critical_functions", tuple(self.critical_functions))
        object.__setattr__(self, "assets", tuple(self.assets))
        object.__setattr__(self, "excluded_assets", tuple(self.excluded_assets))
        object.__setattr__(self, "allowed_actions", tuple(sorted(set(self.allowed_actions))))
        object.__setattr__(self, "emergency_contacts", tuple(self.emergency_contacts))

    def approval_payload(self) -> dict[str, Any]:
        payload = to_primitive(self)
        payload.pop("status", None)
        return payload

    def digest(self) -> str:
        return sha256_digest(self.approval_payload())

    def with_status(self, status: EngagementStatus) -> "Engagement":
        return replace(self, status=status)


@dataclass(frozen=True, slots=True)
class ActionProposal:
    proposal_id: str
    engagement_id: str
    action_id: str
    target: str
    rationale: str
    parameters: Mapping[str, Any]
    proposed_by: str
    proposed_at: datetime

    def __post_init__(self) -> None:
        if not all(
            value.strip()
            for value in (
                self.proposal_id,
                self.engagement_id,
                self.action_id,
                self.rationale,
                self.proposed_by,
            )
        ):
            raise ValueError("Proposal identity, action, rationale, and proposer are required.")
        object.__setattr__(self, "target", canonical_target(self.target))
        object.__setattr__(self, "proposed_at", ensure_aware(self.proposed_at))
        object.__setattr__(self, "parameters", freeze_value(self.parameters))

    def digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    approval_id: str
    subject_kind: SubjectKind
    subject_id: str
    subject_digest: str
    actor_id: str
    role: Role
    decision: ApprovalDecision
    decided_at: datetime
    expires_at: datetime
    comment: str

    def __post_init__(self) -> None:
        if not all(
            value.strip()
            for value in (
                self.approval_id,
                self.subject_id,
                self.subject_digest,
                self.actor_id,
                self.comment,
            )
        ):
            raise ValueError("Approval identity, digest, actor, and comment are required.")
        decided = ensure_aware(self.decided_at)
        expires = ensure_aware(self.expires_at)
        if expires <= decided:
            raise ValueError("Approval expiry must be after its decision time.")
        object.__setattr__(self, "decided_at", decided)
        object.__setattr__(self, "expires_at", expires)


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    code: str
    reasons: tuple[str, ...]
    proposal_digest: str
    decided_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "reasons", tuple(self.reasons))
        object.__setattr__(self, "decided_at", ensure_aware(self.decided_at))


@dataclass(frozen=True, slots=True)
class ExecutionReceipt:
    execution_id: str
    proposal_id: str
    proposal_digest: str
    status: ExecutionStatus
    runner: str
    started_at: datetime
    finished_at: datetime
    evidence: Mapping[str, Any]
    evidence_digest: str

    def __post_init__(self) -> None:
        if not self.execution_id.strip() or not self.proposal_id.strip():
            raise ValueError("Execution and proposal identifiers are required.")
        started = ensure_aware(self.started_at)
        finished = ensure_aware(self.finished_at)
        if finished < started:
            raise ValueError("Execution finish time cannot precede its start time.")
        evidence = freeze_value(self.evidence)
        if sha256_digest(evidence) != self.evidence_digest:
            raise ValueError("Evidence digest does not match the immutable evidence.")
        object.__setattr__(self, "started_at", started)
        object.__setattr__(self, "finished_at", finished)
        object.__setattr__(self, "evidence", evidence)
