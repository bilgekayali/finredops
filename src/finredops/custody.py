"""Evidence metadata registry and tamper-evident chain of custody.

Only metadata and opaque vault locators belong here. Raw evidence is deliberately
kept outside FinRedOps under institution-owned access, encryption, and retention
controls.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Mapping

from .audit import AuditChain, AuditEvent
from .models import (
    DataClassification,
    StringEnum,
    ensure_aware,
    parse_datetime,
    sha256_digest,
    to_primitive,
)


class EvidenceType(StringEnum):
    SCREENSHOT = "screenshot"
    TOOL_OUTPUT = "tool_output"
    LOG_EXTRACT = "log_extract"
    CONFIGURATION_EXPORT = "configuration_export"
    SOURCE_REVIEW = "source_review"
    APPROVAL_RECORD = "approval_record"
    TEST_RESULT = "test_result"
    OTHER = "other"


class CustodyAction(StringEnum):
    REGISTERED = "registered"
    VERIFIED = "verified"
    ACCESSED = "accessed"
    TRANSFERRED = "transferred"
    SUPERSEDED = "superseded"
    LEGAL_HOLD_APPLIED = "legal_hold_applied"
    LEGAL_HOLD_RELEASED = "legal_hold_released"
    DISPOSED = "disposed"


_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$")
_LOCATOR_PREFIXES = (
    "vault://",
    "evidence://",
    "attachment://",
    "qualification-evidence://",
)


@dataclass(frozen=True, slots=True)
class EvidenceArtifact:
    evidence_id: str
    title: str
    evidence_type: EvidenceType
    classification: DataClassification
    content_sha256: str
    size_bytes: int
    media_type: str
    source_system: str
    collected_at: datetime
    collected_by: str
    locator: str
    description: str
    retention_until: str
    contains_personal_data: bool
    sanitized: bool

    def __post_init__(self) -> None:
        required = (
            self.evidence_id,
            self.title,
            self.source_system,
            self.collected_by,
            self.locator,
            self.description,
        )
        if not all(value.strip() for value in required):
            raise ValueError("Evidence identity, source, custodian, locator, and description are required.")
        if not _DIGEST.fullmatch(self.content_sha256):
            raise ValueError("Evidence content_sha256 must be a lowercase SHA-256 digest.")
        if not 0 <= self.size_bytes <= 5_000_000_000:
            raise ValueError("Evidence size must be between 0 and 5 GB.")
        if not _MEDIA_TYPE.fullmatch(self.media_type):
            raise ValueError("Evidence media_type must be a normalized MIME type.")
        if not self.locator.startswith(_LOCATOR_PREFIXES):
            raise ValueError("Evidence locator must be an opaque approved URI.")
        collected_at = ensure_aware(self.collected_at)
        try:
            retention = date.fromisoformat(self.retention_until)
        except ValueError as exc:
            raise ValueError("retention_until must use YYYY-MM-DD format.") from exc
        if retention < collected_at.date():
            raise ValueError("Evidence retention cannot end before collection.")
        if self.contains_personal_data and not self.sanitized:
            if self.classification not in {
                DataClassification.CONFIDENTIAL,
                DataClassification.RESTRICTED,
            }:
                raise ValueError("Unsanitized personal-data evidence must be confidential or restricted.")
        object.__setattr__(self, "collected_at", collected_at)

    def digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class EvidenceManifest:
    engagement_id: str
    artifacts: tuple[EvidenceArtifact, ...]
    custody_events: tuple[AuditEvent, ...]

    def __post_init__(self) -> None:
        if not self.engagement_id.strip():
            raise ValueError("Evidence manifest engagement_id is required.")
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "custody_events", tuple(self.custody_events))

    def digest(self) -> str:
        return sha256_digest(
            {
                "engagement_id": self.engagement_id,
                "artifacts": self.artifacts,
                "custody_events": self.custody_events,
            }
        )

    def verify(self) -> tuple[bool, tuple[str, ...]]:
        errors: list[str] = []
        ids = [artifact.evidence_id for artifact in self.artifacts]
        if len(ids) != len(set(ids)):
            errors.append("Evidence identifiers are not unique.")
        locators = [artifact.locator for artifact in self.artifacts]
        if len(locators) != len(set(locators)):
            errors.append("Evidence locators are not unique.")
        artifacts = {item.evidence_id: item for item in self.artifacts}
        chain = AuditChain(self.custody_events)
        chain_valid, chain_errors = chain.verify()
        if not chain_valid:
            errors.extend(chain_errors)
        first_action: dict[str, str] = {}
        disposed: set[str] = set()
        registrations: dict[str, int] = {evidence_id: 0 for evidence_id in ids}
        known_actions = {item.value for item in CustodyAction}
        for event in self.custody_events:
            if event.engagement_id != self.engagement_id:
                errors.append(f"Custody event {event.sequence} belongs to another engagement.")
            evidence_id = str(event.payload.get("evidence_id", ""))
            if evidence_id not in artifacts:
                errors.append(f"Custody event {event.sequence} references unknown evidence.")
                continue
            action = event.event_type.removeprefix("evidence.")
            if not event.event_type.startswith("evidence.") or action not in known_actions:
                errors.append(f"Custody event {event.sequence} has an unknown action.")
                continue
            first_action.setdefault(evidence_id, action)
            if action == CustodyAction.REGISTERED.value:
                registrations[evidence_id] += 1
                if event.payload.get("artifact_digest") != artifacts[evidence_id].digest():
                    errors.append(f"Evidence {evidence_id} registration digest mismatch.")
            if evidence_id in disposed and action != CustodyAction.DISPOSED.value:
                errors.append(f"Evidence {evidence_id} has activity after disposal.")
            if action == CustodyAction.DISPOSED.value:
                disposed.add(evidence_id)
            if event.timestamp < artifacts[evidence_id].collected_at:
                errors.append(f"Evidence {evidence_id} has custody activity before collection.")
        for evidence_id in ids:
            if first_action.get(evidence_id) != CustodyAction.REGISTERED.value:
                errors.append(f"Evidence {evidence_id} does not begin with registration.")
            if registrations[evidence_id] != 1:
                errors.append(f"Evidence {evidence_id} must have exactly one registration event.")
        return not errors, tuple(errors)

    def as_dict(self) -> dict[str, Any]:
        valid, errors = self.verify()
        return {
            "schema_version": "finredops.evidence-manifest.v1",
            "engagement_id": self.engagement_id,
            "artifacts": to_primitive(self.artifacts),
            "custody_events": [to_primitive(item) for item in self.custody_events],
            "manifest_digest": self.digest(),
            "valid": valid,
            "verification_errors": list(errors),
            "raw_evidence_embedded": False,
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "EvidenceManifest":
        expected = {
            "schema_version",
            "engagement_id",
            "artifacts",
            "custody_events",
            "manifest_digest",
            "valid",
            "verification_errors",
            "raw_evidence_embedded",
        }
        if set(document) != expected:
            raise ValueError("Evidence manifest fields do not match the strict schema.")
        if document.get("schema_version") != "finredops.evidence-manifest.v1":
            raise ValueError("Unsupported evidence manifest schema version.")
        if document.get("raw_evidence_embedded") is not False:
            raise ValueError("Evidence manifest must preserve the metadata-only boundary.")
        try:
            if not isinstance(document["artifacts"], list) or not isinstance(
                document["custody_events"], list
            ):
                raise ValueError("Evidence artifacts and custody_events must be arrays.")
            if not isinstance(document["engagement_id"], str):
                raise ValueError("Evidence engagement_id must be a string.")
            artifacts = tuple(_artifact_from_dict(item) for item in document["artifacts"])
            events_document = "\n".join(
                json.dumps(item, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
                for item in document["custody_events"]
            )
            manifest = cls(
                engagement_id=str(document["engagement_id"]),
                artifacts=artifacts,
                custody_events=AuditChain.from_jsonl(events_document).events,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid evidence manifest: {exc}") from exc
        supplied = document.get("manifest_digest")
        if supplied != manifest.digest():
            raise ValueError("Evidence manifest digest does not match its content.")
        valid, errors = manifest.verify()
        if not isinstance(document.get("valid"), bool) or document["valid"] != valid:
            raise ValueError("Evidence manifest validity does not match its content.")
        supplied_errors = document.get("verification_errors")
        if not isinstance(supplied_errors, list) or any(
            not isinstance(item, str) for item in supplied_errors
        ) or supplied_errors != list(errors):
            raise ValueError("Evidence manifest verification errors do not match its content.")
        return manifest


class EvidenceRegistry:
    """Append-only metadata registry backed by the generic audit chain."""

    def __init__(self, engagement_id: str) -> None:
        if not engagement_id.strip():
            raise ValueError("engagement_id is required.")
        self.engagement_id = engagement_id
        self._artifacts: dict[str, EvidenceArtifact] = {}
        self._custody = AuditChain()
        self._disposed: set[str] = set()

    def register(self, artifact: EvidenceArtifact, *, actor_id: str, now: datetime) -> None:
        if artifact.evidence_id in self._artifacts:
            raise ValueError("Evidence identifier already exists.")
        now = ensure_aware(now)
        if now < artifact.collected_at:
            raise ValueError("Evidence cannot be registered before collection.")
        self._artifacts[artifact.evidence_id] = artifact
        self._append(
            artifact.evidence_id,
            CustodyAction.REGISTERED,
            actor_id=actor_id,
            now=now,
            purpose="Register immutable evidence metadata.",
            extra={"artifact_digest": artifact.digest(), "content_sha256": artifact.content_sha256},
        )

    def record(
        self,
        evidence_id: str,
        action: CustodyAction,
        *,
        actor_id: str,
        now: datetime,
        purpose: str,
        recipient: str = "",
    ) -> None:
        if evidence_id not in self._artifacts:
            raise ValueError("Evidence does not exist.")
        if action == CustodyAction.REGISTERED:
            raise ValueError("Use register() for the first custody event.")
        if evidence_id in self._disposed:
            raise ValueError("Disposed evidence cannot receive further custody events.")
        if action == CustodyAction.TRANSFERRED and not recipient.strip():
            raise ValueError("Evidence transfer requires a named recipient.")
        self._append(
            evidence_id,
            action,
            actor_id=actor_id,
            now=ensure_aware(now),
            purpose=purpose,
            extra={"recipient": recipient} if recipient else {},
        )
        if action == CustodyAction.DISPOSED:
            self._disposed.add(evidence_id)

    def manifest(self) -> EvidenceManifest:
        return EvidenceManifest(
            engagement_id=self.engagement_id,
            artifacts=tuple(self._artifacts[key] for key in sorted(self._artifacts)),
            custody_events=self._custody.events,
        )

    def _append(
        self,
        evidence_id: str,
        action: CustodyAction,
        *,
        actor_id: str,
        now: datetime,
        purpose: str,
        extra: Mapping[str, Any],
    ) -> None:
        if not actor_id.strip() or not purpose.strip():
            raise ValueError("Custody actor and purpose are required.")
        self._custody.append(
            timestamp=now,
            actor_id=actor_id,
            event_type=f"evidence.{action.value}",
            engagement_id=self.engagement_id,
            payload={"evidence_id": evidence_id, "purpose": purpose, **dict(extra)},
        )


def _artifact_from_dict(document: Mapping[str, Any]) -> EvidenceArtifact:
    expected = {
        "evidence_id",
        "title",
        "evidence_type",
        "classification",
        "content_sha256",
        "size_bytes",
        "media_type",
        "source_system",
        "collected_at",
        "collected_by",
        "locator",
        "description",
        "retention_until",
        "contains_personal_data",
        "sanitized",
    }
    if not isinstance(document, Mapping) or set(document) != expected:
        raise ValueError("Evidence artifact fields do not match the strict schema.")
    if not isinstance(document["size_bytes"], int) or isinstance(document["size_bytes"], bool):
        raise ValueError("Evidence size_bytes must be an integer.")
    if not isinstance(document["contains_personal_data"], bool) or not isinstance(
        document["sanitized"], bool
    ):
        raise ValueError("Evidence personal-data and sanitization flags must be booleans.")
    return EvidenceArtifact(
        evidence_id=str(document["evidence_id"]),
        title=str(document["title"]),
        evidence_type=EvidenceType(document["evidence_type"]),
        classification=DataClassification(document["classification"]),
        content_sha256=str(document["content_sha256"]),
        size_bytes=document["size_bytes"],
        media_type=str(document["media_type"]),
        source_system=str(document["source_system"]),
        collected_at=parse_datetime(str(document["collected_at"])),
        collected_by=str(document["collected_by"]),
        locator=str(document["locator"]),
        description=str(document["description"]),
        retention_until=str(document["retention_until"]),
        contains_personal_data=document["contains_personal_data"],
        sanitized=document["sanitized"],
    )
