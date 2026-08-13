"""Version-pinned supply-chain assurance intake contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .cvss40 import Cvss40ValidationError, ValidatedCvss40, validate_cvss40
from .models import canonical_json, sha256_digest, to_primitive

CYCLONEDX_SPEC_VERSION = "1.7"
MAXIMUM_SOURCE_BYTES = 20_000_000
MAXIMUM_JSON_DEPTH = 64
MAXIMUM_JSON_NODES = 500_000
MAXIMUM_COMPONENTS = 50_000
MAXIMUM_RECORDS = 20_000
MAXIMUM_AFFECTED_REFS = 10_000
MAXIMUM_RATINGS = 32
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_BATCH_ID = re.compile(r"^FRX-CDX-[A-F0-9]{24}$")
_RECORD_ID = re.compile(r"^FRX-CDXV-[A-F0-9]{24}$")


class SupplyChainIntakeError(ValueError):
    """Raised when a supply-chain assurance document fails validation."""


@dataclass(frozen=True, slots=True)
class SupplyChainComponent:
    bom_ref: str
    component_type: str
    name: str
    version: str = ""
    purl: str = ""
    cpe: str = ""

    def __post_init__(self) -> None:
        for field_name, value, limit, required in (
            ("bom_ref", self.bom_ref, 1024, True),
            ("component_type", self.component_type, 80, True),
            ("name", self.name, 1024, True),
            ("version", self.version, 1024, False),
            ("purl", self.purl, 2048, False),
            ("cpe", self.cpe, 2048, False),
        ):
            _safe_text(value, field_name, limit, required=required)


@dataclass(frozen=True, slots=True)
class SupplyChainFinding:
    record_id: str
    source_id: str
    source_name: str
    affected_bom_refs: tuple[str, ...]
    cvss40_ratings: tuple[ValidatedCvss40, ...]
    other_rating_methods: tuple[str, ...]
    evidence_ref: str
    human_review_required: bool = True
    regulatory_applicability_inferred: bool = False

    def __post_init__(self) -> None:
        if not _RECORD_ID.fullmatch(self.record_id):
            raise ValueError("Supply-chain record id is invalid.")
        _safe_text(self.source_id, "source_id", 512, required=True)
        _safe_text(self.source_name, "source_name", 256, required=False)
        if not self.affected_bom_refs or len(self.affected_bom_refs) > MAXIMUM_AFFECTED_REFS:
            raise ValueError("Supply-chain record requires bounded affected component refs.")
        if len(set(self.affected_bom_refs)) != len(self.affected_bom_refs):
            raise ValueError("Affected component refs must be unique.")
        if not self.evidence_ref.startswith("evidence://cyclonedx/"):
            raise ValueError("Supply-chain evidence ref is invalid.")
        if self.human_review_required is not True or self.regulatory_applicability_inferred is not False:
            raise ValueError("Supply-chain evidence must remain human-reviewed and non-regulatory.")
        object.__setattr__(self, "affected_bom_refs", tuple(sorted(self.affected_bom_refs)))
        object.__setattr__(self, "other_rating_methods", tuple(sorted(set(self.other_rating_methods))))


@dataclass(frozen=True, slots=True)
class CycloneDxIntakeBatch:
    batch_id: str
    source_content_sha256: str
    source_size_bytes: int
    bom_serial_number: str
    bom_version: int
    components: tuple[SupplyChainComponent, ...]
    findings: tuple[SupplyChainFinding, ...]
    source_format: str = "cyclonedx-json"
    source_version: str = CYCLONEDX_SPEC_VERSION
    human_review_required: bool = True
    raw_source_embedded: bool = False
    regulatory_applicability_inferred: bool = False

    def __post_init__(self) -> None:
        if not _BATCH_ID.fullmatch(self.batch_id):
            raise ValueError("CycloneDX batch id is invalid.")
        if not _DIGEST.fullmatch(self.source_content_sha256):
            raise ValueError("CycloneDX source digest must be SHA-256.")
        if self.batch_id != _batch_id(self.source_content_sha256):
            raise ValueError("CycloneDX batch id does not match source digest.")
        if self.source_format != "cyclonedx-json" or self.source_version != CYCLONEDX_SPEC_VERSION:
            raise ValueError("Supply-chain intake must remain pinned to CycloneDX JSON 1.7.")
        if isinstance(self.source_size_bytes, bool) or not isinstance(self.source_size_bytes, int):
            raise ValueError("CycloneDX source size must be an integer.")
        if not 0 <= self.source_size_bytes <= MAXIMUM_SOURCE_BYTES:
            raise ValueError("CycloneDX source size is outside the intake boundary.")
        if isinstance(self.bom_version, bool) or not isinstance(self.bom_version, int) or self.bom_version < 1:
            raise ValueError("CycloneDX BOM version must be positive.")
        _safe_text(self.bom_serial_number, "bom_serial_number", 256, required=False)
        if len(self.components) > MAXIMUM_COMPONENTS or len(self.findings) > MAXIMUM_RECORDS:
            raise ValueError("Normalized supply-chain object count exceeds the boundary.")
        refs = {item.bom_ref for item in self.components}
        if len(refs) != len(self.components):
            raise ValueError("CycloneDX component bom-ref values must be unique.")
        if any(not set(item.affected_bom_refs).issubset(refs) for item in self.findings):
            raise ValueError("Supply-chain finding references an unknown component.")
        if self.human_review_required is not True or self.raw_source_embedded is not False:
            raise ValueError("CycloneDX intake must exclude raw source and require human review.")
        if self.regulatory_applicability_inferred is not False:
            raise ValueError("CycloneDX intake cannot infer regulatory applicability.")
        object.__setattr__(self, "components", tuple(sorted(self.components, key=lambda item: item.bom_ref)))
        object.__setattr__(self, "findings", tuple(sorted(self.findings, key=lambda item: item.record_id)))

    def digest(self) -> str:
        return sha256_digest(self)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.cyclonedx-intake.v1",
            **to_primitive(self),
            "batch_digest": self.digest(),
        }
