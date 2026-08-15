"""Digest-bound OWASP ASVS 5.0.0 reference coverage."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from .models import StringEnum, sha256_digest, to_primitive

ASVS_VERSION = "5.0.0"
MAXIMUM_REQUIREMENTS = 10_000
MAXIMUM_EVIDENCE_REFS = 128
MAXIMUM_RATIONALE = 4_000
_ASVS_REF = re.compile(r"^v5\.0\.0-[1-9][0-9]*\.[1-9][0-9]*\.[1-9][0-9]*$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class AsvsCoverageError(ValueError):
    """Raised when ASVS coverage evidence fails closed."""


class AsvsCoverageStatus(StringEnum):
    COVERED = "covered"
    PARTIAL = "partial"
    NOT_COVERED = "not_covered"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class AsvsRequirementCatalog:
    source_version: str
    source_sha256: str
    source_ref: str
    requirement_refs: tuple[str, ...]
    standard_name: str = "OWASP ASVS"
    requirement_text_embedded: bool = False

    def __post_init__(self) -> None:
        if self.source_version != ASVS_VERSION:
            raise ValueError("ASVS catalog must remain pinned to version 5.0.0.")
        if not _DIGEST.fullmatch(self.source_sha256):
            raise ValueError("ASVS source digest must be SHA-256.")
        _text(self.source_ref, "source_ref", 2048, 1)
        if not 1 <= len(self.requirement_refs) <= MAXIMUM_REQUIREMENTS:
            raise ValueError("ASVS catalog must contain a bounded requirement set.")
        if any(not _ASVS_REF.fullmatch(item) for item in self.requirement_refs):
            raise ValueError("ASVS requirement refs must use v5.0.0-x.y.z.")
        if len(set(self.requirement_refs)) != len(self.requirement_refs):
            raise ValueError("ASVS catalog requirement refs must be unique.")
        if self.standard_name != "OWASP ASVS" or self.requirement_text_embedded is not False:
            raise ValueError("ASVS catalog must remain reference-only.")
        object.__setattr__(self, "requirement_refs", tuple(sorted(self.requirement_refs, key=_ref_key)))

    def digest(self) -> str:
        return sha256_digest(self)

    def as_dict(self) -> dict[str, Any]:
        return {"schema_version": "finredops.asvs-requirement-catalog.v1", **to_primitive(self), "catalog_digest": self.digest()}


@dataclass(frozen=True, slots=True)
class AsvsCoverageEntry:
    requirement_ref: str
    status: AsvsCoverageStatus
    evidence_refs: tuple[str, ...]
    rationale: str
    human_assessed: bool = True

    def __post_init__(self) -> None:
        if not _ASVS_REF.fullmatch(self.requirement_ref):
            raise ValueError("ASVS coverage entry requires a versioned 5.0.0 requirement ref.")
        if len(self.evidence_refs) > MAXIMUM_EVIDENCE_REFS:
            raise ValueError("ASVS coverage entry contains too many evidence refs.")
        for ref in self.evidence_refs:
            _evidence_ref(ref)
        if self.status in {AsvsCoverageStatus.COVERED, AsvsCoverageStatus.PARTIAL} and not self.evidence_refs:
            raise ValueError("Covered or partial ASVS requirements require evidence refs.")
        if self.status in {AsvsCoverageStatus.NOT_COVERED, AsvsCoverageStatus.NOT_APPLICABLE} and self.evidence_refs:
            raise ValueError("Uncovered or not-applicable ASVS requirements cannot claim evidence.")
        _text(self.rationale, "rationale", MAXIMUM_RATIONALE, 12)
        if self.human_assessed is not True:
            raise ValueError("ASVS coverage status must be explicitly human assessed.")
        object.__setattr__(self, "evidence_refs", tuple(sorted(set(self.evidence_refs))))


@dataclass(frozen=True, slots=True)
class AsvsCoverageAssessment:
    engagement_id: str
    catalog_digest: str
    entries: tuple[AsvsCoverageEntry, ...]
    standard_version: str = ASVS_VERSION
    human_assessment_required: bool = True
    compliance_certified: bool = False
    regulatory_applicability_inferred: bool = False

    def __post_init__(self) -> None:
        _text(self.engagement_id, "engagement_id", 200, 1)
        if not _DIGEST.fullmatch(self.catalog_digest):
            raise ValueError("ASVS coverage catalog digest must be SHA-256.")
        if self.standard_version != ASVS_VERSION:
            raise ValueError("ASVS coverage must remain pinned to version 5.0.0.")
        if not 1 <= len(self.entries) <= MAXIMUM_REQUIREMENTS:
            raise ValueError("ASVS coverage must contain a bounded entry set.")
        refs = [item.requirement_ref for item in self.entries]
        if len(refs) != len(set(refs)):
            raise ValueError("ASVS coverage requirement refs must be unique.")
        if self.human_assessment_required is not True:
            raise ValueError("ASVS coverage must require human assessment.")
        if self.compliance_certified is not False or self.regulatory_applicability_inferred is not False:
            raise ValueError("ASVS coverage cannot certify compliance or infer regulatory applicability.")
        object.__setattr__(self, "entries", tuple(sorted(self.entries, key=lambda item: _ref_key(item.requirement_ref))))

    def digest(self) -> str:
        return sha256_digest(self)

    def evidence_ref(self) -> str:
        return f"evidence://asvs/{self.catalog_digest}/{self.digest()}"

    def as_dict(self) -> dict[str, Any]:
        counts = {status.value: 0 for status in AsvsCoverageStatus}
        for item in self.entries:
            counts[item.status.value] += 1
        return {
            "schema_version": "finredops.asvs-coverage.v1",
            **to_primitive(self),
            "status_counts": counts,
            "coverage_digest": self.digest(),
            "evidence_ref": self.evidence_ref(),
        }


def build_asvs_catalog(
    requirement_refs: Iterable[str],
    *,
    source_sha256: str,
    source_ref: str,
    source_version: str = ASVS_VERSION,
) -> AsvsRequirementCatalog:
    return AsvsRequirementCatalog(
        source_version=source_version,
        source_sha256=source_sha256,
        source_ref=source_ref,
        requirement_refs=tuple(requirement_refs),
    )


def assess_asvs_coverage(
    *,
    engagement_id: str,
    catalog: AsvsRequirementCatalog,
    entries: Iterable[AsvsCoverageEntry],
) -> AsvsCoverageAssessment:
    entry_tuple = tuple(entries)
    allowed = set(catalog.requirement_refs)
    supplied = {item.requirement_ref for item in entry_tuple}
    if supplied != allowed:
        missing = sorted(allowed - supplied, key=_ref_key)
        unknown = sorted(supplied - allowed, key=_ref_key)
        raise AsvsCoverageError(f"ASVS coverage must exactly match its catalog; missing={missing[:10]}, unknown={unknown[:10]}.")
    return AsvsCoverageAssessment(engagement_id=engagement_id, catalog_digest=catalog.digest(), entries=entry_tuple)


def _ref_key(value: str) -> tuple[int, int, int]:
    if not _ASVS_REF.fullmatch(value):
        raise AsvsCoverageError("Invalid ASVS requirement ref.")
    chapter, section, requirement = value.split("-", 1)[1].split(".")
    return int(chapter), int(section), int(requirement)


def _evidence_ref(value: str) -> None:
    _text(value, "evidence_ref", 2048, 1)
    if not value.startswith(("evidence://", "attachment://", "qualification-evidence://")):
        raise ValueError("ASVS evidence refs must use an approved opaque evidence scheme.")


def _text(value: str, name: str, maximum: int, minimum: int) -> None:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum or _CONTROL.search(value):
        raise ValueError(f"{name} violates the bounded text contract.")
