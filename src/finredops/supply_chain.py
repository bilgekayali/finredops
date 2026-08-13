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


def import_cyclonedx_file(path: Path, *, maximum_bytes: int = MAXIMUM_SOURCE_BYTES) -> CycloneDxIntakeBatch:
    if not 1 <= maximum_bytes <= MAXIMUM_SOURCE_BYTES:
        raise ValueError("maximum_bytes must stay within the CycloneDX intake limit.")
    try:
        if not path.is_file():
            raise SupplyChainIntakeError("CycloneDX input must be a regular file.")
        size = path.stat().st_size
        if size > maximum_bytes:
            raise SupplyChainIntakeError("CycloneDX input exceeds the bounded intake size.")
        raw = path.read_bytes()
        if len(raw) != size:
            raise SupplyChainIntakeError("CycloneDX input changed while it was being read.")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except SupplyChainIntakeError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SupplyChainIntakeError(f"Could not read bounded UTF-8 CycloneDX JSON: {exc}") from exc
    return import_cyclonedx_document(
        document,
        source_content_sha256=hashlib.sha256(raw).hexdigest(),
        source_size_bytes=len(raw),
    )


def import_cyclonedx_document(
    document: Any,
    *,
    source_content_sha256: str | None = None,
    source_size_bytes: int | None = None,
) -> CycloneDxIntakeBatch:
    if not isinstance(document, Mapping):
        raise SupplyChainIntakeError("CycloneDX root must be an object.")
    _validate_json_shape(document)
    if document.get("bomFormat") != "CycloneDX":
        raise SupplyChainIntakeError("bomFormat must be exactly CycloneDX.")
    if document.get("specVersion") != CYCLONEDX_SPEC_VERSION:
        raise SupplyChainIntakeError("Only CycloneDX specification version 1.7 is accepted.")
    if source_content_sha256 is None or source_size_bytes is None:
        encoded = canonical_json(document).encode("utf-8")
        source_content_sha256 = hashlib.sha256(encoded).hexdigest()
        source_size_bytes = len(encoded)
    if not _DIGEST.fullmatch(source_content_sha256):
        raise SupplyChainIntakeError("CycloneDX source digest is invalid.")
    if isinstance(source_size_bytes, bool) or not isinstance(source_size_bytes, int) or not 0 <= source_size_bytes <= MAXIMUM_SOURCE_BYTES:
        raise SupplyChainIntakeError("CycloneDX source size is outside the intake limit.")

    bom_version = document.get("version", 1)
    if isinstance(bom_version, bool) or not isinstance(bom_version, int) or bom_version < 1:
        raise SupplyChainIntakeError("CycloneDX version must be a positive integer.")
    serial = document.get("serialNumber", "")
    if not isinstance(serial, str):
        raise SupplyChainIntakeError("CycloneDX serialNumber must be a string.")
    components_raw = document.get("components", [])
    records_raw = document.get("vulnerabilities", [])
    if not isinstance(components_raw, list) or len(components_raw) > MAXIMUM_COMPONENTS:
        raise SupplyChainIntakeError("CycloneDX components must be a bounded array.")
    if not isinstance(records_raw, list) or len(records_raw) > MAXIMUM_RECORDS:
        raise SupplyChainIntakeError("CycloneDX vulnerability records must be a bounded array.")

    components = tuple(_component(item, index) for index, item in enumerate(components_raw))
    refs = {item.bom_ref for item in components}
    if len(refs) != len(components):
        raise SupplyChainIntakeError("CycloneDX component bom-ref values must be unique.")
    findings = tuple(
        _normalize_record(item, index, source_content_sha256, refs)
        for index, item in enumerate(records_raw)
    )
    return CycloneDxIntakeBatch(
        batch_id=_batch_id(source_content_sha256),
        source_content_sha256=source_content_sha256,
        source_size_bytes=source_size_bytes,
        bom_serial_number=serial.strip(),
        bom_version=bom_version,
        components=components,
        findings=findings,
    )


def _component(value: Any, index: int) -> SupplyChainComponent:
    if not isinstance(value, Mapping):
        raise SupplyChainIntakeError(f"components[{index}] must be an object.")
    return SupplyChainComponent(
        bom_ref=_required_text(value, "bom-ref", f"components[{index}]", 1024),
        component_type=_required_text(value, "type", f"components[{index}]", 80),
        name=_required_text(value, "name", f"components[{index}]", 1024),
        version=_optional_text(value.get("version"), f"components[{index}].version", 1024),
        purl=_optional_text(value.get("purl"), f"components[{index}].purl", 2048),
        cpe=_optional_text(value.get("cpe"), f"components[{index}].cpe", 2048),
    )


def _normalize_record(value: Any, index: int, source_digest: str, refs: set[str]) -> SupplyChainFinding:
    if not isinstance(value, Mapping):
        raise SupplyChainIntakeError(f"vulnerabilities[{index}] must be an object.")
    source_id = _required_text(value, "id", f"vulnerabilities[{index}]", 512)
    source = value.get("source", {}) or {}
    if not isinstance(source, Mapping):
        raise SupplyChainIntakeError("CycloneDX source metadata must be an object.")
    source_name = _optional_text(source.get("name"), f"vulnerabilities[{index}].source.name", 256)
    affects = value.get("affects", [])
    if not isinstance(affects, list) or not 1 <= len(affects) <= MAXIMUM_AFFECTED_REFS:
        raise SupplyChainIntakeError("CycloneDX records require a bounded affects array.")
    affected: list[str] = []
    for affect_index, affect in enumerate(affects):
        if not isinstance(affect, Mapping):
            raise SupplyChainIntakeError("CycloneDX affects entries must be objects.")
        ref = _required_text(affect, "ref", f"vulnerabilities[{index}].affects[{affect_index}]", 1024)
        if ref not in refs:
            raise SupplyChainIntakeError("CycloneDX record affects an unknown component bom-ref.")
        affected.append(ref)
    if len(set(affected)) != len(affected):
        raise SupplyChainIntakeError("CycloneDX record contains duplicate affected refs.")

    ratings = value.get("ratings", [])
    if not isinstance(ratings, list) or len(ratings) > MAXIMUM_RATINGS:
        raise SupplyChainIntakeError("CycloneDX ratings must be a bounded array.")
    validated: list[ValidatedCvss40] = []
    other_methods: list[str] = []
    for rating_index, rating in enumerate(ratings):
        if not isinstance(rating, Mapping):
            raise SupplyChainIntakeError("CycloneDX rating entries must be objects.")
        method = _optional_text(rating.get("method"), f"vulnerabilities[{index}].ratings[{rating_index}].method", 80)
        if method != "CVSSv4":
            if method:
                other_methods.append(method)
            continue
        vector = rating.get("vector")
        if not isinstance(vector, str) or not vector:
            raise SupplyChainIntakeError("CycloneDX CVSSv4 rating requires a vector.")
        try:
            validated.append(validate_cvss40(vector, declared_score=rating.get("score"), declared_severity=rating.get("severity")))
        except Cvss40ValidationError as exc:
            raise SupplyChainIntakeError(f"CycloneDX CVSSv4 rating failed validation: {exc}") from exc

    payload = {
        "source_id": source_id,
        "source_name": source_name,
        "affected_bom_refs": tuple(sorted(affected)),
        "cvss40_ratings": tuple(validated),
        "other_rating_methods": tuple(sorted(set(other_methods))),
    }
    digest = sha256_digest(payload)
    return SupplyChainFinding(
        record_id="FRX-CDXV-" + digest[:24].upper(),
        source_id=source_id,
        source_name=source_name,
        affected_bom_refs=tuple(affected),
        cvss40_ratings=tuple(validated),
        other_rating_methods=tuple(other_methods),
        evidence_ref=f"evidence://cyclonedx/{source_digest}/{digest}",
    )


def _batch_id(digest: str) -> str:
    return "FRX-CDX-" + digest[:24].upper()


def _required_text(document: Mapping[str, Any], key: str, path: str, limit: int) -> str:
    if key not in document:
        raise SupplyChainIntakeError(f"{path}.{key} is required.")
    return _optional_text(document[key], f"{path}.{key}", limit, required=True)


def _optional_text(value: Any, path: str, limit: int, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise SupplyChainIntakeError(f"{path} must be a string.")
    value = value.strip()
    if required and not value:
        raise SupplyChainIntakeError(f"{path} must not be empty.")
    _safe_text(value, path, limit, required=required)
    return value


def _safe_text(value: str, name: str, limit: int, *, required: bool) -> None:
    if not isinstance(value, str) or (required and not value) or len(value) > limit or _CONTROL.search(value):
        raise ValueError(f"{name} violates the safe text boundary.")


def _validate_json_shape(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAXIMUM_JSON_NODES or depth > MAXIMUM_JSON_DEPTH:
            raise SupplyChainIntakeError("CycloneDX JSON exceeds bounded structural complexity.")
        if isinstance(current, Mapping):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif current is not None and not isinstance(current, (str, int, float, bool)):
            raise SupplyChainIntakeError("CycloneDX JSON contains an unsupported value type.")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SupplyChainIntakeError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise SupplyChainIntakeError(f"Non-finite JSON constant is not allowed: {value}")
