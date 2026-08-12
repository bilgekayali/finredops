"""Safe, deterministic intake of machine-generated security findings.

The intake boundary treats scanner output as untrusted evidence.  It normalizes
SARIF 2.1.0 results into review candidates, but never promotes them directly to
issued report findings or regulatory conclusions.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
from urllib.parse import quote, unquote, urlsplit

from .evidence import EvidenceGuard
from .models import StringEnum, canonical_json, sha256_digest, to_primitive


SARIF_VERSION = "2.1.0"
MAXIMUM_SARIF_BYTES = 10_000_000
MAXIMUM_INTAKE_BYTES = 40_000_000
MAXIMUM_RUNS = 50
MAXIMUM_RESULTS = 20_000
MAXIMUM_RULES_PER_RUN = 20_000
MAXIMUM_TAGS_PER_FINDING = 64
MAXIMUM_JSON_DEPTH = 64
MAXIMUM_JSON_NODES = 250_000
MAXIMUM_INTAKE_JSON_NODES = 2_000_000

_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_FINDING_ID = re.compile(r"^FRX-SARIF-[A-F0-9]{24}$")
_BATCH_ID = re.compile(r"^FRX-INTAKE-[A-F0-9]{24}$")
_ARTIFACT_DIGEST = re.compile(r"^artifact-digest://[a-f0-9]{64}$")
_EVIDENCE_REF = re.compile(r"^evidence://sarif/[a-f0-9]{64}/[a-f0-9]{64}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|client[_-]?secret|password|passwd|token|secret)\b"
    r"\s*[:=]\s*(?:\"[^\"\r\n]{4,}\"|'[^'\r\n]{4,}'|[^\s,;<>]{4,})"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"(?i)-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
    r"(?:-----END(?: [A-Z0-9]+)? PRIVATE KEY-----|$)"
)
_TOKEN_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\b(?:sk|pk)[-_][A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)


class SarifIntakeError(ValueError):
    """Raised when untrusted SARIF or an intake document fails closed."""


class MachineSeverity(StringEnum):
    """Non-final severity suggested by a source tool."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class MachineConfidence(StringEnum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


_SEVERITY_RANK = {
    MachineSeverity.INFORMATIONAL: 0,
    MachineSeverity.LOW: 1,
    MachineSeverity.MEDIUM: 2,
    MachineSeverity.HIGH: 3,
}


@dataclass(frozen=True, slots=True)
class CanonicalFinding:
    """A scanner observation waiting for qualified human review."""

    finding_id: str
    fingerprint: str
    source_tool: str
    source_tool_version: str
    rule_id: str
    title: str
    machine_severity: MachineSeverity
    machine_confidence: MachineConfidence
    message: str
    artifact_ref: str
    start_line: int | None
    start_column: int | None
    evidence_ref: str
    tags: tuple[str, ...]
    occurrence_count: int
    redaction_kinds: tuple[str, ...]
    review_disposition: str = "pending_review"
    human_validation_required: bool = True

    def __post_init__(self) -> None:
        required = (
            self.finding_id,
            self.fingerprint,
            self.source_tool,
            self.rule_id,
            self.title,
            self.message,
            self.artifact_ref,
            self.evidence_ref,
        )
        if not all(isinstance(value, str) and value.strip() for value in required):
            raise ValueError(
                "Canonical findings require source, identity, narrative, and evidence."
            )
        if not _FINDING_ID.fullmatch(self.finding_id):
            raise ValueError("finding_id must use the derived FRX-SARIF identifier format.")
        if not _DIGEST.fullmatch(self.fingerprint):
            raise ValueError("fingerprint must be a lowercase SHA-256 digest.")
        if self.finding_id != _finding_id(self.fingerprint):
            raise ValueError("finding_id does not match the canonical fingerprint.")
        if self.artifact_ref.startswith("repo://"):
            normalized, unsafe = _safe_artifact_ref(unquote(self.artifact_ref[7:]))
            if unsafe or normalized != self.artifact_ref:
                raise ValueError("artifact_ref contains an unsafe repository path.")
        elif not _ARTIFACT_DIGEST.fullmatch(self.artifact_ref):
            raise ValueError("artifact_ref must be repository-relative or opaque.")
        if not _EVIDENCE_REF.fullmatch(self.evidence_ref) or not self.evidence_ref.endswith(
            "/" + self.fingerprint
        ):
            raise ValueError("evidence_ref must be an opaque SARIF evidence locator.")
        text_limits = {
            "source_tool": 160,
            "source_tool_version": 80,
            "rule_id": 200,
            "title": 240,
            "message": 1_000,
        }
        for name, limit in text_limits.items():
            value = getattr(self, name)
            if len(value) > limit or _CONTROL.search(value):
                raise ValueError(f"{name} exceeds its safe text boundary.")
        _validate_optional_position(self.start_line, "start_line")
        _validate_optional_position(self.start_column, "start_column")
        if (
            isinstance(self.occurrence_count, bool)
            or not isinstance(self.occurrence_count, int)
            or not 1 <= self.occurrence_count <= MAXIMUM_RESULTS
        ):
            raise ValueError("occurrence_count is outside the bounded intake limit.")
        if (
            self.review_disposition != "pending_review"
            or self.human_validation_required is not True
        ):
            raise ValueError("Imported findings must remain pending qualified human review.")
        if len(self.tags) > MAXIMUM_TAGS_PER_FINDING:
            raise ValueError("A canonical finding contains too many tags.")
        if any(
            not isinstance(item, str)
            or not item.strip()
            or len(item) > 120
            or _CONTROL.search(item)
            for item in self.tags
        ):
            raise ValueError("Canonical finding tags contain invalid text.")
        allowed_redactions = {
            "secret_field",
            "payment_card",
            "iban",
            "email",
            "bearer_token",
        }
        if any(
            not isinstance(item, str) or item not in allowed_redactions
            for item in self.redaction_kinds
        ):
            raise ValueError("Canonical finding redaction_kinds are invalid.")
        object.__setattr__(self, "tags", tuple(sorted(set(self.tags))))
        object.__setattr__(
            self,
            "redaction_kinds",
            tuple(sorted(set(self.redaction_kinds))),
        )


@dataclass(frozen=True, slots=True)
class EvidenceIntakeBatch:
    """Metadata-only batch produced from one immutable SARIF document."""

    batch_id: str
    source_format: str
    source_version: str
    source_content_sha256: str
    source_size_bytes: int
    source_evidence_ref: str
    run_count: int
    result_count: int
    duplicate_result_count: int
    unsafe_location_count: int
    redacted_result_count: int
    tools: tuple[str, ...]
    findings: tuple[CanonicalFinding, ...]
    human_review_required: bool = True
    raw_source_embedded: bool = False

    def __post_init__(self) -> None:
        if not _BATCH_ID.fullmatch(self.batch_id):
            raise ValueError("batch_id must use the derived FRX-INTAKE identifier format.")
        if self.source_format != "sarif" or self.source_version != SARIF_VERSION:
            raise ValueError("Only SARIF 2.1.0 intake batches are supported.")
        if not _DIGEST.fullmatch(self.source_content_sha256):
            raise ValueError("source_content_sha256 must be a lowercase SHA-256 digest.")
        if self.batch_id != _batch_id(self.source_content_sha256):
            raise ValueError("batch_id does not match the source digest.")
        expected_evidence = f"evidence://sarif/{self.source_content_sha256}"
        if self.source_evidence_ref != expected_evidence:
            raise ValueError("source_evidence_ref does not match the source digest.")
        count_fields = {
            "source_size_bytes": (0, MAXIMUM_SARIF_BYTES),
            "run_count": (1, MAXIMUM_RUNS),
            "result_count": (0, MAXIMUM_RESULTS),
            "duplicate_result_count": (0, MAXIMUM_RESULTS),
            "unsafe_location_count": (0, MAXIMUM_RESULTS),
            "redacted_result_count": (0, MAXIMUM_RESULTS),
        }
        for name, (minimum, maximum) in count_fields.items():
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise ValueError(f"{name} is outside the bounded intake limit.")
        if self.duplicate_result_count != self.result_count - len(self.findings):
            raise ValueError("duplicate_result_count does not match the normalized findings.")
        for name in (
            "duplicate_result_count",
            "unsafe_location_count",
            "redacted_result_count",
        ):
            if getattr(self, name) > self.result_count:
                raise ValueError(f"{name} is outside the result count.")
        if not self.tools or any(
            not isinstance(item, str) or not item.strip() for item in self.tools
        ):
            raise ValueError("An intake batch must identify at least one source tool.")
        if len(self.tools) > MAXIMUM_RUNS or any(
            len(item) > 160 or _CONTROL.search(item) for item in self.tools
        ):
            raise ValueError("Intake source tools exceed the safe metadata boundary.")
        if len({item.fingerprint for item in self.findings}) != len(self.findings):
            raise ValueError("Canonical finding fingerprints must be unique.")
        if len({item.finding_id for item in self.findings}) != len(self.findings):
            raise ValueError("Derived canonical finding identifiers must be unique.")
        if sum(item.occurrence_count for item in self.findings) != self.result_count:
            raise ValueError("Finding occurrence counts do not match result_count.")
        if not {item.source_tool for item in self.findings}.issubset(set(self.tools)):
            raise ValueError("A finding references an undeclared source tool.")
        expected_prefix = f"evidence://sarif/{self.source_content_sha256}/"
        if any(not item.evidence_ref.startswith(expected_prefix) for item in self.findings):
            raise ValueError("A finding evidence reference belongs to another source document.")
        if self.human_review_required is not True or self.raw_source_embedded is not False:
            raise ValueError("Intake batches must require review and exclude raw source content.")
        object.__setattr__(self, "tools", tuple(sorted(set(self.tools))))
        object.__setattr__(
            self,
            "findings",
            tuple(sorted(self.findings, key=lambda item: item.fingerprint)),
        )

    def digest(self) -> str:
        return sha256_digest(self)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.finding-intake.v1",
            **to_primitive(self),
            "batch_digest": self.digest(),
        }


def import_sarif_file(
    path: Path,
    *,
    maximum_bytes: int = MAXIMUM_SARIF_BYTES,
    maximum_results: int = MAXIMUM_RESULTS,
) -> EvidenceIntakeBatch:
    """Read and normalize one uncompressed UTF-8 SARIF file without dereferencing URIs."""

    if not 1 <= maximum_bytes <= MAXIMUM_SARIF_BYTES:
        raise ValueError("maximum_bytes must stay within the built-in SARIF limit.")
    if not 1 <= maximum_results <= MAXIMUM_RESULTS:
        raise ValueError("maximum_results must stay within the built-in result limit.")
    try:
        if not path.is_file():
            raise SarifIntakeError("SARIF input must be a regular file.")
        size = path.stat().st_size
        if size > maximum_bytes:
            raise SarifIntakeError(
                f"SARIF input exceeds the {maximum_bytes}-byte intake limit."
            )
        raw = path.read_bytes()
        if len(raw) != size:
            raise SarifIntakeError("SARIF input changed while it was being read.")
        text = raw.decode("utf-8")
        document = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except SarifIntakeError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SarifIntakeError(f"Could not read bounded UTF-8 SARIF JSON: {exc}") from exc
    return import_sarif_document(
        document,
        source_content_sha256=hashlib.sha256(raw).hexdigest(),
        source_size_bytes=len(raw),
        maximum_results=maximum_results,
    )


def read_intake_file(
    path: Path, *, maximum_bytes: int = MAXIMUM_INTAKE_BYTES
) -> EvidenceIntakeBatch:
    """Read a canonical intake export with duplicate-key and depth protection."""

    if not 1 <= maximum_bytes <= MAXIMUM_INTAKE_BYTES:
        raise ValueError("maximum_bytes must stay within the intake-document limit.")
    try:
        if not path.is_file():
            raise SarifIntakeError("Finding intake input must be a regular file.")
        size = path.stat().st_size
        if size > maximum_bytes:
            raise SarifIntakeError(
                f"Finding intake input exceeds the {maximum_bytes}-byte validation limit."
            )
        raw = path.read_bytes()
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except SarifIntakeError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SarifIntakeError(f"Could not read bounded finding-intake JSON: {exc}") from exc
    return intake_from_document(document)


def import_sarif_document(
    document: Any,
    *,
    source_content_sha256: str | None = None,
    source_size_bytes: int | None = None,
    maximum_results: int = MAXIMUM_RESULTS,
) -> EvidenceIntakeBatch:
    """Normalize an already parsed SARIF document for tests or trusted integrations."""

    if not 1 <= maximum_results <= MAXIMUM_RESULTS:
        raise ValueError("maximum_results must stay within the built-in result limit.")
    if not isinstance(document, Mapping):
        raise SarifIntakeError("SARIF root must be a JSON object.")
    _validate_json_shape(document)
    if document.get("version") != SARIF_VERSION:
        raise SarifIntakeError("Only SARIF version 2.1.0 is accepted.")
    runs = document.get("runs")
    if not isinstance(runs, list) or not 1 <= len(runs) <= MAXIMUM_RUNS:
        raise SarifIntakeError(
            f"SARIF runs must contain between 1 and {MAXIMUM_RUNS} objects."
        )

    if source_content_sha256 is None or source_size_bytes is None:
        encoded = canonical_json(document).encode("utf-8")
        source_content_sha256 = hashlib.sha256(encoded).hexdigest()
        source_size_bytes = len(encoded)
    if not _DIGEST.fullmatch(source_content_sha256):
        raise SarifIntakeError("The supplied SARIF source digest is invalid.")
    if not 0 <= source_size_bytes <= MAXIMUM_SARIF_BYTES:
        raise SarifIntakeError("The supplied SARIF source size is outside the intake limit.")

    findings: dict[str, CanonicalFinding] = {}
    tools: set[str] = set()
    result_count = 0
    unsafe_location_count = 0
    redacted_result_count = 0

    for run_index, run in enumerate(runs):
        if not isinstance(run, Mapping):
            raise SarifIntakeError(f"runs[{run_index}] must be an object.")
        tool_name, tool_version, rules = _tool_metadata(run, run_index)
        tools.add(tool_name)
        results = run.get("results", [])
        if not isinstance(results, list):
            raise SarifIntakeError(f"runs[{run_index}].results must be an array.")
        if result_count + len(results) > maximum_results:
            raise SarifIntakeError(
                f"SARIF results exceed the {maximum_results}-result intake limit."
            )
        for result_index, result in enumerate(results):
            if not isinstance(result, Mapping):
                raise SarifIntakeError(
                    f"runs[{run_index}].results[{result_index}] must be an object."
                )
            result_count += 1
            finding, unsafe_location, redacted = _normalize_result(
                result,
                run_index=run_index,
                result_index=result_index,
                tool_name=tool_name,
                tool_version=tool_version,
                rules=rules,
                source_digest=source_content_sha256,
            )
            unsafe_location_count += int(unsafe_location)
            redacted_result_count += int(redacted)
            previous = findings.get(finding.fingerprint)
            findings[finding.fingerprint] = (
                finding if previous is None else _merge_occurrences(previous, finding)
            )

    return EvidenceIntakeBatch(
        batch_id=_batch_id(source_content_sha256),
        source_format="sarif",
        source_version=SARIF_VERSION,
        source_content_sha256=source_content_sha256,
        source_size_bytes=source_size_bytes,
        source_evidence_ref=f"evidence://sarif/{source_content_sha256}",
        run_count=len(runs),
        result_count=result_count,
        duplicate_result_count=result_count - len(findings),
        unsafe_location_count=unsafe_location_count,
        redacted_result_count=redacted_result_count,
        tools=tuple(tools),
        findings=tuple(findings.values()),
    )


def intake_from_document(document: Any) -> EvidenceIntakeBatch:
    """Load a strict exported intake document and verify its digest."""

    if not isinstance(document, Mapping):
        raise SarifIntakeError("Finding intake document must be a JSON object.")
    _validate_json_shape(document, maximum_nodes=MAXIMUM_INTAKE_JSON_NODES)
    fields = {
        "batch_id",
        "source_format",
        "source_version",
        "source_content_sha256",
        "source_size_bytes",
        "source_evidence_ref",
        "run_count",
        "result_count",
        "duplicate_result_count",
        "unsafe_location_count",
        "redacted_result_count",
        "tools",
        "findings",
        "human_review_required",
        "raw_source_embedded",
    }
    metadata = {"schema_version", "batch_digest"}
    missing = fields - set(document)
    unknown = set(document) - fields - metadata
    if missing or unknown:
        raise SarifIntakeError(
            f"Invalid intake fields: missing {sorted(missing)}, unknown {sorted(unknown)}."
        )
    if document.get("schema_version") != "finredops.finding-intake.v1":
        raise SarifIntakeError("Unsupported finding intake schema version.")
    if not isinstance(document.get("batch_digest"), str):
        raise SarifIntakeError("batch_digest must be a SHA-256 string.")
    findings_raw = document["findings"]
    tools_raw = document["tools"]
    if not isinstance(findings_raw, list) or not isinstance(tools_raw, list):
        raise SarifIntakeError("findings and tools must be arrays.")
    if any(not isinstance(item, str) for item in tools_raw):
        raise SarifIntakeError("tools must contain only strings.")
    try:
        findings = tuple(_finding_from_document(item) for item in findings_raw)
        batch = EvidenceIntakeBatch(
            batch_id=_required_string(document, "batch_id"),
            source_format=_required_string(document, "source_format"),
            source_version=_required_string(document, "source_version"),
            source_content_sha256=_required_string(document, "source_content_sha256"),
            source_size_bytes=_required_integer(document, "source_size_bytes"),
            source_evidence_ref=_required_string(document, "source_evidence_ref"),
            run_count=_required_integer(document, "run_count"),
            result_count=_required_integer(document, "result_count"),
            duplicate_result_count=_required_integer(document, "duplicate_result_count"),
            unsafe_location_count=_required_integer(document, "unsafe_location_count"),
            redacted_result_count=_required_integer(document, "redacted_result_count"),
            tools=tuple(tools_raw),
            findings=findings,
            human_review_required=document["human_review_required"],
            raw_source_embedded=document["raw_source_embedded"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, SarifIntakeError):
            raise
        raise SarifIntakeError(f"Invalid finding intake value: {exc}") from exc
    if document["batch_digest"] != batch.digest():
        raise SarifIntakeError("Finding intake digest does not match its content.")
    return batch


def _tool_metadata(
    run: Mapping[str, Any], run_index: int
) -> tuple[str, str, tuple[Mapping[str, Any], ...]]:
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, Mapping) else None
    if not isinstance(driver, Mapping):
        raise SarifIntakeError(f"runs[{run_index}].tool.driver must be an object.")
    tool_name, _ = _safe_text(driver.get("name"), "tool.driver.name", 160)
    tool_version, _ = _safe_text(
        driver.get("semanticVersion", driver.get("version", "unspecified")),
        "tool.driver.version",
        80,
    )
    rules_raw = driver.get("rules", [])
    if not isinstance(rules_raw, list) or len(rules_raw) > MAXIMUM_RULES_PER_RUN:
        raise SarifIntakeError(
            f"runs[{run_index}].tool.driver.rules must be a bounded array."
        )
    if any(not isinstance(item, Mapping) for item in rules_raw):
        raise SarifIntakeError(f"runs[{run_index}].tool.driver.rules contains a non-object.")
    rule_ids: list[str] = []
    for rule_index, rule in enumerate(rules_raw):
        rule_id, _ = _safe_text(
            rule.get("id"),
            f"runs[{run_index}].tool.driver.rules[{rule_index}].id",
            200,
        )
        rule_ids.append(rule_id)
    if len(rule_ids) != len(set(rule_ids)):
        raise SarifIntakeError(f"runs[{run_index}].tool.driver.rules contains duplicate IDs.")
    return tool_name, tool_version, tuple(rules_raw)


def _normalize_result(
    result: Mapping[str, Any],
    *,
    run_index: int,
    result_index: int,
    tool_name: str,
    tool_version: str,
    rules: tuple[Mapping[str, Any], ...],
    source_digest: str,
) -> tuple[CanonicalFinding, bool, bool]:
    path = f"runs[{run_index}].results[{result_index}]"
    rule_id, descriptor = _resolve_rule(result, rules, path)
    message_raw = result.get("message")
    if not isinstance(message_raw, Mapping):
        raise SarifIntakeError(f"{path}.message must be an object.")
    message_value = _message_value(message_raw, descriptor, path)
    message, message_redactions = _safe_text(message_value, f"{path}.message", 1_000)

    title_value: Any = rule_id
    short_description = descriptor.get("shortDescription")
    if isinstance(short_description, Mapping):
        title_value = short_description.get("text", rule_id)
    elif isinstance(descriptor.get("name"), str):
        title_value = descriptor["name"]
    title, title_redactions = _safe_text(title_value, f"{path}.title", 240)

    severity = _machine_severity(result, descriptor, path)
    confidence = _machine_confidence(result, descriptor)
    artifact_ref, unsafe_location, start_line, start_column = _location(result, path)
    tags = _tags(result, descriptor, path)
    partials = _fingerprint_material(result, path)
    fingerprint = sha256_digest(
        {
            "source_format": "sarif-2.1.0",
            "tool": tool_name.casefold(),
            "rule_id": rule_id,
            "partial_fingerprints": partials,
            "fallback": None
            if partials
            else {
                "artifact_ref": artifact_ref,
                "start_line": start_line,
                "message": message.casefold(),
            },
        }
    )
    redaction_kinds = tuple(sorted(message_redactions | title_redactions))
    finding = CanonicalFinding(
        finding_id=_finding_id(fingerprint),
        fingerprint=fingerprint,
        source_tool=tool_name,
        source_tool_version=tool_version,
        rule_id=rule_id,
        title=title,
        machine_severity=severity,
        machine_confidence=confidence,
        message=message,
        artifact_ref=artifact_ref,
        start_line=start_line,
        start_column=start_column,
        evidence_ref=f"evidence://sarif/{source_digest}/{fingerprint}",
        tags=tags,
        occurrence_count=1,
        redaction_kinds=redaction_kinds,
    )
    return finding, unsafe_location, bool(redaction_kinds)


def _message_value(
    message: Mapping[str, Any], descriptor: Mapping[str, Any], path: str
) -> Any:
    value = message.get("text", message.get("markdown"))
    if value is not None:
        return value
    message_id = message.get("id")
    if not isinstance(message_id, str) or not message_id.strip():
        raise SarifIntakeError(f"{path}.message requires text, markdown, or a rule message ID.")
    message_strings = descriptor.get("messageStrings")
    if not isinstance(message_strings, Mapping) or len(message_strings) > 2_000:
        raise SarifIntakeError(f"{path}.message.id cannot be resolved safely.")
    template = message_strings.get(message_id)
    if not isinstance(template, Mapping):
        raise SarifIntakeError(f"{path}.message.id is not present in the rule descriptor.")
    value = template.get("text", template.get("markdown"))
    if value is None:
        raise SarifIntakeError(f"{path}.message.id has no safe text template.")
    return value


def _resolve_rule(
    result: Mapping[str, Any],
    rules: tuple[Mapping[str, Any], ...],
    path: str,
) -> tuple[str, Mapping[str, Any]]:
    descriptor: Mapping[str, Any] = {}
    rule_index = result.get("ruleIndex")
    result_rule = result.get("rule")
    nested_index = result_rule.get("index") if isinstance(result_rule, Mapping) else None
    if rule_index is not None and nested_index is not None and rule_index != nested_index:
        raise SarifIntakeError(f"{path} contains conflicting rule indexes.")
    if rule_index is None:
        rule_index = nested_index
    if rule_index is not None:
        if isinstance(rule_index, bool) or not isinstance(rule_index, int):
            raise SarifIntakeError(f"{path}.ruleIndex must be an integer.")
        if not 0 <= rule_index < len(rules):
            raise SarifIntakeError(f"{path}.ruleIndex is outside tool.driver.rules.")
        descriptor = rules[rule_index]
    rule_id_value = result.get("ruleId")
    nested_id = result_rule.get("id") if isinstance(result_rule, Mapping) else None
    if rule_id_value is not None and nested_id is not None:
        top_id, _ = _safe_text(rule_id_value, f"{path}.ruleId", 200)
        reference_id, _ = _safe_text(nested_id, f"{path}.rule.id", 200)
        if top_id != reference_id:
            raise SarifIntakeError(f"{path} contains conflicting rule identifiers.")
    if rule_id_value is None:
        rule_id_value = nested_id
    if not descriptor and rule_id_value is not None:
        candidate_id, _ = _safe_text(rule_id_value, f"{path}.ruleId", 200)
        matches = []
        for rule in rules:
            descriptor_id, _ = _safe_text(rule.get("id"), f"{path}.rule descriptor", 200)
            if descriptor_id == candidate_id:
                matches.append(rule)
        if len(matches) == 1:
            descriptor = matches[0]
    if rule_id_value is None:
        rule_id_value = descriptor.get("id")
    rule_id, _ = _safe_text(rule_id_value, f"{path}.ruleId", 200)
    descriptor_id = descriptor.get("id")
    if isinstance(descriptor_id, str) and descriptor_id.strip() != rule_id:
        raise SarifIntakeError(f"{path}.ruleId does not match its rule descriptor.")
    return rule_id, descriptor


def _machine_severity(
    result: Mapping[str, Any], descriptor: Mapping[str, Any], path: str
) -> MachineSeverity:
    level = result.get("level")
    if level is None:
        configuration = descriptor.get("defaultConfiguration")
        level = configuration.get("level") if isinstance(configuration, Mapping) else "warning"
    if not isinstance(level, str):
        raise SarifIntakeError(f"{path}.level must be a SARIF level string.")
    mapping = {
        "none": MachineSeverity.INFORMATIONAL,
        "note": MachineSeverity.LOW,
        "warning": MachineSeverity.MEDIUM,
        "error": MachineSeverity.HIGH,
    }
    try:
        return mapping[level.casefold()]
    except KeyError as exc:
        raise SarifIntakeError(f"{path}.level is not a supported SARIF level.") from exc


def _machine_confidence(
    result: Mapping[str, Any], descriptor: Mapping[str, Any]
) -> MachineConfidence:
    value: Any = None
    for container in (result.get("properties"), descriptor.get("properties")):
        if isinstance(container, Mapping) and value is None:
            value = container.get("precision", container.get("confidence"))
    if not isinstance(value, str):
        return MachineConfidence.UNKNOWN
    normalized = value.casefold().replace("_", "-")
    if normalized in {"very-high", "high", "certain"}:
        return MachineConfidence.HIGH
    if normalized in {"medium", "moderate"}:
        return MachineConfidence.MEDIUM
    if normalized in {"low", "very-low"}:
        return MachineConfidence.LOW
    return MachineConfidence.UNKNOWN


def _location(
    result: Mapping[str, Any], path: str
) -> tuple[str, bool, int | None, int | None]:
    locations = result.get("locations", [])
    if not isinstance(locations, list):
        raise SarifIntakeError(f"{path}.locations must be an array.")
    if not locations:
        return _opaque_artifact("unlocated"), True, None, None
    location = locations[0]
    if not isinstance(location, Mapping):
        raise SarifIntakeError(f"{path}.locations[0] must be an object.")
    physical = location.get("physicalLocation")
    if not isinstance(physical, Mapping):
        return _opaque_artifact("unlocated"), True, None, None
    artifact = physical.get("artifactLocation")
    uri = artifact.get("uri") if isinstance(artifact, Mapping) else None
    artifact_ref, unsafe = _safe_artifact_ref(uri)
    region = physical.get("region", {})
    if region is None:
        region = {}
    if not isinstance(region, Mapping):
        raise SarifIntakeError(f"{path}.locations[0].physicalLocation.region must be an object.")
    start_line = _optional_position(region.get("startLine"), f"{path}.startLine")
    start_column = _optional_position(region.get("startColumn"), f"{path}.startColumn")
    return artifact_ref, unsafe, start_line, start_column


def _safe_artifact_ref(value: Any) -> tuple[str, bool]:
    if not isinstance(value, str) or not value.strip() or len(value) > 2_000:
        return _opaque_artifact(str(value)[:2_000]), True
    candidate = unicodedata.normalize("NFKC", value.strip())
    parsed = urlsplit(candidate)
    decoded = unquote(parsed.path).replace("\\", "/")
    pure = PurePosixPath(decoded)
    unsafe = bool(
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or decoded.startswith("/")
        or _CONTROL.search(decoded)
        or any(part in {"", ".", ".."} for part in pure.parts)
        or len(decoded) > 512
    )
    if unsafe:
        return _opaque_artifact(candidate), True
    normalized = pure.as_posix()
    return "repo://" + quote(normalized, safe="/._-~"), False


def _opaque_artifact(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    return f"artifact-digest://{digest}"


def _tags(
    result: Mapping[str, Any], descriptor: Mapping[str, Any], path: str
) -> tuple[str, ...]:
    values: list[str] = []
    for container in (descriptor.get("properties"), result.get("properties")):
        if not isinstance(container, Mapping) or "tags" not in container:
            continue
        raw = container["tags"]
        if not isinstance(raw, list):
            raise SarifIntakeError(f"{path}.properties.tags must be an array.")
        if len(raw) + len(values) > MAXIMUM_TAGS_PER_FINDING:
            raise SarifIntakeError(f"{path} contains too many tags.")
        for item in raw:
            tag, _ = _safe_text(item, f"{path}.properties.tags", 120)
            values.append(tag)
    return tuple(sorted(set(values)))


def _fingerprint_material(result: Mapping[str, Any], path: str) -> dict[str, str]:
    for name in ("partialFingerprints", "fingerprints"):
        raw = result.get(name)
        if raw is None:
            continue
        if not isinstance(raw, Mapping) or len(raw) > 32:
            raise SarifIntakeError(f"{path}.{name} must be a bounded string map.")
        material: dict[str, str] = {}
        for key, value in raw.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or not key.strip()
                or not value.strip()
                or len(key) > 120
                or len(value) > 512
                or _CONTROL.search(key)
                or _CONTROL.search(value)
            ):
                raise SarifIntakeError(f"{path}.{name} contains an invalid fingerprint.")
            material[key.strip()] = value.strip()
        if material:
            return dict(sorted(material.items()))
    return {}


def _safe_text(value: Any, name: str, maximum_chars: int) -> tuple[str, set[str]]:
    if not isinstance(value, str) or not value.strip():
        raise SarifIntakeError(f"{name} must be a non-empty string.")
    normalized = unicodedata.normalize("NFKC", value)
    normalized = _CONTROL.sub(" ", normalized)
    normalized = " ".join(normalized.split())
    secret_redacted = bool(
        _SECRET_ASSIGNMENT.search(normalized)
        or _PRIVATE_KEY_BLOCK.search(normalized)
        or any(pattern.search(normalized) for pattern in _TOKEN_PATTERNS)
    )
    normalized = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}=[REDACTED:SECRET]",
        normalized,
    )
    normalized = _PRIVATE_KEY_BLOCK.sub("[REDACTED:SECRET]", normalized)
    for pattern in _TOKEN_PATTERNS:
        normalized = pattern.sub("[REDACTED:SECRET]", normalized)
    guarded = EvidenceGuard().sanitize({"value": normalized})
    sanitized = str(guarded.evidence["value"])
    redactions = {item.kind.value for item in guarded.findings}
    if secret_redacted:
        redactions.add("secret_field")
    if len(sanitized) > maximum_chars:
        sanitized = sanitized[: maximum_chars - 1].rstrip() + "…"
    if not sanitized:
        raise SarifIntakeError(f"{name} became empty after safe normalization.")
    return sanitized, redactions


def _merge_occurrences(
    current: CanonicalFinding, incoming: CanonicalFinding
) -> CanonicalFinding:
    if current.fingerprint != incoming.fingerprint:
        raise ValueError("Only identical canonical fingerprints can be merged.")
    severity = max(
        (current.machine_severity, incoming.machine_severity),
        key=lambda item: _SEVERITY_RANK[item],
    )
    confidence_rank = {
        MachineConfidence.UNKNOWN: 0,
        MachineConfidence.LOW: 1,
        MachineConfidence.MEDIUM: 2,
        MachineConfidence.HIGH: 3,
    }
    confidence = max(
        (current.machine_confidence, incoming.machine_confidence),
        key=lambda item: confidence_rank[item],
    )
    lines = [item for item in (current.start_line, incoming.start_line) if item is not None]
    columns = [
        item for item in (current.start_column, incoming.start_column) if item is not None
    ]
    return replace(
        current,
        title=min(current.title, incoming.title),
        machine_severity=severity,
        machine_confidence=confidence,
        message=min(current.message, incoming.message),
        artifact_ref=min(current.artifact_ref, incoming.artifact_ref),
        start_line=min(lines) if lines else None,
        start_column=min(columns) if columns else None,
        tags=tuple(sorted(set(current.tags) | set(incoming.tags))),
        occurrence_count=current.occurrence_count + incoming.occurrence_count,
        redaction_kinds=tuple(
            sorted(set(current.redaction_kinds) | set(incoming.redaction_kinds))
        ),
    )


def _finding_from_document(document: Any) -> CanonicalFinding:
    if not isinstance(document, Mapping):
        raise SarifIntakeError("Each canonical finding must be an object.")
    keys = {
        "finding_id",
        "fingerprint",
        "source_tool",
        "source_tool_version",
        "rule_id",
        "title",
        "machine_severity",
        "machine_confidence",
        "message",
        "artifact_ref",
        "start_line",
        "start_column",
        "evidence_ref",
        "tags",
        "occurrence_count",
        "redaction_kinds",
        "review_disposition",
        "human_validation_required",
    }
    if set(document) != keys:
        raise SarifIntakeError("Canonical finding fields do not match the strict schema.")
    tags = document["tags"]
    redactions = document["redaction_kinds"]
    if not isinstance(tags, list) or any(not isinstance(item, str) for item in tags):
        raise SarifIntakeError("Finding tags must be a string array.")
    if not isinstance(redactions, list) or any(
        not isinstance(item, str) for item in redactions
    ):
        raise SarifIntakeError("Finding redaction_kinds must be a string array.")
    return CanonicalFinding(
        finding_id=_required_string(document, "finding_id"),
        fingerprint=_required_string(document, "fingerprint"),
        source_tool=_required_string(document, "source_tool"),
        source_tool_version=_required_string(document, "source_tool_version"),
        rule_id=_required_string(document, "rule_id"),
        title=_required_string(document, "title"),
        machine_severity=MachineSeverity(_required_string(document, "machine_severity")),
        machine_confidence=MachineConfidence(
            _required_string(document, "machine_confidence")
        ),
        message=_required_string(document, "message"),
        artifact_ref=_required_string(document, "artifact_ref"),
        start_line=_document_optional_position(document, "start_line"),
        start_column=_document_optional_position(document, "start_column"),
        evidence_ref=_required_string(document, "evidence_ref"),
        tags=tuple(tags),
        occurrence_count=_required_integer(document, "occurrence_count"),
        redaction_kinds=tuple(redactions),
        review_disposition=_required_string(document, "review_disposition"),
        human_validation_required=document["human_validation_required"],
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SarifIntakeError(f"SARIF JSON contains a duplicate object key: {key!r}.")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise SarifIntakeError(f"SARIF JSON contains a non-finite number: {value}.")


def _validate_json_shape(
    document: Any,
    *,
    maximum_nodes: int = MAXIMUM_JSON_NODES,
    maximum_depth: int = MAXIMUM_JSON_DEPTH,
) -> None:
    stack: list[tuple[Any, int]] = [(document, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > maximum_nodes:
            raise SarifIntakeError(
                f"JSON exceeds the {maximum_nodes}-node structure limit."
            )
        if depth > maximum_depth:
            raise SarifIntakeError(
                f"JSON exceeds the {maximum_depth}-level nesting limit."
            )
        if isinstance(value, Mapping):
            if any(not isinstance(key, str) for key in value):
                raise SarifIntakeError("SARIF object keys must be strings.")
            stack.extend((child, depth + 1) for child in value.values())
            continue
        if isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
            continue
        if value is None or isinstance(value, (str, bool, int)):
            continue
        if isinstance(value, float) and math.isfinite(value):
            continue
        raise SarifIntakeError("SARIF contains a non-JSON or non-finite value.")


def _required_string(document: Mapping[str, Any], name: str) -> str:
    value = document[name]
    if not isinstance(value, str) or not value.strip():
        raise SarifIntakeError(f"{name} must be a non-empty string.")
    return value.strip()


def _required_integer(document: Mapping[str, Any], name: str) -> int:
    value = document[name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise SarifIntakeError(f"{name} must be an integer.")
    return value


def _document_optional_position(document: Mapping[str, Any], name: str) -> int | None:
    value = document[name]
    if value is None:
        return None
    return _required_integer(document, name)


def _optional_position(value: Any, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10_000_000:
        raise SarifIntakeError(f"{name} must be an integer between 1 and 10000000.")
    return value


def _validate_optional_position(value: int | None, name: str) -> None:
    if value is not None and (
        isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10_000_000
    ):
        raise ValueError(f"{name} must be between 1 and 10000000 when supplied.")


def _finding_id(fingerprint: str) -> str:
    return f"FRX-SARIF-{fingerprint[:24].upper()}"


def _batch_id(source_digest: str) -> str:
    return f"FRX-INTAKE-{source_digest[:24].upper()}"
