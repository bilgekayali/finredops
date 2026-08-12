"""Deterministic, metadata-only audit dossier bundles and offline verification."""

from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .applicability import (
    ApplicabilityAssessment,
    ApplicabilityDecision,
)
from .audit import AuditChain
from .custody import EvidenceManifest
from .diffing import ReportDelta
from .models import (
    StringEnum,
    canonical_json,
    ensure_aware,
    parse_datetime,
    sha256_digest,
    to_primitive,
)
from .reporting import (
    AssessmentReport,
    ControlConclusion,
    ReportStatus,
    regulatory_crosswalk,
    render_report_markdown,
    report_from_document,
    validate_report,
)
from .regulations import (
    AssessmentType,
    RegulatoryProfile,
    turkey_financial_regulatory_profile,
)


class BundlePurpose(StringEnum):
    HUMAN_REVIEW = "human_review"
    REGULATORY_SUBMISSION = "regulatory_submission"
    ARCHIVE = "archive"


@dataclass(frozen=True, slots=True)
class BundleEntry:
    path: str
    sha256: str
    size_bytes: int
    media_type: str


@dataclass(frozen=True, slots=True)
class AuditBundleResult:
    path: str
    bundle_id: str
    purpose: BundlePurpose
    manifest_digest: str
    bundle_sha256: str
    size_bytes: int
    ready_for_submission: bool
    blockers: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return to_primitive(self)


@dataclass(frozen=True, slots=True)
class BundleVerification:
    valid: bool
    bundle_id: str
    bundle_sha256: str
    manifest_digest: str
    purpose: str
    ready_for_submission: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return to_primitive(self)


_MEDIA_TYPES = {
    "README.txt": "text/plain",
    "applicability.json": "application/json",
    "audit.jsonl": "application/x-ndjson",
    "evidence-manifest.json": "application/json",
    "regulatory-crosswalk.json": "application/json",
    "report-delta.json": "application/json",
    "report.json": "application/json",
    "report.md": "text/markdown",
}
_REQUIRED_ENTRIES = frozenset(
    {
        "README.txt",
        "applicability.json",
        "audit.jsonl",
        "evidence-manifest.json",
        "regulatory-crosswalk.json",
        "report.json",
        "report.md",
    }
)
_MAX_BUNDLE_BYTES = 25_000_000
_MAX_ENTRY_BYTES = 5_000_000
_MAX_ENTRIES = 16


def build_audit_bundle(
    output: Path,
    *,
    report: AssessmentReport,
    applicability: ApplicabilityAssessment,
    evidence: EvidenceManifest,
    audit: AuditChain,
    created_at: datetime,
    purpose: BundlePurpose = BundlePurpose.HUMAN_REVIEW,
    profile: RegulatoryProfile | None = None,
    delta: ReportDelta | None = None,
) -> AuditBundleResult:
    """Build a reproducible ZIP containing only audit-support metadata."""

    created_at = ensure_aware(created_at)
    profile = profile or turkey_financial_regulatory_profile()
    audit_valid, audit_errors = audit.verify()
    evidence_valid, evidence_errors = evidence.verify()
    report_validation = validate_report(report, profile)
    blockers = _submission_blockers(
        report=report,
        applicability=applicability,
        evidence=evidence,
        audit_valid=audit_valid,
        audit_errors=audit_errors,
        evidence_valid=evidence_valid,
        evidence_errors=evidence_errors,
        report_valid=report_validation.valid,
        report_ready=report_validation.ready_for_issue,
        profile=profile,
    )
    ready_for_submission = not blockers
    if purpose == BundlePurpose.REGULATORY_SUBMISSION and not ready_for_submission:
        raise ValueError(
            "Regulatory submission bundle is blocked: " + " ".join(blockers)
        )
    if not audit_valid:
        raise ValueError("Cannot bundle an invalid audit chain: " + " ".join(audit_errors))
    if not evidence_valid:
        raise ValueError(
            "Cannot bundle an invalid evidence manifest: " + " ".join(evidence_errors)
        )
    if not report_validation.valid:
        raise ValueError("Cannot bundle a structurally invalid report.")

    report_document = report.as_dict()
    crosswalk = regulatory_crosswalk(report, profile)
    content: dict[str, bytes] = {
        "README.txt": _readme(report, applicability, purpose).encode("utf-8"),
        "applicability.json": _json_bytes(applicability.as_dict()),
        "audit.jsonl": audit.to_jsonl().encode("utf-8"),
        "evidence-manifest.json": _json_bytes(evidence.as_dict()),
        "regulatory-crosswalk.json": _json_bytes(crosswalk),
        "report.json": _json_bytes(report_document),
        "report.md": render_report_markdown(report, profile).encode("utf-8"),
    }
    if delta is not None:
        if delta.current_digest != report.digest():
            raise ValueError("Report delta current digest does not match the bundled report.")
        content["report-delta.json"] = _json_bytes(delta.as_dict())
    entries = tuple(
        BundleEntry(
            path=name,
            sha256=_bytes_sha256(body),
            size_bytes=len(body),
            media_type=_MEDIA_TYPES[name],
        )
        for name, body in sorted(content.items())
    )
    audit_tip = audit.events[-1].event_hash if audit.events else ""
    bundle_seed = {
        "created_at": created_at,
        "purpose": purpose,
        "report_digest": report.digest(),
        "applicability_digest": applicability.digest(),
        "evidence_manifest_digest": evidence.digest(),
        "audit_tip": audit_tip,
        "entries": entries,
    }
    bundle_id = "FRX-BND-" + sha256_digest(bundle_seed)[:20].upper()
    manifest = {
        "schema_version": "finredops.audit-bundle.v1",
        "bundle_id": bundle_id,
        "created_at": to_primitive(created_at),
        "purpose": purpose,
        "report_id": report.report_id,
        "report_digest": report.digest(),
        "assessment_type": report.assessment_type,
        "regulatory_profile_id": profile.profile_id,
        "regulatory_profile_digest": profile.digest(),
        "applicability_digest": applicability.digest(),
        "evidence_manifest_digest": evidence.digest(),
        "audit_event_count": len(audit.events),
        "audit_chain_tip": audit_tip,
        "entries": entries,
        "ready_for_submission": ready_for_submission,
        "submission_blockers": blockers,
        "raw_evidence_embedded": False,
        "cryptographic_signature_attached": False,
    }
    manifest_bytes = _json_bytes(manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w") as archive:
        _write_zip_entry(archive, "manifest.json", manifest_bytes)
        for name, body in sorted(content.items()):
            _write_zip_entry(archive, name, body)
    bundle_bytes = output.read_bytes()
    return AuditBundleResult(
        path=str(output),
        bundle_id=bundle_id,
        purpose=purpose,
        manifest_digest=_bytes_sha256(manifest_bytes),
        bundle_sha256=_bytes_sha256(bundle_bytes),
        size_bytes=len(bundle_bytes),
        ready_for_submission=ready_for_submission,
        blockers=tuple(blockers),
    )


def verify_audit_bundle(path: Path) -> BundleVerification:
    """Verify ZIP safety, file digests, and embedded FinRedOps documents offline."""

    errors: list[str] = []
    warnings: list[str] = []
    if not path.is_file():
        return _failed_verification(path, "Bundle file does not exist.")
    size = path.stat().st_size
    if size > _MAX_BUNDLE_BYTES:
        return _failed_verification(path, "Bundle exceeds the 25 MB metadata limit.")
    bundle_sha = _bytes_sha256(path.read_bytes())
    manifest: dict[str, Any] = {}
    manifest_bytes = b""
    documents: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if len(infos) > _MAX_ENTRIES:
                errors.append("Bundle contains too many entries.")
            if len(names) != len(set(names)):
                errors.append("Bundle contains duplicate paths.")
            if sum(item.file_size for item in infos) > _MAX_BUNDLE_BYTES:
                errors.append("Bundle uncompressed content exceeds the 25 MB metadata limit.")
            for info in infos:
                if not _safe_archive_path(info.filename):
                    errors.append(f"Unsafe archive path: {info.filename!r}.")
                if info.flag_bits & 0x1:
                    errors.append(f"Encrypted entry is unsupported: {info.filename!r}.")
                if stat.S_ISLNK(info.external_attr >> 16):
                    errors.append(f"Symbolic link entry is forbidden: {info.filename!r}.")
                if info.file_size > _MAX_ENTRY_BYTES:
                    errors.append(f"Entry exceeds size limit: {info.filename!r}.")
                if info.compress_type != zipfile.ZIP_DEFLATED:
                    errors.append(f"Unexpected compression method: {info.filename!r}.")
            if errors:
                raise ValueError("Archive safety validation failed.")
            if "manifest.json" not in names:
                raise ValueError("Bundle manifest is missing.")
            manifest_bytes = archive.read("manifest.json")
            manifest = json.loads(manifest_bytes)
            manifest_fields = {
                "schema_version",
                "bundle_id",
                "created_at",
                "purpose",
                "report_id",
                "report_digest",
                "assessment_type",
                "regulatory_profile_id",
                "regulatory_profile_digest",
                "applicability_digest",
                "evidence_manifest_digest",
                "audit_event_count",
                "audit_chain_tip",
                "entries",
                "ready_for_submission",
                "submission_blockers",
                "raw_evidence_embedded",
                "cryptographic_signature_attached",
            }
            if not isinstance(manifest, dict) or set(manifest) != manifest_fields:
                raise ValueError("Bundle manifest fields do not match the strict schema.")
            if manifest.get("schema_version") != "finredops.audit-bundle.v1":
                raise ValueError("Unsupported audit bundle schema version.")
            purpose = BundlePurpose(manifest.get("purpose"))
            for key in (
                "report_digest",
                "regulatory_profile_digest",
                "applicability_digest",
                "evidence_manifest_digest",
            ):
                if not _is_digest(manifest.get(key)):
                    raise ValueError(f"Bundle {key} is not a valid SHA-256 digest.")
            for key in ("bundle_id", "report_id", "regulatory_profile_id"):
                if not isinstance(manifest.get(key), str) or not manifest[key].strip():
                    raise ValueError(f"Bundle {key} must be a non-empty string.")
            AssessmentType(manifest.get("assessment_type"))
            if not isinstance(manifest.get("audit_event_count"), int) or isinstance(
                manifest.get("audit_event_count"), bool
            ) or manifest["audit_event_count"] < 0:
                raise ValueError("Bundle audit_event_count must be a non-negative integer.")
            if manifest.get("audit_chain_tip") != "" and not _is_digest(
                manifest.get("audit_chain_tip")
            ):
                raise ValueError("Bundle audit_chain_tip is invalid.")
            if not isinstance(manifest.get("created_at"), str):
                raise ValueError("Bundle created_at must be an ISO-8601 string.")
            parse_datetime(manifest["created_at"])
            if not isinstance(manifest.get("ready_for_submission"), bool):
                raise ValueError("Bundle readiness must be a boolean.")
            blockers = manifest.get("submission_blockers")
            if not isinstance(blockers, list) or any(
                not isinstance(item, str) or not item.strip() for item in blockers
            ):
                raise ValueError("Bundle submission blockers must be a string array.")
            if not isinstance(manifest.get("cryptographic_signature_attached"), bool):
                raise ValueError("Bundle signature flag must be a boolean.")
            entries = manifest.get("entries")
            if not isinstance(entries, list):
                raise ValueError("Bundle entries manifest must be an array.")
            entry_fields = {"path", "sha256", "size_bytes", "media_type"}
            if any(not isinstance(item, dict) or set(item) != entry_fields for item in entries):
                raise ValueError("Bundle entry fields do not match the strict schema.")
            for item in entries:
                if not isinstance(item["path"], str) or not item["path"]:
                    raise ValueError("Bundle entry path must be a non-empty string.")
                if not _is_digest(item["sha256"]):
                    raise ValueError("Bundle entry digest is invalid.")
                if not isinstance(item["size_bytes"], int) or isinstance(
                    item["size_bytes"], bool
                ):
                    raise ValueError("Bundle entry size must be an integer.")
                if not isinstance(item["media_type"], str) or not item["media_type"]:
                    raise ValueError("Bundle entry media type is invalid.")
            entry_paths = [str(item["path"]) for item in entries]
            if len(entry_paths) != len(set(entry_paths)):
                raise ValueError("Bundle manifest declares duplicate paths.")
            if entry_paths != sorted(entry_paths):
                raise ValueError("Bundle manifest entries must be sorted by path.")
            declared = {str(item["path"]): item for item in entries}
            declared_entries = tuple(
                BundleEntry(
                    path=item["path"],
                    sha256=item["sha256"],
                    size_bytes=item["size_bytes"],
                    media_type=item["media_type"],
                )
                for item in entries
            )
            bundle_seed = {
                "created_at": parse_datetime(manifest["created_at"]),
                "purpose": purpose,
                "report_digest": manifest.get("report_digest"),
                "applicability_digest": manifest.get("applicability_digest"),
                "evidence_manifest_digest": manifest.get("evidence_manifest_digest"),
                "audit_tip": manifest.get("audit_chain_tip"),
                "entries": declared_entries,
            }
            expected_bundle_id = "FRX-BND-" + sha256_digest(bundle_seed)[:20].upper()
            if manifest.get("bundle_id") != expected_bundle_id:
                raise ValueError("Bundle identifier does not match its manifest content.")
            expected_names = {"manifest.json", *declared}
            if set(names) != expected_names:
                raise ValueError("Archive paths do not exactly match the manifest.")
            if not _REQUIRED_ENTRIES.issubset(declared):
                raise ValueError("Bundle is missing a required audit-support entry.")
            for entry_path, item in declared.items():
                body = archive.read(entry_path)
                documents[entry_path] = body
                if len(body) != item.get("size_bytes"):
                    errors.append(f"Size mismatch for {entry_path}.")
                if _bytes_sha256(body) != item.get("sha256"):
                    errors.append(f"Digest mismatch for {entry_path}.")
                if item.get("media_type") != _MEDIA_TYPES.get(entry_path):
                    errors.append(f"Media type mismatch for {entry_path}.")
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        errors.append(str(exc))

    if not errors:
        try:
            report = report_from_document(json.loads(documents["report.json"]))
            applicability = ApplicabilityAssessment.from_dict(
                json.loads(documents["applicability.json"])
            )
            evidence = EvidenceManifest.from_dict(
                json.loads(documents["evidence-manifest.json"])
            )
            audit = AuditChain.from_jsonl(documents["audit.jsonl"].decode("utf-8"))
            crosswalk = json.loads(documents["regulatory-crosswalk.json"])
            profile = turkey_financial_regulatory_profile()
            audit_valid, audit_errors = audit.verify()
            evidence_valid, evidence_errors = evidence.verify()
            report_validation = validate_report(report, profile)
            if not audit_valid:
                errors.extend(audit_errors)
            if not evidence_valid:
                errors.extend(evidence_errors)
            if not report_validation.valid:
                errors.append("Embedded report fails structural validation.")
            comparisons = {
                "report_id": report.report_id,
                "report_digest": report.digest(),
                "assessment_type": report.assessment_type.value,
                "regulatory_profile_id": profile.profile_id,
                "regulatory_profile_digest": profile.digest(),
                "applicability_digest": applicability.digest(),
                "evidence_manifest_digest": evidence.digest(),
                "audit_event_count": len(audit.events),
                "audit_chain_tip": audit.events[-1].event_hash if audit.events else "",
            }
            for key, actual in comparisons.items():
                if manifest.get(key) != actual:
                    errors.append(f"Manifest {key} does not match embedded content.")
            if crosswalk.get("report_digest") != report.digest():
                errors.append("Regulatory crosswalk is bound to another report.")
            if crosswalk != regulatory_crosswalk(report, profile):
                errors.append("Regulatory crosswalk does not match the embedded report and profile.")
            if documents["report.md"] != render_report_markdown(report, profile).encode("utf-8"):
                errors.append("Rendered report does not match the embedded report JSON.")
            if documents["README.txt"] != _readme(
                report, applicability, BundlePurpose(manifest["purpose"])
            ).encode("utf-8"):
                errors.append("Bundle README does not match the embedded metadata.")
            if "report-delta.json" in documents:
                delta = ReportDelta.from_dict(json.loads(documents["report-delta.json"]))
                if delta.current_digest != report.digest():
                    errors.append("Report delta current digest does not match the report.")
            if manifest.get("raw_evidence_embedded") is not False:
                errors.append("Bundle does not preserve the metadata-only evidence boundary.")
            if manifest.get("cryptographic_signature_attached") is not False:
                errors.append(
                    "v0.3 cannot validate a claimed external cryptographic signature."
                )
            computed_blockers = _submission_blockers(
                report=report,
                applicability=applicability,
                evidence=evidence,
                audit_valid=audit_valid,
                audit_errors=audit_errors,
                evidence_valid=evidence_valid,
                evidence_errors=evidence_errors,
                report_valid=report_validation.valid,
                report_ready=report_validation.ready_for_issue,
                profile=profile,
            )
            if manifest.get("submission_blockers") != computed_blockers:
                errors.append("Bundle submission blockers do not match the embedded content.")
            if manifest.get("ready_for_submission") != (not computed_blockers):
                errors.append("Bundle readiness does not match the embedded content.")
            if (
                purpose == BundlePurpose.REGULATORY_SUBMISSION
                and computed_blockers
            ):
                errors.append("Submission bundle no longer satisfies issuance gates.")
        except (UnicodeDecodeError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            errors.append(f"Embedded document validation failed: {exc}")

    ready = bool(manifest.get("ready_for_submission")) and not errors
    if manifest.get("purpose") != BundlePurpose.REGULATORY_SUBMISSION.value:
        warnings.append("Bundle is a review/archive package, not a regulatory submission package.")
    if not manifest.get("cryptographic_signature_attached", False):
        warnings.append("No external cryptographic signature is attached.")
    return BundleVerification(
        valid=not errors,
        bundle_id=str(manifest.get("bundle_id", "")),
        bundle_sha256=bundle_sha,
        manifest_digest=_bytes_sha256(manifest_bytes) if manifest_bytes else "",
        purpose=str(manifest.get("purpose", "")),
        ready_for_submission=ready,
        errors=tuple(errors),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def _submission_blockers(
    *,
    report: AssessmentReport,
    applicability: ApplicabilityAssessment,
    evidence: EvidenceManifest,
    audit_valid: bool,
    audit_errors: tuple[str, ...],
    evidence_valid: bool,
    evidence_errors: tuple[str, ...],
    report_valid: bool,
    report_ready: bool,
    profile: RegulatoryProfile,
) -> list[str]:
    blockers: list[str] = []
    if report.regulatory_profile_digest != profile.digest():
        blockers.append("Report regulatory profile is not current for this bundle.")
    if applicability.regulatory_profile_digest != profile.digest():
        blockers.append("Applicability profile does not match the bundle profile.")
    if applicability.regulatory_profile_id != profile.profile_id:
        blockers.append("Applicability profile identifier does not match the bundle profile.")
    if applicability.context.assessment_type != report.assessment_type:
        blockers.append("Applicability and report assessment types differ.")
    if applicability.context.institution_name.casefold() != report.organization.casefold():
        blockers.append("Applicability institution and report organization differ.")
    if not applicability.ready_for_audit:
        blockers.append("Regulatory applicability lacks complete human confirmation.")
    if not report_valid:
        blockers.append("Report fails structural validation.")
    if not report_ready or report.status != ReportStatus.ISSUED:
        blockers.append("Report is not issued with two distinct human approvals.")
    if not audit_valid:
        blockers.append("Audit chain is invalid: " + " ".join(audit_errors))
    if not evidence_valid:
        blockers.append("Evidence custody is invalid: " + " ".join(evidence_errors))
    locators = {item.locator for item in evidence.artifacts}
    missing_evidence = sorted(_report_evidence_refs(report) - locators)
    if missing_evidence:
        blockers.append(
            "Evidence manifest is missing report references: " + ", ".join(missing_evidence)
        )
    conclusions = {item.control_id: item.conclusion for item in report.control_assessments}
    controls = {
        item.control_id: item for item in profile.controls_for(report.assessment_type)
    }
    decisions = {item.control_id: item for item in applicability.decisions}
    if set(decisions) != set(controls):
        blockers.append("Applicability decisions do not cover the exact current control set.")
    for item in applicability.decisions:
        control = controls.get(item.control_id)
        if control is None or item.authority != control.authority or item.source_url != control.source_url:
            blockers.append(
                f"Applicability decision {item.control_id} does not match the current control registry."
            )
        conclusion = conclusions.get(item.control_id)
        if item.decision == ApplicabilityDecision.APPLICABLE and conclusion == ControlConclusion.NOT_APPLICABLE:
            blockers.append(
                f"Applicable control {item.control_id} is marked not_applicable in the report."
            )
        if item.decision == ApplicabilityDecision.NOT_APPLICABLE and conclusion not in {
            None,
            ControlConclusion.NOT_APPLICABLE,
        }:
            blockers.append(
                f"Out-of-scope control {item.control_id} has an assessment conclusion without reconciliation."
            )
        if item.decision == ApplicabilityDecision.REQUIRES_CONFIRMATION:
            blockers.append(f"Control {item.control_id} still requires applicability confirmation.")
    return list(dict.fromkeys(blockers))


def _report_evidence_refs(report: AssessmentReport) -> set[str]:
    values = {report.rules_of_engagement_ref, *report.tester_qualifications}
    for finding in report.findings:
        values.update(finding.evidence_refs)
        values.update(finding.retest_evidence_refs)
    for control in report.control_assessments:
        values.update(control.evidence_refs)
    return {item for item in values if item}


def _json_bytes(value: Any) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _write_zip_entry(archive: zipfile.ZipFile, name: str, body: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o600 << 16
    archive.writestr(info, body, compresslevel=9)


def _safe_archive_path(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and "\\" not in name
        and not any(ord(character) < 32 for character in name)
        and not path.is_absolute()
        and ".." not in path.parts
        and not name.endswith("/")
    )


def _readme(
    report: AssessmentReport,
    applicability: ApplicabilityAssessment,
    purpose: BundlePurpose,
) -> str:
    return (
        "FinRedOps v0.3 audit-support dossier\n"
        "=====================================\n\n"
        f"Report: {report.report_id}\n"
        f"Assessment: {report.assessment_type.value}\n"
        f"Purpose: {purpose.value}\n"
        f"Applicability: {applicability.context.context_id}\n\n"
        "This package contains metadata, report documents, opaque evidence locators, "
        "and hash-chained audit/custody records. It contains no raw evidence. It is not "
        "a legal opinion, regulator acceptance, independent audit opinion, or ISO "
        "certification. Verify the bundle offline before review.\n"
    )


def _failed_verification(path: Path, message: str) -> BundleVerification:
    return BundleVerification(
        valid=False,
        bundle_id="",
        bundle_sha256="",
        manifest_digest="",
        purpose="",
        ready_for_submission=False,
        errors=(message,),
        warnings=(),
    )
