"""Audit-support reporting for regulated security assessments.

The report model deliberately records conclusions and evidence references without
storing exploit recipes or raw sensitive evidence.  It is an audit-support
package, not a legal opinion, certification, or regulator acceptance decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any

from .models import StringEnum, ensure_aware, parse_datetime, sha256_digest, to_primitive
from .regulations import (
    AssessmentType,
    Authority,
    RegulatoryProfile,
    turkey_financial_regulatory_profile,
)


class ReportStatus(StringEnum):
    DRAFT = "draft"
    HUMAN_REVIEW = "human_review"
    APPROVED = "approved"
    ISSUED = "issued"


class FindingSeverity(StringEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StringEnum):
    OPEN = "open"
    RISK_ACCEPTED = "risk_accepted"
    REMEDIATED = "remediated"
    CLOSED = "closed"


class RetestStatus(StringEnum):
    NOT_TESTED = "not_tested"
    PLANNED = "planned"
    FAILED = "failed"
    PASSED = "passed"
    NOT_APPLICABLE = "not_applicable"


class ControlConclusion(StringEnum):
    CONFORMS = "conforms"
    PARTIAL = "partial"
    GAP = "gap"
    NOT_APPLICABLE = "not_applicable"
    NOT_TESTED = "not_tested"


@dataclass(frozen=True, slots=True)
class SecurityFinding:
    finding_id: str
    title: str
    severity: FindingSeverity
    affected_assets: tuple[str, ...]
    summary: str
    business_impact: str
    recommendation: str
    evidence_refs: tuple[str, ...]
    control_refs: tuple[str, ...]
    owner: str = ""
    due_date: str = ""
    status: FindingStatus = FindingStatus.OPEN
    retest_status: RetestStatus = RetestStatus.NOT_TESTED
    retest_date: str = ""
    retest_evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        required = (
            self.finding_id,
            self.title,
            self.summary,
            self.business_impact,
            self.recommendation,
        )
        if not all(value.strip() for value in required):
            raise ValueError("Finding identity, narrative, impact, and recommendation are required.")
        if not self.affected_assets:
            raise ValueError("A finding must identify at least one affected asset.")
        if not self.evidence_refs:
            raise ValueError("A finding must include a safe evidence reference.")
        if not self.control_refs:
            raise ValueError("A finding must map to at least one regulatory control.")
        _validate_evidence_refs(self.evidence_refs)
        _validate_evidence_refs(self.retest_evidence_refs)
        _validate_date(self.due_date, "due_date", allow_empty=True)
        _validate_date(self.retest_date, "retest_date", allow_empty=True)
        object.__setattr__(self, "affected_assets", tuple(self.affected_assets))
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        object.__setattr__(self, "control_refs", tuple(self.control_refs))
        object.__setattr__(self, "retest_evidence_refs", tuple(self.retest_evidence_refs))


@dataclass(frozen=True, slots=True)
class ControlAssessment:
    control_id: str
    conclusion: ControlConclusion
    evidence_refs: tuple[str, ...]
    finding_ids: tuple[str, ...]
    notes: str

    def __post_init__(self) -> None:
        if not self.control_id.strip() or not self.notes.strip():
            raise ValueError("Control assessment identity and human-readable notes are required.")
        _validate_evidence_refs(self.evidence_refs)
        if self.conclusion != ControlConclusion.NOT_APPLICABLE and not (
            self.evidence_refs or self.finding_ids
        ):
            raise ValueError("Applicable control assessments require evidence or a finding.")
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))
        object.__setattr__(self, "finding_ids", tuple(self.finding_ids))


@dataclass(frozen=True, slots=True)
class AssessmentReport:
    report_id: str
    title: str
    assessment_type: AssessmentType
    organization: str
    period_start: str
    period_end: str
    issued_at: datetime
    classification: str
    rules_of_engagement_ref: str
    in_scope_assets: tuple[str, ...]
    excluded_assets: tuple[str, ...]
    tester_organization: str
    lead_tester: str
    independence_declaration: str
    tester_qualifications: tuple[str, ...]
    methodology: tuple[str, ...]
    coverage_areas: tuple[str, ...]
    executive_summary: str
    limitations: tuple[str, ...]
    findings: tuple[SecurityFinding, ...]
    control_assessments: tuple[ControlAssessment, ...]
    regulatory_profile_id: str
    regulatory_profile_digest: str
    status: ReportStatus = ReportStatus.DRAFT
    human_approvals: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        required = (
            self.report_id,
            self.title,
            self.organization,
            self.classification,
            self.rules_of_engagement_ref,
            self.tester_organization,
            self.lead_tester,
            self.executive_summary,
            self.regulatory_profile_id,
            self.regulatory_profile_digest,
        )
        if not all(value.strip() for value in required):
            raise ValueError("Report identity, ownership, scope, and profile metadata are required.")
        _validate_date(self.period_start, "period_start")
        _validate_date(self.period_end, "period_end")
        if date.fromisoformat(self.period_end) < date.fromisoformat(self.period_start):
            raise ValueError("Report period_end cannot precede period_start.")
        if not self.in_scope_assets or not self.methodology or not self.coverage_areas:
            raise ValueError("Report scope, methodology, and coverage are required.")
        object.__setattr__(self, "issued_at", ensure_aware(self.issued_at))
        for name in (
            "in_scope_assets",
            "excluded_assets",
            "tester_qualifications",
            "methodology",
            "coverage_areas",
            "limitations",
            "findings",
            "control_assessments",
            "human_approvals",
        ):
            object.__setattr__(self, name, tuple(getattr(self, name)))

    def digest(self) -> str:
        return sha256_digest(self)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.regulatory-report.v1",
            **to_primitive(self),
            "report_digest": self.digest(),
            "audit_support_only": True,
        }


@dataclass(frozen=True, slots=True)
class ReportIssue:
    code: str
    message: str
    path: str
    blocking: bool


@dataclass(frozen=True, slots=True)
class ReportValidation:
    issues: tuple[ReportIssue, ...]

    @property
    def valid(self) -> bool:
        return not any(issue.blocking for issue in self.issues)

    @property
    def ready_for_issue(self) -> bool:
        return self.valid and not any(issue.code == "HUMAN_APPROVAL_REQUIRED" for issue in self.issues)

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "ready_for_issue": self.ready_for_issue,
            "issues": to_primitive(self.issues),
        }


class ReportDocumentError(ValueError):
    """Raised when a report JSON document does not match the strict model."""


REQUIRED_COVERAGE: dict[AssessmentType, frozenset[str]] = {
    AssessmentType.ANNUAL_BANK_PENETRATION: frozenset(
        {
            "communication_infrastructure",
            "dns",
            "domain_and_endpoints",
            "email",
            "database",
            "web",
            "mobile",
            "wireless",
            "atm",
            "service_resilience",
        }
    ),
    AssessmentType.VENDOR_SOURCE_CODE_REVIEW: frozenset(
        {
            "security_requirements",
            "sast",
            "manual_code_review",
            "dependency_analysis",
            "secret_detection",
            "authentication_authorization",
            "cryptography",
            "logging_error_handling",
            "release_integrity",
        }
    ),
    AssessmentType.VENDOR_APPLICATION_PENETRATION: frozenset(
        {
            "unauthenticated",
            "authenticated",
            "authorization",
            "session_management",
            "input_validation",
            "api",
            "business_logic",
            "data_protection",
            "error_handling",
            "retest",
        }
    ),
    AssessmentType.REMEDIATION_VERIFICATION: frozenset(
        {"finding_traceability", "retest", "closure_evidence"}
    ),
}


def validate_report(
    report: AssessmentReport, profile: RegulatoryProfile | None = None
) -> ReportValidation:
    """Validate audit completeness without claiming regulatory acceptance."""

    profile = profile or turkey_financial_regulatory_profile()
    issues: list[ReportIssue] = []

    def add(code: str, message: str, path: str, *, blocking: bool = True) -> None:
        issues.append(ReportIssue(code, message, path, blocking))

    if report.regulatory_profile_id != profile.profile_id or (
        report.regulatory_profile_digest != profile.digest()
    ):
        add(
            "PROFILE_MISMATCH",
            "Report regulatory profile metadata does not match the supplied profile.",
            "regulatory_profile_digest",
        )

    missing_coverage = REQUIRED_COVERAGE[report.assessment_type] - set(report.coverage_areas)
    for coverage in sorted(missing_coverage):
        add(
            "COVERAGE_MISSING",
            f"Mandatory assessment area {coverage!r} is not recorded.",
            "coverage_areas",
        )

    finding_ids = [finding.finding_id for finding in report.findings]
    if len(finding_ids) != len(set(finding_ids)):
        add("DUPLICATE_FINDING", "Finding identifiers must be unique.", "findings")
    finding_id_set = set(finding_ids)
    applicable_controls = {
        control.control_id: control
        for control in profile.controls_for(report.assessment_type)
    }
    assessed_ids = [item.control_id for item in report.control_assessments]
    if len(assessed_ids) != len(set(assessed_ids)):
        add("DUPLICATE_CONTROL", "Control assessments must be unique.", "control_assessments")
    for control_id in sorted(set(applicable_controls) - set(assessed_ids)):
        add(
            "CONTROL_NOT_ASSESSED",
            f"Applicable control {control_id} has no recorded conclusion.",
            "control_assessments",
        )

    for index, assessment in enumerate(report.control_assessments):
        control = profile.get(assessment.control_id)
        if control is None:
            add(
                "UNKNOWN_CONTROL",
                f"Control {assessment.control_id!r} is not in the selected profile.",
                f"control_assessments[{index}].control_id",
            )
        elif report.assessment_type not in control.assessment_types:
            add(
                "CONTROL_NOT_APPLICABLE_TO_TYPE",
                f"Control {assessment.control_id!r} is not mapped to this assessment type.",
                f"control_assessments[{index}].control_id",
            )
        unknown_findings = set(assessment.finding_ids) - finding_id_set
        if unknown_findings:
            add(
                "CONTROL_FINDING_UNKNOWN",
                "Control assessment references unknown findings: "
                + ", ".join(sorted(unknown_findings)),
                f"control_assessments[{index}].finding_ids",
            )

    for index, finding in enumerate(report.findings):
        for control_id in finding.control_refs:
            if control_id not in applicable_controls:
                add(
                    "FINDING_CONTROL_INVALID",
                    f"Finding maps to unknown or inapplicable control {control_id!r}.",
                    f"findings[{index}].control_refs",
                )
        if finding.severity in {FindingSeverity.HIGH, FindingSeverity.CRITICAL} and (
            finding.status == FindingStatus.OPEN
        ):
            if not finding.owner.strip() or not finding.due_date:
                add(
                    "HIGH_RISK_OWNERSHIP_REQUIRED",
                    "Open high or critical findings require an owner and due date.",
                    f"findings[{index}]",
                )
        if finding.retest_status == RetestStatus.PASSED and not (
            finding.retest_date and finding.retest_evidence_refs
        ):
            add(
                "RETEST_EVIDENCE_REQUIRED",
                "A passed retest requires a date and separate closure evidence.",
                f"findings[{index}].retest_status",
            )

    if report.assessment_type == AssessmentType.ANNUAL_BANK_PENETRATION:
        if not report.independence_declaration.strip():
            add(
                "INDEPENDENCE_REQUIRED",
                "Annual bank penetration testing requires an independence declaration.",
                "independence_declaration",
            )
        if not report.tester_qualifications:
            add(
                "QUALIFICATION_REQUIRED",
                "Annual bank penetration testing requires tester qualification evidence.",
                "tester_qualifications",
            )

    if report.status in {ReportStatus.APPROVED, ReportStatus.ISSUED}:
        if len(set(report.human_approvals)) < 2:
            add(
                "HUMAN_APPROVAL_REQUIRED",
                "Approved or issued reports require two distinct human approval records.",
                "human_approvals",
            )
    elif len(set(report.human_approvals)) < 2:
        add(
            "HUMAN_APPROVAL_REQUIRED",
            "Draft is structurally valid but is not ready for issue without two human approvals.",
            "human_approvals",
            blocking=False,
        )

    return ReportValidation(tuple(issues))


def regulatory_crosswalk(
    report: AssessmentReport, profile: RegulatoryProfile | None = None
) -> dict[str, Any]:
    profile = profile or turkey_financial_regulatory_profile()
    assessments = {item.control_id: item for item in report.control_assessments}
    findings = {finding.finding_id: finding for finding in report.findings}
    rows: list[dict[str, Any]] = []
    for control in profile.controls_for(report.assessment_type):
        assessment = assessments.get(control.control_id)
        rows.append(
            {
                "control_id": control.control_id,
                "authority": control.authority,
                "instrument": control.instrument,
                "reference": control.reference,
                "objective_summary": control.objective_summary,
                "source_url": control.source_url,
                "applicability_note": control.applicability_note,
                "conclusion": assessment.conclusion if assessment else ControlConclusion.NOT_TESTED,
                "evidence_refs": assessment.evidence_refs if assessment else (),
                "finding_ids": assessment.finding_ids if assessment else (),
                "finding_severities": [
                    findings[item].severity
                    for item in assessment.finding_ids
                    if item in findings
                ]
                if assessment
                else [],
                "notes": assessment.notes if assessment else "No conclusion recorded.",
            }
        )
    validation = validate_report(report, profile)
    return {
        "schema_version": "finredops.regulatory-crosswalk.v1",
        "profile": profile.as_dict(),
        "report_id": report.report_id,
        "report_digest": report.digest(),
        "assessment_type": report.assessment_type,
        "controls": to_primitive(rows),
        "validation": validation.as_dict(),
        "audit_support_only": True,
    }


def render_report_markdown(
    report: AssessmentReport, profile: RegulatoryProfile | None = None
) -> str:
    profile = profile or turkey_financial_regulatory_profile()
    validation = validate_report(report, profile)
    crosswalk = regulatory_crosswalk(report, profile)
    severity_counts = {
        severity.value: sum(1 for item in report.findings if item.severity == severity)
        for severity in FindingSeverity
    }
    lines = [
        f"# {report.title}",
        "",
        "> **Denetim destek taslağıdır.** Hukuki görüş, düzenleyici kabul, bağımsız denetim görüşü veya ISO belgelendirmesi değildir.",
        "",
        "## Belge kontrolü",
        "",
        "| Alan | Değer |",
        "|---|---|",
        f"| Rapor kimliği | `{report.report_id}` |",
        f"| Kuruluş | {report.organization} |",
        f"| Değerlendirme | `{report.assessment_type.value}` |",
        f"| Dönem | {report.period_start} – {report.period_end} |",
        f"| Durum | `{report.status.value}` |",
        f"| Sınıflandırma | {report.classification} |",
        f"| Düzenleyici profil | `{profile.profile_id}` / `{profile.digest()[:16]}` |",
        f"| Rapor özeti | `{report.digest()}` |",
        "",
        "## Yönetici özeti",
        "",
        report.executive_summary,
        "",
        "## Kapsam ve yöntem",
        "",
        f"- Çalışma kuralları: `{report.rules_of_engagement_ref}`",
        f"- Test kuruluşu / lideri: {report.tester_organization} / {report.lead_tester}",
        f"- Bağımsızlık beyanı: {report.independence_declaration or 'Kaydedilmedi'}",
        f"- Kapsam: {', '.join(f'`{item}`' for item in report.in_scope_assets)}",
        f"- Hariç tutulanlar: {', '.join(f'`{item}`' for item in report.excluded_assets) or 'Yok'}",
        f"- Yöntem: {', '.join(report.methodology)}",
        f"- Zorunlu kapsam alanları: {', '.join(f'`{item}`' for item in report.coverage_areas)}",
        "",
        "## Bulgu özeti",
        "",
        "| Kritik | Yüksek | Orta | Düşük | Bilgi |",
        "|---:|---:|---:|---:|---:|",
        f"| {severity_counts['critical']} | {severity_counts['high']} | {severity_counts['medium']} | {severity_counts['low']} | {severity_counts['informational']} |",
        "",
    ]
    for finding in report.findings:
        lines.extend(
            [
                f"### {finding.finding_id} — {finding.title}",
                "",
                f"- Önem / durum: `{finding.severity.value}` / `{finding.status.value}`",
                f"- Etkilenen varlık: {', '.join(f'`{item}`' for item in finding.affected_assets)}",
                f"- Güvenli özet: {finding.summary}",
                f"- İş etkisi: {finding.business_impact}",
                f"- Öneri: {finding.recommendation}",
                f"- Kanıt: {', '.join(f'`{item}`' for item in finding.evidence_refs)}",
                f"- Kontroller: {', '.join(f'`{item}`' for item in finding.control_refs)}",
                f"- Sorumlu / hedef tarih: {finding.owner or 'Atanmadı'} / {finding.due_date or 'Atanmadı'}",
                f"- Yeniden test: `{finding.retest_status.value}` / {finding.retest_date or 'Tarih yok'}",
                "",
            ]
        )
    lines.extend(
        [
            "## Düzenleyici çapraz kontrol",
            "",
            "| Kurum | Dayanak | Sonuç | Kanıt / bulgu |",
            "|---|---|---|---|",
        ]
    )
    for row in crosswalk["controls"]:
        evidence = [*row["evidence_refs"], *row["finding_ids"]]
        lines.append(
            f"| {row['authority']} | `{row['control_id']}` — {row['reference']} | `{row['conclusion']}` | {', '.join(evidence) or '—'} |"
        )
    lines.extend(
        [
            "",
            "## Sınırlamalar ve insan onayı",
            "",
            *(f"- {item}" for item in report.limitations),
            f"- Yapısal doğrulama: `{'geçti' if validation.valid else 'başarısız'}`",
            f"- Yayıma hazır: `{'evet' if validation.ready_for_issue else 'hayır'}`",
            f"- İnsan onay kayıtları: {', '.join(report.human_approvals) or 'Henüz yok'}",
            "- BDDK/SPK tabiiyeti, TSE şartname kapsamı, istisnalar ve teslim süreleri her çalışma öncesinde hukuk/uyum ve yetkili test sorumlularınca doğrulanmalıdır.",
            "- TS 13638/T2 ve ISO/IEC kontrol metinleri kuruluşun yetkili/lisanslı standart nüshalarından teyit edilmelidir.",
            "- Ham kanıtlar rapora gömülmemeli; erişim kontrollü kanıt deposunda tutulmalıdır.",
            "",
        ]
    )
    return "\n".join(lines)


def demo_regulatory_report(*, issued_at: datetime | None = None) -> AssessmentReport:
    """Return a complete synthetic annual-bank report draft."""

    profile = turkey_financial_regulatory_profile()
    issued_at = ensure_aware(issued_at or datetime.now(timezone.utc))
    applicable = profile.controls_for(AssessmentType.ANNUAL_BANK_PENETRATION)
    finding = SecurityFinding(
        finding_id="FRX-SYN-001",
        title="Synthetic security-header policy gap",
        severity=FindingSeverity.MEDIUM,
        affected_assets=("payments-lab.example.test",),
        summary="Bundled demonstration evidence records a policy header requiring human review; no live target was contacted.",
        business_impact="A missing browser-side policy could reduce defence in depth in an equivalent real deployment.",
        recommendation="Confirm the application baseline, document the approved policy, and retest in an authorized environment.",
        evidence_refs=("evidence://FRX-DEMO-2026-001/headers/SYNTH-HTTP-001",),
        control_refs=(
            "TR-BDDK-GEN-2012-1",
            "TR-KVKK-GUIDE-3.2",
            "ISO27001-A.8.8-A.8.16",
        ),
        owner="Synthetic Application Owner",
        due_date="2026-09-30",
    )
    control_assessments = []
    for control in applicable:
        if control.control_id == "TR-SPK-VII-128.10-8-6-7":
            control_assessments.append(
                ControlAssessment(
                    control.control_id,
                    ControlConclusion.NOT_APPLICABLE,
                    (),
                    (),
                    "Synthetic bank scenario; SPK entity applicability requires legal confirmation.",
                )
            )
            continue
        linked = control.control_id in finding.control_refs
        control_assessments.append(
            ControlAssessment(
                control.control_id,
                ControlConclusion.PARTIAL if linked else ControlConclusion.CONFORMS,
                (f"evidence://FRX-DEMO-2026-001/crosswalk/{control.control_id}",),
                (finding.finding_id,) if linked else (),
                "Synthetic evidence mapping for product demonstration; human verification is required.",
            )
        )
    return AssessmentReport(
        report_id="FRX-RPT-2026-001",
        title="Sentetik Yıllık Banka Sızma Testi Denetim Destek Raporu",
        assessment_type=AssessmentType.ANNUAL_BANK_PENETRATION,
        organization="Example Financial Institution (Synthetic)",
        period_start="2026-08-01",
        period_end="2026-08-12",
        issued_at=issued_at,
        classification="RESTRICTED — SYNTHETIC",
        rules_of_engagement_ref="attachment://FRX-DEMO-2026-001/approved-roe",
        in_scope_assets=("payments-lab.example.test", "identity-lab.example.test"),
        excluded_assets=("core-banking.example.test",),
        tester_organization="Independent Test Team (Synthetic)",
        lead_tester="Synthetic Lead Tester",
        independence_declaration="Test ekibinin geliştirme ve işletim ekiplerinden ayrı olduğu sentetik senaryo kapsamında beyan edilmiştir.",
        tester_qualifications=("qualification-evidence://synthetic/lead-tester",),
        methodology=(
            "BDDK 2012/1 scope matrix",
            "TSE TS 13638/T2 qualification and scope matrix",
            "risk-based safe validation",
            "evidence-based retest",
        ),
        coverage_areas=tuple(sorted(REQUIRED_COVERAGE[AssessmentType.ANNUAL_BANK_PENETRATION])),
        executive_summary=(
            "Bu belge, canlı hedefe erişmeden üretilen sentetik kanıtlarla FinRedOps raporlama "
            "ve mevzuat çapraz kontrol kabiliyetini gösterir. Tek orta seviye örnek bulgu insan "
            "incelemesi ve yetkili ortamda yeniden test gerektirir."
        ),
        limitations=(
            "Çalışma yalnızca paketlenmiş sentetik kanıt kullandı; sonuçlar gerçek bir kuruluşa genellenemez.",
            "Hizmet engelleme ve sosyal mühendislik gibi etkili faaliyetler yerleşik çalıştırıcı tarafından yürütülmez.",
        ),
        findings=(finding,),
        control_assessments=tuple(control_assessments),
        regulatory_profile_id=profile.profile_id,
        regulatory_profile_digest=profile.digest(),
    )


def report_template_document(
    assessment_type: AssessmentType,
    profile: RegulatoryProfile | None = None,
) -> dict[str, Any]:
    """Return a fillable JSON template without making assessment conclusions."""

    profile = profile or turkey_financial_regulatory_profile()
    return {
        "schema_version": "finredops.regulatory-report.v1",
        "report_id": "TODO",
        "title": "TODO",
        "assessment_type": assessment_type.value,
        "organization": "TODO",
        "period_start": "YYYY-MM-DD",
        "period_end": "YYYY-MM-DD",
        "issued_at": "YYYY-MM-DDTHH:MM:SSZ",
        "classification": "RESTRICTED",
        "rules_of_engagement_ref": "attachment://TODO/approved-roe",
        "in_scope_assets": [],
        "excluded_assets": [],
        "tester_organization": "TODO",
        "lead_tester": "TODO",
        "independence_declaration": "TODO",
        "tester_qualifications": [],
        "methodology": [],
        "coverage_areas": sorted(REQUIRED_COVERAGE[assessment_type]),
        "executive_summary": "TODO",
        "limitations": [],
        "findings": [],
        "control_assessments": [
            {
                "control_id": control.control_id,
                "conclusion": ControlConclusion.NOT_TESTED.value,
                "evidence_refs": [],
                "finding_ids": [],
                "notes": "TODO: record evidence-based conclusion or justified applicability decision.",
            }
            for control in profile.controls_for(assessment_type)
        ],
        "regulatory_profile_id": profile.profile_id,
        "regulatory_profile_digest": profile.digest(),
        "status": ReportStatus.DRAFT.value,
        "human_approvals": [],
        "audit_support_only": True,
    }


def report_from_document(document: Any) -> AssessmentReport:
    """Load a strict JSON-compatible report and verify any supplied digest."""

    if not isinstance(document, dict):
        raise ReportDocumentError("Report must be a JSON object.")
    report_fields = {
        "report_id",
        "title",
        "assessment_type",
        "organization",
        "period_start",
        "period_end",
        "issued_at",
        "classification",
        "rules_of_engagement_ref",
        "in_scope_assets",
        "excluded_assets",
        "tester_organization",
        "lead_tester",
        "independence_declaration",
        "tester_qualifications",
        "methodology",
        "coverage_areas",
        "executive_summary",
        "limitations",
        "findings",
        "control_assessments",
        "regulatory_profile_id",
        "regulatory_profile_digest",
        "status",
        "human_approvals",
    }
    metadata = {"schema_version", "report_digest", "audit_support_only"}
    missing = report_fields - set(document)
    unknown = set(document) - report_fields - metadata
    if missing or unknown:
        raise ReportDocumentError(
            f"Invalid report fields: missing {sorted(missing)}, unknown {sorted(unknown)}."
        )
    if document.get("schema_version") != "finredops.regulatory-report.v1":
        raise ReportDocumentError("Unsupported regulatory report schema version.")
    if document.get("audit_support_only") is not True:
        raise ReportDocumentError("Report must preserve audit_support_only=true.")

    def text_field(name: str, *, allow_empty: bool = False) -> str:
        value = document[name]
        if not isinstance(value, str) or (not allow_empty and not value.strip()):
            raise ReportDocumentError(f"{name} must be a string with valid content.")
        return value.strip()

    def string_array(name: str, *, allow_empty: bool = True) -> tuple[str, ...]:
        value = document[name]
        if not isinstance(value, list) or (not allow_empty and not value):
            raise ReportDocumentError(f"{name} must be a string array.")
        if any(not isinstance(item, str) or not item.strip() for item in value):
            raise ReportDocumentError(f"{name} must contain only non-empty strings.")
        return tuple(item.strip() for item in value)

    finding_keys = {
        "finding_id",
        "title",
        "severity",
        "affected_assets",
        "summary",
        "business_impact",
        "recommendation",
        "evidence_refs",
        "control_refs",
        "owner",
        "due_date",
        "status",
        "retest_status",
        "retest_date",
        "retest_evidence_refs",
    }
    control_keys = {"control_id", "conclusion", "evidence_refs", "finding_ids", "notes"}
    try:
        findings_raw = document["findings"]
        controls_raw = document["control_assessments"]
        if not isinstance(findings_raw, list) or not isinstance(controls_raw, list):
            raise ReportDocumentError("findings and control_assessments must be arrays.")
        findings: list[SecurityFinding] = []
        for index, item in enumerate(findings_raw):
            if not isinstance(item, dict) or set(item) != finding_keys:
                raise ReportDocumentError(f"findings[{index}] has invalid fields.")
            findings.append(
                SecurityFinding(
                    finding_id=item["finding_id"],
                    title=item["title"],
                    severity=FindingSeverity(item["severity"]),
                    affected_assets=_document_strings(item["affected_assets"], f"findings[{index}].affected_assets", False),
                    summary=item["summary"],
                    business_impact=item["business_impact"],
                    recommendation=item["recommendation"],
                    evidence_refs=_document_strings(item["evidence_refs"], f"findings[{index}].evidence_refs", False),
                    control_refs=_document_strings(item["control_refs"], f"findings[{index}].control_refs", False),
                    owner=item["owner"],
                    due_date=item["due_date"],
                    status=FindingStatus(item["status"]),
                    retest_status=RetestStatus(item["retest_status"]),
                    retest_date=item["retest_date"],
                    retest_evidence_refs=_document_strings(item["retest_evidence_refs"], f"findings[{index}].retest_evidence_refs", True),
                )
            )
        controls: list[ControlAssessment] = []
        for index, item in enumerate(controls_raw):
            if not isinstance(item, dict) or set(item) != control_keys:
                raise ReportDocumentError(f"control_assessments[{index}] has invalid fields.")
            controls.append(
                ControlAssessment(
                    control_id=item["control_id"],
                    conclusion=ControlConclusion(item["conclusion"]),
                    evidence_refs=_document_strings(item["evidence_refs"], f"control_assessments[{index}].evidence_refs", True),
                    finding_ids=_document_strings(item["finding_ids"], f"control_assessments[{index}].finding_ids", True),
                    notes=item["notes"],
                )
            )
        report = AssessmentReport(
            report_id=text_field("report_id"),
            title=text_field("title"),
            assessment_type=AssessmentType(text_field("assessment_type")),
            organization=text_field("organization"),
            period_start=text_field("period_start"),
            period_end=text_field("period_end"),
            issued_at=parse_datetime(text_field("issued_at")),
            classification=text_field("classification"),
            rules_of_engagement_ref=text_field("rules_of_engagement_ref"),
            in_scope_assets=string_array("in_scope_assets", allow_empty=False),
            excluded_assets=string_array("excluded_assets"),
            tester_organization=text_field("tester_organization"),
            lead_tester=text_field("lead_tester"),
            independence_declaration=text_field("independence_declaration", allow_empty=True),
            tester_qualifications=string_array("tester_qualifications"),
            methodology=string_array("methodology", allow_empty=False),
            coverage_areas=string_array("coverage_areas", allow_empty=False),
            executive_summary=text_field("executive_summary"),
            limitations=string_array("limitations"),
            findings=tuple(findings),
            control_assessments=tuple(controls),
            regulatory_profile_id=text_field("regulatory_profile_id"),
            regulatory_profile_digest=text_field("regulatory_profile_digest"),
            status=ReportStatus(text_field("status")),
            human_approvals=string_array("human_approvals"),
        )
    except ReportDocumentError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ReportDocumentError(f"Invalid report value: {exc}") from exc
    supplied_digest = document.get("report_digest")
    if supplied_digest is not None and supplied_digest != report.digest():
        raise ReportDocumentError("Supplied report_digest does not match the report body.")
    return report


def _validate_evidence_refs(values: tuple[str, ...]) -> None:
    allowed = ("evidence://", "attachment://", "qualification-evidence://")
    for value in values:
        if not isinstance(value, str) or not value.startswith(allowed):
            raise ValueError("Evidence references must use an approved opaque URI scheme.")


def _document_strings(value: Any, path: str, allow_empty: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ReportDocumentError(f"{path} must be a string array.")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ReportDocumentError(f"{path} must contain only non-empty strings.")
    return tuple(item.strip() for item in value)


def _validate_date(value: str, name: str, *, allow_empty: bool = False) -> None:
    if allow_empty and not value:
        return
    try:
        date.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must use YYYY-MM-DD format.") from exc
