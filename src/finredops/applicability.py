"""Human-confirmed regulatory applicability for assurance dossiers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .models import StringEnum, ensure_aware, parse_datetime, sha256_digest, to_primitive
from .regulations import (
    AssessmentType,
    Authority,
    RegulatoryProfile,
    turkey_financial_regulatory_profile,
)


class InstitutionType(StringEnum):
    BANK = "bank"
    PAYMENT_OR_E_MONEY = "payment_or_e_money"
    CAPITAL_MARKET = "capital_market"
    INSURANCE_OR_PENSION = "insurance_or_pension"
    FINANCIAL_TECHNOLOGY_VENDOR = "financial_technology_vendor"
    OTHER_REGULATED_FINANCIAL = "other_regulated_financial"


class ApplicabilityDecision(StringEnum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    REQUIRES_CONFIRMATION = "requires_confirmation"


@dataclass(frozen=True, slots=True)
class ApplicabilityContext:
    context_id: str
    institution_name: str
    institution_type: InstitutionType
    assessment_type: AssessmentType
    bddk_in_scope: bool | None
    spk_in_scope: bool | None
    processes_personal_data: bool | None
    iso27001_in_scope: bool | None
    tse_ts13638_in_scope: bool | None
    outsourced_service: bool
    internet_facing: bool
    critical_system: bool
    rationale: str
    confirmed_by: str = ""
    confirmed_at: datetime | None = None
    exceptions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.context_id, str) or not isinstance(
            self.institution_name, str
        ) or not self.context_id.strip() or not self.institution_name.strip():
            raise ValueError("Applicability context identity and institution are required.")
        if not isinstance(self.rationale, str) or not self.rationale.strip():
            raise ValueError("Applicability rationale is required.")
        scope_flags = (
            self.bddk_in_scope,
            self.spk_in_scope,
            self.processes_personal_data,
            self.iso27001_in_scope,
            self.tse_ts13638_in_scope,
        )
        if any(value is not None and not isinstance(value, bool) for value in scope_flags):
            raise ValueError("Applicability scope flags must be boolean or null.")
        if any(
            not isinstance(value, bool)
            for value in (self.outsourced_service, self.internet_facing, self.critical_system)
        ):
            raise ValueError("Applicability context risk flags must be booleans.")
        if not isinstance(self.confirmed_by, str):
            raise ValueError("confirmed_by must be a string.")
        if bool(self.confirmed_by.strip()) != (self.confirmed_at is not None):
            raise ValueError("confirmed_by and confirmed_at must be recorded together.")
        if self.confirmed_at is not None:
            object.__setattr__(self, "confirmed_at", ensure_aware(self.confirmed_at))
        if any(not isinstance(item, str) or not item.strip() for item in self.exceptions):
            raise ValueError("Applicability exceptions must be non-empty strings.")
        object.__setattr__(self, "exceptions", tuple(item.strip() for item in self.exceptions))

    @property
    def fully_classified(self) -> bool:
        return all(
            value is not None
            for value in (
                self.bddk_in_scope,
                self.spk_in_scope,
                self.processes_personal_data,
                self.iso27001_in_scope,
                self.tse_ts13638_in_scope,
            )
        )

    @property
    def human_confirmed(self) -> bool:
        return self.fully_classified and bool(self.confirmed_by.strip())

    def digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ControlApplicability:
    control_id: str
    authority: Authority
    decision: ApplicabilityDecision
    rationale: str
    source_url: str

    def __post_init__(self) -> None:
        if not self.control_id.strip() or not self.rationale.strip():
            raise ValueError("Applicability decision identity and rationale are required.")
        if not self.source_url.startswith("https://"):
            raise ValueError("Applicability decisions require an HTTPS source URL.")


@dataclass(frozen=True, slots=True)
class ApplicabilityAssessment:
    context: ApplicabilityContext
    regulatory_profile_id: str
    regulatory_profile_digest: str
    decisions: tuple[ControlApplicability, ...]
    warnings: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.regulatory_profile_id.strip() or not _is_digest(
            self.regulatory_profile_digest
        ):
            raise ValueError("Applicability regulatory profile metadata is invalid.")
        if not self.decisions:
            raise ValueError("Applicability assessment requires control decisions.")
        control_ids = [item.control_id for item in self.decisions]
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("Applicability control decisions must be unique.")
        if any(not isinstance(item, str) or not item.strip() for item in self.warnings):
            raise ValueError("Applicability warnings must be non-empty strings.")
        object.__setattr__(self, "decisions", tuple(self.decisions))
        object.__setattr__(self, "warnings", tuple(self.warnings))

    @property
    def ready_for_audit(self) -> bool:
        return self.context.human_confirmed and not any(
            item.decision == ApplicabilityDecision.REQUIRES_CONFIRMATION
            for item in self.decisions
        )

    def digest(self) -> str:
        return sha256_digest(self)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.applicability.v1",
            **to_primitive(self),
            "ready_for_audit": self.ready_for_audit,
            "assessment_digest": self.digest(),
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "ApplicabilityAssessment":
        expected = {
            "schema_version",
            "context",
            "regulatory_profile_id",
            "regulatory_profile_digest",
            "decisions",
            "warnings",
            "ready_for_audit",
            "assessment_digest",
        }
        if set(document) != expected:
            raise ValueError("Applicability document fields do not match the strict schema.")
        if document.get("schema_version") != "finredops.applicability.v1":
            raise ValueError("Unsupported applicability schema version.")
        try:
            raw_context = document["context"]
            raw_decisions = document["decisions"]
            if not isinstance(raw_context, dict) or not isinstance(raw_decisions, list):
                raise ValueError("Applicability context and decisions have invalid types.")
            context_fields = {
                "context_id",
                "institution_name",
                "institution_type",
                "assessment_type",
                "bddk_in_scope",
                "spk_in_scope",
                "processes_personal_data",
                "iso27001_in_scope",
                "tse_ts13638_in_scope",
                "outsourced_service",
                "internet_facing",
                "critical_system",
                "rationale",
                "confirmed_by",
                "confirmed_at",
                "exceptions",
            }
            if set(raw_context) != context_fields:
                raise ValueError("Applicability context fields do not match the strict schema.")
            context = ApplicabilityContext(
                context_id=_required_text(raw_context, "context_id"),
                institution_name=_required_text(raw_context, "institution_name"),
                institution_type=InstitutionType(raw_context["institution_type"]),
                assessment_type=AssessmentType(raw_context["assessment_type"]),
                bddk_in_scope=_optional_bool(raw_context, "bddk_in_scope"),
                spk_in_scope=_optional_bool(raw_context, "spk_in_scope"),
                processes_personal_data=_optional_bool(raw_context, "processes_personal_data"),
                iso27001_in_scope=_optional_bool(raw_context, "iso27001_in_scope"),
                tse_ts13638_in_scope=_optional_bool(raw_context, "tse_ts13638_in_scope"),
                outsourced_service=_required_bool(raw_context, "outsourced_service"),
                internet_facing=_required_bool(raw_context, "internet_facing"),
                critical_system=_required_bool(raw_context, "critical_system"),
                rationale=_required_text(raw_context, "rationale"),
                confirmed_by=_optional_text(raw_context, "confirmed_by"),
                confirmed_at=parse_datetime(raw_context["confirmed_at"])
                if raw_context.get("confirmed_at")
                else None,
                exceptions=_string_tuple(raw_context.get("exceptions", []), "exceptions"),
            )
            decisions_list: list[ControlApplicability] = []
            decision_fields = {
                "control_id",
                "authority",
                "decision",
                "rationale",
                "source_url",
            }
            for item in raw_decisions:
                if not isinstance(item, dict) or set(item) != decision_fields:
                    raise ValueError("Applicability decision fields are invalid.")
                decisions_list.append(
                    ControlApplicability(
                        control_id=_required_text(item, "control_id"),
                        authority=Authority(item["authority"]),
                        decision=ApplicabilityDecision(item["decision"]),
                        rationale=_required_text(item, "rationale"),
                        source_url=_required_text(item, "source_url"),
                    )
                )
            decisions = tuple(decisions_list)
            assessment = cls(
                context=context,
                regulatory_profile_id=_required_text(document, "regulatory_profile_id"),
                regulatory_profile_digest=_required_text(document, "regulatory_profile_digest"),
                decisions=decisions,
                warnings=_string_tuple(document.get("warnings", []), "warnings"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid applicability assessment: {exc}") from exc
        supplied = document.get("assessment_digest")
        if supplied != assessment.digest():
            raise ValueError("Applicability assessment digest does not match its content.")
        if not isinstance(document.get("ready_for_audit"), bool) or (
            document["ready_for_audit"] != assessment.ready_for_audit
        ):
            raise ValueError("Applicability readiness does not match its content.")
        return assessment


def assess_applicability(
    context: ApplicabilityContext,
    profile: RegulatoryProfile | None = None,
) -> ApplicabilityAssessment:
    """Map applicable controls without inferring legal scope from institution type."""

    profile = profile or turkey_financial_regulatory_profile()
    decisions: list[ControlApplicability] = []
    warnings: list[str] = []
    authority_flags: dict[Authority, bool | None] = {
        Authority.BDDK: context.bddk_in_scope,
        Authority.SPK: context.spk_in_scope,
        Authority.KVKK: context.processes_personal_data,
        Authority.TSE: context.tse_ts13638_in_scope,
        Authority.ISO: context.iso27001_in_scope,
    }
    labels = {
        Authority.BDDK: "BDDK tabiiyeti",
        Authority.SPK: "SPK tabiiyeti",
        Authority.KVKK: "kişisel veri işleme kapsamı",
        Authority.TSE: "TSE TS 13638/T2 şartname kapsamı",
        Authority.ISO: "ISO/IEC 27001 BGYS kapsamı",
    }
    for control in profile.controls_for(context.assessment_type):
        flag = authority_flags[control.authority]
        if flag is None:
            decision = ApplicabilityDecision.REQUIRES_CONFIRMATION
            rationale = f"{labels[control.authority]} hukuk/uyum tarafından teyit edilmedi."
        elif flag:
            decision = ApplicabilityDecision.APPLICABLE
            rationale = f"{labels[control.authority]} bu çalışma için teyit edildi."
        else:
            decision = ApplicabilityDecision.NOT_APPLICABLE
            rationale = (
                f"{labels[control.authority]} bu çalışma için kapsam dışı olarak "
                "işaretlendi; gerekçe ve istisnalar insan incelemesine tabidir."
            )
        decisions.append(
            ControlApplicability(
                control_id=control.control_id,
                authority=control.authority,
                decision=decision,
                rationale=rationale,
                source_url=control.source_url,
            )
        )
    if context.institution_type == InstitutionType.BANK and context.bddk_in_scope is False:
        warnings.append(
            "Banka türündeki kuruluş için BDDK kapsam dışı seçildi; özel hukuk/uyum gerekçesi zorunludur."
        )
    if context.institution_type == InstitutionType.CAPITAL_MARKET and context.spk_in_scope is False:
        warnings.append(
            "Sermaye piyasası kuruluşu için SPK kapsam dışı seçildi; özel hukuk/uyum gerekçesi zorunludur."
        )
    if context.processes_personal_data is False and (
        context.internet_facing or context.critical_system
    ):
        warnings.append(
            "Kritik veya internete açık kapsamda kişisel veri işlenmediği beyanı veri envanteriyle doğrulanmalıdır."
        )
    if context.outsourced_service:
        warnings.append(
            "Tedarikçi sorumlulukları, sözleşme güvenlik hükümleri ve kanıt erişimi ayrıca doğrulanmalıdır."
        )
    if not context.human_confirmed:
        warnings.append(
            "Tabiiyet matrisi henüz yetkili hukuk/uyum personeli tarafından tarihli olarak onaylanmadı."
        )
    return ApplicabilityAssessment(
        context=context,
        regulatory_profile_id=profile.profile_id,
        regulatory_profile_digest=profile.digest(),
        decisions=tuple(decisions),
        warnings=tuple(warnings),
    )


def demo_applicability_context(
    *, confirmed_at: datetime
) -> ApplicabilityContext:
    return ApplicabilityContext(
        context_id="APP-FRX-DEMO-001",
        institution_name="Example Financial Institution (Synthetic)",
        institution_type=InstitutionType.BANK,
        assessment_type=AssessmentType.ANNUAL_BANK_PENETRATION,
        bddk_in_scope=True,
        spk_in_scope=False,
        processes_personal_data=True,
        iso27001_in_scope=True,
        tse_ts13638_in_scope=True,
        outsourced_service=False,
        internet_facing=True,
        critical_system=True,
        rationale=(
            "Sentetik yıllık banka sızma testi için BDDK, KVKK, TSE şartname ve BGYS kapsamı; "
            "SPK kapsam dışı senaryosu kaydedildi."
        ),
        confirmed_by="demo.legal-compliance",
        confirmed_at=confirmed_at,
        exceptions=("Sentetik demo; gerçek hukuki tabiiyet kararı değildir.",),
    )


def _required_text(document: dict[str, Any], key: str) -> str:
    value = document[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string.")
    return value.strip()


def _required_bool(document: dict[str, Any], key: str) -> bool:
    value = document[key]
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean.")
    return value


def _optional_text(document: dict[str, Any], key: str) -> str:
    value = document[key]
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string.")
    return value.strip()


def _optional_bool(document: dict[str, Any], key: str) -> bool | None:
    value = document[key]
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"{key} must be boolean or null.")
    return value


def _string_tuple(value: Any, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise ValueError(f"{key} must be a string array.")
    return tuple(item.strip() for item in value)


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
