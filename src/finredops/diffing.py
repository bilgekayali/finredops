"""Finding, severity, retest, and control deltas between report revisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import sha256_digest, to_primitive
from .reporting import (
    AssessmentReport,
    ControlConclusion,
    FindingSeverity,
    FindingStatus,
    RetestStatus,
)


_SEVERITY_RANK = {
    FindingSeverity.INFORMATIONAL: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}
_CONTROL_RANK = {
    ControlConclusion.CONFORMS: 0,
    ControlConclusion.NOT_APPLICABLE: 0,
    ControlConclusion.NOT_TESTED: 1,
    ControlConclusion.PARTIAL: 2,
    ControlConclusion.GAP: 3,
}
_CLOSED = {FindingStatus.REMEDIATED, FindingStatus.CLOSED}


@dataclass(frozen=True, slots=True)
class ValueChange:
    item_id: str
    previous: str
    current: str

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and value.strip()
            for value in (self.item_id, self.previous, self.current)
        ):
            raise ValueError("Report delta changes require non-empty string values.")


@dataclass(frozen=True, slots=True)
class ReportDelta:
    baseline_report_id: str
    baseline_digest: str
    current_report_id: str
    current_digest: str
    new_findings: tuple[str, ...]
    missing_findings: tuple[str, ...]
    closed_findings: tuple[str, ...]
    reopened_findings: tuple[str, ...]
    severity_increases: tuple[ValueChange, ...]
    severity_decreases: tuple[ValueChange, ...]
    status_changes: tuple[ValueChange, ...]
    retest_changes: tuple[ValueChange, ...]
    control_regressions: tuple[ValueChange, ...]
    control_improvements: tuple[ValueChange, ...]

    def __post_init__(self) -> None:
        if not self.baseline_report_id.strip() or not self.current_report_id.strip():
            raise ValueError("Report delta identities are required.")
        if not _is_digest(self.baseline_digest) or not _is_digest(self.current_digest):
            raise ValueError("Report delta source digests are invalid.")
        tuple_fields = (
            "new_findings",
            "missing_findings",
            "closed_findings",
            "reopened_findings",
            "severity_increases",
            "severity_decreases",
            "status_changes",
            "retest_changes",
            "control_regressions",
            "control_improvements",
        )
        for name in tuple_fields:
            object.__setattr__(self, name, tuple(getattr(self, name)))
        for name in (
            "new_findings",
            "missing_findings",
            "closed_findings",
            "reopened_findings",
        ):
            values = getattr(self, name)
            if any(not isinstance(item, str) or not item.strip() for item in values):
                raise ValueError(f"{name} must contain non-empty identifiers.")
            if len(values) != len(set(values)):
                raise ValueError(f"{name} must not contain duplicate identifiers.")

    @property
    def has_regressions(self) -> bool:
        return any(
            (
                self.new_findings,
                self.missing_findings,
                self.reopened_findings,
                self.severity_increases,
                self.control_regressions,
            )
        )

    def digest(self) -> str:
        return sha256_digest(self)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "finredops.report-delta.v1",
            **to_primitive(self),
            "has_regressions": self.has_regressions,
            "delta_digest": self.digest(),
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "ReportDelta":
        expected = {
            "schema_version",
            "baseline_report_id",
            "baseline_digest",
            "current_report_id",
            "current_digest",
            "new_findings",
            "missing_findings",
            "closed_findings",
            "reopened_findings",
            "severity_increases",
            "severity_decreases",
            "status_changes",
            "retest_changes",
            "control_regressions",
            "control_improvements",
            "has_regressions",
            "delta_digest",
        }
        if set(document) != expected or document.get("schema_version") != "finredops.report-delta.v1":
            raise ValueError("Report delta fields or schema version are invalid.")

        def text(name: str) -> str:
            value = document[name]
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string.")
            return value.strip()

        def identifiers(name: str) -> tuple[str, ...]:
            value = document[name]
            if not isinstance(value, list) or any(
                not isinstance(item, str) or not item.strip() for item in value
            ):
                raise ValueError(f"{name} must be a string array.")
            return tuple(item.strip() for item in value)

        def changes(name: str) -> tuple[ValueChange, ...]:
            value = document[name]
            if not isinstance(value, list):
                raise ValueError(f"{name} must be an array.")
            parsed: list[ValueChange] = []
            for item in value:
                if not isinstance(item, dict) or set(item) != {
                    "item_id",
                    "previous",
                    "current",
                }:
                    raise ValueError(f"{name} contains invalid change fields.")
                parsed.append(
                    ValueChange(
                        item_id=item["item_id"],
                        previous=item["previous"],
                        current=item["current"],
                    )
                )
            return tuple(parsed)

        delta = cls(
            baseline_report_id=text("baseline_report_id"),
            baseline_digest=text("baseline_digest"),
            current_report_id=text("current_report_id"),
            current_digest=text("current_digest"),
            new_findings=identifiers("new_findings"),
            missing_findings=identifiers("missing_findings"),
            closed_findings=identifiers("closed_findings"),
            reopened_findings=identifiers("reopened_findings"),
            severity_increases=changes("severity_increases"),
            severity_decreases=changes("severity_decreases"),
            status_changes=changes("status_changes"),
            retest_changes=changes("retest_changes"),
            control_regressions=changes("control_regressions"),
            control_improvements=changes("control_improvements"),
        )
        if not isinstance(document.get("has_regressions"), bool) or (
            document["has_regressions"] != delta.has_regressions
        ):
            raise ValueError("Report delta regression flag does not match its content.")
        if document.get("delta_digest") != delta.digest():
            raise ValueError("Report delta digest does not match its content.")
        return delta


def compare_reports(baseline: AssessmentReport, current: AssessmentReport) -> ReportDelta:
    """Compare stable finding/control identities without hiding removed records."""

    if baseline.assessment_type != current.assessment_type:
        raise ValueError("Reports must use the same assessment type.")
    if baseline.organization.casefold() != current.organization.casefold():
        raise ValueError("Reports must belong to the same organization.")
    if current.issued_at < baseline.issued_at:
        raise ValueError("Current report cannot predate its baseline.")

    before = {item.finding_id: item for item in baseline.findings}
    after = {item.finding_id: item for item in current.findings}
    new_ids = sorted(set(after) - set(before))
    missing_ids = sorted(set(before) - set(after))
    closed: list[str] = []
    reopened: list[str] = []
    severity_up: list[ValueChange] = []
    severity_down: list[ValueChange] = []
    status_changes: list[ValueChange] = []
    retest_changes: list[ValueChange] = []

    for finding_id in sorted(set(before) & set(after)):
        old = before[finding_id]
        new = after[finding_id]
        if old.status != new.status:
            status_changes.append(ValueChange(finding_id, old.status.value, new.status.value))
            if old.status not in _CLOSED and new.status in _CLOSED:
                closed.append(finding_id)
            if old.status in _CLOSED and new.status == FindingStatus.OPEN:
                reopened.append(finding_id)
        old_rank = _SEVERITY_RANK[old.severity]
        new_rank = _SEVERITY_RANK[new.severity]
        if new_rank > old_rank:
            severity_up.append(ValueChange(finding_id, old.severity.value, new.severity.value))
        elif new_rank < old_rank:
            severity_down.append(ValueChange(finding_id, old.severity.value, new.severity.value))
        if old.retest_status != new.retest_status:
            retest_changes.append(
                ValueChange(finding_id, old.retest_status.value, new.retest_status.value)
            )

    before_controls = {item.control_id: item for item in baseline.control_assessments}
    after_controls = {item.control_id: item for item in current.control_assessments}
    control_regressions: list[ValueChange] = []
    control_improvements: list[ValueChange] = []
    for control_id in sorted(set(before_controls) | set(after_controls)):
        old = before_controls.get(control_id)
        new = after_controls.get(control_id)
        if old is None:
            if new and new.conclusion in {ControlConclusion.PARTIAL, ControlConclusion.GAP}:
                control_regressions.append(
                    ValueChange(control_id, "unassessed", new.conclusion.value)
                )
            continue
        if new is None:
            control_regressions.append(
                ValueChange(control_id, old.conclusion.value, "missing")
            )
            continue
        old_rank = _CONTROL_RANK[old.conclusion]
        new_rank = _CONTROL_RANK[new.conclusion]
        change = ValueChange(control_id, old.conclusion.value, new.conclusion.value)
        if new_rank > old_rank:
            control_regressions.append(change)
        elif new_rank < old_rank:
            control_improvements.append(change)

    # New informational/low findings still require triage, while high/critical
    # findings are especially visible to consumers of the delta document.
    return ReportDelta(
        baseline_report_id=baseline.report_id,
        baseline_digest=baseline.digest(),
        current_report_id=current.report_id,
        current_digest=current.digest(),
        new_findings=tuple(new_ids),
        missing_findings=tuple(missing_ids),
        closed_findings=tuple(closed),
        reopened_findings=tuple(reopened),
        severity_increases=tuple(severity_up),
        severity_decreases=tuple(severity_down),
        status_changes=tuple(status_changes),
        retest_changes=tuple(retest_changes),
        control_regressions=tuple(control_regressions),
        control_improvements=tuple(control_improvements),
    )


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
