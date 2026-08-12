from __future__ import annotations

from datetime import datetime, timedelta, timezone

from finredops.models import (
    ActionProposal,
    ApprovalDecision,
    ApprovalRecord,
    AssetKind,
    DataClassification,
    Engagement,
    EngagementStatus,
    Environment,
    Role,
    ScopeAsset,
    SubjectKind,
)


NOW = datetime(2026, 8, 12, 10, 0, tzinfo=timezone.utc)


def make_engagement(*, status: EngagementStatus = EngagementStatus.APPROVED) -> Engagement:
    return Engagement(
        engagement_id="ENG-TEST-001",
        name="Synthetic test engagement",
        requester_id="requester",
        critical_functions=("payments",),
        assets=(
            ScopeAsset(
                asset_id="A-1",
                kind=AssetKind.HOSTNAME,
                value="payments.example.test",
                environment=Environment.LAB,
                data_classification=DataClassification.INTERNAL,
                critical_function="payments",
            ),
        ),
        excluded_assets=(
            ScopeAsset(
                asset_id="A-X",
                kind=AssetKind.HOSTNAME,
                value="excluded.example.test",
                environment=Environment.PRODUCTION,
                data_classification=DataClassification.RESTRICTED,
                critical_function="ledger",
            ),
        ),
        allowed_actions=(
            "http.response_headers.inspect",
            "vulnerability.validation.controlled",
        ),
        window_start=NOW - timedelta(hours=1),
        window_end=NOW + timedelta(hours=1),
        emergency_contacts=("control@example.test",),
        status=status,
    )


def make_proposal(
    engagement: Engagement | None = None,
    *,
    action_id: str = "http.response_headers.inspect",
    target: str = "payments.example.test",
    parameters: dict[str, str] | None = None,
) -> ActionProposal:
    engagement = engagement or make_engagement()
    return ActionProposal(
        proposal_id="PROP-TEST-001",
        engagement_id=engagement.engagement_id,
        action_id=action_id,
        target=target,
        rationale="Review supplied synthetic evidence for the declared control.",
        parameters=parameters
        if parameters is not None
        else {"expected_control": "TEST-01", "evidence_reference": "SYNTH-1"},
        proposed_by="ai-planner",
        proposed_at=NOW,
    )


def make_approval(
    subject: Engagement | ActionProposal,
    *,
    actor_id: str,
    role: Role,
    decision: ApprovalDecision = ApprovalDecision.APPROVED,
    approval_id: str | None = None,
) -> ApprovalRecord:
    is_engagement = isinstance(subject, Engagement)
    return ApprovalRecord(
        approval_id=approval_id or f"APR-{actor_id}-{role.value}",
        subject_kind=SubjectKind.ENGAGEMENT if is_engagement else SubjectKind.PROPOSAL,
        subject_id=subject.engagement_id if is_engagement else subject.proposal_id,
        subject_digest=subject.digest(),
        actor_id=actor_id,
        role=role,
        decision=decision,
        decided_at=NOW - timedelta(minutes=5),
        expires_at=NOW + timedelta(minutes=30),
        comment="Synthetic test approval.",
    )


def proposal_approvals(proposal: ActionProposal) -> tuple[ApprovalRecord, ApprovalRecord]:
    return (
        make_approval(proposal, actor_id="control", role=Role.CONTROL_TEAM),
        make_approval(proposal, actor_id="executor", role=Role.EXECUTION_APPROVER),
    )
