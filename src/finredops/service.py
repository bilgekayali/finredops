"""In-memory governance control plane used by the FinRedOps MVP."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from .audit import AuditChain
from .models import (
    ActionProposal,
    ApprovalRecord,
    Engagement,
    EngagementStatus,
    ExecutionReceipt,
    PolicyDecision,
    Role,
    SubjectKind,
    ensure_aware,
    to_primitive,
)
from .planner import GuardedPlanningGateway
from .policy import PolicyEngine
from .profiles import PolicyProfile, PreflightReport, regulated_financial_profile
from .regulations import RegulatoryProfile, turkey_financial_regulatory_profile
from .runner import SimulationRunner


class FinRedOpsService:
    """Coordinate governance state without hiding authorization decisions."""

    def __init__(
        self,
        profile: PolicyProfile | None = None,
        regulatory_profile: RegulatoryProfile | None = None,
    ) -> None:
        self.engagements: dict[str, Engagement] = {}
        self.proposals: dict[str, ActionProposal] = {}
        self.approvals: list[ApprovalRecord] = []
        self.decisions: dict[str, PolicyDecision] = {}
        self.receipts: dict[str, ExecutionReceipt] = {}
        self.preflight_reports: dict[str, PreflightReport] = {}
        self.audit = AuditChain()
        self.policy = PolicyEngine()
        self.planner = GuardedPlanningGateway()
        self.runner = SimulationRunner()
        self.profile = profile or regulated_financial_profile()
        self.regulatory_profile = (
            regulatory_profile or turkey_financial_regulatory_profile()
        )
        self._emergency_stops: set[str] = set()

    def register_engagement(
        self, engagement: Engagement, *, actor_id: str, now: datetime
    ) -> Engagement:
        now = ensure_aware(now)
        if engagement.engagement_id in self.engagements:
            raise ValueError("Engagement ID already exists.")
        if engagement.status != EngagementStatus.DRAFT:
            raise ValueError("New engagements must start in draft state.")
        if actor_id != engagement.requester_id:
            raise PermissionError("Only the declared requester can register the engagement.")
        report = self.profile.lint(engagement)
        self.engagements[engagement.engagement_id] = engagement
        self.preflight_reports[engagement.engagement_id] = report
        self.audit.append(
            timestamp=now,
            actor_id=actor_id,
            event_type="engagement.registered",
            engagement_id=engagement.engagement_id,
            payload={
                "engagement_digest": engagement.digest(),
                "status": engagement.status,
                "profile_id": self.profile.profile_id,
                "profile_digest": self.profile.digest(),
                "preflight_allowed": report.allowed,
                "preflight_blocking_count": report.blocking_count,
            },
        )
        return engagement

    def submit_engagement(self, engagement_id: str, *, actor_id: str, now: datetime) -> Engagement:
        now = ensure_aware(now)
        engagement = self.engagements[engagement_id]
        if actor_id != engagement.requester_id:
            raise PermissionError("Only the requester can submit the engagement.")
        if engagement.status != EngagementStatus.DRAFT:
            raise ValueError("Only a draft engagement can be submitted.")
        report = self.profile.lint(engagement)
        self.preflight_reports[engagement_id] = report
        if not report.allowed:
            codes = ", ".join(item.code for item in report.findings if item.blocking)
            raise PermissionError(f"Engagement failed institution preflight: {codes}.")
        engagement = engagement.with_status(EngagementStatus.PENDING_APPROVAL)
        self.engagements[engagement_id] = engagement
        self.audit.append(
            timestamp=now,
            actor_id=actor_id,
            event_type="engagement.submitted",
            engagement_id=engagement_id,
            payload={"engagement_digest": engagement.digest()},
        )
        return engagement

    def record_approval(self, approval: ApprovalRecord) -> ApprovalRecord:
        if approval.subject_kind == SubjectKind.ENGAGEMENT:
            subject = self.engagements.get(approval.subject_id)
        else:
            subject = self.proposals.get(approval.subject_id)
        if subject is None:
            raise ValueError("Approval subject does not exist.")
        if approval.subject_digest != subject.digest():
            raise ValueError("Approval digest does not match the current immutable subject.")
        duplicate = any(
            item.subject_kind == approval.subject_kind
            and item.subject_id == approval.subject_id
            and item.actor_id == approval.actor_id
            and item.role == approval.role
            and item.expires_at > approval.decided_at
            for item in self.approvals
        )
        if duplicate:
            raise ValueError("An active approval already exists for this actor and role.")
        self.approvals.append(approval)
        engagement_id = (
            subject.engagement_id
            if isinstance(subject, ActionProposal)
            else subject.engagement_id
        )
        self.audit.append(
            timestamp=approval.decided_at,
            actor_id=approval.actor_id,
            event_type=f"{approval.subject_kind.value}.approval_recorded",
            engagement_id=engagement_id,
            payload={
                "approval_id": approval.approval_id,
                "subject_id": approval.subject_id,
                "subject_digest": approval.subject_digest,
                "role": approval.role,
                "decision": approval.decision,
                "expires_at": approval.expires_at,
            },
        )
        return approval

    def activate_engagement(
        self, engagement_id: str, *, actor_id: str, role: Role, now: datetime
    ) -> Engagement:
        now = ensure_aware(now)
        engagement = self.engagements[engagement_id]
        if role != Role.CONTROL_TEAM:
            raise PermissionError("Only the control team can activate an engagement.")
        if engagement.status != EngagementStatus.PENDING_APPROVAL:
            raise ValueError("Engagement is not pending approval.")
        report = self.profile.lint(engagement)
        self.preflight_reports[engagement_id] = report
        if not report.allowed:
            raise PermissionError("Engagement no longer satisfies the institution profile.")
        ready, reasons = self.policy.engagement_approval_ready(
            engagement, self.approvals, now=now
        )
        if not ready:
            raise PermissionError(" ".join(reasons))
        engagement = engagement.with_status(EngagementStatus.APPROVED)
        self.engagements[engagement_id] = engagement
        self.audit.append(
            timestamp=now,
            actor_id=actor_id,
            event_type="engagement.activated",
            engagement_id=engagement_id,
            payload={"engagement_digest": engagement.digest(), "status": engagement.status},
        )
        return engagement

    def ingest_plan(
        self,
        engagement_id: str,
        document: str | Mapping[str, Any],
        *,
        proposed_by: str,
        now: datetime,
    ) -> tuple[ActionProposal, ...]:
        now = ensure_aware(now)
        engagement = self.engagements[engagement_id]
        if engagement.status != EngagementStatus.APPROVED:
            raise PermissionError("Plans can only be added to an approved engagement.")
        proposals = self.planner.parse(
            document,
            engagement=engagement,
            proposed_by=proposed_by,
            now=now,
        )
        for proposal in proposals:
            if proposal.proposal_id in self.proposals:
                raise ValueError("Proposal ID already exists.")
            self.proposals[proposal.proposal_id] = proposal
            self.audit.append(
                timestamp=now,
                actor_id=proposed_by,
                event_type="proposal.imported",
                engagement_id=engagement_id,
                payload={
                    "proposal_id": proposal.proposal_id,
                    "proposal_digest": proposal.digest(),
                    "action_id": proposal.action_id,
                    "target": proposal.target,
                },
            )
        return proposals

    def execute_proposal(
        self, proposal_id: str, *, actor_id: str, role: Role, now: datetime
    ) -> tuple[PolicyDecision, ExecutionReceipt | None]:
        now = ensure_aware(now)
        if role != Role.OPERATOR:
            raise PermissionError("Only an operator can request proposal execution.")
        proposal = self.proposals[proposal_id]
        engagement = self.engagements[proposal.engagement_id]
        decision = self.policy.evaluate(
            engagement,
            proposal,
            self.approvals,
            now=now,
            emergency_stop=engagement.engagement_id in self._emergency_stops,
        )
        self.decisions[proposal_id] = decision
        self.audit.append(
            timestamp=now,
            actor_id=actor_id,
            event_type="policy.allowed" if decision.allowed else "policy.denied",
            engagement_id=engagement.engagement_id,
            payload={
                "proposal_id": proposal_id,
                "proposal_digest": decision.proposal_digest,
                "code": decision.code,
                "reasons": decision.reasons,
            },
        )
        if not decision.allowed:
            return decision, None
        receipt = self.runner.execute(proposal, now=now)
        self.receipts[proposal_id] = receipt
        self.audit.append(
            timestamp=now,
            actor_id=actor_id,
            event_type="simulation.completed",
            engagement_id=engagement.engagement_id,
            payload={
                "proposal_id": proposal_id,
                "execution_id": receipt.execution_id,
                "proposal_digest": receipt.proposal_digest,
                "evidence_digest": receipt.evidence_digest,
                "runner": receipt.runner,
            },
        )
        return decision, receipt

    def pause_engagement(
        self, engagement_id: str, *, actor_id: str, role: Role, now: datetime
    ) -> Engagement:
        now = ensure_aware(now)
        if role not in {Role.CONTROL_TEAM, Role.EXECUTION_APPROVER}:
            raise PermissionError("Only a control or execution approver can pause an engagement.")
        engagement = self.engagements[engagement_id]
        self._emergency_stops.add(engagement_id)
        engagement = engagement.with_status(EngagementStatus.PAUSED)
        self.engagements[engagement_id] = engagement
        self.audit.append(
            timestamp=now,
            actor_id=actor_id,
            event_type="engagement.emergency_stopped",
            engagement_id=engagement_id,
            payload={"status": engagement.status},
        )
        return engagement

    def snapshot(self, engagement_id: str) -> dict[str, Any]:
        engagement = self.engagements[engagement_id]
        proposal_ids = [
            proposal_id
            for proposal_id, proposal in self.proposals.items()
            if proposal.engagement_id == engagement_id
        ]
        subject_ids = {engagement_id, *proposal_ids}
        return {
            "schema_version": "finredops.snapshot.v2",
            "simulation_only": True,
            "policy_profile": self.profile.as_dict(),
            "regulatory_profile": self.regulatory_profile.as_dict(),
            "preflight": self.preflight_reports[engagement_id].as_dict(),
            "engagement": to_primitive(engagement),
            "engagement_digest": engagement.digest(),
            "proposals": [to_primitive(self.proposals[item]) for item in proposal_ids],
            "approvals": [
                to_primitive(approval)
                for approval in self.approvals
                if approval.subject_id in subject_ids
            ],
            "decisions": {
                item: to_primitive(self.decisions[item])
                for item in proposal_ids
                if item in self.decisions
            },
            "receipts": {
                item: to_primitive(self.receipts[item])
                for item in proposal_ids
                if item in self.receipts
            },
            "audit": self.audit.as_list(),
        }
