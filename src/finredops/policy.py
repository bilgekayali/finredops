"""Deny-by-default authorization policy for engagements and proposals."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from typing import Any

from .catalog import ACTION_CATALOG
from .models import (
    ActionProposal,
    ApprovalDecision,
    ApprovalRecord,
    Engagement,
    EngagementStatus,
    PolicyDecision,
    RiskLevel,
    Role,
    SubjectKind,
    ensure_aware,
)


_FORBIDDEN_PARAMETER_KEYS = frozenset(
    {
        "command",
        "credential",
        "exploit",
        "password",
        "payload",
        "script",
        "secret",
        "shell",
        "token",
    }
)


def _parameter_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, Mapping):
        for key, child in value.items():
            keys.add(str(key).casefold())
            keys.update(_parameter_keys(child))
    elif isinstance(value, (list, tuple)):
        for child in value:
            keys.update(_parameter_keys(child))
    return keys


def _current_approvals(
    approvals: Iterable[ApprovalRecord],
    *,
    kind: SubjectKind,
    subject_id: str,
    digest: str,
    now: datetime,
) -> list[ApprovalRecord]:
    return [
        approval
        for approval in approvals
        if approval.subject_kind == kind
        and approval.subject_id == subject_id
        and approval.subject_digest == digest
        and approval.decided_at <= now < approval.expires_at
    ]


class PolicyEngine:
    """Evaluate immutable, digest-bound approvals against explicit policy."""

    engagement_roles = frozenset({Role.BUSINESS_OWNER, Role.CONTROL_TEAM})
    proposal_roles = frozenset({Role.CONTROL_TEAM, Role.EXECUTION_APPROVER})

    def engagement_approval_ready(
        self,
        engagement: Engagement,
        approvals: Iterable[ApprovalRecord],
        *,
        now: datetime,
    ) -> tuple[bool, tuple[str, ...]]:
        now = ensure_aware(now)
        current = _current_approvals(
            approvals,
            kind=SubjectKind.ENGAGEMENT,
            subject_id=engagement.engagement_id,
            digest=engagement.digest(),
            now=now,
        )
        reasons: list[str] = []
        valid_ttl = timedelta(minutes=engagement.approval_ttl_minutes)
        if any(item.expires_at - item.decided_at > valid_ttl for item in current):
            reasons.append("An engagement approval exceeds the configured approval TTL.")
        current = [
            item for item in current if item.expires_at - item.decided_at <= valid_ttl
        ]
        if any(item.decision == ApprovalDecision.DENIED for item in current):
            reasons.append("A current engagement denial exists.")
        approved = [item for item in current if item.decision == ApprovalDecision.APPROVED]
        roles = {item.role for item in approved}
        missing = self.engagement_roles - roles
        if missing:
            reasons.append(
                "Missing engagement approval roles: "
                + ", ".join(sorted(role.value for role in missing))
                + "."
            )
        actors = {item.actor_id for item in approved if item.role in self.engagement_roles}
        if len(actors) < len(self.engagement_roles):
            reasons.append("Engagement approvals must come from distinct actors.")
        if engagement.requester_id in actors:
            reasons.append("The requester cannot approve the engagement.")
        return not reasons, tuple(reasons)

    def evaluate(
        self,
        engagement: Engagement,
        proposal: ActionProposal,
        approvals: Iterable[ApprovalRecord],
        *,
        now: datetime,
        emergency_stop: bool = False,
    ) -> PolicyDecision:
        now = ensure_aware(now)
        reasons: list[str] = []
        digest = proposal.digest()

        if emergency_stop:
            reasons.append("Emergency stop is active.")
        if proposal.engagement_id != engagement.engagement_id:
            reasons.append("Proposal is bound to a different engagement.")
        if engagement.status != EngagementStatus.APPROVED:
            reasons.append("Engagement is not approved and active.")
        if not engagement.window_start <= now <= engagement.window_end:
            reasons.append("Current time is outside the authorized execution window.")
        if not engagement.window_start <= proposal.proposed_at <= engagement.window_end:
            reasons.append("Proposal was created outside the authorized window.")

        try:
            excluded = any(asset.contains(proposal.target) for asset in engagement.excluded_assets)
            included = any(asset.contains(proposal.target) for asset in engagement.assets)
        except ValueError:
            excluded = False
            included = False
        if excluded:
            reasons.append("Target is explicitly excluded from the engagement.")
        elif not included:
            reasons.append("Target is outside the exact approved scope.")

        action = ACTION_CATALOG.get(proposal.action_id)
        if action is None:
            reasons.append("Action is not present in the closed catalog.")
        else:
            if proposal.action_id not in engagement.allowed_actions:
                reasons.append("Action is not allowed by the engagement.")
            if not action.supported_in_mvp:
                reasons.append("Action has no approved v0.1 runner implementation.")
            if action.risk_level in {RiskLevel.CONTROLLED, RiskLevel.IMPACTING}:
                reasons.append("The simulation runner rejects controlled or impacting actions.")
            unexpected = set(proposal.parameters) - action.allowed_parameter_keys
            if unexpected:
                reasons.append(
                    "Unexpected action parameters: " + ", ".join(sorted(unexpected)) + "."
                )

        forbidden = _parameter_keys(proposal.parameters) & _FORBIDDEN_PARAMETER_KEYS
        if forbidden:
            reasons.append(
                "Forbidden command or secret-bearing parameters: "
                + ", ".join(sorted(forbidden))
                + "."
            )

        current = _current_approvals(
            approvals,
            kind=SubjectKind.PROPOSAL,
            subject_id=proposal.proposal_id,
            digest=digest,
            now=now,
        )
        valid_ttl = timedelta(minutes=engagement.approval_ttl_minutes)
        if any(item.expires_at - item.decided_at > valid_ttl for item in current):
            reasons.append("A proposal approval exceeds the configured approval TTL.")
        current = [
            item for item in current if item.expires_at - item.decided_at <= valid_ttl
        ]
        if any(item.decision == ApprovalDecision.DENIED for item in current):
            reasons.append("A current proposal denial exists.")
        approved = [item for item in current if item.decision == ApprovalDecision.APPROVED]
        roles = {item.role for item in approved}
        missing = self.proposal_roles - roles
        if missing:
            reasons.append(
                "Missing proposal approval roles: "
                + ", ".join(sorted(role.value for role in missing))
                + "."
            )
        actors = {item.actor_id for item in approved if item.role in self.proposal_roles}
        if len(actors) < len(self.proposal_roles):
            reasons.append("Proposal approvals must come from distinct actors.")
        if proposal.proposed_by in actors:
            reasons.append("The proposer cannot approve their own proposal.")

        return PolicyDecision(
            allowed=not reasons,
            code="POLICY_ALLOW" if not reasons else "POLICY_DENY",
            reasons=tuple(reasons) if reasons else ("All mandatory controls passed.",),
            proposal_digest=digest,
            decided_at=now,
        )
