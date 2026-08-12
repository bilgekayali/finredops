"""Deterministic simulation runner with no network or shell capability."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .catalog import ACTION_CATALOG
from .evidence import EvidenceGuard, guard_summary
from .models import (
    ActionProposal,
    ExecutionReceipt,
    ExecutionStatus,
    RiskLevel,
    ensure_aware,
    sha256_digest,
)


_SYNTHETIC_EVIDENCE: dict[str, dict[str, Any]] = {
    "http.response_headers.inspect": {
        "source": "bundled synthetic fixture",
        "observations": [
            {"control": "strict-transport-security", "state": "present"},
            {"control": "content-security-policy", "state": "review_required"},
        ],
        "network_activity": False,
    },
    "tls.certificate_metadata.inspect": {
        "source": "bundled synthetic fixture",
        "issuer_class": "demonstration-ca",
        "days_to_expiry": 87,
        "network_activity": False,
    },
    "dns.metadata.inspect": {
        "source": "bundled synthetic fixture",
        "records_reviewed": 3,
        "network_activity": False,
    },
    "identity.configuration.review": {
        "source": "bundled synthetic fixture",
        "controls_reviewed": 4,
        "review_outcome": "one_human_follow_up",
        "network_activity": False,
    },
    "cloud.configuration.review": {
        "source": "bundled synthetic fixture",
        "controls_reviewed": 5,
        "review_outcome": "human_validation_required",
        "network_activity": False,
    },
    "transaction.workflow.review": {
        "source": "bundled synthetic fixture",
        "controls_reviewed": 3,
        "review_outcome": "segregation_of_duties_present",
        "network_activity": False,
    },
}


class SimulationRunner:
    name = "finredops-simulation:v1"

    def __init__(self, evidence_guard: EvidenceGuard | None = None) -> None:
        self.evidence_guard = evidence_guard or EvidenceGuard()

    def execute(self, proposal: ActionProposal, *, now: datetime) -> ExecutionReceipt:
        """Evaluate a bundled fixture only; never contact the proposal target."""

        now = ensure_aware(now)
        action = ACTION_CATALOG.get(proposal.action_id)
        if action is None or not action.supported_in_mvp:
            raise ValueError("The action has no simulation runner implementation.")
        if action.risk_level in {RiskLevel.CONTROLLED, RiskLevel.IMPACTING}:
            raise ValueError("The simulation runner refuses controlled or impacting actions.")
        candidate_evidence = {
            **_SYNTHETIC_EVIDENCE[proposal.action_id],
            "target_label": proposal.target,
            "action_id": proposal.action_id,
            "simulation": True,
            "disclaimer": "Synthetic evidence; not a security finding or compliance opinion.",
        }
        guard_result = self.evidence_guard.sanitize(candidate_evidence)
        evidence = {
            **guard_result.evidence,
            "data_guard": guard_summary(guard_result),
        }
        evidence_digest = sha256_digest(evidence)
        return ExecutionReceipt(
            execution_id="EXEC-" + sha256_digest(
                {"proposal_digest": proposal.digest(), "evidence_digest": evidence_digest}
            )[:16].upper(),
            proposal_id=proposal.proposal_id,
            proposal_digest=proposal.digest(),
            status=ExecutionStatus.SIMULATED,
            runner=self.name,
            started_at=now,
            finished_at=now,
            evidence=evidence,
            evidence_digest=evidence_digest,
        )
