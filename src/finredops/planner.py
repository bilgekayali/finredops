"""Strict gateway for importing AI-generated plan documents."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from .catalog import ACTION_CATALOG
from .models import ActionProposal, Engagement, ensure_aware, sha256_digest


class PlanValidationError(ValueError):
    """Raised when an AI plan crosses the structured planning boundary."""


class GuardedPlanningGateway:
    """Convert strict JSON into proposals; never interpret commands or payloads."""

    top_level_keys = frozenset({"objective", "proposals"})
    proposal_keys = frozenset({"action_id", "target", "rationale", "parameters"})

    def parse(
        self,
        document: str | Mapping[str, Any],
        *,
        engagement: Engagement,
        proposed_by: str,
        now: datetime,
    ) -> tuple[ActionProposal, ...]:
        now = ensure_aware(now)
        if isinstance(document, str):
            if len(document.encode("utf-8")) > 64_000:
                raise PlanValidationError("Plan document exceeds 64 KB.")
            try:
                raw = json.loads(document)
            except json.JSONDecodeError as exc:
                raise PlanValidationError(f"Plan is not valid JSON: {exc.msg}.") from exc
        else:
            raw = dict(document)

        if not isinstance(raw, Mapping):
            raise PlanValidationError("Plan must be a JSON object.")
        unknown = set(raw) - self.top_level_keys
        if unknown:
            raise PlanValidationError(f"Unknown plan fields: {', '.join(sorted(unknown))}.")
        objective = raw.get("objective")
        items = raw.get("proposals")
        if not isinstance(objective, str) or not objective.strip():
            raise PlanValidationError("Plan objective is required.")
        if not isinstance(items, list) or not 1 <= len(items) <= 12:
            raise PlanValidationError("Plan must contain between 1 and 12 proposals.")

        proposals: list[ActionProposal] = []
        seen: set[tuple[str, str]] = set()
        for index, item in enumerate(items, start=1):
            if not isinstance(item, Mapping):
                raise PlanValidationError(f"Proposal {index} must be an object.")
            missing = self.proposal_keys - set(item)
            extra = set(item) - self.proposal_keys
            if missing or extra:
                details = []
                if missing:
                    details.append("missing " + ", ".join(sorted(missing)))
                if extra:
                    details.append("unknown " + ", ".join(sorted(extra)))
                raise PlanValidationError(f"Proposal {index}: {'; '.join(details)}.")

            action_id = item["action_id"]
            target = item["target"]
            rationale = item["rationale"]
            parameters = item["parameters"]
            if not isinstance(action_id, str) or action_id not in ACTION_CATALOG:
                raise PlanValidationError(f"Proposal {index} uses an unknown catalog action.")
            if not isinstance(target, str) or not target.strip():
                raise PlanValidationError(f"Proposal {index} requires a target.")
            if not isinstance(rationale, str) or not 10 <= len(rationale.strip()) <= 600:
                raise PlanValidationError(
                    f"Proposal {index} rationale must contain 10 to 600 characters."
                )
            if not isinstance(parameters, Mapping):
                raise PlanValidationError(f"Proposal {index} parameters must be an object.")
            for key, value in parameters.items():
                if not isinstance(key, str):
                    raise PlanValidationError(f"Proposal {index} parameter keys must be strings.")
                if isinstance(value, (Mapping, list, tuple)):
                    raise PlanValidationError(
                        f"Proposal {index} parameters must contain scalar values only."
                    )
                if isinstance(value, str) and len(value) > 500:
                    raise PlanValidationError(f"Proposal {index} parameter value is too long.")

            proposal_seed = {
                "engagement_id": engagement.engagement_id,
                "action_id": action_id,
                "target": target,
                "rationale": rationale.strip(),
                "parameters": dict(parameters),
                "proposed_by": proposed_by,
                "proposed_at": now,
            }
            proposal_id = "PROP-" + sha256_digest(proposal_seed)[:16].upper()
            try:
                proposal = ActionProposal(
                    proposal_id=proposal_id,
                    engagement_id=engagement.engagement_id,
                    action_id=action_id,
                    target=target,
                    rationale=rationale.strip(),
                    parameters=dict(parameters),
                    proposed_by=proposed_by,
                    proposed_at=now,
                )
            except ValueError as exc:
                raise PlanValidationError(f"Proposal {index} is invalid: {exc}") from exc
            unique_key = (proposal.action_id, proposal.target)
            if unique_key in seen:
                raise PlanValidationError(
                    f"Proposal {index} duplicates action and target {unique_key!r}."
                )
            seen.add(unique_key)
            proposals.append(proposal)
        return tuple(proposals)


def synthetic_plan_document() -> dict[str, Any]:
    """Return a harmless plan used by the local demo and tests."""

    return {
        "objective": "Demonstrate governed evidence review in a reserved test namespace.",
        "proposals": [
            {
                "action_id": "http.response_headers.inspect",
                "target": "payments-lab.example.test",
                "rationale": "Review supplied synthetic header evidence for a declared baseline.",
                "parameters": {
                    "expected_control": "FR-HTTP-01",
                    "evidence_reference": "SYNTH-HTTP-001",
                },
            },
            {
                "action_id": "tls.certificate_metadata.inspect",
                "target": "payments-lab.example.test",
                "rationale": "Review supplied synthetic certificate metadata and expiry posture.",
                "parameters": {
                    "expected_control": "FR-TLS-02",
                    "evidence_reference": "SYNTH-TLS-001",
                },
            },
            {
                "action_id": "identity.configuration.review",
                "target": "identity-lab.example.test",
                "rationale": "Review synthetic identity-control evidence for privileged access.",
                "parameters": {
                    "control_family": "privileged-access",
                    "evidence_reference": "SYNTH-IAM-001",
                },
            },
            {
                "action_id": "vulnerability.validation.controlled",
                "target": "payments-lab.example.test",
                "rationale": "Demonstrate that unsupported controlled validation is denied safely.",
                "parameters": {"finding_reference": "SYNTH-FINDING-001"},
            },
        ],
    }
