"""Synthetic end-to-end scenario for the dashboard and CI."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

from .dashboard import render_dashboard
from .models import (
    ApprovalDecision,
    ApprovalRecord,
    AssetKind,
    DataClassification,
    Engagement,
    Environment,
    Role,
    ScopeAsset,
    SubjectKind,
    ensure_aware,
    utc_now,
)
from .planner import synthetic_plan_document
from .reporting import (
    demo_regulatory_report,
    regulatory_crosswalk,
    render_report_markdown,
)
from .service import FinRedOpsService
from .store import SQLiteGovernanceStore


def _approval(
    *,
    approval_id: str,
    subject_kind: SubjectKind,
    subject_id: str,
    subject_digest: str,
    actor_id: str,
    role: Role,
    now: datetime,
) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=approval_id,
        subject_kind=subject_kind,
        subject_id=subject_id,
        subject_digest=subject_digest,
        actor_id=actor_id,
        role=role,
        decision=ApprovalDecision.APPROVED,
        decided_at=now,
        expires_at=now + timedelta(minutes=90),
        comment="Synthetic demonstration approval; not valid for a real system.",
    )


def build_demo_service(*, now: datetime | None = None) -> tuple[FinRedOpsService, str]:
    now = ensure_aware(now or utc_now())
    engagement = Engagement(
        engagement_id="FRX-DEMO-2026-001",
        name="Synthetic payment resilience review",
        requester_id="demo.requester",
        critical_functions=("card authorization", "customer identity"),
        assets=(
            ScopeAsset(
                asset_id="ASSET-PAY-001",
                kind=AssetKind.HOSTNAME,
                value="payments-lab.example.test",
                environment=Environment.LAB,
                data_classification=DataClassification.INTERNAL,
                critical_function="card authorization",
            ),
            ScopeAsset(
                asset_id="ASSET-IAM-001",
                kind=AssetKind.HOSTNAME,
                value="identity-lab.example.test",
                environment=Environment.LAB,
                data_classification=DataClassification.CONFIDENTIAL,
                critical_function="customer identity",
            ),
        ),
        excluded_assets=(
            ScopeAsset(
                asset_id="ASSET-CORE-EXCLUDED",
                kind=AssetKind.HOSTNAME,
                value="core-banking.example.test",
                environment=Environment.PRODUCTION,
                data_classification=DataClassification.RESTRICTED,
                critical_function="core ledger",
            ),
        ),
        allowed_actions=(
            "http.response_headers.inspect",
            "tls.certificate_metadata.inspect",
            "identity.configuration.review",
            "vulnerability.validation.controlled",
        ),
        window_start=now - timedelta(minutes=30),
        window_end=now + timedelta(hours=2),
        emergency_contacts=("demo.control@example.test", "demo.ops@example.test"),
        max_requests_per_minute=5,
        approval_ttl_minutes=90,
    )

    service = FinRedOpsService()
    service.register_engagement(
        engagement, actor_id=engagement.requester_id, now=now - timedelta(minutes=14)
    )
    engagement = service.submit_engagement(
        engagement.engagement_id,
        actor_id=engagement.requester_id,
        now=now - timedelta(minutes=13),
    )
    for approval in (
        _approval(
            approval_id="APR-ENG-OWNER",
            subject_kind=SubjectKind.ENGAGEMENT,
            subject_id=engagement.engagement_id,
            subject_digest=engagement.digest(),
            actor_id="demo.business-owner",
            role=Role.BUSINESS_OWNER,
            now=now - timedelta(minutes=12),
        ),
        _approval(
            approval_id="APR-ENG-CONTROL",
            subject_kind=SubjectKind.ENGAGEMENT,
            subject_id=engagement.engagement_id,
            subject_digest=engagement.digest(),
            actor_id="demo.control-officer",
            role=Role.CONTROL_TEAM,
            now=now - timedelta(minutes=11),
        ),
    ):
        service.record_approval(approval)
    service.activate_engagement(
        engagement.engagement_id,
        actor_id="demo.control-officer",
        role=Role.CONTROL_TEAM,
        now=now - timedelta(minutes=10),
    )

    proposals = service.ingest_plan(
        engagement.engagement_id,
        synthetic_plan_document(),
        proposed_by="demo.ai-planner",
        now=now - timedelta(minutes=8),
    )
    for index, proposal in enumerate(proposals, start=1):
        for suffix, actor_id, role in (
            ("CTRL", "demo.control-officer", Role.CONTROL_TEAM),
            ("EXEC", "demo.execution-approver", Role.EXECUTION_APPROVER),
        ):
            service.record_approval(
                _approval(
                    approval_id=f"APR-P{index}-{suffix}",
                    subject_kind=SubjectKind.PROPOSAL,
                    subject_id=proposal.proposal_id,
                    subject_digest=proposal.digest(),
                    actor_id=actor_id,
                    role=role,
                    now=now - timedelta(minutes=6),
                )
            )
    for proposal in proposals:
        service.execute_proposal(
            proposal.proposal_id,
            actor_id="demo.operator",
            role=Role.OPERATOR,
            now=now - timedelta(minutes=2),
        )
    return service, engagement.engagement_id


def write_demo(output: Path, *, now: datetime | None = None) -> dict[str, Path]:
    effective_now = ensure_aware(now or utc_now())
    service, engagement_id = build_demo_service(now=effective_now)
    snapshot = service.snapshot(engagement_id)
    report = demo_regulatory_report(issued_at=effective_now)
    crosswalk = regulatory_crosswalk(report, service.regulatory_profile)
    output.mkdir(parents=True, exist_ok=True)
    paths = {
        "dashboard": output / "dashboard.html",
        "audit": output / "audit.jsonl",
        "snapshot": output / "snapshot.json",
        "database": output / "finredops.db",
        "report_markdown": output / "regulatory-report.md",
        "report_json": output / "regulatory-report.json",
        "crosswalk": output / "regulatory-crosswalk.json",
    }
    paths["dashboard"].write_text(render_dashboard(snapshot), encoding="utf-8")
    service.audit.write(paths["audit"])
    paths["snapshot"].write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    with SQLiteGovernanceStore(paths["database"]) as store:
        store.persist_audit_chain(engagement_id, service.audit)
        store.save_snapshot(snapshot, now=effective_now)
    paths["report_markdown"].write_text(
        render_report_markdown(report, service.regulatory_profile), encoding="utf-8"
    )
    paths["report_json"].write_text(
        json.dumps(report.as_dict(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    paths["crosswalk"].write_text(
        json.dumps(crosswalk, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return paths
