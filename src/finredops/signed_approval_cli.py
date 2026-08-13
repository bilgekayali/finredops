"""v0.7.1 operator commands for key-backed business and report approvals."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .intake import read_intake_file
from .models import parse_datetime, sha256_digest
from .reporting import report_from_document, validate_report
from .review import read_review_json, review_from_document, risk_acceptance_from_document
from .signed_approvals import (
    SignedApprovalError,
    approval_signature_from_document,
    approval_signature_request,
    load_and_approve_report,
    load_verified_risk_acceptances,
    validate_trusted_promotion_manifest,
    write_approved_report_outputs,
)


SIGNED_APPROVAL_COMMANDS = {
    "risk-acceptance-signature-request",
    "report-approval-signature-request",
    "finalize-approval-signature",
    "verify-signed-risk-acceptances",
    "approve-trusted-report",
}


def signed_approval_help() -> str:
    return (
        "\nv0.7.1 key-backed approvals:\n"
        "  risk-acceptance-signature-request create exact business-risk-owner signing request\n"
        "  report-approval-signature-request create exact report-approver signing request\n"
        "  finalize-approval-signature       attach an externally produced Ed25519 signature\n"
        "  verify-signed-risk-acceptances    verify signed business risk acceptances\n"
        "  approve-trusted-report            require two signed approvers and mark draft approved\n"
    )


def _parser(command: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"finredops {command}")
    if command == "risk-acceptance-signature-request":
        parser.add_argument("--intake", type=Path, required=True)
        parser.add_argument("--review", type=Path, required=True)
        parser.add_argument("--acceptance", type=Path, required=True)
        parser.add_argument("--trust-resolution", type=Path, required=True)
        parser.add_argument("--engagement-id", required=True)
        parser.add_argument("--issuer", required=True)
        parser.add_argument("--key-id", required=True)
        parser.add_argument("--issued-at", required=True)
        parser.add_argument("--expires-at", required=True)
        parser.add_argument("--output", type=Path, required=True)
        return parser
    if command == "report-approval-signature-request":
        parser.add_argument("--report", type=Path, required=True)
        parser.add_argument("--trusted-promotion-manifest", type=Path, required=True)
        parser.add_argument("--engagement-id", required=True)
        parser.add_argument("--subject", required=True)
        parser.add_argument("--issuer", required=True)
        parser.add_argument("--key-id", required=True)
        parser.add_argument("--issued-at", required=True)
        parser.add_argument("--expires-at", required=True)
        parser.add_argument("--output", type=Path, required=True)
        return parser
    if command == "finalize-approval-signature":
        parser.add_argument("--request", type=Path, required=True)
        parser.add_argument("--signature", required=True)
        parser.add_argument("--output", type=Path, required=True)
        return parser
    if command == "verify-signed-risk-acceptances":
        parser.add_argument("--intake", type=Path, required=True)
        parser.add_argument("--review", type=Path, action="append", required=True)
        parser.add_argument("--acceptance", type=Path, action="append", default=[])
        parser.add_argument("--approval-signature", type=Path, action="append", default=[])
        parser.add_argument("--trust-resolution", type=Path, required=True)
        parser.add_argument("--approval-trust-bundle", type=Path, required=True)
        parser.add_argument("--engagement-id", required=True)
        parser.add_argument("--as-of", required=True)
        return parser
    if command == "approve-trusted-report":
        parser.add_argument("--report", type=Path, required=True)
        parser.add_argument("--trusted-promotion-manifest", type=Path, required=True)
        parser.add_argument("--approval-signature", type=Path, action="append", required=True)
        parser.add_argument("--approval-trust-bundle", type=Path, required=True)
        parser.add_argument("--engagement-id", required=True)
        parser.add_argument("--as-of", required=True)
        parser.add_argument("--output-dir", type=Path, required=True)
        return parser
    raise ValueError(f"Unknown signed approval command: {command}")


def _write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(document, ensure_ascii=False, indent=2) + "\n")


def _validated_review_resolution(path: Path, engagement_id: str) -> Mapping[str, Any]:
    document = read_review_json(path)
    if not isinstance(document, Mapping):
        raise SignedApprovalError("Trust resolution must be a JSON object.")
    required = {
        "schema_version",
        "engagement_id",
        "trust_bundle_digest",
        "authoritative_review_ids",
        "revoked_finding_ids",
        "verified_assertion_ids",
        "lifecycle_event_ids",
        "cryptographic_signatures_verified",
        "signature_algorithm",
        "external_idp_protocol_verified",
        "resolution_digest",
    }
    if set(document) != required or document.get("schema_version") != "finredops.trusted-review-resolution.v1":
        raise SignedApprovalError("Trust resolution does not match the v1 contract.")
    body = {key: document[key] for key in document if key != "resolution_digest"}
    if sha256_digest(body) != document.get("resolution_digest"):
        raise SignedApprovalError("Trust resolution digest is invalid.")
    if document.get("engagement_id") != engagement_id:
        raise SignedApprovalError("Trust resolution is bound to a different engagement.")
    if document.get("cryptographic_signatures_verified") is not True:
        raise SignedApprovalError("Trust resolution does not attest verified signatures.")
    return document


def _risk_request(args: argparse.Namespace) -> dict[str, Any]:
    batch = read_intake_file(args.intake)
    review = review_from_document(read_review_json(args.review), batch)
    acceptance = risk_acceptance_from_document(read_review_json(args.acceptance), batch, review)
    resolution = _validated_review_resolution(args.trust_resolution, args.engagement_id)
    authoritative = resolution.get("authoritative_review_ids")
    if not isinstance(authoritative, list) or review.review_id not in authoritative:
        raise SignedApprovalError("Risk acceptance is not bound to a current authoritative review.")
    return approval_signature_request(
        {
            "issuer": args.issuer,
            "subject": acceptance.accepted_by,
            "key_id": args.key_id,
            "algorithm": "Ed25519",
            "purpose": "risk_acceptance",
            "role": "business_risk_owner",
            "engagement_id": args.engagement_id,
            "object_type": "risk_acceptance",
            "object_id": acceptance.acceptance_id,
            "object_digest": acceptance.digest(),
            "context_digest": resolution["resolution_digest"],
            "issued_at": args.issued_at,
            "expires_at": args.expires_at,
        }
    )


def _report_request(args: argparse.Namespace) -> dict[str, Any]:
    report = report_from_document(read_review_json(args.report))
    manifest = validate_trusted_promotion_manifest(
        read_review_json(args.trusted_promotion_manifest)
    )
    if manifest.get("engagement_id") != args.engagement_id:
        raise SignedApprovalError("Trusted-promotion manifest is bound to a different engagement.")
    if manifest.get("report_id") != report.report_id or manifest.get("report_digest") != report.digest():
        raise SignedApprovalError("Trusted-promotion manifest does not match the draft report.")
    return approval_signature_request(
        {
            "issuer": args.issuer,
            "subject": args.subject,
            "key_id": args.key_id,
            "algorithm": "Ed25519",
            "purpose": "report_approval",
            "role": "report_approver",
            "engagement_id": args.engagement_id,
            "object_type": "regulatory_report",
            "object_id": report.report_id,
            "object_digest": report.digest(),
            "context_digest": manifest["trusted_promotion_digest"],
            "issued_at": args.issued_at,
            "expires_at": args.expires_at,
        }
    )


def _verify_risk(args: argparse.Namespace) -> dict[str, Any]:
    batch = read_intake_file(args.intake)
    reviews = tuple(review_from_document(read_review_json(path), batch) for path in args.review)
    resolution = _validated_review_resolution(args.trust_resolution, args.engagement_id)
    authoritative = resolution.get("authoritative_review_ids")
    if not isinstance(authoritative, list) or set(authoritative) != {item.review_id for item in reviews}:
        raise SignedApprovalError("Supplied reviews must exactly match the trust-resolution authority set.")
    acceptances, signed = load_verified_risk_acceptances(
        batch=batch,
        reviews=reviews,
        acceptance_paths=tuple(args.acceptance),
        signature_paths=tuple(args.approval_signature),
        approval_trust_bundle_path=args.approval_trust_bundle,
        engagement_id=args.engagement_id,
        review_trust_resolution_digest=str(resolution["resolution_digest"]),
        as_of=parse_datetime(args.as_of),
    )
    return {
        "acceptance_count": len(acceptances),
        "signature_count": len(signed.signature_ids),
        **signed.as_dict(),
    }


def run_signed_approval_command(argv: Sequence[str]) -> int:
    command = argv[0]
    args = _parser(command).parse_args(list(argv[1:]))
    try:
        if command == "risk-acceptance-signature-request":
            request = _risk_request(args)
            _write_json(args.output, request)
            print(json.dumps({"signature_id": request["signature_id"], "signature_required": True, "output": str(args.output)}, indent=2))
            return 0
        if command == "report-approval-signature-request":
            request = _report_request(args)
            _write_json(args.output, request)
            print(json.dumps({"signature_id": request["signature_id"], "signature_required": True, "output": str(args.output)}, indent=2))
            return 0
        if command == "finalize-approval-signature":
            request = read_review_json(args.request)
            if not isinstance(request, Mapping):
                raise SignedApprovalError("Approval signing request must be an object.")
            approval = approval_signature_from_document({**request, "signature": args.signature})
            _write_json(args.output, approval.as_dict())
            print(json.dumps({"signature_id": approval.signature_id, "output": str(args.output)}, indent=2))
            return 0
        if command == "verify-signed-risk-acceptances":
            print(json.dumps(_verify_risk(args), ensure_ascii=False, indent=2))
            return 0
        if command == "approve-trusted-report":
            approved, resolution = load_and_approve_report(
                report_path=args.report,
                trusted_manifest_path=args.trusted_promotion_manifest,
                signature_paths=tuple(args.approval_signature),
                approval_trust_bundle_path=args.approval_trust_bundle,
                engagement_id=args.engagement_id,
                as_of=parse_datetime(args.as_of),
            )
            write_approved_report_outputs(args.output_dir, approved, resolution)
            validation = validate_report(approved)
            print(
                json.dumps(
                    {
                        "report_id": approved.report_id,
                        "approved_report_digest": approved.digest(),
                        "status": approved.status.value,
                        "valid": validation.valid,
                        "ready_for_issue": validation.ready_for_issue,
                        "report_issued": False,
                        "approval_resolution_digest": resolution.as_dict()["approval_resolution_digest"],
                        "output_dir": str(args.output_dir),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        raise SignedApprovalError("Unknown signed approval command.")
    except (OSError, ValueError, SignedApprovalError) as exc:
        print(f"INVALID: {exc}")
        return 1
