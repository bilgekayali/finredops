"""v0.7 operator commands for externally signed reviewer trust and lifecycle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .intake import read_intake_file
from .models import parse_datetime, sha256_digest
from .promotion import build_reviewed_report
from .reporting import render_report_markdown, validate_report
from .review import read_review_json, review_from_document
from .signed_approvals import load_verified_risk_acceptances
from .trust import (
    ReviewTrustError,
    identity_assertion_from_document,
    identity_assertion_signing_document,
    lifecycle_event_from_document,
    lifecycle_event_from_draft,
    load_trusted_review_resolution,
)

TRUST_COMMANDS = {
    "review-lifecycle-template",
    "finalize-review-lifecycle",
    "identity-assertion-request",
    "finalize-identity-assertion",
    "verify-review-trust",
    "promote-trusted-reviewed-report",
}


def trust_help() -> str:
    return (
        "\nv0.7 review trust and lifecycle:\n"
        "  review-lifecycle-template       create a supersede/revoke lifecycle draft\n"
        "  finalize-review-lifecycle       freeze a lifecycle event and digest\n"
        "  identity-assertion-request      create exact bytes/fields for external signing\n"
        "  finalize-identity-assertion     attach an externally produced signature\n"
        "  verify-review-trust             verify identity signatures and resolve authority\n"
        "  promote-trusted-reviewed-report promote current trusted reviews; signed risk acceptance required\n"
    )


def _parser(command: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"finredops {command}")
    if command == "review-lifecycle-template":
        parser.add_argument("--intake", type=Path, required=True)
        parser.add_argument("--prior-review", type=Path, required=True)
        parser.add_argument("--action", choices=("supersede", "revoke"), required=True)
        parser.add_argument("--replacement-review", type=Path)
        parser.add_argument("--actor-id", required=True)
        parser.add_argument("--output", type=Path, required=True)
        return parser
    if command == "finalize-review-lifecycle":
        parser.add_argument("--draft", type=Path, required=True)
        parser.add_argument("--output", type=Path, required=True)
        return parser
    if command == "identity-assertion-request":
        parser.add_argument("--intake", type=Path, required=True)
        parser.add_argument("--engagement-id", required=True)
        parser.add_argument("--issuer", required=True)
        parser.add_argument("--key-id", required=True)
        parser.add_argument("--issued-at", required=True)
        parser.add_argument("--expires-at", required=True)
        protected = parser.add_mutually_exclusive_group(required=True)
        protected.add_argument("--review", type=Path)
        protected.add_argument("--lifecycle-event", type=Path)
        parser.add_argument("--output", type=Path, required=True)
        return parser
    if command == "finalize-identity-assertion":
        parser.add_argument("--request", type=Path, required=True)
        parser.add_argument("--signature", required=True)
        parser.add_argument("--output", type=Path, required=True)
        return parser
    if command in {"verify-review-trust", "promote-trusted-reviewed-report"}:
        parser.add_argument("--intake", type=Path, required=True)
        parser.add_argument("--review", type=Path, action="append", required=True)
        parser.add_argument("--lifecycle-event", type=Path, action="append", default=[])
        parser.add_argument("--identity-assertion", type=Path, action="append", required=True)
        parser.add_argument("--trust-bundle", type=Path, required=True)
        parser.add_argument("--engagement-id", required=True)
        parser.add_argument("--as-of", required=True)
        if command == "promote-trusted-reviewed-report":
            parser.add_argument("--acceptance", type=Path, action="append", default=[])
            parser.add_argument("--acceptance-signature", type=Path, action="append", default=[])
            parser.add_argument("--approval-trust-bundle", type=Path)
            parser.add_argument("--spec", type=Path, required=True)
            parser.add_argument("--output-dir", type=Path, required=True)
        return parser
    raise ValueError(f"Unknown trust command: {command}")


def _write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(document, ensure_ascii=False, indent=2) + "\n")


def _load_review(path: Path, batch: Any) -> Any:
    return review_from_document(read_review_json(path), batch)


def _lifecycle_template(args: argparse.Namespace) -> dict[str, Any]:
    batch = read_intake_file(args.intake)
    prior = _load_review(args.prior_review, batch)
    replacement = None
    if args.replacement_review is not None:
        replacement = _load_review(args.replacement_review, batch)
    if args.action == "supersede":
        if replacement is None:
            raise ReviewTrustError("Supersede requires --replacement-review.")
        if replacement.finding_id != prior.finding_id:
            raise ReviewTrustError("Replacement review must cover the same finding.")
    elif replacement is not None:
        raise ReviewTrustError("Revoke cannot supply --replacement-review.")
    return {
        "batch_id": batch.batch_id,
        "batch_digest": batch.digest(),
        "finding_id": prior.finding_id,
        "action": args.action,
        "prior_review_id": prior.review_id,
        "prior_review_digest": prior.digest(),
        "replacement_review_id": replacement.review_id if replacement else "",
        "replacement_review_digest": replacement.digest() if replacement else "",
        "actor_id": args.actor_id,
        "event_at": "YYYY-MM-DDTHH:MM:SSZ",
        "reason": "TODO: explain why this immutable review is superseded or revoked.",
    }


def _identity_request(args: argparse.Namespace) -> dict[str, Any]:
    batch = read_intake_file(args.intake)
    if args.review is not None:
        item = _load_review(args.review, batch)
        subject = item.reviewer_id
        purpose, role = "finding_review", "qualified_tester"
        object_id, object_digest, finding_id = item.review_id, item.digest(), item.finding_id
    else:
        item = lifecycle_event_from_document(read_review_json(args.lifecycle_event))
        if item.batch_id != batch.batch_id or item.batch_digest != batch.digest():
            raise ReviewTrustError("Lifecycle event is bound to a different intake batch.")
        subject = item.actor_id
        purpose, role = "review_lifecycle", "review_governor"
        object_id, object_digest, finding_id = item.event_id, item.digest(), item.finding_id
    return identity_assertion_signing_document(
        {
            "issuer": args.issuer,
            "subject": subject,
            "key_id": args.key_id,
            "algorithm": "Ed25519",
            "purpose": purpose,
            "role": role,
            "engagement_id": args.engagement_id,
            "batch_id": batch.batch_id,
            "batch_digest": batch.digest(),
            "finding_id": finding_id,
            "object_id": object_id,
            "object_digest": object_digest,
            "issued_at": args.issued_at,
            "expires_at": args.expires_at,
        }
    )


def _refuse_outputs(output_dir: Path) -> None:
    names = (
        "regulatory-report.json",
        "regulatory-report.md",
        "promotion-manifest.json",
        "trust-resolution.json",
        "trusted-promotion-manifest.json",
        "signed-risk-acceptance-resolution.json",
    )
    if output_dir.exists() and not output_dir.is_dir():
        raise ReviewTrustError("output-dir must be a directory path.")
    collisions = [name for name in names if (output_dir / name).exists()]
    if collisions:
        raise ReviewTrustError(f"Refusing to overwrite trusted promotion outputs: {collisions}.")


def _trusted_inputs(args: argparse.Namespace) -> tuple[Any, Any]:
    return load_trusted_review_resolution(
        intake_path=args.intake,
        review_paths=tuple(args.review),
        lifecycle_paths=tuple(args.lifecycle_event),
        assertion_paths=tuple(args.identity_assertion),
        trust_bundle_path=args.trust_bundle,
        engagement_id=args.engagement_id,
        as_of=parse_datetime(args.as_of),
    )


def _promote(args: argparse.Namespace) -> dict[str, Any]:
    _refuse_outputs(args.output_dir)
    batch, resolution = _trusted_inputs(args)
    if resolution.revoked_finding_ids:
        raise ReviewTrustError(
            "Trusted promotion is blocked while a finding has a revoked review without replacement."
        )
    trust_document = resolution.as_dict()
    acceptance_paths = tuple(args.acceptance)
    acceptance_signature_paths = tuple(args.acceptance_signature)
    signed_acceptance_resolution = None
    if acceptance_paths or acceptance_signature_paths:
        if args.approval_trust_bundle is None:
            raise ReviewTrustError(
                "Trusted risk acceptance requires --approval-trust-bundle and signed acceptance records."
            )
        acceptances, signed_acceptance_resolution = load_verified_risk_acceptances(
            batch=batch,
            reviews=resolution.authoritative_reviews,
            acceptance_paths=acceptance_paths,
            signature_paths=acceptance_signature_paths,
            approval_trust_bundle_path=args.approval_trust_bundle,
            engagement_id=args.engagement_id,
            review_trust_resolution_digest=trust_document["resolution_digest"],
            as_of=parse_datetime(args.as_of),
        )
    else:
        acceptances = ()

    spec = read_review_json(args.spec)
    report, base_manifest = build_reviewed_report(
        batch,
        resolution.authoritative_reviews,
        acceptances,
        spec,
        as_of=parse_datetime(args.as_of),
    )
    validation = validate_report(report)
    if not validation.valid:
        raise ReviewTrustError("Trusted promotion produced an invalid draft report.")
    trusted_body: dict[str, Any] = {
        "schema_version": "finredops.trusted-report-promotion.v1",
        "base_promotion_digest": base_manifest["promotion_digest"],
        "report_id": report.report_id,
        "report_digest": report.digest(),
        "engagement_id": resolution.engagement_id,
        "trust_resolution_digest": trust_document["resolution_digest"],
        "trust_bundle_digest": resolution.trust_bundle_digest,
        "cryptographic_signatures_verified": True,
        "signature_algorithm": "Ed25519",
        "report_issued": False,
        "human_approval_required": True,
    }
    if signed_acceptance_resolution is not None:
        signed_document = signed_acceptance_resolution.as_dict()
        trusted_body.update(
            {
                "signed_risk_acceptance_resolution_digest": signed_document["resolution_digest"],
                "signed_risk_acceptance_signature_count": len(signed_acceptance_resolution.signature_ids),
                "approval_trust_bundle_digest": signed_acceptance_resolution.approval_trust_bundle_digest,
            }
        )
    trusted_manifest = {**trusted_body, "trusted_promotion_digest": sha256_digest(trusted_body)}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "regulatory-report.json").write_text(
        json.dumps(report.as_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "regulatory-report.md").write_text(
        render_report_markdown(report), encoding="utf-8"
    )
    (args.output_dir / "promotion-manifest.json").write_text(
        json.dumps(base_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "trust-resolution.json").write_text(
        json.dumps(trust_document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (args.output_dir / "trusted-promotion-manifest.json").write_text(
        json.dumps(trusted_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if signed_acceptance_resolution is not None:
        (args.output_dir / "signed-risk-acceptance-resolution.json").write_text(
            json.dumps(signed_acceptance_resolution.as_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    return {
        "report_id": report.report_id,
        "report_digest": report.digest(),
        "valid": validation.valid,
        "ready_for_issue": validation.ready_for_issue,
        "authoritative_review_count": len(resolution.authoritative_reviews),
        "verified_assertion_count": len(resolution.verified_assertion_ids),
        "signed_risk_acceptance_count": len(acceptances),
        "trusted_promotion_digest": trusted_manifest["trusted_promotion_digest"],
        "output_dir": str(args.output_dir),
    }


def run_trust_command(argv: Sequence[str]) -> int:
    command = argv[0]
    args = _parser(command).parse_args(list(argv[1:]))
    try:
        if command == "review-lifecycle-template":
            _write_json(args.output, _lifecycle_template(args))
            print(f"Review lifecycle draft: {args.output}")
            return 0
        if command == "finalize-review-lifecycle":
            event = lifecycle_event_from_draft(read_review_json(args.draft))
            _write_json(args.output, event.as_dict())
            print(json.dumps({"event_id": event.event_id, "event_digest": event.digest()}, indent=2))
            return 0
        if command == "identity-assertion-request":
            request = _identity_request(args)
            _write_json(args.output, request)
            print(
                json.dumps(
                    {
                        "assertion_id": request["assertion_id"],
                        "output": str(args.output),
                        "signature_required": True,
                        "signing_format": "canonical-json/utf-8/sorted-keys/no-whitespace",
                        "algorithm": "Ed25519",
                    },
                    indent=2,
                )
            )
            return 0
        if command == "finalize-identity-assertion":
            request = read_review_json(args.request)
            if not isinstance(request, Mapping):
                raise ReviewTrustError("Identity assertion request must be an object.")
            document = {**request, "signature": args.signature}
            assertion = identity_assertion_from_document(document)
            _write_json(args.output, assertion.as_dict())
            print(json.dumps({"assertion_id": assertion.assertion_id, "output": str(args.output)}, indent=2))
            return 0
        if command == "verify-review-trust":
            _, resolution = _trusted_inputs(args)
            print(json.dumps(resolution.as_dict(), ensure_ascii=False, indent=2))
            return 0
        if command == "promote-trusted-reviewed-report":
            print(json.dumps(_promote(args), ensure_ascii=False, indent=2))
            return 0
        raise ReviewTrustError("Unknown trust command.")
    except (OSError, ValueError, ReviewTrustError) as exc:
        print(f"INVALID: {exc}")
        return 1
