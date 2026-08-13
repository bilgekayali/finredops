"""Operator CLI for independently approved configuration changes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .change_control import (
    ChangeControlError,
    PostgresServiceAccountChange,
    approved_change_package,
    change_request_from_document,
    change_signature_from_document,
    change_signature_request,
    change_trust_bundle_from_document,
    finalize_change_signature,
    postgres_service_account_change_request,
    postgres_service_account_disable_request,
    tenant_policy_change_request,
    verify_approved_change_package,
)
from .institution import institution_context_from_document
from .models import parse_datetime
from .postgres_rls import PostgresRLSContract
from .serialization import DocumentValidationError, read_json_document
from .tenant_auth import tenant_policy_from_document

CHANGE_CONTROL_COMMANDS = frozenset(
    {
        "validate-change-trust-bundle",
        "tenant-policy-change-request",
        "postgres-service-account-change-request",
        "postgres-service-account-disable-request",
        "change-signature-request",
        "finalize-change-signature",
        "resolve-change-control",
        "verify-change-control",
    }
)


def _write_json(path: Path, document: dict) -> None:
    if path.exists():
        raise ChangeControlError(f"Refusing to overwrite existing output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _add_contract_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--schema", default="finredops_secure")
    parser.add_argument("--owner-role", default="finredops_owner")
    parser.add_argument("--reader-role", default="finredops_reader")
    parser.add_argument("--writer-role", default="finredops_writer")


def _contract(args: argparse.Namespace) -> PostgresRLSContract:
    return PostgresRLSContract(
        schema_name=args.schema,
        owner_role=args.owner_role,
        reader_role=args.reader_role,
        writer_role=args.writer_role,
    )


def _add_request_metadata(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--requested-by", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--requested-at", required=True)
    parser.add_argument("--valid-until", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="finredops")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate-change-trust-bundle")
    validate.add_argument("--bundle", type=Path, required=True)

    tenant = sub.add_parser("tenant-policy-change-request")
    tenant.add_argument("--policy", type=Path, required=True)
    tenant.add_argument("--institution-context", type=Path, required=True)
    tenant.add_argument("--operation", choices=("create", "update"), required=True)
    tenant.add_argument("--prior-policy-digest")
    _add_request_metadata(tenant)
    tenant.add_argument("--output", type=Path, required=True)

    mapping = sub.add_parser("postgres-service-account-change-request")
    _add_contract_args(mapping)
    mapping.add_argument("--service-role", required=True)
    mapping.add_argument("--institution", required=True)
    mapping.add_argument("--access", choices=("read", "write"), required=True)
    mapping.add_argument("--operation", choices=("create", "update"), required=True)
    mapping.add_argument("--prior-mapping-digest")
    _add_request_metadata(mapping)
    mapping.add_argument("--mapping-output", type=Path, required=True)
    mapping.add_argument("--request-output", type=Path, required=True)

    disable = sub.add_parser("postgres-service-account-disable-request")
    _add_contract_args(disable)
    disable.add_argument("--service-role", required=True)
    disable.add_argument("--institution", required=True)
    disable.add_argument("--prior-mapping-digest", required=True)
    _add_request_metadata(disable)
    disable.add_argument("--output", type=Path, required=True)

    sign = sub.add_parser("change-signature-request")
    sign.add_argument("--change-request", type=Path, required=True)
    sign.add_argument("--issuer", required=True)
    sign.add_argument("--subject", required=True)
    sign.add_argument("--key-id", required=True)
    sign.add_argument(
        "--role",
        choices=("configuration_governor", "security_governor"),
        required=True,
    )
    sign.add_argument("--issued-at", required=True)
    sign.add_argument("--expires-at", required=True)
    sign.add_argument("--output", type=Path, required=True)

    finalize = sub.add_parser("finalize-change-signature")
    finalize.add_argument("--request", type=Path, required=True)
    finalize.add_argument("--signature-file", type=Path, required=True)
    finalize.add_argument("--output", type=Path, required=True)

    resolve = sub.add_parser("resolve-change-control")
    resolve.add_argument("--change-request", type=Path, required=True)
    resolve.add_argument("--signature", type=Path, action="append", required=True)
    resolve.add_argument("--trust-bundle", type=Path, required=True)
    resolve.add_argument("--approved-at", required=True)
    resolve.add_argument("--output", type=Path, required=True)

    verify = sub.add_parser("verify-change-control")
    verify.add_argument("--package", type=Path, required=True)
    verify.add_argument("--trust-bundle", type=Path, required=True)
    return parser


def run_change_control_command(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate-change-trust-bundle":
            bundle = change_trust_bundle_from_document(
                read_json_document(args.bundle, maximum_bytes=256_000)
            )
            print(
                json.dumps(
                    {
                        "valid": True,
                        "bundle_id": bundle.bundle_id,
                        "bundle_digest": bundle.digest(),
                        "active_roles": sorted(
                            {item.role for item in bundle.keys if item.status == "active"}
                        ),
                    },
                    indent=2,
                )
            )
            return 0

        if args.command == "tenant-policy-change-request":
            policy = tenant_policy_from_document(
                read_json_document(args.policy, maximum_bytes=256_000)
            )
            context = institution_context_from_document(
                read_json_document(args.institution_context, maximum_bytes=128_000)
            )
            request = tenant_policy_change_request(
                policy,
                context,
                operation=args.operation,
                prior_policy_digest=args.prior_policy_digest,
                requested_by=args.requested_by,
                reason=args.reason,
                requested_at=parse_datetime(args.requested_at),
                valid_until=parse_datetime(args.valid_until),
            )
            _write_json(args.output, request.as_dict())
            print(f"Tenant-policy change request: {args.output}")
            return 0

        if args.command == "postgres-service-account-change-request":
            contract = _contract(args)
            contract_digest = contract.as_dict()["contract_digest"]
            change = PostgresServiceAccountChange(
                service_role=args.service_role,
                institution_id=args.institution,
                access_mode=args.access,
                contract_digest=contract_digest,
            )
            request = postgres_service_account_change_request(
                change,
                operation=args.operation,
                prior_mapping_digest=args.prior_mapping_digest,
                requested_by=args.requested_by,
                reason=args.reason,
                requested_at=parse_datetime(args.requested_at),
                valid_until=parse_datetime(args.valid_until),
            )
            _write_json(args.mapping_output, change.as_dict())
            _write_json(args.request_output, request.as_dict())
            print(f"PostgreSQL service-account mapping intent: {args.mapping_output}")
            print(f"PostgreSQL service-account change request: {args.request_output}")
            return 0

        if args.command == "postgres-service-account-disable-request":
            contract = _contract(args)
            request = postgres_service_account_disable_request(
                service_role=args.service_role,
                institution_id=args.institution,
                contract_digest=contract.as_dict()["contract_digest"],
                prior_mapping_digest=args.prior_mapping_digest,
                requested_by=args.requested_by,
                reason=args.reason,
                requested_at=parse_datetime(args.requested_at),
                valid_until=parse_datetime(args.valid_until),
            )
            _write_json(args.output, request.as_dict())
            print(f"PostgreSQL service-account disable request: {args.output}")
            return 0

        if args.command == "change-signature-request":
            request = change_request_from_document(
                read_json_document(args.change_request, maximum_bytes=128_000)
            )
            document = change_signature_request(
                request,
                issuer=args.issuer,
                subject=args.subject,
                key_id=args.key_id,
                role=args.role,
                issued_at=parse_datetime(args.issued_at),
                expires_at=parse_datetime(args.expires_at),
            )
            _write_json(args.output, document)
            print(f"Change signature request: {args.output}")
            return 0

        if args.command == "finalize-change-signature":
            signing_request = read_json_document(args.request, maximum_bytes=128_000)
            signature = args.signature_file.read_text(encoding="utf-8").strip()
            finalized = finalize_change_signature(signing_request, signature)
            _write_json(args.output, finalized.as_dict())
            print(f"Finalized change signature: {args.output}")
            return 0

        if args.command == "resolve-change-control":
            request = change_request_from_document(
                read_json_document(args.change_request, maximum_bytes=128_000)
            )
            signatures = tuple(
                change_signature_from_document(
                    read_json_document(path, maximum_bytes=128_000)
                )
                for path in args.signature
            )
            bundle = change_trust_bundle_from_document(
                read_json_document(args.trust_bundle, maximum_bytes=256_000)
            )
            package = approved_change_package(
                request,
                signatures,
                bundle,
                approved_at=parse_datetime(args.approved_at),
            )
            _write_json(args.output, package)
            print(f"Approved change package: {args.output}")
            return 0

        if args.command == "verify-change-control":
            bundle = change_trust_bundle_from_document(
                read_json_document(args.trust_bundle, maximum_bytes=256_000)
            )
            package = read_json_document(args.package, maximum_bytes=512_000)
            request = verify_approved_change_package(package, bundle)
            print(
                json.dumps(
                    {
                        "valid": True,
                        "change_id": request.change_id,
                        "institution_id": request.institution_id,
                        "change_type": request.change_type,
                        "operation": request.operation,
                        "object_id": request.object_id,
                        "request_digest": request.digest(),
                        "independent_change_approval_verified": True,
                    },
                    indent=2,
                )
            )
            return 0
    except (ChangeControlError, DocumentValidationError, OSError, ValueError) as exc:
        print(f"INVALID: {exc}")
        return 1
    raise AssertionError("unreachable")


def change_control_help() -> str:
    return (
        "\nSigned configuration change-control commands:\n"
        "  validate-change-trust-bundle             validate dedicated configuration-governor trust roots\n"
        "  tenant-policy-change-request             bind a tenant-routing policy change for independent approval\n"
        "  postgres-service-account-change-request create service-account mapping intent + change request\n"
        "  postgres-service-account-disable-request create a mapping-disable change request\n"
        "  change-signature-request                 create deterministic Ed25519 signing envelope\n"
        "  finalize-change-signature                attach externally produced Ed25519 signature\n"
        "  resolve-change-control                   require two independent governor signatures\n"
        "  verify-change-control                    reverify approved change package offline\n"
    )