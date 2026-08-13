"""CLI for authenticated tenant routing and authorization verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .institution import institution_context_from_document
from .models import parse_datetime
from .oidc_identity import oidc_verification_from_document
from .serialization import DocumentValidationError, read_json_document
from .tenant_auth import (
    AuthorizedTenantSession,
    TenantAuthorizationError,
    authorize_tenant_route,
    tenant_authorization_from_document,
    tenant_policy_from_document,
    tenant_policy_template,
    verify_tenant_authorization,
)

TENANT_AUTH_COMMANDS = frozenset(
    {
        "tenant-routing-policy-template",
        "authorize-tenant-route",
        "verify-tenant-authorization",
        "authorized-tenant-store-metadata",
    }
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="finredops")
    subparsers = parser.add_subparsers(dest="command", required=True)

    template = subparsers.add_parser(
        "tenant-routing-policy-template",
        help="Create an exact-subject tenant routing policy template from verified OIDC identity.",
    )
    template.add_argument("--institution-context", type=Path, required=True)
    template.add_argument("--oidc-verification", type=Path, required=True)
    template.add_argument("--output", type=Path, required=True)

    authorize = subparsers.add_parser(
        "authorize-tenant-route",
        help="Authorize exact OIDC subject/provider access to one institution and capability set.",
    )
    authorize.add_argument("--policy", type=Path, required=True)
    authorize.add_argument("--institution-context", type=Path, required=True)
    authorize.add_argument("--oidc-verification", type=Path, required=True)
    authorize.add_argument("--capability", action="append", required=True)
    authorize.add_argument("--as-of", required=True)
    authorize.add_argument("--output", type=Path, required=True)

    verify = subparsers.add_parser(
        "verify-tenant-authorization",
        help="Revalidate a tenant authorization against current policy, context, and OIDC identity.",
    )
    verify.add_argument("--authorization", type=Path, required=True)
    verify.add_argument("--policy", type=Path, required=True)
    verify.add_argument("--institution-context", type=Path, required=True)
    verify.add_argument("--oidc-verification", type=Path, required=True)
    verify.add_argument("--as-of", required=True)

    metadata = subparsers.add_parser(
        "authorized-tenant-store-metadata",
        help="Read store metadata only after tenant authorization is revalidated.",
    )
    metadata.add_argument("database", type=Path)
    metadata.add_argument("--authorization", type=Path, required=True)
    metadata.add_argument("--policy", type=Path, required=True)
    metadata.add_argument("--institution-context", type=Path, required=True)
    metadata.add_argument("--oidc-verification", type=Path, required=True)
    metadata.add_argument("--as-of", required=True)
    return parser


def _documents(args: argparse.Namespace):
    context = institution_context_from_document(
        read_json_document(args.institution_context, maximum_bytes=128_000)
    )
    verification = oidc_verification_from_document(
        read_json_document(args.oidc_verification, maximum_bytes=128_000)
    )
    return context, verification


def _authorization_documents(args: argparse.Namespace):
    context, verification = _documents(args)
    policy = tenant_policy_from_document(
        read_json_document(args.policy, maximum_bytes=256_000)
    )
    authorization = tenant_authorization_from_document(
        read_json_document(args.authorization, maximum_bytes=128_000)
    )
    return context, verification, policy, authorization


def _write_json(path: Path, document: dict) -> None:
    if path.exists():
        raise TenantAuthorizationError(f"Refusing to overwrite existing output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run_tenant_auth_command(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "tenant-routing-policy-template":
            context, verification = _documents(args)
            document = tenant_policy_template(context=context, verification=verification)
            _write_json(args.output, document)
            print(f"Tenant routing policy template: {args.output}")
            return 0

        if args.command == "authorize-tenant-route":
            context, verification = _documents(args)
            policy = tenant_policy_from_document(
                read_json_document(args.policy, maximum_bytes=256_000)
            )
            authorization = authorize_tenant_route(
                verification,
                policy,
                context,
                requested_capabilities=tuple(args.capability),
                as_of=parse_datetime(args.as_of),
            )
            _write_json(args.output, authorization.as_dict())
            print(f"Tenant authorization: {args.output}")
            return 0

        if args.command == "verify-tenant-authorization":
            context, verification, policy, authorization = _authorization_documents(args)
            verify_tenant_authorization(
                authorization,
                verification,
                policy,
                context,
                as_of=parse_datetime(args.as_of),
            )
            print(
                json.dumps(
                    {
                        "valid": True,
                        "authorization_id": authorization.authorization_id,
                        "institution_id": authorization.institution_id,
                        "subject": authorization.subject,
                        "roles": list(authorization.roles),
                        "capabilities": list(authorization.capabilities),
                        "external_idp_protocol_verified": True,
                        "tenant_route_authorized": True,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0

        if args.command == "authorized-tenant-store-metadata":
            context, verification, policy, authorization = _authorization_documents(args)
            session = AuthorizedTenantSession.create(
                authorization,
                verification,
                policy,
                context,
                as_of=parse_datetime(args.as_of),
            )
            with session.open_store(args.database, access="read") as store:
                metadata = store.metadata()
            print(
                json.dumps(
                    {
                        "valid": True,
                        "authorization_id": authorization.authorization_id,
                        "institution_id": metadata["institution_id"],
                        "tenant_scope_enforced": metadata["tenant_scope_enforced"],
                        "encryption_at_rest_verified": metadata["encryption_at_rest_verified"],
                        "engagements": metadata["engagements"],
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
    except (
        DocumentValidationError,
        TenantAuthorizationError,
        OSError,
        ValueError,
    ) as exc:
        print(f"INVALID: {exc}")
        return 1
    raise AssertionError("unreachable")


def tenant_auth_help() -> str:
    return (
        "\nAuthenticated tenant-routing commands:\n"
        "  tenant-routing-policy-template    create exact-subject institution routing policy\n"
        "  authorize-tenant-route            authorize OIDC identity for one tenant/capability set\n"
        "  verify-tenant-authorization       revalidate tenant authorization and source bindings\n"
        "  authorized-tenant-store-metadata read tenant store metadata through authorization boundary\n"
    )
