"""Operator commands for institution-scoped persistence and key-boundary evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .institution import (
    InstitutionContextError,
    institution_context_from_document,
    institution_context_template,
)
from .serialization import DocumentValidationError, read_json_document
from .store import SQLiteGovernanceStore

HARDENING_COMMANDS = frozenset(
    {
        "institution-context-template",
        "validate-institution-context",
        "verify-tenant-store",
    }
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="finredops")
    subparsers = parser.add_subparsers(dest="command", required=True)

    template = subparsers.add_parser(
        "institution-context-template",
        help="Create an institution-owned KMS/HSM key-reference context template.",
    )
    template.add_argument("--output", type=Path, required=True)

    validate = subparsers.add_parser(
        "validate-institution-context",
        help="Validate an institution security context and its digest.",
    )
    validate.add_argument("path", type=Path)

    verify = subparsers.add_parser(
        "verify-tenant-store",
        help="Verify one institution-scoped persisted audit chain.",
    )
    verify.add_argument("database", type=Path)
    verify.add_argument("engagement_id")
    verify.add_argument("--institution-id", required=True)
    return parser


def run_hardening_command(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    if args.command == "institution-context-template":
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(institution_context_template(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Institution context template: {args.output}")
        return 0
    if args.command == "validate-institution-context":
        try:
            context = institution_context_from_document(
                read_json_document(args.path, maximum_bytes=128_000)
            )
            data_key = context.active_key("data_encryption")
            audit_key = context.active_key("audit_signing")
        except (
            DocumentValidationError,
            InstitutionContextError,
            OSError,
            ValueError,
        ) as exc:
            print(f"INVALID: {exc}")
            return 1
        print(
            json.dumps(
                {
                    "valid": True,
                    "institution_id": context.institution_id,
                    "context_digest": context.digest(),
                    "active_data_key_id": data_key.key_id,
                    "active_audit_key_id": audit_key.key_id,
                    "secret_material_stored": False,
                    "encryption_at_rest_verified": False,
                    "audit_signature_verified": False,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    if args.command == "verify-tenant-store":
        try:
            with SQLiteGovernanceStore(
                args.database, institution_id=args.institution_id
            ) as store:
                valid, errors = store.verify_persisted_audit(args.engagement_id)
                metadata = store.metadata()
        except (OSError, ValueError) as exc:
            print(f"INVALID: {exc}")
            return 1
        if not valid:
            for error in errors:
                print(f"INVALID: {error}")
            return 1
        print(
            json.dumps(
                {
                    "valid": True,
                    "institution_id": metadata["institution_id"],
                    "engagement_id": args.engagement_id,
                    "tenant_scope_enforced": metadata["tenant_scope_enforced"],
                    "encryption_at_rest_verified": metadata[
                        "encryption_at_rest_verified"
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    raise AssertionError("unreachable")


def hardening_help() -> str:
    return (
        "\nPlatform-hardening commands:\n"
        "  institution-context-template   create institution-owned key-reference context\n"
        "  validate-institution-context   validate key custody references and context digest\n"
        "  verify-tenant-store            verify an institution-scoped persisted audit chain\n"
    )
