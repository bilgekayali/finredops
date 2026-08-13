"""v0.7.2 operator commands for offline OIDC/JWKS identity verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from .models import parse_datetime
from .oidc_identity import (
    OIDCIdentityError,
    bind_oidc_identity,
    oidc_binding_from_document,
    oidc_verification_from_document,
    provider_template_document,
    resolve_oidc_workflow_bindings,
    verify_oidc_id_token_from_files,
)
from .review import read_review_json

OIDC_COMMANDS = {
    "oidc-provider-template",
    "verify-oidc-id-token",
    "bind-oidc-identity",
    "verify-oidc-workflow-bindings",
}


def oidc_help() -> str:
    return (
        "\nv0.7.2 external IdP / OIDC identity binding:\n"
        "  oidc-provider-template          create a pinned offline provider configuration\n"
        "  verify-oidc-id-token            verify an ID token against supplied JWKS and claims\n"
        "  bind-oidc-identity              bind verified OIDC subject/role to a signed FinRedOps object\n"
        "  verify-oidc-workflow-bindings   require exact OIDC coverage for signed workflow identities\n"
    )


def _parser(command: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"finredops {command}")
    if command == "oidc-provider-template":
        parser.add_argument("--output", type=Path, required=True)
        return parser
    if command == "verify-oidc-id-token":
        parser.add_argument("--provider-config", type=Path, required=True)
        parser.add_argument("--jwks", type=Path, required=True)
        parser.add_argument("--id-token", type=Path, required=True)
        parser.add_argument("--expected-nonce", required=True)
        parser.add_argument("--as-of", required=True)
        parser.add_argument("--output", type=Path, required=True)
        return parser
    if command == "bind-oidc-identity":
        parser.add_argument("--verification", type=Path, required=True)
        protected = parser.add_mutually_exclusive_group(required=True)
        protected.add_argument("--identity-assertion", type=Path)
        protected.add_argument("--approval-signature", type=Path)
        parser.add_argument("--as-of", required=True)
        parser.add_argument("--output", type=Path, required=True)
        return parser
    if command == "verify-oidc-workflow-bindings":
        parser.add_argument("--binding", type=Path, action="append", required=True)
        parser.add_argument("--identity-assertion", type=Path, action="append", default=[])
        parser.add_argument("--approval-signature", type=Path, action="append", default=[])
        parser.add_argument("--engagement-id", required=True)
        parser.add_argument("--output", type=Path, required=True)
        return parser
    raise ValueError(f"Unknown OIDC command: {command}")


def _write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(document, ensure_ascii=False, indent=2) + "\n")


def run_oidc_command(argv: Sequence[str]) -> int:
    command = argv[0]
    args = _parser(command).parse_args(list(argv[1:]))
    try:
        if command == "oidc-provider-template":
            _write_json(args.output, provider_template_document())
            print(f"OIDC provider template: {args.output}")
            return 0
        if command == "verify-oidc-id-token":
            verification = verify_oidc_id_token_from_files(
                provider_config_path=args.provider_config,
                jwks_path=args.jwks,
                id_token_path=args.id_token,
                expected_nonce=args.expected_nonce,
                as_of=parse_datetime(args.as_of),
            )
            _write_json(args.output, verification.as_dict())
            print(
                json.dumps(
                    {
                        "verification_id": verification.verification_id,
                        "subject": verification.subject,
                        "roles": list(verification.roles),
                        "provider_id": verification.provider_id,
                        "external_idp_protocol_verified": True,
                        "raw_id_token_retained": False,
                        "output": str(args.output),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if command == "bind-oidc-identity":
            verification = oidc_verification_from_document(read_review_json(args.verification))
            protected_path = args.identity_assertion or args.approval_signature
            binding = bind_oidc_identity(
                verification,
                read_review_json(protected_path),
                as_of=parse_datetime(args.as_of),
            )
            _write_json(args.output, binding.as_dict())
            print(
                json.dumps(
                    {
                        "binding_id": binding.binding_id,
                        "protected_id": binding.protected_id,
                        "subject": binding.subject,
                        "role": binding.role,
                        "external_idp_protocol_verified": True,
                        "output": str(args.output),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if command == "verify-oidc-workflow-bindings":
            bindings = tuple(
                oidc_binding_from_document(read_review_json(path)) for path in args.binding
            )
            protected = [
                *(read_review_json(path) for path in args.identity_assertion),
                *(read_review_json(path) for path in args.approval_signature),
            ]
            resolution = resolve_oidc_workflow_bindings(
                bindings,
                tuple(protected),
                engagement_id=args.engagement_id,
            )
            document = resolution.as_dict()
            _write_json(args.output, document)
            print(json.dumps(document, ensure_ascii=False, indent=2))
            return 0
        raise OIDCIdentityError("Unknown OIDC command.")
    except (OSError, ValueError, OIDCIdentityError) as exc:
        print(f"INVALID: {exc}")
        return 1
