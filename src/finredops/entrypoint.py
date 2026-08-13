"""Top-level command router for FinRedOps operator and trust workflows."""

from __future__ import annotations

import sys

from .change_control_cli import (
    CHANGE_CONTROL_COMMANDS,
    change_control_help,
    run_change_control_command,
)
from .hardening_cli import (
    HARDENING_COMMANDS,
    hardening_help,
    run_hardening_command,
)
from .oidc_cli import OIDC_COMMANDS, oidc_help, run_oidc_command
from .operator_cli import entrypoint as operator_entrypoint
from .postgres_cli import POSTGRES_COMMANDS, postgres_help, run_postgres_command
from .signed_approval_cli import (
    SIGNED_APPROVAL_COMMANDS,
    run_signed_approval_command,
    signed_approval_help,
)
from .tenant_auth_cli import (
    TENANT_AUTH_COMMANDS,
    run_tenant_auth_command,
    tenant_auth_help,
)
from .trust_cli import TRUST_COMMANDS, run_trust_command, trust_help


def entrypoint(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] in TRUST_COMMANDS:
        return run_trust_command(raw)
    if raw and raw[0] in SIGNED_APPROVAL_COMMANDS:
        return run_signed_approval_command(raw)
    if raw and raw[0] in OIDC_COMMANDS:
        return run_oidc_command(raw)
    if raw and raw[0] in CHANGE_CONTROL_COMMANDS:
        return run_change_control_command(raw)
    if raw and raw[0] in TENANT_AUTH_COMMANDS:
        return run_tenant_auth_command(raw)
    if raw and raw[0] in POSTGRES_COMMANDS:
        return run_postgres_command(raw)
    if raw and raw[0] in HARDENING_COMMANDS:
        return run_hardening_command(raw)
    if raw and raw[0] in {"-h", "--help"}:
        result = operator_entrypoint(raw)
        print(trust_help(), end="")
        print(signed_approval_help(), end="")
        print(oidc_help(), end="")
        print(change_control_help(), end="")
        print(tenant_auth_help(), end="")
        print(postgres_help(), end="")
        print(hardening_help(), end="")
        return result
    return operator_entrypoint(raw)