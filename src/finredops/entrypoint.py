"""Top-level command router for FinRedOps operator and trust workflows."""

from __future__ import annotations

import sys

from .operator_cli import entrypoint as operator_entrypoint
from .signed_approval_cli import (
    SIGNED_APPROVAL_COMMANDS,
    run_signed_approval_command,
    signed_approval_help,
)
from .trust_cli import TRUST_COMMANDS, run_trust_command, trust_help


def entrypoint(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] in TRUST_COMMANDS:
        return run_trust_command(raw)
    if raw and raw[0] in SIGNED_APPROVAL_COMMANDS:
        return run_signed_approval_command(raw)
    if raw and raw[0] in {"-h", "--help"}:
        result = operator_entrypoint(raw)
        print(trust_help(), end="")
        print(signed_approval_help(), end="")
        return result
    return operator_entrypoint(raw)
