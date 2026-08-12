"""Allow ``python -m finredops`` execution."""

from .operator_cli import entrypoint


raise SystemExit(entrypoint())
