"""Allow ``python -m finredops`` execution."""

from .cli import entrypoint


raise SystemExit(entrypoint())
