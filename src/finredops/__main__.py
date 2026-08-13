"""Allow ``python -m finredops`` execution."""

from .entrypoint import entrypoint


raise SystemExit(entrypoint())
