"""Shared contracts for the evidence vault lifecycle."""

from __future__ import annotations


class EvidenceVaultError(ValueError):
    """Raised when evidence-vault data is invalid."""
