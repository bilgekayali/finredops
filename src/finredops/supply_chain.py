"""Version-pinned supply-chain assurance intake contracts."""

from __future__ import annotations

CYCLONEDX_SPEC_VERSION = "1.7"


class SupplyChainIntakeError(ValueError):
    """Raised when a supply-chain assurance document fails validation."""
