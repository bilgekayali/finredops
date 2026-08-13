"""Bounded JSON reader for CycloneDX 1.7 evidence."""

from __future__ import annotations

from .supply_chain import CYCLONEDX_SPEC_VERSION, SupplyChainIntakeError


def validate_root(document):
    if not isinstance(document, dict):
        raise SupplyChainIntakeError("CycloneDX root must be an object.")
    if document.get("bomFormat") != "CycloneDX":
        raise SupplyChainIntakeError("bomFormat must be CycloneDX.")
    if document.get("specVersion") != CYCLONEDX_SPEC_VERSION:
        raise SupplyChainIntakeError("Only CycloneDX 1.7 is accepted.")
    return document
