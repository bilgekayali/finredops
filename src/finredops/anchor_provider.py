"""Provider-neutral client contract for independent audit anchoring."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .anchor_models import AuditAnchorCommitment, AuditAnchorReceipt


@runtime_checkable
class AuditAnchorProvider(Protocol):
    """External append-only service boundary used after source verification."""

    anchor_id: str

    def append(self, commitment: AuditAnchorCommitment) -> AuditAnchorReceipt: ...
