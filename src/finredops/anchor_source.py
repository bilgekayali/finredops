"""Create external anchor commitments only from verified institution-signed audit state."""

from __future__ import annotations

from .anchor_models import AuditAnchorCommitment, AuditAnchorError
from .audit import AuditChain
from .crypto_provider import KmsHsmProvider
from .institution import InstitutionSecurityContext
from .models import sha256_digest
from .signed_evidence import (
    KeyBackedSignatureArtifact,
    audit_chain_target,
    verify_audit_chain_signature,
)


def create_verified_audit_anchor_commitment(
    engagement_id: str,
    chain: AuditChain,
    audit_signature: KeyBackedSignatureArtifact,
    *,
    institution_context: InstitutionSecurityContext,
    provider: KmsHsmProvider,
) -> AuditAnchorCommitment:
    """Verify the KMS/HSM audit signature, then bind that exact state for anchoring."""

    if not verify_audit_chain_signature(
        engagement_id,
        chain,
        audit_signature,
        institution_context=institution_context,
        provider=provider,
    ):
        raise AuditAnchorError("Audit chain KMS/HSM signature verification failed.")
    target = audit_chain_target(engagement_id, chain)
    target_digest = sha256_digest(target)
    if audit_signature.institution_id != institution_context.institution_id:
        raise AuditAnchorError("Audit signature belongs to another institution.")
    if audit_signature.object_id != engagement_id or audit_signature.object_digest != target_digest:
        raise AuditAnchorError("Audit signature does not cover the current audit target.")
    source_digest = sha256_digest(
        {
            "schema_version": "finredops.audit-anchor-source.v1",
            "audit_chain": chain.as_list(),
            "audit_signature": audit_signature.as_dict(),
        }
    )
    item = AuditAnchorCommitment(
        institution_id=institution_context.institution_id,
        engagement_id=engagement_id,
        event_count=target["event_count"],
        head_event_hash=target["head_event_hash"],
        audit_document_digest=target["audit_document_digest"],
        audit_target_digest=target_digest,
        audit_signature_artifact_digest=audit_signature.digest(),
        source_artifact_digest=source_digest,
    )
    return AuditAnchorCommitment(**item.core(), commitment_digest=item.digest())
