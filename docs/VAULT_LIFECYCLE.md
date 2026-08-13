# Vault lifecycle

FinRedOps v0.9.0 introduces an institution-scoped encrypted evidence lifecycle. Records use the existing institution-owned KMS/HSM envelope-encryption boundary and append-only custody history. The encrypted object is bound to institution, engagement and evidence identity plus immutable classification, source, timing and digest metadata.

The older `custody.py` registry remains the metadata-only path for evidence stored outside FinRedOps. The v0.9.0 vault is additive and is used only when an institution deliberately places raw evidence inside this encrypted boundary.

## Retention and legal hold

The record establishes the initial retention date. Later custody events may extend that date but cannot move it backwards. Legal holds are independent from retention and are derived from verified append-only history rather than a mutable flag. A hold can be released only while active and a hold identifier cannot later be reused for another case.

Lifecycle eligibility is recomputed from the current record digest, custody head, effective retention date and active holds. An approval event is evidence of the lifecycle decision only; physical storage disposition remains outside the v0.9.0 reference service.

## Custody and recovery

Custody actions cover ingest, access, controlled export, hold application/release, retention extension, lifecycle approval and restore. Verification rejects sequence or hash gaps, cross-tenant/object replay, non-monotonic timestamps, duplicate ingest and invalid hold/retention transitions.

A recovery bundle contains the encrypted record and the complete verified custody history. Restore requires the same institution context, verifies the full history, checks envelope recoverability through the configured crypto provider, rejects an occupied target identifier and appends a restore event bound to the recovery-bundle digest.

## Reference backend

`SQLiteEvidenceVaultBackend` uses institution/evidence composite keys and append-only custody rows with transactionally checked head extension. It is a deterministic reference backend, not a storage-level immutability product. Metadata explicitly reports `physical_worm_verified: false` and `destructive_delete_supported: false`.

Production deployments may implement the provider-neutral backend over institution-approved immutable storage. Storage sanitization and disposal remain separate institution-governed operating procedures. NIST SP 800-88 Rev.2, AWS S3 Object Lock and Google Cloud locked retention are conceptual references only; FinRedOps does not claim protocol compatibility, automatic legal interpretation or compliance certification.

## CI boundary

The dedicated `Evidence Vault Boundary` workflow runs the focused regression suite and statically rejects network/process capabilities in the vault core, destructive service method names and mutable SQL paths for vault record/event tables. The normal Python 3.11/3.12/3.13 and package-smoke workflows remain the broader regression gate.
