# Institution-owned KMS/HSM envelope encryption and evidence signatures

FinRedOps v0.8.1 adds a real cryptographic-operation boundary for institution-owned keys while keeping key custody outside the FinRedOps process.

## Security model

FinRedOps treats the institution KMS/HSM key as a **key-encryption/signing key**, not as application key material that may be exported. The control plane receives only an opaque `key_ref` from the institution security context and invokes a `KmsHsmProvider` implementation.

For protected persistence records:

1. FinRedOps generates a fresh 256-bit data-encryption key (DEK) for the individual record.
2. The record is encrypted locally with AES-256-GCM and a fresh 96-bit nonce.
3. Additional authenticated data binds the ciphertext to the institution, object type/id, institution key id, provider and key-reference digest.
4. The DEK is wrapped through the institution provider. Only the wrapped DEK is persisted with the ciphertext.
5. The plaintext DEK and the institution KEK are never persisted by FinRedOps.

The provider context also carries a bounded institution/object binding so a wrapped DEK cannot be silently replayed under a different tenant/object context when the provider supports authenticated encryption context.

## Persistence integration

`SQLiteGovernanceStore` schema v3 adds protection metadata to snapshot and audit-event rows. When both an `InstitutionSecurityContext` and a matching `KmsHsmProvider` are supplied, new snapshot and audit JSON payloads are written as `finredops.envelope-encrypted-artifact.v1` documents rather than plaintext JSON.

Logical digests, event hashes and tenant/index columns remain outside the encrypted payload. This allows deterministic integrity, ordering and idempotency checks without pretending SQLite itself supplies row-level security.

Existing v1/v2/v3 plaintext rows are not silently relabelled as encrypted. An explicit `encrypt_existing_records()` maintenance operation rewrites plaintext snapshot/audit payloads under the active institution key. `metadata()` reports both encrypted and remaining plaintext record counts; `encryption_at_rest_verified` is true only when cryptographic protection is configured, at least one protected row exists, and no legacy plaintext snapshot/audit rows remain for the bound institution.

## Key rotation

The institution context has exactly one **active** data-encryption key and one active audit-signing key. Historical key references may remain as `retiring` so old envelopes/signatures can still be decrypted or verified while new writes use the new active key.

A `disabled` key fails closed for decryption/signature verification. Removing an old key reference before all dependent artifacts are re-encrypted or retired will make those artifacts unavailable by design.

## Provider interface

`src/finredops/crypto_provider.py` defines the provider-neutral operations FinRedOps requires:

- wrap a 32-byte DEK under an opaque institution key reference;
- unwrap a previously wrapped DEK with the same bound context;
- sign a 32-byte SHA-256 digest;
- verify a digest signature.

A provider implementation is responsible for its own service authentication, authorization, audit logging and key policy.

### AWS KMS

`AwsKmsProvider` is a concrete production adapter using a boto3-compatible AWS KMS client:

- `Encrypt` / `Decrypt` wrap and unwrap the per-record DEK with an exact `EncryptionContext`;
- `Sign` / `Verify` operate on precomputed SHA-256 digests with `MessageType=DIGEST`;
- accepted signing algorithms are explicitly configured and restricted to SHA-256 modes (`ECDSA_SHA_256`, `RSASSA_PSS_SHA_256`, or `RSASSA_PKCS1_V1_5_SHA_256`);
- the AWS dependency is optional: `pip install 'finredops[aws-kms]'`.

FinRedOps never calls an API that exports the KMS key itself.

Other provider categories in the institution context (`azure_key_vault`, `gcp_kms`, `pkcs11`, `external_hsm`, `other`) remain supported by the provider-neutral interface, but v0.8.1 does **not** claim built-in adapters for all of them. An institution may inject a separately reviewed implementation of the protocol.

## Key-backed audit signatures

`sign_audit_chain()` signs a canonical digest target containing:

- engagement id;
- event count;
- current audit head hash;
- digest of the complete ordered audit document.

The resulting `finredops.key-backed-signature.v1` artifact also binds institution id, key id/provider/key-reference digest, signing time and exact signing-document digest.

A modified, extended, truncated or cross-institution audit chain therefore does not verify against an old signature.

## Key-backed execution-receipt signatures

`sign_execution_receipt()` signs a canonical receipt target containing the execution/proposal identities, proposal digest, status, runner, timestamps, evidence digest and complete immutable receipt digest.

A signature over one receipt cannot be reused for a receipt whose evidence or lifecycle fields changed.

## What is and is not claimed

v0.8.1 demonstrates **real application-layer envelope encryption** when a real provider such as `AwsKmsProvider` is configured, and real provider-backed audit/receipt signing when the provider executes those operations.

It does not claim:

- that SQLite supplies authenticated tenant routing or database row-level security;
- that an institution has correctly configured IAM/KMS/HSM key policy merely because a `key_ref` parses;
- automatic KMS/HSM key creation, rotation or deletion;
- universal Azure/GCP/PKCS#11 adapters;
- guaranteed zeroization of all transient Python byte copies;
- external immutable/timestamped audit anchoring;
- evidence-vault retention, legal hold or regulated deletion enforcement;
- regulatory acceptance, certification, or automatic report submission.

The existing FinRedOps simulation default, bounded controlled-validation policy, human review/approval separation, OIDC identity layer and non-issuance boundary are unchanged.
