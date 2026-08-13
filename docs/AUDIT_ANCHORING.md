# External audit anchoring

FinRedOps v0.8.5 introduces a provider-neutral boundary for publishing signed
audit-head commitments to an independently operated append-only service and for
verifying the returned receipts offline.

The purpose is tamper evidence across administrative boundaries. Local database
integrity, institution KMS/HSM signatures and external anchor receipts are
separate controls; none substitutes for the others.

## Trust sequence

1. Verify the local `AuditChain` hash chain.
2. Verify the existing `finredops.key-backed-signature.v1` audit-chain artifact
   against the institution-owned `audit_signing` KMS/HSM key.
3. Construct an `finredops.audit-anchor-commitment.v1` document that binds the
   institution, engagement, event count, audit head, full audit-document digest,
   audit-signature target digest, signature-artifact digest and combined source
   artifact digest.
4. Submit that canonical commitment to an independently operated anchor service.
5. Retain the returned `finredops.audit-anchor-receipt.v1` outside the local
   persistence boundary where appropriate.
6. Verify receipts offline with an independently distributed
   `finredops.audit-anchor-trust-bundle.v1` public-key bundle.

External anchoring MUST NOT be treated as proof that the original local audit
signature was valid. KMS/HSM verification is a mandatory source-side
precondition before a commitment is published.

## Commitment contract

A commitment contains no raw evidence. It binds:

- `institution_id` and `engagement_id`;
- exact `event_count` and `head_event_hash`;
- digest of the complete audit document;
- digest of the existing audit-signature target;
- digest of the KMS/HSM-backed signature artifact;
- a source digest over the audit chain and signature artifact;
- its own deterministic commitment digest.

Changing the local audit history or its signature therefore produces a different
commitment.

## Receipt contract

Each anchor receipt contains:

- `anchor_id` and signing `key_id`;
- global positive `sequence`;
- institution and engagement identity;
- exact commitment digest;
- `previous_receipt_digest`;
- timezone-aware `anchored_at` timestamp;
- Ed25519 signature over a deterministic SHA-256 signing-document digest;
- deterministic receipt digest.

The receipt chain begins with an all-zero previous digest. Offline verification
checks sequence continuity, previous-digest continuity, non-decreasing anchor
timestamps, duplicate commitment replay, key trust window/status and receipt
signature integrity.

This hash-linked receipt sequence is intentionally simple and provider-neutral.
It follows the same broad transparency principle as append-only transparency
logs, but FinRedOps does not claim RFC 6962, Rekor or Merkle-tree protocol
compatibility.

## Independent anchor trust root

Anchor signing keys are independent from:

- institution KMS/HSM encryption and audit-signing keys;
- finding-review trust keys;
- report/risk approval trust keys;
- configuration-change trust keys.

Only raw Ed25519 public keys appear in the FinRedOps anchor trust bundle.
Production clients must not receive the anchor private key.

A trust key can be `active`, `retiring` or `disabled`. Verification fails closed
for a disabled key or a receipt timestamp outside the key's configured trust
window. Historical trust bundles therefore need a deliberate retention and key
rotation policy.

## HTTPS client boundary

`HttpsAuditAnchorProvider` is the network-capable client adapter. It:

- accepts HTTPS endpoints only;
- rejects URL userinfo, query strings and fragments;
- uses the platform TLS-verifying context by default;
- disables HTTP redirect following;
- sends one canonical JSON commitment per POST;
- accepts only HTTP 200/201;
- limits response size to 128 KiB;
- parses the receipt through the strict runtime contract;
- requires the expected `anchor_id`.

Receipt cryptographic verification remains an offline step. Merely receiving a
JSON document over TLS is not sufficient trust.

## Reference append-only authority

`ReferenceAppendOnlyAnchorAuthority` is a small service-side implementation for
CI, integration testing and reference deployments. It serializes writers with a
SQLite `BEGIN IMMEDIATE` transaction, assigns a global sequence, links every new
receipt to the previous receipt digest, signs the receipt and exposes no
update/delete API.

The reference SQLite file is **not** a claim of physical WORM storage or
Byzantine transparency. An operating-system or storage administrator with direct
file access can still destroy or rewrite the database. Production deployments
that require stronger independence should run the anchor under a separate
administrative domain and use an append-only transparency service, immutable
object/WORM retention, external witnessing, or equivalent controls. Independently
retained signed receipts and continuity monitoring are necessary to detect
rollback, truncation or divergence.

## Failure modes

Verification fails closed when, among other cases:

- a receipt belongs to another anchor, institution or engagement;
- a receipt references another commitment;
- sequence numbers are reordered or missing;
- the previous receipt digest does not match;
- the same commitment appears more than once in a supplied receipt chain;
- anchor time moves backwards;
- the signing key is unknown, disabled or outside its trust window;
- signing-document, receipt or signature bytes are altered.

A single receipt can be verified against its exact commitment. Detecting
truncation or missing history requires continuity state: a prior receipt digest,
expected sequence, or a complete independently observed receipt stream.

## Separation from testing authority

Anchoring is evidence integrity infrastructure only. It does not:

- authorize a security test;
- expand target scope or action capability;
- approve risk acceptance or issue a report;
- determine regulatory applicability;
- certify compliance;
- make the built-in runner autonomous.

The existing engagement, approval, tenant, change-control and active-validation
boundaries remain authoritative.

## Standards context

The design is conceptually informed by public transparency-log systems in which
append-only history and independently verifiable signed log state make later
history rewriting detectable. RFC 6962 describes append-only consistency for
certificate-transparency Merkle trees, and Sigstore Rekor is an example of a
public, verifiable append-only transparency log. FinRedOps uses neither protocol
as a wire-format dependency in v0.8.5.
