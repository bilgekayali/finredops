# Tenant isolation and institution-owned key boundaries

FinRedOps v0.8.0 introduces a persistence-level tenant boundary and a
provider-neutral institution key-reference contract. The goal is to prevent
cross-institution state collisions before adding concrete KMS/HSM cryptographic
adapters.

This release deliberately separates three claims:

1. **tenant-scoped persistence is implemented** for the SQLite governance store;
2. **institution-owned key custody references are modeled and validated**;
3. **encryption at rest and KMS/HSM-backed signing are not yet implemented or claimed**.

## Tenant-scoped SQLite persistence

`SQLiteGovernanceStore` is bound to exactly one `institution_id` when opened:

```python
with SQLiteGovernanceStore(
    "finredops.db",
    institution_id="bank-a",
) as store:
    ...
```

Individual store methods do not accept an alternate tenant identifier. Every
snapshot, audit event and idempotency record is queried and written through the
bound institution context.

Schema v2 uses composite keys:

```text
engagement_snapshots
  PRIMARY KEY (institution_id, engagement_id, revision)

audit_events
  PRIMARY KEY (institution_id, engagement_id, sequence)

idempotency_records
  PRIMARY KEY (institution_id, idempotency_key)
```

The same engagement id or idempotency key can therefore exist independently in
two institutions without one tenant reading, overwriting or conflicting with
the other through the FinRedOps store API.

`metadata()` reports the active `institution_id` and
`tenant_scope_enforced: true`. It also explicitly reports
`encryption_at_rest_verified: false`.

## Legacy database migration

A schema-v1 database is migrated transactionally to schema v2. Existing v1
records are assigned to the explicit `default` institution so historical data
remains readable through the backward-compatible default store context.

FinRedOps does not guess a real institution for legacy records. Operators that
need a different institutional assignment must perform a separately reviewed
data migration outside this automatic compatibility step.

## Audit engagement binding

Persistence now also rejects an incoming `AuditChain` if an event carries an
engagement id different from the engagement namespace supplied to
`persist_audit_chain`. This prevents a valid hash chain from being stored under a
different engagement label.

## Institution security context

The versioned `finredops.institution-security-context.v1` document records:

- institution id and display name;
- opaque institution-owned key references;
- key purpose;
- provider category;
- lifecycle status;
- optional public-key fingerprint;
- deterministic context digest.

Supported key purposes are:

```text
data_encryption
audit_signing
workload_identity
```

A valid context requires one active `data_encryption` key reference and one
active `audit_signing` key reference. The validator does not contact the key
provider and therefore does not claim that either operation has occurred.

## Key custody boundary

The context is intentionally a **reference-only** contract. `key_ref` is an
opaque handle such as an institution-managed KMS resource identifier, PKCS#11
handle, vault path or HSM alias.

FinRedOps rejects obvious PEM private-key material in `key_ref`. Private keys,
client secrets, wrapped data keys and HSM credentials do not belong in the
context document.

Provider categories currently include:

```text
aws_kms
azure_key_vault
gcp_kms
pkcs11
external_hsm
other
```

These names describe custody locations only. v0.8.0 does not contain provider
SDK calls or network access for these providers.

## Operator commands

Create a reference document:

```bash
finredops institution-context-template \
  --output institution-security-context.json
```

After replacing the synthetic references with institution-managed identifiers,
validate the context and digest:

```bash
finredops validate-institution-context \
  institution-security-context.json
```

The validation output explicitly contains:

```text
secret_material_stored: false
encryption_at_rest_verified: false
audit_signature_verified: false
```

Verify a persisted audit chain inside one institution namespace:

```bash
finredops verify-tenant-store \
  finredops.db \
  FRX-ENGAGEMENT-001 \
  --institution-id bank-a
```

A chain stored only under another institution fails closed as absent from the
requested tenant.

## Security properties

v0.8.0 provides these additional properties:

- institution-scoped snapshot revision namespaces;
- institution-scoped append-only audit namespaces;
- institution-scoped idempotency namespaces;
- deterministic migration of legacy records into `default`;
- explicit engagement-id consistency checks during audit persistence;
- strict, digest-bound institution key-reference configuration;
- no secret key material in the key-reference contract;
- explicit non-claims for encryption/signature execution.

## What v0.8.0 does not provide

This is not yet a production multi-tenant control plane. In particular, v0.8.0
does **not** provide:

- authenticated tenant routing at an HTTP/API gateway;
- row-level security enforced by an external database engine;
- institution-specific envelope encryption;
- verified KMS/HSM key operations;
- key rotation execution or cryptoperiod enforcement;
- HSM/KMS-backed audit signatures;
- tenant-specific authorization policy bundles;
- external immutable audit anchoring;
- evidence-vault retention or legal-hold enforcement.

Those remain separate hardening milestones so each capability can receive an
independent threat model and failure-mode review.

## Next hardening step

The next key-management milestone should turn the current reference contract
into a provider interface for institution-owned envelope encryption and signing
without allowing application code to export private key material. A concrete
adapter should keep provider access explicit, testable and deny-by-default rather
than silently introducing network capability into the core persistence layer.
