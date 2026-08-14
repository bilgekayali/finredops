# Failure recovery and migration runbook

FinRedOps v0.9.3 treats migration and partial-write recovery as controlled
operations. A release upgrade must never rely on an in-place downgrade to recover.
The supported rollback unit is a verified pre-migration backup or a previously
validated environment that still owns its compatible data copy.

## Before an upgrade

1. Stop writers for the target persistence boundary or enter an institution-
approved maintenance window.
2. Record the running FinRedOps version, current database `PRAGMA user_version`,
institution id, active encryption/signing key ids, and current audit/vault heads.
3. Produce a storage-engine-consistent backup. For the SQLite reference paths,
close the FinRedOps handle before a direct file copy; production engines should
use their native online backup/snapshot mechanism.
4. Verify that the backup is readable in an isolated restore environment before
starting migration.
5. Preserve historical KMS/HSM references required to decrypt or verify retained
artifacts. Do not disable a retiring key before dependent records are migrated or
expired under policy.
6. Retain release checksum/provenance evidence for the old and candidate builds.

## Compatibility contract

`finredops.release_compatibility.release_compatibility_manifest()` records the
release-candidate persistence contract. v0.9.3 reads/writes governance SQLite
schema v3 and automatically upgrades v1/v2 to v3. The evidence-vault,
reference-anchor and one-time-grant ledgers use schema v1. Unknown future
versions fail closed.

FinRedOps does **not** implement destructive automatic downgrade. If rollback is
required after a schema migration, restore the verified pre-migration backup and
run the prior compatible build against that restored copy. Do not point an older
binary at a newer database and attempt to edit `PRAGMA user_version` manually.

## Partial-transaction behavior

Governance snapshot writes, audit-chain extension, legacy-envelope rewrite,
vault record+initial-event creation, vault restore and custody append use explicit
transactions and rollback on failure. v0.9.3 regression tests inject failures
inside governance and vault transactions and verify that no partial object remains.
The one-time test-account grant is intentionally different: consumption is
committed **before** an external isolated-worker call. A worker failure does not
make the grant reusable; issue a new governed grant instead.

## Recovery decision tree

- **Process fails before database transaction starts:** correct the input or
  dependency and retry under the same governance rules.
- **Transaction raises and rolls back:** verify persisted head/state, then retry
  only if the original authorization is still valid.
- **One-time grant was consumed:** do not replay it. Create a new proposal/grant
  or follow the institution incident procedure.
- **Database opens with a future/unsupported schema:** stop. Do not rewrite the
  version marker. Recover with the release that owns that schema or restore a
  compatible backup.
- **Encrypted record cannot authenticate/decrypt:** stop writes, preserve the
  database and relevant KMS/HSM/key-policy state, collect audit evidence, and
  investigate as integrity/key-availability incident.
- **Persisted audit/vault history no longer verifies:** treat the copy as
  untrusted; preserve it for investigation and restore from an independently
  verified source where available.
- **External anchor continuity is missing:** do not fabricate predecessor state.
  Reconcile against independently retained receipts/witness data.

## Post-recovery validation

After a restore or retry, verify the institution namespace, governance store
metadata/schema version, latest snapshot digest, persisted audit chain, encrypted
record protection state, vault custody head/retention/holds, external anchor
continuity, current change-control/tenant authorization inputs, and workload
one-time-grant state. Re-enable writers only after these checks succeed.

This runbook is an application reference. Database, backup platform, KMS/HSM,
incident-management and legal-retention procedures remain institution-owned.
