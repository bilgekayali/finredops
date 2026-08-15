# Backup and restore boundary review

FinRedOps contains multiple persistence domains with different trust properties.
A backup procedure must preserve those distinctions rather than treating every
SQLite/PostgreSQL file or exported artifact as interchangeable.

## Governance persistence

The SQLite governance reference store contains institution-scoped snapshots,
audit events and idempotency digests. Protected snapshot/audit payloads may be
AES-256-GCM envelope encrypted under institution KMS/HSM keys; indexed metadata
remains visible. A backup is recoverable only while the required historical key
references and provider access remain available.

For a direct SQLite file backup, close the application handle before copying the
file. The store uses WAL mode for file-backed databases; copying an open database
file without a database-consistent backup operation can omit committed WAL state.
Production deployments should prefer PostgreSQL-native backup/PITR or an
institution-approved SQLite online-backup/snapshot method rather than live file
copy.

## Evidence vault

The reference evidence vault persists encrypted envelope records plus append-only
custody events. The backup must preserve both tables as one consistency unit.
Restoring the record without its complete custody chain, or vice versa, is not a
valid evidence recovery state. Legal-hold and retention state is derived from
verified custody history and therefore cannot be reconstructed from current
metadata alone.

v0.9.3 regression coverage verifies closed-file copy/reopen of encrypted vault
state with the same institution context/provider. The existing recovery-bundle
workflow remains the portable, explicit evidence-level recovery mechanism and
preserves the encrypted record plus complete verified custody history.

## PostgreSQL production path

The PostgreSQL RLS backend requires database-native backups that preserve schema,
role/ownership assumptions and administrator-owned tenant registry state. A data
restore alone is insufficient if service-account mappings, RLS/FORCE RLS policies,
privileges or role attributes differ from the validated production contract.
After restore, rerun the live PostgreSQL runtime verifier before enabling the
application.

## External audit anchor

The reference anchor is intentionally under a separate administrative boundary.
Do not use a backup of the FinRedOps application database as the only backup or
witness for anchor receipts. Recovery should reconcile local receipts with an
independently retained continuity checkpoint or external witness. A privileged
administrator can rewrite the reference SQLite anchor; backup does not transform
it into WORM or a Byzantine transparency service.

## Keys and secrets

Database backups do not replace KMS/HSM disaster recovery. Preserve the ability
to resolve every required `retiring` data-encryption, audit-signing and workload-
identity key according to institution policy. Private keys and test-account
credentials must not be added to FinRedOps backup artifacts merely to make a
restore self-contained.

OIDC/JWKS, reviewer/approval/change-control trust bundles and historical policy
artifacts needed to reproduce old decisions should be retained under their own
controlled configuration/evidence retention rules.

## Restore acceptance checklist

Before a restored environment is accepted:

- verify release checksum/provenance and exact application version;
- verify database/schema compatibility before writes;
- verify institution id and tenant-routing/configuration-change state;
- verify PostgreSQL RLS/service-account contract when that backend is used;
- verify latest snapshot and complete audit-chain integrity;
- confirm envelope-encrypted records decrypt/authenticate under expected keys;
- verify evidence-vault custody, retention and legal holds;
- verify external anchor receipt continuity from independently retained state;
- confirm no one-time grant was unintentionally made reusable;
- test emergency-stop and isolated-worker connectivity in an approved non-
  production validation window before active capability is enabled.

Backup retention, geographic replication, RPO/RTO, cloud-vault immutability,
media sanitization and legal hold requirements are deployment-owner decisions;
FinRedOps does not infer them automatically.
