# Supported upgrade from v0.9.3 to v1.0.0

The supported direct pre-v1 upgrade baseline is **FinRedOps 0.9.3**. The v1 release does not introduce a destructive SQLite downgrade mechanism and does not authorize opening a future schema with an older binary.

## Before upgrading

1. stop writers and quiesce active operator workflows;
2. record the installed package version and current institution/routing/change-control digests;
3. take closed, consistent backups of governance SQLite state, evidence-vault state and any reference anchor/one-time-grant ledgers that are deployed locally;
4. separately verify PostgreSQL backups using the institution database process;
5. retain institution KMS/HSM historical key references required to decrypt/verify existing artifacts;
6. retain historical reviewer, approval, OIDC provider-config, change-control and audit-anchor trust bundles needed to reproduce past decisions;
7. verify the v0.9.3 audit/evidence state before package replacement.

## Package transition

Install the 1.0.0 wheel from the verified release artifact. Verify `CHECKSUMS.sha256` locally and verify GitHub artifact provenance independently as described in `RELEASE_INTEGRITY.md` and `RELEASE_VERIFICATION.md`.

The v1 compatibility contract continues to recognize the existing governance SQLite schema v3, evidence-vault schema v1, reference-anchor schema v1 and one-time-grant-ledger schema v1. Unknown future schema versions remain fail-closed.

## Post-upgrade checks

Before re-enabling writes:

- confirm `finredops.__version__ == "1.0.0"`;
- run the normal audit/store verification for each required institution/engagement;
- re-run PostgreSQL runtime assessment under every production runtime service role;
- verify current institution KMS references and historical decrypt/verify requirements;
- verify active tenant routing policies against their approved change packages;
- verify external anchor continuity from independently retained receipt state;
- verify evidence-vault custody/retention/hold state for sampled and legally held evidence;
- validate the production-reference deployment profile used by the environment;
- run the institution's operational smoke and monitoring checks.

## Failure and rollback

FinRedOps does **not** implement destructive automatic downgrade. If the package transition fails before any supported schema-changing maintenance step, restore the pre-upgrade package and validate the unchanged data. If persisted state has changed in a way the old version does not support, restore the verified pre-upgrade backup instead of manually lowering schema metadata or editing security artifacts.

Never:

- manually decrement SQLite `user_version`;
- edit cryptographic digests to make an older binary accept new state;
- remove legal-hold or custody events to regain compatibility;
- disable PostgreSQL RLS/BYPASS protections for rollback convenience;
- reuse an expired/revoked trust bundle as if it were current.

The broader partial-failure and backup guidance in `FAILURE_RECOVERY.md` and `BACKUP_RESTORE.md` remains authoritative.

## Earlier releases

A deployment older than 0.9.3 is not a supported direct v1 upgrade target. It should first advance through the documented v0.8/v0.9 migrations so that tenant scoping, envelope encryption, authenticated routing, PostgreSQL RLS, signed change control, external anchoring, evidence lifecycle, assurance and workload boundaries are established before the v1 compatibility contract applies.
