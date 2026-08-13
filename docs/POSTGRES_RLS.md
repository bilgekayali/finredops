# PostgreSQL RLS and service-account boundary

FinRedOps v0.8.3 adds an optional PostgreSQL persistence path for deployments that need a database-engine tenant boundary in addition to the application-layer tenant authorization introduced in v0.8.2.

This is a **security boundary**, not a compliance certification. Operators remain responsible for database administration, network controls, identity lifecycle, KMS/HSM policy, backups, incident response and legal/regulatory applicability.

## Security model

The PostgreSQL boundary uses two independent checks before FinRedOps persists tenant data:

1. the application must already hold a valid `AuthorizedTenantSession`; and
2. the authenticated PostgreSQL `session_user` must independently map to the same institution and access mode in the administrator-owned service-account registry.

The institution is **not** selected with a client-controlled PostgreSQL custom setting. The RLS policies resolve tenant identity from `session_user`, so a caller cannot obtain another tenant simply by changing a request field or issuing `SET finredops.institution_id = ...`.

## Boundary roles

The deterministic installation contract creates three NOLOGIN boundary roles:

- `finredops_owner` — owns the schema, functions and protected tables;
- `finredops_reader` — SELECT-only runtime group role;
- `finredops_writer` — SELECT + INSERT runtime group role.

The boundary roles are created as `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`, `NOREPLICATION` and `NOBYPASSRLS`.

Actual LOGIN service accounts are provisioned **outside FinRedOps** by the institution's database/IAM process. FinRedOps does not create, generate, print or retain service-account passwords. An administrator then registers each existing LOGIN role to exactly one institution and either `read` or `write` access.

Runtime verification rejects a service account if it is a superuser, has `BYPASSRLS`, database/role-creation or replication privileges, inherits the owner role, has the wrong read/write group membership, or resolves to a different institution/access mode than expected.

## RLS tables and policies

The protected PostgreSQL schema contains:

- `engagement_snapshots`;
- `audit_events`;
- `idempotency_records`.

All three tables use both:

```sql
ALTER TABLE ... ENABLE ROW LEVEL SECURITY;
ALTER TABLE ... FORCE ROW LEVEL SECURITY;
```

SELECT policies permit only rows whose `institution_id` matches the current authenticated service-account mapping. INSERT policies additionally require a `write` mapping. Runtime roles receive no UPDATE or DELETE privileges.

The `tenant_service_accounts` registry is not readable by runtime reader/writer roles. Tenant resolution is exposed only through narrowly scoped `SECURITY DEFINER` functions with an explicit search path.

PostgreSQL superusers and roles with `BYPASSRLS` can bypass row security by design; table owners also normally bypass it unless row security is forced. FinRedOps therefore uses `FORCE ROW LEVEL SECURITY` and refuses privileged runtime roles. Privileged DBA, backup and recovery operations remain outside the tenant-runtime isolation claim.

## Envelope encryption remains mandatory

PostgreSQL does not replace the v0.8.1 cryptographic boundary. `PostgresGovernanceStore` requires an `InstitutionSecurityContext` and matching `KmsHsmProvider` and stores protected snapshot/audit payloads only as `envelope_v1` artifacts.

The result is defense in depth:

- RLS constrains which tenant rows a runtime database identity can see or insert;
- institution-owned KMS/HSM envelope encryption protects the stored payload itself;
- application authorization separately binds the OIDC-authenticated subject to tenant capabilities.

## Installation workflow

Generate deterministic administrator-reviewed installation SQL:

```bash
finredops postgres-rls-install-sql \
  --output postgres-rls-install.sql
```

The generated SQL creates the boundary roles, protected schema/tables, service-account registry, resolver functions, policies, grants and a digest of the expected FinRedOps database contract.

Create institution LOGIN roles using your database/IAM process. Then generate the mapping SQL, for example:

```bash
finredops postgres-service-account-sql \
  --service-role bank_a_finredops_writer \
  --institution bank-a \
  --access write \
  --output bank-a-writer.sql
```

The mapping operation verifies that the role already exists and is a LOGIN role without dangerous PostgreSQL role attributes. It revokes FinRedOps owner/reader/writer memberships and then grants exactly the selected runtime group role before updating the registry.

Disable a mapping with:

```bash
finredops postgres-disable-service-account-sql \
  --service-role bank_a_finredops_writer \
  --output disable-bank-a-writer.sql
```

Disabling marks the registry mapping inactive and revokes both runtime group roles.

## Live runtime verification

A production connection should be accepted only after live catalog verification:

```bash
export FINREDOPS_POSTGRES_DSN='postgresql://...'
finredops verify-postgres-runtime \
  --institution bank-a \
  --access write \
  --output postgres-runtime-assessment.json
```

The DSN is deliberately read from an environment variable instead of a command-line argument to reduce accidental credential exposure through shell history and process listings.

The verifier checks:

- `session_user == current_user` so a changed `SET ROLE` identity is not accepted;
- unsafe PostgreSQL role attributes are absent;
- exact reader-only or writer-only boundary membership;
- no owner-role membership;
- exact institution/access mapping from the administrator-owned registry;
- the installed FinRedOps contract digest;
- all required tables have RLS enabled and forced;
- all expected tenant SELECT/INSERT policies exist;
- effective table privileges match the registered access mode.

Only after those checks pass does the assessment set:

- `database_rls_verified: true`;
- `service_account_isolation_verified: true`;
- `rls_bypass_role_verified_absent: true`.

## Application authorization bridge

`open_authorized_postgres_store()` accepts an existing `AuthorizedTenantSession` and a PostgreSQL DSN but does **not** accept an institution id from the caller.

The application institution is derived from the verified tenant session. The database connection must independently resolve the same institution from its authenticated `session_user`. A mismatch fails closed before the store is returned.

This intentionally requires compromise of more than one boundary to cross tenants: changing an application request is insufficient, and obtaining a database credential for another institution still does not make it match the current application authorization.

## CI verification

The repository runs a live PostgreSQL 17 service in CI. The integration suite provisions synthetic bank-A reader/writer and bank-B writer LOGIN roles and verifies:

- live catalog assessment;
- bank-A writer cannot insert a bank-B row;
- bank-B writer cannot see bank-A rows;
- bank-A reader cannot insert;
- encrypted snapshot/audit/idempotency persistence works through the verified store;
- stored snapshot payload is `envelope_v1` rather than plaintext;
- wrong expected institution or access mode fails closed.

Python 3.11/3.12/3.13 unit regression and clean-wheel smoke tests remain separate from the live database job.

## Explicit non-claims

v0.8.3 does not provide or claim:

- PostgreSQL credential provisioning or password rotation;
- cloud database IAM configuration;
- connection-pooler tenant isolation by itself;
- API gateway or network authentication;
- KMS IAM/key-policy correctness;
- protection from a privileged PostgreSQL superuser/DBA intentionally reading database state;
- backup-vault or disaster-recovery isolation;
- signed/independently approved routing-policy or service-account mapping changes;
- immutable external timestamping/anchoring of audit heads;
- evidence-vault retention, legal hold or deletion enforcement;
- regulatory certification or automatic legal applicability decisions.

The existing FinRedOps execution boundary is unchanged: simulation remains the default, and the bounded active validator remains limited to explicitly approved non-production TLS `HEAD` validation. No target discovery, crawling, arbitrary commands, exploit payloads, credential attacks or production active testing are added by this PostgreSQL work.

## Reference

PostgreSQL row-security semantics and role attributes should be validated against the version deployed by the institution. The FinRedOps integration suite currently exercises PostgreSQL 17.
