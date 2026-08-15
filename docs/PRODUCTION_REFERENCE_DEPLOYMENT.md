# v1 production reference deployment

FinRedOps 1.0.0 ships a **production-reference architecture profile**, not a turnkey hosted service. The profile makes every production-facing trust dependency explicit and keeps credentials/private keys outside the repository.

The machine-readable profile is `deploy/reference/production-reference.json` and is validated by `finredops.reference_deployment.validate_reference_deployment()` plus `schemas/production-reference-deployment.schema.json`.

## Required trust chain

A conforming reference deployment wires the following boundaries together:

1. **External identity** — a pinned OIDC provider configuration and operator-supplied bounded JWKS are verified offline. FinRedOps does not perform `.well-known` discovery or remote JWKS retrieval in the verifier.
2. **Tenant authorization** — the verified OIDC provider/config digest and exact subject grant authorize one institution and closed capability subset.
3. **PostgreSQL 17 RLS** — the runtime database role resolves the institution from authenticated `session_user`; `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` are required and the runtime role must not be superuser, `BYPASSRLS`, owner, or able to `SET ROLE` into a privileged path.
4. **Institution cryptography** — the reference profile uses the built-in AWS KMS adapter. Institution-managed keys cover `data_encryption`, `audit_signing`, and `workload_identity`. AWS credentials, IAM and KMS key policy are external deployment responsibilities.
5. **Configuration change control** — tenant-policy and PostgreSQL service-account mapping changes require the independently trusted `configuration_governor` and `security_governor` approvals.
6. **External audit anchor** — institution-signed audit state is submitted through the pinned-HTTPS anchor boundary to an independently administered service/trust root.
7. **Evidence lifecycle** — selected raw evidence remains institution-bound and envelope encrypted, with append-only custody, forward-only retention and legal-hold state. Production WORM/object-lock technology is supplied by the institution.
8. **Isolated worker** — active validation remains non-production only, exact-proposal/lease bound, one-time-test-account bound, strict-egress bound, emergency-stop checked and signed by the institution workload key.

## Separation of control plane and provider responsibilities

FinRedOps supplies deterministic verification and reference interfaces. A production deployment must separately operate and secure:

- OIDC identity lifecycle and privileged-user governance;
- PostgreSQL network access, service-account credential lifecycle, backups and DBA controls;
- AWS KMS identity/IAM/key policies, rotation schedules and deletion controls;
- isolated-worker VM/container/kernel and network-policy enforcement;
- the external anchor service, immutable storage/witnessing and service authentication;
- evidence storage immutability, retention schedules, legal holds and final disposition;
- monitoring, secrets management, incident response, disaster recovery and regulatory applicability.

No credential, password, OIDC token, KMS credential, private key or worker test-account secret belongs in `production-reference.json`. The validator rejects secret-bearing field names as a defense against accidentally turning the deployment artifact into a credential bundle.

## Reference CI

The v1 release-gate workflow validates the profile and schema, exercises the compatibility/recovery suites, builds and installs the wheel, checks the stable CLI contract, and runs PostgreSQL integration through the existing live PostgreSQL test job. Production cloud-provider authentication is deliberately not emulated as proof of IAM correctness; the AWS KMS adapter is contract-tested separately and deployment IAM remains an institution responsibility.

The reference profile is therefore an **end-to-end architecture and integration contract** whose production-facing provider interfaces are concrete and testable, while real institutional credentials and external administrative domains remain outside CI.

## Deployment sequence

A deployment owner should:

1. establish external OIDC, AWS KMS, PostgreSQL and anchor trust roots;
2. apply PostgreSQL installation SQL with an administrator role;
3. provision non-superuser/non-`BYPASSRLS` LOGIN service accounts;
4. create and independently approve the institution routing and DB mapping changes;
5. verify the database runtime assessment before enabling application traffic;
6. configure institution security context with opaque AWS KMS references;
7. configure independently administered audit anchoring and evidence storage;
8. deploy the isolated worker with institution-owned workload identity and enforced egress;
9. run the v1 operational, backup/restore and incident checks before any authorized non-production active validation.

## Non-claims

The reference architecture does not certify a deployment, prove cloud IAM correctness, make SQLite WORM, provide an HSM, guarantee container isolation, provide a public transparency log, perform legal analysis, or permit production active testing. See `V1_NON_CLAIMS.md`.
