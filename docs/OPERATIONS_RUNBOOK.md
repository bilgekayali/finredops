# Operations runbook

This runbook describes the FinRedOps reference operating sequence for a governed
institution deployment. It does not replace the institution's change, incident,
backup, KMS/HSM, identity or regulatory procedures.

## Deployment sequence

1. Verify the candidate source/repository revision and release provenance.
2. Install from the verified wheel into a dedicated runtime environment; enable
   optional AWS KMS/PostgreSQL dependencies only where required.
3. Configure institution security context with opaque key references. Keep
   private keys outside FinRedOps.
4. Configure external OIDC provider/JWKS policy and purpose-separated reviewer,
   approval, change-control and anchor trust roots.
5. For production persistence, install the PostgreSQL contract under privileged
   administration, map runtime service accounts through independently approved
   change packages, and run the live RLS/runtime verifier.
6. Configure tenant-routing policy and obtain the required independent signed
   change approval before authorization is used.
7. Configure institution KMS/HSM providers and verify encrypted persistence on
   non-production records before accepting sensitive data.
8. Configure the external audit-anchor service under an administrative boundary
   independent from the local application store.
9. Configure evidence-vault storage, retention/legal-hold governance and backup
   procedures.
10. If isolated active validation is enabled, configure a separately operated
    worker with institution workload identity, enforce the exact network policy
    outside the control plane, test the emergency-stop path, and keep production
    targets excluded.
11. Run end-to-end synthetic/non-production verification before enabling normal
    operators.

## Key rotation

### Data-encryption key

- introduce a new `active` data-encryption key reference through governed
  institution configuration;
- move the previous key to `retiring`, not `disabled`;
- new writes use the new active key;
- migrate/re-encrypt historical records under an approved maintenance process as
  required by policy;
- verify all retained records before disabling the old key;
- preserve backup recoverability for every backup that still depends on the old
  key.

### Audit-signing and workload-identity keys

New signatures/attestations use the active purpose-specific key. Historical
verification requires the matching historical reference to remain resolvable
until governed retention ends. Disable a compromised key immediately according
to incident policy, but treat historical artifacts signed by it as requiring
incident-specific review rather than silently re-signing them.

### Reviewer/approval/change/anchor public trust

Trust-bundle changes are configuration/security events. Preserve historical
bundles needed to reproduce old decisions. Never reuse one public/private key
identity across incompatible roles merely to simplify rotation.

## Incident response

### Suspected unauthorized active testing

- activate the institution emergency stop and pause the engagement;
- terminate/disable the isolated worker through the worker platform's own kill
  mechanism;
- disable/revoke relevant one-time account/credential resolver access;
- preserve proposal, policy decision, lease, signed worker receipt, audit chain
  and anchor receipts;
- verify whether the observed peer/target/time remained within the signed lease;
- rotate compromised workload/credential material as required;
- do not resume from the same one-time grant.

### Suspected data or audit tampering

- stop writes to the affected persistence domain;
- preserve database files/snapshots and relevant KMS/HSM state;
- verify audit chain, KMS-backed audit signature, external anchor receipts and
  independently retained continuity state;
- verify envelope authentication before reading protected payloads;
- restore only from a copy that independently passes integrity checks.

### Identity or approval compromise

- revoke/disable the affected external identity/key in its authoritative system;
- preserve historical signed artifacts;
- use the FinRedOps review lifecycle/change-control mechanisms rather than
  editing old decisions in place;
- reassess downstream reports/risk acceptances that relied on the compromised
  identity.

### KMS/HSM availability or policy failure

- fail closed on protected reads/writes/signatures;
- do not switch to plaintext storage or software private keys as an emergency
  bypass;
- restore provider/IAM/key policy under institution change control;
- verify key id/reference and historical decryptability before resuming.

## Disaster recovery

Use `BACKUP_RESTORE.md` and `FAILURE_RECOVERY.md` as the detailed recovery
boundary. The minimum sequence is: establish clean runtime, verify release,
restore database/storage from a consistent backup, restore KMS/HSM/trust access,
verify tenant/RLS configuration, verify audit and anchor continuity, verify vault
custody/holds, verify encryption, then test emergency stop and non-production
execution before reopening operators.

Never use an unsupported automatic schema downgrade as DR. Roll back by restoring
a pre-migration backup into the prior compatible environment.

## Routine verification

At an institution-defined cadence, verify:

- current release provenance/checksums;
- database schema compatibility and PostgreSQL RLS/service identity;
- active/retiring KMS/HSM key inventory;
- OIDC/trust/configuration policy freshness;
- audit-chain and external-anchor continuity;
- evidence-vault retention/legal-hold state;
- backup restore tests and required historical-key availability;
- isolated-worker image/isolation/network-policy evidence and emergency stop;
- expired reviews/risk acceptances/engagement windows;
- dependency advisories and institution software-supply-chain policy.

## Change freeze and rollback

Do not combine schema migration, key rotation, identity-provider migration and
worker-network changes into one uncontrolled deployment. Each should have a
bounded change plan, pre-change evidence, rollback point and post-change
verification. If verification fails, keep the system paused and restore the
last independently verified state rather than weakening a security boundary to
make the deployment pass.
