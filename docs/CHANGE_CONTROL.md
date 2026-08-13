# Signed configuration change control

FinRedOps v0.8.4 adds a verification-only change-control layer for two production-facing configuration boundaries:

1. authenticated tenant-routing policies; and
2. PostgreSQL service-account institution/access mappings.

The objective is to make a configuration file, database mapping request, or operator intent insufficient by itself. A specific state transition must be digest-bound and independently approved before the guarded CLI path consumes it.

## Separate trust root

Configuration-change trust roots are intentionally separate from:

- qualified reviewer trust;
- business risk acceptance trust; and
- report approval trust.

A `qualified_tester`, `review_governor`, `business_risk_owner`, or `report_approver` credential therefore does not automatically authorize configuration changes.

The change trust bundle contains public Ed25519 verification keys only. FinRedOps does not create, import, escrow, rotate, or store approver private keys.

Exactly two approval roles are recognized:

- `configuration_governor`;
- `security_governor`.

An approved change requires one signature from each role, two distinct key identities, and two distinct human subjects. The same subject cannot satisfy both roles.

## Change request

`finredops.change-request.v1` binds:

- institution;
- change type;
- operation (`create`, `update`, or `disable`);
- object identifier;
- prior-state digest when applicable;
- target-state digest when applicable;
- institution or PostgreSQL contract context digest;
- requester;
- bounded rationale;
- request time and approval deadline.

The request ID and request digest are deterministic. A modified reason, institution, object, prior digest, target digest, or context creates a different signed object.

Create transitions require a target digest and no prior digest. Update transitions require distinct prior and target digests. Disable transitions require the prior digest and no target digest.

## Signatures and resolution

Each approver signs `finredops.change-signature.v1`, which binds the exact change ID and request digest plus issuer, subject, key, role, institution, and validity window.

Signatures are Ed25519 and may be valid for at most 24 hours. A change request may remain open for at most seven days.

`resolve-change-control` verifies both signatures at the recorded approval instant and emits `finredops.approved-change-package.v1`. The package contains:

- original digest-bound change request;
- both signed approval objects;
- reproducible change-control resolution;
- exact change-trust-bundle digest;
- independent-approval and cryptographic-verification markers;
- package digest.

The short-lived signatures represent the approval event. A previously approved policy does not expire merely because the signature envelope later passes its `expires_at`; package verification reproduces signature validity at the recorded `approved_at` instant. Historical trust bundles therefore need to be retained when historical approvals remain authoritative.

## Tenant-routing policy gate

The v0.8.4 CLI path for:

- `authorize-tenant-route`;
- `verify-tenant-authorization`; and
- `authorized-tenant-store-metadata`

requires both an approved change package and the exact change trust bundle.

The package must cover:

- `change_type = tenant_routing_policy`;
- the exact policy ID;
- the exact institution;
- the exact current institution-security-context digest;
- the exact policy digest;
- a `create` or `update` operation.

A package approved for another policy, institution, context version, or policy digest does not authorize the current policy.

Low-level Python policy primitives remain available for testing and composition, but the production-facing operator CLI is the governed path.

## PostgreSQL service-account mapping gate

The intended mapping is represented as `finredops.postgres-service-account-change.v1` and binds:

- PostgreSQL LOGIN role name;
- institution;
- `read` or `write` access mode;
- exact PostgreSQL RLS contract digest.

`postgres-service-account-sql` will generate mapping SQL only when the supplied approved change package covers the exact mapping digest.

`postgres-disable-service-account-sql` similarly requires an independently approved `disable` request bound to the exact service role, institution, prior mapping digest, and current PostgreSQL contract digest.

This does not make a PostgreSQL DBA cryptographically unable to execute SQL outside FinRedOps. It makes the FinRedOps production operator path fail closed unless change approval evidence exists.

## Operator sequence

A typical tenant-policy change is:

```text
tenant-routing-policy-template
        |
tenant-policy-change-request
        |
change-signature-request  (configuration_governor)
change-signature-request  (security_governor)
        |
external Ed25519 signing
        |
finalize-change-signature x2
        |
resolve-change-control
        |
verify-change-control
        |
authorize-tenant-route
```

A service-account mapping follows the same signing and resolution steps after `postgres-service-account-change-request`, then feeds the approved package to `postgres-service-account-sql`.

## Fail-closed conditions

The resolver or guarded consumer rejects, among other cases:

- missing or extra signatures;
- two signatures from the same subject;
- two signatures from the same key identity;
- duplicate governor role instead of one of each;
- unknown, disabled, expired, or not-yet-valid trust key at approval time;
- signature tampering;
- request digest tampering;
- trust-bundle digest mismatch;
- cross-institution replay;
- policy-ID or policy-digest mismatch;
- stale institution-security-context replay;
- PostgreSQL service-role, access-mode, or contract-digest mismatch;
- update without an exact prior-state digest;
- disable without an exact prior-state digest.

## Explicit non-claims

v0.8.4 does **not** claim:

- private-key custody or HSM enforcement for human change-approver keys;
- automatic enterprise ticket-system integration;
- automatic reconciliation with GitHub branch protection or CODEOWNERS;
- prevention of an intentionally privileged DBA changing PostgreSQL outside FinRedOps;
- automatic IdP group lifecycle or HR joiner/mover/leaver processing;
- external immutable timestamping of the change package;
- evidence-vault retention/legal-hold enforcement;
- regulatory certification or legal applicability determination.

External immutable anchoring and evidence lifecycle remain later release gates on the path to v1.0.0.
