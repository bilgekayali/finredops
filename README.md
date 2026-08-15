# FinRedOps

**Governance-first AI-assisted security testing orchestration for regulated financial institutions.**

[![CI](https://github.com/bilgekayali/finredops/actions/workflows/ci.yml/badge.svg)](https://github.com/bilgekayali/finredops/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-68f5b5.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-c9ff67.svg)](pyproject.toml)
[![Safety](https://img.shields.io/badge/active-validation%20approval--gated-ffc764.svg)](docs/SAFETY_BOUNDARY.md)

FinRedOps is an open-source control-plane prototype for teams that need to use
AI in security-testing workflows without allowing a model to decide what may
run. Models may propose typed actions; deterministic policy enforces scope,
time, separation of duties, immutable approvals, and a closed action catalog.

> [!IMPORTANT]
> **Version 0.9.3** keeps simulation as the safe default and preserves the
> bounded active-validation, signed-decision, tenant, database-RLS,
> configuration-change, external-audit-anchor, encrypted-evidence-vault,
> assurance-evidence, isolated-workload and report-issuance boundaries. It adds
> release-candidate compatibility/recovery controls: explicit persisted-schema
> compatibility, future-schema fail-closed guards, migration/rollback tests,
> backup/restore validation, a complete architecture threat model and deployment,
> key-rotation, incident and disaster-recovery runbooks. It does **not** perform
> destructive automatic downgrade and does not claim that independent security,
> legal or accessibility review has been completed.

FinRedOps is **not** a general-purpose exploit framework, autonomous penetration
tester, legal opinion, regulatory acceptance decision, independent audit, or
compliance certificate.

## Example reviewed security report

The repository contains a readable synthetic output of the governed
**SARIF → qualified review → draft report** workflow:

**[Open the example security report](EXAMPLE_SECURITY_REPORT.md)**

The example contains no live-target data and remains a `draft`,
human-approval-required audit-support artifact.

## Summary

In regulated environments, “the AI decided to run it” is not an acceptable
authorization model. A defensible workflow requires explicit rules of
engagement, accountable people, constrained execution, evidence minimization,
reversible controls, and an audit trail that can be independently reviewed.

```mermaid
flowchart TD
    A["Human or AI plan"] --> B["Strict planning gateway"]
    B --> C["Deny-by-default policy"]
    D["Scope + role-separated approval"] --> C
    C -->|allowed| E["Synthetic or bounded controlled runner"]
    C -->|denied| F["Recorded denial"]
    E --> G["Evidence receipt"]
    C --> WI["Short-lived institution workload identity"]
    WI --> WL["Single-use lease + egress + emergency stop"]
    WL --> WX["Separately operated isolated worker"]
    WX --> WS["Signed worker execution envelope"]
    WS --> G
    F --> H["Hash-chained audit"]
    G --> H
    G --> VV["Institution-scoped encrypted evidence vault"]
    I["Untrusted SARIF / CycloneDX"] --> J["Bounded intake + normalization"]
    J --> K["Qualified human review"]
    AS["ASVS 5.0.0 coverage + CVSS 4.0 technical severity"] --> K
    O["OIDC/JWKS verified subject + role"] --> L["Signed reviewer / approval identity"]
    K --> L
    L --> N["Authoritative review resolution"]
    N --> R["Signed risk acceptance when used"]
    R --> M["Trusted draft-report promotion"]
    M --> P["Two signed report approvers"]
    P --> Q["Approved, not automatically issued"]
    O --> W["Exact-subject + pinned-provider tenant routing policy"]
    CC["Two independent signed change governors"] --> W
    W --> X["Digest-bound tenant authorization"]
    X --> S["Institution-scoped persistence"]
    X --> Y["Verified PostgreSQL service identity"]
    CC --> Y
    Y --> Z["FORCE RLS tenant persistence"]
    Z --> S
    S --> H
    T["Fresh AES-256-GCM DEK + institution KMS/HSM"] --> S
    T --> VV
    VV --> H
    H --> U["KMS/HSM-backed audit signature"]
    U --> AA["External audit commitment"]
    AA --> AB["Independent signed anchor receipt chain"]
    G --> V["KMS/HSM-backed receipt signature"]
```

## Regulatory & security assurance coverage

FinRedOps analyzes security evidence and draft assurance conclusions against a
combination of **implemented financial-sector regulatory/control mappings** and
**international security-testing, privacy, operational-resilience and AI-risk
baselines**. Framework names are not decorative report labels: where structured
support exists, findings can be linked to control identifiers, applicability,
evidence and human-reviewed conclusions.

| Framework / authority | How FinRedOps uses it today |
|---|---|
| **BDDK** | Implemented Turkish banking regulatory crosswalk/applicability and penetration-testing assurance context |
| **SPK VII-128.10** | Implemented capital-markets information-systems crosswalk/applicability |
| **KVKK 6698** | Implemented personal-data security crosswalk/applicability and evidence-minimization context |
| **TSE / TS 13638/T2** | Public penetration-testing prerequisites and licensed-clause evidence boundary |
| **ISO/IEC 27001:2022 & 27002:2022** | ISMS/control applicability and control-oriented assurance mapping; no certification claim |
| **NIST SP 800-115** | Technical security-testing and assessment methodology baseline |
| **OWASP ASVS 5.0.0** | Version-pinned requirement catalog/coverage evidence with human-assessed status and no compliance-certification claim |
| **CycloneDX 1.7** | Bounded SBOM/supply-chain component and vulnerability intake with source digest and human-review boundary |
| **FIRST CVSS 4.0** | Vector-derived technical severity validation; explicitly separated from financial/business impact |
| **GDPR — Regulation (EU) 2016/679** | EU privacy/security, minimization and evidence-handling analysis baseline; no clause-level compliance claim |
| **DORA — Regulation (EU) 2022/2554** | Financial-sector ICT risk, operational-resilience and TLPT analysis baseline |
| **TIBER-EU** | Intelligence-led testing governance and human-accountability baseline |
| **NIST AI RMF** | AI-assisted workflow governance, traceability and human-oversight baseline |
| **MITRE ATT&CK** | Adversary-behavior and controlled-emulation planning reference |
| **OASIS SARIF 2.1.0** | Implemented bounded machine-finding intake and canonical review queue |

The intended assurance chain is:

```text
security evidence
    -> bounded normalization
    -> qualified human disposition
    -> external OIDC/JWKS subject + role verification when used
    -> signed identity + engagement binding
    -> authoritative review lifecycle resolution
    -> signed business risk acceptance when applicable
    -> technical + business impact
    -> regulatory / standard / requirement references
    -> human-confirmed applicability
    -> trusted draft assurance conclusion
    -> two signed human report approvals
```

This does **not** mean FinRedOps certifies compliance with BDDK, SPK, KVKK,
GDPR, DORA, TSE, ISO or ASVS requirements. It provides structured analysis,
traceability and audit-support evidence while keeping legal applicability,
regulatory acceptance, certification and final approval with authorized humans.

See **[Regulatory and security assurance baseline](docs/ASSURANCE_BASELINE.md)**
and **[v0.9.1 assurance completeness](docs/ASSURANCE_COMPLETENESS.md)** for the
coverage model, version pins and explicit non-claims.

## Core control model

| Boundary | v0.9.3 behavior |
|---|---|
| AI authority | May propose typed JSON only; cannot authorize or execute |
| Target scope | Exact hostname, IP, or CIDR allowlist; exclusions win |
| Action scope | Closed typed catalog; no free-form command field |
| Approvals | Role-separated, digest-bound, time-limited human decisions |
| Execution | Simulation by default; optional one-request TLS `HEAD` validation on approved non-production targets |
| Active boundary | No redirects, response-body collection, discovery, crawling, payloads, embedded credentials, shell, or production active tests |
| Isolated worker | Separately operated provider boundary; the FinRedOps control-plane workload modules have no built-in network/process execution capability |
| Workload identity | Short-lived KMS/HSM-backed institution identity binds worker/deployment, runtime-image digest, isolation-evidence digest and exact network-policy digest |
| Test account | One-time grant bound to institution/engagement/proposal/action/target; stores only account reference digest and no credential material |
| Workload egress | Exact action/target/port/path plus bounded peer CIDRs and one-request limit; signed result must report an allowed peer |
| Emergency stop | State checked before and after provider invocation; changed/active state rejects execution or result promotion, but does not claim rollback of a request already sent |
| Worker result | Execution envelope is bound to identity, lease, grant, egress, stop state and receipt, then verified under the institution workload key |
| Persistence compatibility | Governance SQLite schema v3 with tested v1/v2 upgrade; vault, reference anchor and one-time-grant ledger schema v1; future schema versions fail closed |
| Downgrade/rollback | No destructive automatic downgrade; rollback uses a verified pre-migration backup or prior compatible environment |
| Recovery testing | Injected transaction-failure tests verify governance/vault rollback; closed-file backup/reopen tests cover governance and encrypted vault state |
| Evidence handling | Deterministic minimization and redaction of likely sensitive identifiers |
| Evidence vault | Optional institution-scoped raw-evidence boundary with KMS/HSM envelope encryption, append-only custody, forward-only retention, history-derived legal holds and recovery bundles; reference SQLite is not WORM |
| Machine findings | Bounded SARIF 2.1.0 intake with stable fingerprints and mandatory review |
| Supply-chain evidence | Bounded CycloneDX 1.7 JSON normalization with source SHA-256, known-component reference integrity, no raw-source embedding and mandatory human review |
| CVSS evidence | CVSS 4.0 vector validation and qualitative technical severity only; financial/business impact is not inferred |
| ASVS evidence | Digest-bound OWASP ASVS 5.0.0 versioned requirement refs; human-assessed coverage, no embedded standard text, no compliance certification |
| Assurance linkage | Qualified-review `validation_evidence_refs` carry CycloneDX/ASVS evidence into draft finding evidence and governed report/audit metadata |
| Finding disposition | Qualified-tester decision with evidence, final severity, impact, recommendation, and control mapping |
| Reviewer identity | External Ed25519 assertion verification; subject/role bound to engagement, intake, finding and immutable review digest |
| External IdP identity | Offline OIDC ID-token + supplied-JWKS verification; pinned issuer/client/alg policy, nonce, ACR, authentication age and role claims |
| OIDC decision binding | Verified OIDC `sub` + role bound to signed reviewer/lifecycle or business/report approval object; aggregate resolver requires exact coverage |
| Review lifecycle | Signed `review_governor` supersession/revocation; history is preserved and parallel/orphan/cyclic chains fail closed |
| Authoritative review | Trusted promotion receives only the current cryptographically verified review for each finding |
| Risk acceptance | Separate `business_risk_owner`; acceptance signature is bound to acceptance digest + trusted-review-resolution digest |
| Approval trust roots | Dedicated public-key bundle; reviewer keys cannot authorize business risk or report approval |
| Report approval | Exactly two distinct `report_approver` signatures bound to source draft digest + trusted-promotion digest |
| Tenant persistence | Store handle binds one institution; snapshots/audit/idempotency use institution-scoped composite keys |
| Authenticated tenant routing | Verified OIDC provider + pinned provider-config digest + exact subject grant + current policy/context digests + closed capabilities; stored authorization is revalidated before use |
| Configuration change trust | Dedicated Ed25519 public-key bundle; exact trust-pinned `configuration_governor` + `security_governor` subjects and distinct key material are required |
| Configuration state transition | Exact institution/object/prior-target/context digests; create/update/disable semantics fail closed; tenant and PostgreSQL operator paths require the approved package |
| PostgreSQL tenant source | Production DB path resolves institution from authenticated `session_user` through an administrator-owned registry; no client-selected tenant GUC |
| Database RLS | Snapshot/audit/idempotency tables use PostgreSQL `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY`; live catalog verification is required before use |
| Service-account isolation | Exact reader-only or writer-only runtime membership; superuser, `BYPASSRLS`, owner membership and unsafe role attributes fail closed |
| Authorized PostgreSQL bridge | Application tenant authorization and independently database-resolved institution/access must agree |
| Authorized store writes | `store_write` capability plus institution crypto provider required, preventing silent plaintext bypass of v0.8.1 protection |
| Institution envelope encryption | Fresh per-record AES-256-GCM DEK; DEK wrapped by matching institution KMS/HSM provider; tenant/object context authenticated |
| Key-backed evidence | Audit-chain and execution-receipt digests can be signed/verified through the institution `audit_signing` key |
| External audit anchoring | A current KMS/HSM-verified audit head can be commitment-bound to an independent anchor; signed receipts link global sequence, prior receipt digest, institution, engagement and timestamp, and verify offline under a separate public-key trust root |
| Anchor network boundary | Only the dedicated HTTPS adapter has network capability; offline source/receipt/trust verification modules are CI-guarded from network/process imports |
| Concrete KMS adapter | AWS KMS `Encrypt`/`Decrypt` + `Sign`/`Verify`; AWS credentials/key policy remain outside FinRedOps |
| Regulatory assurance | BDDK, SPK, KVKK, TSE and ISO applicability/crosswalk support plus international analysis baselines |
| Draft promotion | Complete review set plus human-supplied asset, owner, and due date; never issues a report |
| Operator workflow | One CLI surface for legacy commands, trust verification, signed approvals, OIDC binding, signed change control, authenticated tenant routing, PostgreSQL runtime verification, audit-anchor verification, promotion and synthetic demonstration; vault, assurance and isolated-workload boundaries remain provider-neutral library surfaces |
| Release integrity | Wheel/sdist checksums, packaged examples, clean-wheel smoke test, version-tag binding, GitHub/Sigstore provenance |
| Reporting | Audit-support report templates and deterministic validation |
| Accountability | Append-only local hash chain, provider-backed signatures, independent external anchor receipts and offline-verifiable artifacts |

## v0.6 end-to-end operator workflow

Install the package in editable mode:

```bash
python -m pip install -e .
```

### 1. Import scanner evidence

```bash
finredops import-sarif examples/synthetic_sast.sarif.json \
  --output work/finding-intake.json
finredops validate-intake work/finding-intake.json
```

### 2. Review every candidate

```bash
finredops finding-review-template \
  --intake work/finding-intake.json \
  --finding-id FRX-SARIF-REPLACE-ME \
  --assessment-type vendor_source_code_review \
  --output work/review-draft.json

finredops finalize-finding-review \
  --intake work/finding-intake.json \
  --draft work/review-draft.json \
  --output work/review.json
```

Every candidate must receive one finalized human disposition before report
promotion can proceed.

### 3. Create the reviewed-report specification

```bash
finredops reviewed-report-spec-template \
  --intake work/finding-intake.json \
  --assessment-type vendor_source_code_review \
  --review work/review-1.json \
  --review work/review-2.json \
  --output work/reviewed-report-spec.json
```

The generated template is intentionally incomplete. The operator must replace
all `TODO` and date placeholders with accountable assessment metadata.
FinRedOps refuses to promote an unfinished template.

### 4. Promote reviewed findings into a draft report

```bash
finredops promote-reviewed-report \
  --intake work/finding-intake.json \
  --review work/review-1.json \
  --review work/review-2.json \
  --spec work/reviewed-report-spec.json \
  --output-dir work/reviewed-report
```

The legacy reviewed-report promotion path remains available for compatibility.
For signed reviewer and risk-acceptance enforcement use the trusted promotion
path described below.

The command produces:

```text
regulatory-report.json
regulatory-report.md
promotion-manifest.json
```

Existing operator outputs are not overwritten. The resulting report is always
`draft` and remains `ready_for_issue: false` until separate human report
approvals are provided.

### 5. Validate and render independently

```bash
finredops validate-report work/reviewed-report/regulatory-report.json
finredops render-report work/reviewed-report/regulatory-report.json \
  --output work/reviewed-report/verified-report.md
```

For the complete sequence, see
**[v0.6 Operator Workflow](docs/OPERATOR_WORKFLOW.md)**.

## v0.7 signed reviewer trust and lifecycle

v0.7 adds cryptographic identity binding **without putting private keys inside
FinRedOps**. A qualified review or lifecycle event receives a short-lived,
externally produced Ed25519 signature assertion. FinRedOps verifies that
assertion against a configured public-key trust bundle and binds it to the exact
engagement, intake batch, finding and immutable object digest.

Create an external signing request for a finalized review:

```bash
finredops identity-assertion-request \
  --intake work/finding-intake.json \
  --review work/review.json \
  --engagement-id FRX-ENGAGEMENT-001 \
  --issuer idp.example-bank.test \
  --key-id reviewer-key-2026 \
  --issued-at 2026-08-13T09:00:00Z \
  --expires-at 2026-08-13T10:00:00Z \
  --output work/review-signing-request.json
```

The external signer returns an Ed25519 signature; FinRedOps attaches it with
`finalize-identity-assertion`, then verifies it only when the protected review,
trust bundle and engagement context are supplied.

Review decisions are never edited in place. A separately signed
`review_governor` lifecycle event can `supersede` an old review with a new one or
`revoke` it without deleting history. `verify-review-trust` rejects invalid
signatures, engagement replay, role/subject mismatch, digest tampering, cycles,
branches and orphan histories.

```bash
finredops verify-review-trust \
  --intake work/finding-intake.json \
  --review work/review-a.json \
  --review work/review-b.json \
  --lifecycle-event work/lifecycle-event.json \
  --identity-assertion work/review-a.assertion.json \
  --identity-assertion work/review-b.assertion.json \
  --identity-assertion work/lifecycle.assertion.json \
  --trust-bundle trust/reviewer-trust.json \
  --engagement-id FRX-ENGAGEMENT-001 \
  --as-of 2026-08-13T10:30:00Z
```

`promote-trusted-reviewed-report` performs the same trust resolution before
calling the existing draft-report promotion boundary. Only current authoritative
signed reviews are passed forward. If business risk acceptance is supplied,
v0.7.1 additionally requires a dedicated approval trust bundle and a valid
signed acceptance for every acceptance record. The output can include
`signed-risk-acceptance-resolution.json` in addition to `trust-resolution.json`
and `trusted-promotion-manifest.json`. The report remains a `draft`.

Provider-neutral Ed25519 signatures remain independently verifiable. v0.7.2
adds the separate OIDC/JWKS layer described below when an operator needs evidence
that the signed `subject` and role were backed by a verified external IdP ID
token. Existing `trust-resolution.json` artifacts do not silently change their
meaning; OIDC protocol evidence is carried in its own verification/binding
artifacts.

See **[Reviewer trust, identity binding and lifecycle](docs/TRUST_IDENTITY.md)**
for the reviewer trust boundary and lifecycle model.

## v0.7.1 signed business and report approvals

Approval keys are kept in a **separate** `approval-trust-bundle` with only
`business_risk_owner` and `report_approver` roles. This prevents reviewer trust
keys from being reused as business or final-report approval credentials.

A signed risk acceptance is bound to both the immutable `RiskAcceptance` digest
and the current trusted-review-resolution digest. An accepted-risk finding cannot
enter the trusted draft report path without that signature.

A trusted draft report is approved only after **exactly two distinct**
`report_approver` signatures are verified against the source report digest and
`trusted_promotion_digest`:

```bash
finredops approve-trusted-report \
  --report work/trusted-report/regulatory-report.json \
  --trusted-promotion-manifest work/trusted-report/trusted-promotion-manifest.json \
  --approval-signature work/report-approval-1.json \
  --approval-signature work/report-approval-2.json \
  --approval-trust-bundle trust/approval-trust.json \
  --engagement-id FRX-ENGAGEMENT-001 \
  --as-of 2026-08-13T11:00:00Z \
  --output-dir work/approved-report
```

Outputs:

```text
approved-regulatory-report.json
approved-regulatory-report.md
signed-report-approval.json
```

The derived report has `status: approved` and can satisfy the existing
`ready_for_issue` structural check because its two `human_approvals` are verified
signature ids. This command **does not issue, transmit, file, or submit the
report**; `signed-report-approval.json` always records `report_issued: false`.

See **[Signed business and report approvals](docs/SIGNED_APPROVALS.md)** for the
full signing workflow and trust boundaries.

## v0.7.2 offline OIDC/JWKS identity binding

v0.7.2 verifies an external OpenID Provider ID token without adding autonomous
network access to FinRedOps. The operator supplies a pinned provider config, a
bounded JWKS export, the compact ID token and the expected authentication nonce.

```bash
finredops verify-oidc-id-token \
  --provider-config trust/oidc-provider.json \
  --jwks trust/idp-jwks.json \
  --id-token work/id-token.jwt \
  --expected-nonce "$OIDC_NONCE" \
  --as-of 2026-08-13T10:30:00Z \
  --output work/oidc-verification.json
```

The verifier checks the cryptographic signature plus exact issuer/client
binding, configured asymmetric algorithm allow-list, `kid`, nonce, token and
authentication age, ACR and the configured FinRedOps role claim. The output
stores SHA-256 token/JWKS/config digests and minimized claims; the raw ID token is
not retained.

Bind the verified IdP identity to an existing signed reviewer or approval object:

```bash
finredops bind-oidc-identity \
  --verification work/oidc-verification.json \
  --identity-assertion work/reviewer.assertion.json \
  --as-of 2026-08-13T10:30:00Z \
  --output work/reviewer.oidc-binding.json
```

For an entire assessment identity chain, `verify-oidc-workflow-bindings`
requires exact one-for-one coverage of all supplied signed reviewer/lifecycle and
business/report approval objects. A successful resolution records
`external_idp_protocol_verified: true` and `exact_binding_coverage: true`.

No `.well-known` discovery or remote JWKS retrieval occurs in this path. This
keeps verification deterministic and prevents IdP metadata URLs from becoming
an implicit network capability.

See **[OIDC / JWKS identity verification](docs/OIDC_IDENTITY.md)** for the full
provider contract, validation rules, role binding and remaining limitations.

## v0.8.0 tenant isolation and institution key boundaries

The SQLite governance store binds every handle to one `institution_id`.
Snapshots, audit events and idempotency records use composite institution-scoped
keys, so the same engagement or request identifier can exist independently in
two institutions. Schema-v1 data is migrated transactionally into the explicit
`default` institution.

Create and validate an institution-owned key-reference context:

```bash
finredops institution-context-template \
  --output institution-security-context.json

finredops validate-institution-context \
  institution-security-context.json
```

The context contains only opaque provider references and a deterministic digest.
It rejects obvious private-key material and requires one active data-encryption
reference and one active audit-signing reference. v0.9.2 isolated-worker use
additionally requires exactly one active `workload_identity` key reference; the
older store/envelope paths do not require that optional key purpose.

Verify one institution-scoped persisted audit chain:

```bash
finredops verify-tenant-store \
  finredops.db \
  FRX-ENGAGEMENT-001 \
  --institution-id bank-a
```

Tenant namespaces are supplemented by the authenticated v0.8.2 routing boundary,
the optional v0.8.3 PostgreSQL database RLS boundary and the v0.8.4 signed
configuration-change gate described below. SQLite remains the local/demo
persistence path rather than the database-engine RLS path.

See **[Tenant isolation and institution-owned key boundaries](docs/TENANT_ISOLATION.md)**
for migration behavior, key custody references, security properties and explicit
non-claims.

## v0.8.1 KMS/HSM envelope encryption and signed evidence

v0.8.1 turns the v0.8 key-reference boundary into an executable cryptographic
provider interface. When a matching institution security context and
`KmsHsmProvider` are supplied, the SQLite store encrypts new snapshot and audit
payloads before persistence with a fresh per-record AES-256-GCM DEK. The DEK is
wrapped by the institution provider, and the stored envelope is bound to the
institution and exact object context through authenticated data.

Legacy plaintext records remain visibly `plaintext` until an explicit
`encrypt_existing_records()` maintenance operation rewrites them. Store metadata
reports encrypted/plaintext counts and only sets `encryption_at_rest_verified`
when the configured institution has protected records and no remaining legacy
plaintext snapshot/audit payloads.

The same provider boundary signs canonical SHA-256 targets for audit chains and
execution receipts. Signatures bind the institution, exact key reference,
object digest and signing time. A modified/extended audit chain or modified
receipt therefore cannot reuse the old signature.

A concrete `AwsKmsProvider` is included. Install its optional dependency with:

```bash
python -m pip install 'finredops[aws-kms]'
```

It uses AWS KMS `Encrypt`/`Decrypt` with an encryption context and `Sign`/`Verify`
with explicitly configured SHA-256 signing algorithms. AWS credentials, IAM/key
policy, key creation and key lifecycle remain institution responsibilities.

Other KMS/HSM provider categories are represented by the protocol but do not
all have built-in v0.8.1 adapters. See
**[Institution-owned KMS/HSM envelope encryption and evidence signatures](docs/KMS_ENVELOPE_SIGNING.md)**
for the cryptographic model, rotation semantics and explicit limitations.

## v0.8.2 authenticated tenant routing and authorization

v0.8.2 consumes the minimized v0.7.2 OIDC verification artifact and an explicit
institution routing policy. One policy binds one OIDC provider **and the exact
provider-config digest** to one institution and contains exact-subject grants;
wildcards and implicit membership are not supported. Requested access is limited
to the closed capability set `store_read`, `store_write`, `audit_verify`, and
`crypto_use`.

Create a conservative policy template. In v0.8.4, the finished policy must then
be independently approved through the change-control workflow before it is used
to authorize or revalidate a tenant route:

```bash
finredops tenant-routing-policy-template \
  --institution-context institution-security-context.json \
  --oidc-verification oidc-verification.json \
  --output tenant-routing-policy.json

# After tenant-policy-change-request -> two external signatures ->
# resolve-change-control produces approved-policy-change.json.
finredops authorize-tenant-route \
  --policy tenant-routing-policy.json \
  --institution-context institution-security-context.json \
  --oidc-verification oidc-verification.json \
  --change-package approved-policy-change.json \
  --change-trust-bundle trust/change-control-trust.json \
  --capability store_read \
  --capability audit_verify \
  --as-of 2026-08-13T10:00:00Z \
  --output tenant-authorization.json

finredops verify-tenant-authorization \
  --authorization tenant-authorization.json \
  --policy tenant-routing-policy.json \
  --institution-context institution-security-context.json \
  --oidc-verification oidc-verification.json \
  --change-package approved-policy-change.json \
  --change-trust-bundle trust/change-control-trust.json \
  --as-of 2026-08-13T10:15:00Z
```

The authorization binds the exact OIDC verification digest, policy digest,
current institution-context digest, effective role intersection and capability
subset. The policy digest itself pins the OIDC provider configuration. It
expires with the source identity. A saved authorization is not trusted alone:
current source artifacts are required again. The authorized store session derives
the institution namespace from those validated bindings, and writes require the
institution cryptographic provider so the envelope-encryption path cannot be
silently bypassed. v0.8.4 additionally requires the policy approval package to
reproduce successfully against its exact historical change trust bundle.

See **[Authenticated tenant routing and authorization](docs/TENANT_AUTHORIZATION.md)**
for the full policy model, fail-closed rules and production non-claims.

## v0.8.3 PostgreSQL RLS and service-account isolation

v0.8.3 adds an optional PostgreSQL persistence backend that independently derives
the tenant from the authenticated database `session_user`. The administrator-owned
registry maps one existing LOGIN service role to exactly one institution and one
access mode. Runtime roles with superuser, `BYPASSRLS`, owner membership or other
unsafe role attributes are rejected before FinRedOps accepts the connection.

Generate the base installation SQL directly. In v0.8.4, service-account mapping
or disable SQL additionally requires an exact independently approved change
package:

```bash
finredops postgres-rls-install-sql \
  --output postgres-rls-install.sql

finredops postgres-service-account-sql \
  --service-role bank_a_finredops_writer \
  --institution bank-a \
  --access write \
  --change-package approved-service-account-change.json \
  --change-trust-bundle trust/change-control-trust.json \
  --output bank-a-writer.sql
```

Runtime verification reads the DSN from an environment variable rather than a
command-line credential:

```bash
export FINREDOPS_POSTGRES_DSN='postgresql://...'
finredops verify-postgres-runtime \
  --institution bank-a \
  --access write \
  --output postgres-runtime-assessment.json
```

The verifier checks database role attributes/membership, the exact registry
mapping, installation contract digest, table RLS + FORCE RLS state, expected
policies and effective SELECT/INSERT/UPDATE/DELETE privileges. A successful live
assessment sets `database_rls_verified`, `service_account_isolation_verified`
and `rls_bypass_role_verified_absent` to true.

`PostgresGovernanceStore` still requires the institution security context and
matching KMS/HSM provider; protected snapshot and audit payloads are written only
as v0.8.1 `envelope_v1` artifacts. The application bridge does not accept an
institution argument: the v0.8.2 `AuthorizedTenantSession` institution must
independently match the database service account's resolved institution.

See **[PostgreSQL RLS and service-account boundary](docs/POSTGRES_RLS.md)** for
the threat model, administrator workflow, live verification and explicit
privileged-DBA/non-production claims.

## v0.8.4 signed configuration change control

v0.8.4 adds a dedicated change-control trust root for production-facing tenant
policy and PostgreSQL service-account mapping changes. It is deliberately
separate from reviewer, business-risk and report-approval keys.

A change request binds the exact institution, object, operation, prior state,
target state, context digest, requester, rationale and approval window. The
resolver requires exactly two Ed25519 signatures: one trust-pinned
`configuration_governor` and one trust-pinned `security_governor`. The subjects,
key identities and public-key material must be distinct.

Example tenant-policy approval sequence:

```bash
finredops tenant-policy-change-request \
  --policy tenant-routing-policy.json \
  --institution-context institution-security-context.json \
  --operation create \
  --requested-by platform-owner \
  --reason 'Introduce governed tenant routing policy' \
  --requested-at 2026-08-13T09:00:00Z \
  --valid-until 2026-08-13T12:00:00Z \
  --output policy-change-request.json

finredops change-signature-request \
  --change-request policy-change-request.json \
  --issuer bank-a-change-ca \
  --subject config-governor-user \
  --key-id config-2026 \
  --role configuration_governor \
  --issued-at 2026-08-13T09:10:00Z \
  --expires-at 2026-08-13T10:10:00Z \
  --output config-signing-request.json

# Repeat for security_governor, sign both requests externally, then finalize.
finredops resolve-change-control \
  --change-request policy-change-request.json \
  --signature config-change-signature.json \
  --signature security-change-signature.json \
  --trust-bundle trust/change-control-trust.json \
  --approved-at 2026-08-13T09:20:00Z \
  --output approved-policy-change.json

finredops verify-change-control \
  --package approved-policy-change.json \
  --trust-bundle trust/change-control-trust.json
```

Short-lived signature envelopes prove the approval event. The resulting approved
package remains reproducible by checking the signatures at its recorded
`approved_at` instant against the exact trust-bundle digest; a valid production
policy therefore does not expire merely because the approval signature window
later closes. Historical trust bundles must be retained while historical
approvals remain authoritative.

The PostgreSQL workflow starts with
`postgres-service-account-change-request` or
`postgres-service-account-disable-request`; the approved package is then required
by the SQL-generation command. A privileged DBA can still act outside FinRedOps,
so this is an operator-path governance boundary rather than a claim that the
repository can constrain an intentionally privileged database administrator.

See **[Signed configuration change control](docs/CHANGE_CONTROL.md)** for the
full state-transition model, trust separation and non-claims. The remaining
release gates through v1.0.0 are tracked in **[Roadmap](docs/ROADMAP.md)**.

## v0.8.5 independent external audit anchoring

v0.8.5 adds a trust boundary outside the local persistence and institution KMS/HSM
administrative domains. `create_verified_audit_anchor_commitment()` first
re-verifies the current KMS/HSM-backed audit-chain signature. Only that exact
signed state can be converted into a digest-bound commitment containing the
institution, engagement, event count, audit head, full audit-document digest,
signature-target digest, signature-artifact digest and combined source digest.
If the audit chain changes after signing, commitment creation fails closed.

`AuditAnchorProvider` is the provider-neutral client interface. The included
`HttpsAuditAnchorProvider` posts one canonical commitment to one exact HTTPS
endpoint, disables redirects, bounds time and response size, and parses a strict
receipt contract. It does not retrieve credentials or discover an anchor service.
Network capability is isolated in that adapter; the source builder, artifact
models, CLI and receipt verifier remain offline and are protected by a dedicated
CI import-boundary check.

A receipt binds a global sequence, the previous receipt digest, `anchor_id`,
institution, engagement, commitment digest, anchor timestamp and anchor signing
key. It is Ed25519-signed under a trust root separate from institution KMS/HSM,
reviewer, approval and configuration-change trust. `verify-audit-anchor-chain`
rejects reordered history, broken previous-digest continuity, duplicate
commitments, backwards time and invalid/disabled/out-of-window signing keys.
Single-receipt verification can additionally pin an expected sequence and prior
receipt digest.

Offline operator verification:

```bash
finredops validate-audit-anchor-commitment work/audit-anchor-commitment.json
finredops validate-audit-anchor-trust-bundle trust/audit-anchor-trust.json
finredops verify-audit-anchor-receipt \
  work/audit-anchor-commitment.json \
  work/audit-anchor-receipt.json \
  trust/audit-anchor-trust.json
finredops verify-audit-anchor-chain \
  work/audit-anchor-receipts.jsonl \
  trust/audit-anchor-trust.json
```

`ReferenceAppendOnlyAnchorAuthority` is intentionally a small **service-side**
reference implementation for CI and isolated reference deployments. It serializes
append writers, assigns global sequence numbers, links receipts and exposes no
update/delete API. Its SQLite file is **not** physical WORM storage and is not a
Byzantine transparency service: a privileged storage administrator can still
destroy or rewrite it. Stronger deployments should operate the anchor under a
separate administrative domain and use immutable/WORM storage, external
witnessing, a transparency-log service, or equivalent controls. FinRedOps v0.8.5
also does not claim RFC 6962 or Sigstore Rekor wire-protocol compatibility.

External anchoring is evidence-integrity infrastructure only. It does not
authorize testing, expand scope/capabilities, approve risk, issue reports,
determine regulatory applicability or certify compliance.

See **[External audit anchoring](docs/AUDIT_ANCHORING.md)** for the receipt
contract, trust model, continuity requirements, transport boundary and explicit
non-claims.

## v0.9.0 encrypted evidence vault lifecycle

v0.9.0 adds a provider-neutral raw-evidence lifecycle beside the existing
metadata-only custody registry. An `EvidenceVaultRecord` can be created only with
an institution-bound `envelope_v1` object whose authenticated context includes
the institution, engagement and evidence identity. The SQLite reference store
therefore persists ciphertext/wrapped-key material plus immutable metadata rather
than raw evidence bytes.

Custody state is reconstructed from a hash-linked append-only event history.
Retention starts on the immutable record and may only be extended. Legal holds
are independent from retention, can be released only while active and use
non-reusable hold identifiers. Lifecycle eligibility is recomputed against the
exact record digest, custody head, effective retention date and active holds.
The approval event explicitly records that no physical storage disposition was
executed; v0.9.0 intentionally has no destructive vault service operation.

Recovery bundles contain the encrypted record plus complete verified custody
history and no plaintext evidence. Restore is allowed only under the same
institution boundary, verifies envelope recoverability through the configured
KMS/HSM provider, rejects an occupied target identifier and appends a restore
event bound to the bundle digest. Cross-institution restore fails closed.

`SQLiteEvidenceVaultBackend` is an application-level append-only **reference**
backend, not physical WORM storage. Production deployments can implement the
same backend protocol over institution-approved storage. See
**[Vault lifecycle](docs/VAULT_LIFECYCLE.md)** for retention, legal-hold,
recovery and non-claim details.

## v0.9.1 assurance completeness

v0.9.1 adds three offline, version-pinned assurance evidence boundaries while
keeping all conclusions behind the existing qualified-review workflow.

`finredops.supply_chain` accepts a deliberately bounded CycloneDX JSON subset
with `bomFormat: CycloneDX` and `specVersion: 1.7`, source-digest binding, unique
component references, affected-component referential integrity and optional
CVSSv4 ratings. The normalized batch never embeds the raw source and cannot
promote findings by itself.

`finredops.cvss40` accepts only CVSS 4.0 vectors and validates vector-derived
technical score/severity plus optional published score/severity assertions. Its
artifact explicitly records that financial/business impact was **not** inferred.

`finredops.asvs_coverage` keeps OWASP ASVS source material external, pins the
source digest and version `5.0.0`, and uses versioned requirement refs such as
`v5.0.0-1.2.5`. Coverage is explicitly human-assessed and non-certifying.

CycloneDX and ASVS evidence references enter governed reporting only when a
qualified tester places them in `validation_evidence_refs`; the existing report
promotion path carries those exact refs into draft finding evidence and the
audit dossier retains the governed report metadata. See
**[Assurance completeness](docs/ASSURANCE_COMPLETENESS.md)** for supported input
boundaries, linkage semantics and non-claims.

## v0.9.2 isolated workload execution

v0.9.2 introduces an explicit boundary between the governance control plane and
a separately operated active-validation worker. The control plane verifies a
short-lived KMS/HSM-backed institution workload identity, an exact policy-approved
proposal, one one-time test-account grant, a single-request egress rule and the
current emergency-stop generation before an external provider can be invoked.

The execution lease is valid for at most 15 minutes and cannot enable production
active testing, autonomous discovery or arbitrary commands. It cannot outlive
the workload identity, test-account grant or engagement window. The account
grant contains only an opaque account-reference digest and is atomically consumed
before worker invocation so it cannot be replayed after a failed attempt.

The external worker returns a typed execution envelope plus a workload-key-backed
signature. Verification binds the result to the exact identity, lease, grant,
egress rule, emergency-stop state, observed peer address and underlying
`ExecutionReceipt`. The stop state is checked again after the call; a change
rejects the result for promotion. This does not claim retroactive rollback of a
request already sent by the external worker.

The repository does not claim to create or independently attest a secure
container/VM/sandbox, enforce kernel/SDN egress, provision test-account secrets,
or implement SPIFFE/SPIRE. Those deployment controls remain institution
responsibilities. See **[Isolated workload execution](docs/WORKLOAD_EXECUTION.md)**
for the trust flow, provider contract, replay behavior, egress semantics and
explicit non-claims.

## v0.9.3 release-candidate hardening

v0.9.3 makes persistence and operational recovery expectations explicit before
the v1 gate. `release_compatibility_manifest()` records the current persistence
schemas and security-artifact schema identifiers, states that automatic downgrade
is unsupported, and requires a pre-migration backup/previous compatible
environment for rollback.

Regression coverage exercises governance schema v2→v3 migration, future-schema
rejection across governance/vault/anchor/grant-ledger databases, unknown future
security-artifact rejection, injected transaction rollback and closed-file
backup/reopen of governance plus encrypted vault state. The reference anchor and
one-time-grant ledger now also persist explicit SQLite schema version 1 and reject
unknown versions.

The release candidate adds dedicated failure-recovery, backup/restore,
release-security and operations runbooks and updates the threat model to the full
OIDC/tenant/RLS/KMS/change-control/anchor/vault/assurance/isolated-worker
architecture. These are maintainer/reference controls; independent security,
legal and accessibility review remain open v1 gates.

See **[Failure recovery](docs/FAILURE_RECOVERY.md)**,
**[Backup and restore](docs/BACKUP_RESTORE.md)**,
**[Release security review](docs/RELEASE_SECURITY_REVIEW.md)** and
**[Operations runbook](docs/OPERATIONS_RUNBOOK.md)**.

## Reproduce the reviewed-report demo from an installed wheel

The synthetic engagement, plan, and SARIF input ship as package data. A source
checkout is not required for the reviewed-report demo:

```bash
finredops export-examples --output-dir finredops-examples
finredops demo-reviewed-report --output-dir demo-output/reviewed
finredops validate-report demo-output/reviewed/regulatory-report.json
```

`demo-reviewed-report` uses the packaged synthetic SARIF by default. An explicit
SARIF file may still be supplied with `--sarif`.

The demo creates canonical intake, two finalized synthetic reviews, one promoted
finding, a draft JSON/Markdown report, and a promotion manifest. No live target
is contacted.

## Release integrity and provenance

Tagged releases build a wheel and source distribution, smoke-test the installed
wheel in a clean environment with declared runtime dependencies, generate a
`CHECKSUMS.sha256` manifest, and create GitHub/Sigstore artifact provenance.

Local checksum verification:

```bash
finredops verify-release-checksums \
  --manifest ./CHECKSUMS.sha256 \
  --directory .
```

This verifies local SHA-256 integrity only. It deliberately does **not** claim
that provenance has been verified.

Verify the build origin separately with GitHub CLI artifact attestations:

```bash
gh attestation verify finredops-0.9.3-py3-none-any.whl \
  --repo bilgekayali/finredops
```

See **[Release integrity and provenance](docs/RELEASE_INTEGRITY.md)** for the
trust model, tag/version binding, clean-wheel test, and verification boundaries.

## Existing visual and assurance demo

```bash
python -m finredops demo --output demo-output
python -m finredops verify-audit demo-output/audit.jsonl
python -m finredops verify-store demo-output/finredops.db FRX-DEMO-2026-001
python -m finredops verify-tenant-store demo-output/finredops.db FRX-DEMO-2026-001 --institution-id default
python -m finredops validate-report demo-output/regulatory-report.json
python -m finredops validate-applicability demo-output/applicability.json
python -m finredops validate-evidence-manifest demo-output/evidence-manifest.json
python -m finredops verify-bundle demo-output/audit-dossier.zip
python -m finredops render-report demo-output/regulatory-report.json \
  --output demo-output/verified-report.md
python -m finredops serve --host 127.0.0.1 --port 8080
```

The demo includes a synthetic engagement, digest-bound approvals, policy
decisions, evidence receipts, an intentional denial, an operations dashboard,
SQLite persistence, a BDDK/SPK/KVKK/TSE/ISO regulatory crosswalk, international
security/resilience analysis baselines, evidence custody, and an offline review
dossier.

## Repository map

```text
src/finredops/
  planner.py              strict AI-to-control-plane boundary
  policy.py               deterministic deny-by-default authorization
  catalog.py              closed catalog of typed actions
  runner.py               network-free synthetic evidence runner
  validation.py           optional bounded active validation
  workload_identity.py    KMS/HSM-backed short-lived external worker identity and signed receipts
  workload_execution.py   exact non-production execution lease, egress, one-time grant and stop verification
  workload_ledger.py      versioned atomic institution-scoped one-time grant consumption ledger
  intake.py               bounded SARIF parser and canonical candidates
  supply_chain.py         bounded CycloneDX 1.7 assurance intake
  cvss40.py               CVSS 4.0 technical severity validation
  asvs_coverage.py        ASVS 5.0.0 digest-bound requirement coverage
  review.py               qualified disposition and role-separated risk acceptance
  trust.py                reviewer identity verification and authoritative review lifecycle
  trust_cli.py            v0.7 trust/lifecycle and trusted-promotion commands
  approval_keys.py        separate business/report public-key trust roots
  signed_approvals.py     signed risk-acceptance and report-approval verification
  signed_approval_cli.py  v0.7.1 signed approval operator commands
  oidc_identity.py        offline OIDC/JWKS verification and signed-identity binding
  oidc_cli.py             v0.7.2 external-IdP operator commands
  change_control.py       v0.8.4 independent signed configuration state transitions
  change_control_cli.py   v0.8.4 change-request/signature/resolution operator commands
  tenant_auth.py          exact-subject authenticated tenant authorization and store session
  tenant_auth_cli.py      tenant routing gated by approved v0.8.4 policy changes
  postgres_rls.py         PostgreSQL RLS contract, live verifier and encrypted store
  postgres_tenant.py      application tenant authorization to verified PostgreSQL bridge
  postgres_cli.py         RLS/runtime commands and approved service-account mapping gate
  institution.py          institution security context and opaque KMS/HSM references
  crypto_provider.py      provider-neutral KMS/HSM wrap/unwrap/sign/verify boundary
  aws_kms.py              AWS KMS production adapter
  envelope.py             per-record AES-256-GCM envelope encryption
  signed_evidence.py      KMS/HSM-backed audit-chain and receipt signatures
  anchor_models.py        strict external anchor commitment/trust/receipt artifacts
  anchor_provider.py      provider-neutral external anchor client interface
  anchor_source.py        KMS/HSM-verified audit state to exact anchor commitment
  anchor_verify.py        offline external receipt and receipt-chain verification
  anchor_http.py          pinned-HTTPS external anchor client adapter
  reference_anchor.py     versioned service-side signed append-only reference authority
  anchor_cli.py           offline anchor artifact verification commands
  hardening_cli.py        v0.8 tenant/key/anchor-boundary operator commands
  evidence_vault.py       institution-bound encrypted raw-evidence lifecycle service
  vault_common.py         strict vault record, identifiers and retention contracts
  vault_custody.py        custody events, state and lifecycle eligibility artifacts
  vault_history.py        deterministic hold/retention/custody verification
  vault_bundle.py         encrypted recovery bundle and parser
  vault_store.py          append-only institution-scoped SQLite reference vault
  release_compatibility.py release/persistence/security-artifact compatibility manifest
  promotion.py            explicit reviewed-finding to draft-report boundary
  operator_cli.py         reviewed-report and release-integrity commands
  entrypoint.py           top-level operator/trust/approval/OIDC/change/tenant/PostgreSQL/hardening router
  release_integrity.py    packaged examples and strict local checksum verification
  examples/               installed-wheel synthetic engagement, plan, and SARIF
  evidence.py             sensitive-data minimization boundary
  custody.py              metadata-only external-evidence registry and custody hash chain
  audit.py                append-only SHA-256 audit chain
  store.py                institution-scoped, optional envelope-encrypted SQLite persistence
  service.py              engagement and approval state machine
  profiles.py             financial-institution preflight policy
  regulations.py          versioned Turkish regulatory control registry
  applicability.py        human-confirmed regulatory/standards scope
  reporting.py            audit-support validation, crosswalk, and renderer
  diffing.py              report revision and remediation delta
  bundle.py               deterministic audit dossier builder and verifier
  api.py                  loopback-first read-only API
  dashboard.py            self-contained operations interface
schemas/                  versioned reviewer, approval, OIDC, change-control, tenant, PostgreSQL, institution, envelope, anchor, vault, assurance and workload contracts
docs/                     architecture, safety, assurance, operator, release, trust, tenant, database, anchor, vault, workload and recovery documentation
tests/                    policy, integrity, trust, approvals, change control, OIDC, tenant, PostgreSQL, KMS/envelope, anchor, vault, assurance, workload, recovery, packaging and end-to-end tests
```

## Trust claims—and limits

FinRedOps demonstrates technical patterns that can support governed security
testing. Hash chaining alone provides **tamper evidence**, not non-repudiation.
SQLite remains demonstration/local persistence rather than a production
multi-tenant system of record. Regulatory mappings do not establish legal
applicability, certification, or compliance.

Release checksum validation establishes local byte integrity relative to the
supplied manifest; it does not establish build origin. GitHub/Sigstore artifact
attestations address build provenance only when the consumer verifies them.
The v0.7 reviewer trust layer verifies Ed25519 reviewer/lifecycle assertions
against configured public keys and exact engagement/object bindings. v0.7.1
separately verifies business-risk-owner and report-approver signatures using
dedicated approval trust roots and context-bound object digests.

v0.7.2 can additionally prove that a supplied external OIDC ID token was
cryptographically validated against pinned provider policy and supplied JWKS,
and that its `sub` + FinRedOps role claims were exactly bound to signed workflow
identities. It does **not** fetch or continuously refresh IdP metadata, interpret
the business meaning of an ACR value, validate SAML/device posture, or prove
regulatory acceptance.

v0.8.1 can perform real application-layer envelope encryption and provider-backed
audit/receipt signing when a matching `KmsHsmProvider` is configured. The AWS KMS
adapter is built in; other KMS/HSM families require separate adapter
implementations. FinRedOps does not claim that a configured key reference proves
correct IAM/key policy, does not create/export institution keys, and cannot
guarantee zeroization of every transient Python byte copy.

v0.8.2 authorizes one verified OIDC subject/provider configuration to one
institution through a digest-bound routing policy and closed capability set. It
rejects stale policy or institution context, changed provider configuration,
cross-tenant/provider/subject replay and capability escalation. The v0.8.4
operator path additionally requires that the exact routing policy be covered by
an independently approved change package.

v0.8.3 adds a PostgreSQL database-engine RLS/service-account boundary and a live
catalog verification artifact. The runtime claim applies only after the current
connection passes the verifier. PostgreSQL superuser/DBA, backup/recovery,
service-account credential provisioning/rotation, pooler isolation, cloud DB
IAM and KMS IAM/key-policy correctness remain institution responsibilities.

v0.8.4 verifies exact configuration state transitions against a dedicated
Ed25519 change trust bundle and requires distinct trust-pinned governor subjects,
key identities and public-key material. The trust-bundle `subject` is an
institution-issued binding; FinRedOps does not itself prove HR identity,
employment state, current external IdP session, or approver private-key custody.
A privileged DBA or direct low-level library caller remains outside the guarded
CLI governance claim. FinRedOps also does not automatically issue, deliver or
submit an approved report.

v0.8.5 can bind a current institution-KMS/HSM-verified audit state to a separate
signed anchor receipt chain. This improves cross-boundary tamper evidence but is
not equivalent to a trusted timestamp authority, physical WORM storage, a
Byzantine transparency system, or an automatically witnessed public log. The
reference SQLite authority can be rewritten by a sufficiently privileged host or
storage administrator. Truncation detection requires independently retained
continuity state or a complete observed receipt stream. Production independence,
anchor availability, storage immutability, witnessing, key custody and service
authentication remain deployment responsibilities.

v0.9.0 can persist deliberately selected raw evidence as institution-bound
application-layer encrypted envelopes and verify append-only lifecycle history.
The reference vault is not physical WORM storage and does not perform media
sanitization. Retention periods and legal holds remain institution/legal-policy
inputs, and production storage immutability, backup/restore governance, access
authorization and final disposition procedures remain deployment responsibilities.

v0.9.1 can normalize a bounded CycloneDX 1.7 subset, validate CVSS 4.0 technical
severity and represent digest-bound ASVS 5.0.0 coverage. It does not make supply-
chain data trustworthy merely by parsing it, normalize every CycloneDX extension,
turn CVSS into financial or regulatory risk, certify ASVS compliance, infer
regulatory applicability, or bypass qualified human review.

v0.9.2 can cryptographically bind an external worker identity and returned result
to one approved non-production proposal, one-time grant, network-policy digest,
egress rule and emergency-stop state. It does not independently prove the
worker's VM/container/kernel isolation or enforcement of a firewall/SDN policy,
does not provision credentials, does not implement SPIFFE/SPIRE, and cannot undo
a network request already sent before an emergency-stop change is observed.
Worker runtime hardening, network enforcement, workload-key policy, credential
resolution and emergency termination remain deployment responsibilities.

v0.9.3 tests and documents migration/recovery behavior and rejects unknown future
persistence/security-artifact schemas in the covered boundaries. A successful
reference restore test does not establish production RPO/RTO, backup immutability,
cloud snapshot correctness or disaster-recovery readiness. The release security
review is maintainer-authored, not independent. Independent security, legal and
accessibility review/disposition remains an explicit v1 gate.

## Reference baseline

The design and analysis model are informed by, but do not claim conformance with:

- [BDDK Bankaların Bilgi Sistemleri ve Elektronik Bankacılık Hizmetleri Hakkında Yönetmelik](https://www.resmigazete.gov.tr/eskiler/2020/03/20200315-10.htm)
- [BDDK Bilgi Sistemlerine İlişkin Sızma Testleri Hakkında Genelge 2012/1](https://www.bddk.org.tr/Mevzuat/DokumanGetir/915)
- [SPK Bilgi Sistemleri Yönetimine İlişkin Usul ve Esaslar Tebliği VII-128.10](https://www.resmigazete.gov.tr/eskiler/2025/03/20250313-8.htm)
- [KVKK 6698 sayılı Kanun Madde 12](https://www.kvkk.gov.tr/Icerik/2097/Kanun-doc) and [Personal Data Security Guide](https://www.kvkk.gov.tr/SharedFolderServer/CMSFiles/7512d0d4-f345-41cb-bc5b-8d5cf125e3a1.pdf)
- [TSE Bilişim Teknolojileri Sızma Testleri](https://www.tse.org.tr/sizma-testleri/) and [TS 13638/T2 firm certification prerequisites](https://www.tse.org.tr/sizma-testi-belgelendirmesi/)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001) and [ISO/IEC 27002:2022](https://www.iso.org/standard/75652.html)
- [NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
- [NIST SP 800-38D — GCM authenticated encryption](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [NIST SP 800-88 Rev.2 — Guidelines for Media Sanitization](https://csrc.nist.gov/pubs/sp/800/88/r2/final)
- [NIST SP 800-207A — Zero Trust Architecture Model for Access Control in Cloud-Native Applications](https://csrc.nist.gov/pubs/sp/800/207/a/final)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project/application-security-verification-standard/)
- [CycloneDX Specification 1.7](https://cyclonedx.org/docs/1.7/json/)
- [FIRST Common Vulnerability Scoring System v4.0](https://www.first.org/cvss/v4-0/)
- [SPIFFE Standards](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)
- [GDPR — Regulation (EU) 2016/679](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [DORA — Regulation (EU) 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj)
- [Commission Delegated Regulation (EU) 2025/1190](https://eur-lex.europa.eu/eli/reg_del/2025/1190/oj/eng)
- [ECB TIBER-EU framework](https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html)
- [MITRE ATT&CK adversary emulation plans](https://attack.mitre.org/resources/adversary-emulation-plans/)
- [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 7517 — JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 7519 — JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 8725 — JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [PostgreSQL Row Security Policies](https://www.postgresql.org/docs/17/ddl-rowsecurity.html)
- [PostgreSQL Database Roles / role attributes](https://www.postgresql.org/docs/17/database-roles.html)
- [RFC 6962 — Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962)
- [Sigstore Rekor transparency log](https://docs.sigstore.dev/logging/overview/)

Key documentation:

- [Regulatory and security assurance baseline](docs/ASSURANCE_BASELINE.md)
- [Assurance completeness](docs/ASSURANCE_COMPLETENESS.md)
- [Isolated workload execution](docs/WORKLOAD_EXECUTION.md)
- [Failure recovery](docs/FAILURE_RECOVERY.md)
- [Backup and restore](docs/BACKUP_RESTORE.md)
- [Release security review](docs/RELEASE_SECURITY_REVIEW.md)
- [Operations runbook](docs/OPERATIONS_RUNBOOK.md)
- [Reviewer trust, identity binding and lifecycle](docs/TRUST_IDENTITY.md)
- [Signed business and report approvals](docs/SIGNED_APPROVALS.md)
- [OIDC / JWKS identity verification](docs/OIDC_IDENTITY.md)
- [Signed configuration change control](docs/CHANGE_CONTROL.md)
- [Tenant isolation and institution-owned key boundaries](docs/TENANT_ISOLATION.md)
- [Institution-owned KMS/HSM envelope encryption and evidence signatures](docs/KMS_ENVELOPE_SIGNING.md)
- [Authenticated tenant routing and authorization](docs/TENANT_AUTHORIZATION.md)
- [PostgreSQL RLS and service-account boundary](docs/POSTGRES_RLS.md)
- [External audit anchoring](docs/AUDIT_ANCHORING.md)
- [Vault lifecycle](docs/VAULT_LIFECYCLE.md)
- [Safety boundary](docs/SAFETY_BOUNDARY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Controlled validation](docs/CONTROLLED_VALIDATION.md)
- [Machine finding intake](docs/EVIDENCE_INTAKE.md)
- [Qualified finding review](docs/FINDING_REVIEW.md)
- [Reviewed report promotion](docs/REVIEWED_REPORT_PROMOTION.md)
- [v0.6 Operator Workflow](docs/OPERATOR_WORKFLOW.md)
- [Release integrity and provenance](docs/RELEASE_INTEGRITY.md)
- [Reporting model](docs/REPORTING_MODEL.md)
- [Türkiye regulatory mapping](docs/TURKEY_REGULATORY_MAPPING.md)
- [Applicability](docs/APPLICABILITY.md)
- [Chain of custody](docs/CHAIN_OF_CUSTODY.md)
- [Audit dossier](docs/AUDIT_DOSSIER.md)
- [Roadmap to v1.0](docs/ROADMAP.md)

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Contributions must preserve the
closed catalog, safe-default execution model, human-approval boundaries, and
controlled-validation limits. Security issues should be reported through the
private vulnerability-reporting process described in [SECURITY.md](SECURITY.md).

Apache-2.0 licensed. Copyright 2026 Bilge Kayalı.