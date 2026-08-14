# Threat model

This threat model covers the FinRedOps v0.9.3 production-reference candidate
architecture. It documents repository controls and residual deployment risks; it
is not an independent penetration test, legal assessment or certification.

## Security objectives

Protect:

- testing authorization intent, exact target/action scope and engagement windows;
- authenticated human identity and role separation for review, risk, report and
  configuration decisions;
- institution/tenant isolation across application and database boundaries;
- KMS/HSM key-reference integrity and encrypted persisted content;
- evidence confidentiality, custody, retention and legal-hold history;
- audit continuity and independently anchored audit commitments;
- software supply-chain/assurance evidence without turning machine output into a
  final conclusion;
- isolated-worker authorization, one-time test-account use, egress binding and
  signed execution receipts;
- release/migration compatibility and recoverability.

## Trust boundaries

1. **AI/model → planning gateway.** Model output is untrusted typed input; it
   cannot authorize or execute.
2. **Operator/IdP → human decision artifacts.** OIDC/JWKS verification and
   purpose-separated signature trust roots establish bounded evidence of subject
   and role; external identity lifecycle remains outside FinRedOps.
3. **Tenant authorization → persistence.** Application routing binds one verified
   subject/provider/policy/context to one institution; PostgreSQL independently
   derives institution from authenticated `session_user` and FORCE RLS.
4. **Application → institution KMS/HSM.** FinRedOps holds opaque key references,
   not institution private keys. Provider IAM/key policy is external.
5. **Application store → external audit anchor.** Anchor receipt trust is
   purpose-separated from local DB and institution KMS/HSM trust.
6. **Application → evidence vault.** Raw evidence enters only deliberate,
   institution-bound encrypted vault records; custody history determines lifecycle
   state.
7. **Control plane → isolated worker.** The control plane validates a signed
   workload identity and exact single-use lease; network/process execution occurs
   in a separately operated provider boundary.
8. **Build/repository → deployed release.** Checksums and GitHub/Sigstore
   provenance must be independently verified by the consumer.

## Principal threats and controls

| Threat | Repository control | Residual/deployment risk |
|---|---|---|
| Prompt injection requests a dangerous action | Strict proposal schema, closed catalog, deny-by-default policy | External model/content gateway still needs controls |
| Executable text is smuggled through a proposal | No free-form command field; forbidden keys; built-in runner has no interpreter | Future adapters require separate review |
| Proposal changes after approval | Canonical digest-bound approvals/policy/signatures | Authorized humans may still approve unsafe intent |
| Self-approval or role collapse | Distinct purpose/role checks and separate trust roots | External IAM/HR conflict policy remains authoritative |
| Stale/replayed external identity | OIDC signature/issuer/audience/nonce/time/ACR checks; signed-object binding | IdP compromise or incorrect provider policy remains external |
| Token/JWKS retrieval becomes SSRF/network capability | OIDC verifier uses operator-supplied pinned config/JWKS and no discovery/network path | Operators must refresh trust data safely |
| Tenant id is selected by an untrusted request | Authorized tenant session derives institution from verified policy/context | Policy administrator can still misconfigure grants |
| Database tenant bypass | PostgreSQL service identity, administrator registry, FORCE RLS, live privilege verification | Superuser/DBA/pooler/cloud-IAM bypass remains deployment risk |
| Cross-tenant key/data replay | Institution id in store keys, envelope AAD, tenant authorization and provider context | KMS/key-policy mistakes can defeat intended separation |
| Plaintext persistence bypass | Authenticated writes require configured crypto; encrypted store reports protection state | Legacy/local plaintext mode still exists outside authenticated production path |
| Envelope ciphertext is modified/replayed | AES-256-GCM + institution/object/key AAD + plaintext/envelope digests | Availability and KMS compromise are not solved by AEAD |
| KMS/HSM private key leaks into app | Provider interface exposes wrap/unwrap/sign/verify only; key refs reject obvious secrets | Provider SDK/host credentials and IAM remain external |
| Disabled/rotated key invalidates history | Active/retiring/disabled lifecycle and exact historical key lookup | Operator can disable a still-required key; backup key availability must be governed |
| Config policy/service mapping changes without approval | Exact prior/target digests and two purpose-separated signed governors | Privileged administrator can act outside guarded CLI |
| Local audit history is replaced | Hash chain, KMS/HSM audit signature, independent external anchor receipt chain | Anchor independence, availability, witnessing/WORM are deployment choices |
| Anchor ledger is rewritten/truncated | Signed receipt sequence/previous digest and offline continuity verification | Detecting truncation requires independently retained continuity state |
| Raw evidence leaks from normal artifacts | Minimization, opaque refs, raw source excluded from SARIF/CycloneDX normalization | Humans/tools can still introduce sensitive free text |
| Vault record/custody history is altered | Envelope encryption, strict record digests, append-only hash-linked custody verification | Reference SQLite is not physical WORM |
| Legal hold/retention is shortened | Retention moves only forward; hold state derives from complete history | Correct retention periods/legal applicability remain human/legal inputs |
| Vault restore crosses institutions | Record/envelope/custody institution bindings and restore verification | Backup platform access controls remain external |
| Scanner/SBOM output becomes a final vulnerability | SARIF/CycloneDX candidates require qualified human review | Human reviewer can still be wrong |
| CVSS becomes financial/regulatory risk automatically | CVSS v4 artifact explicitly technical-only; business impact separate | Business-risk judgment remains human |
| ASVS/framework tag becomes certification | Versioned digest-bound coverage, human status, explicit non-certification | External audit/legal interpretation still required |
| Malformed machine evidence exhausts parser | Bounded UTF-8 JSON/SARIF/CycloneDX counts, sizes, depth and stored text | Service-level CPU/memory/malware quotas remain deployment controls |
| Active validation escapes target | Exact scope/exclusions, non-production gate, one bounded HEAD request, no redirects/body/discovery | DNS/asset ownership and remote service behavior remain external |
| Isolated worker impersonation | Short-lived institution workload-key-backed identity binds worker/deployment/image/network-policy/isolation evidence | Signed evidence does not prove VM/container/kernel isolation is correct |
| Worker receives a reusable credential | One-time grant contains only opaque account reference digest and is atomically consumed before call | External credential resolver must enforce its own one-time/least-privilege semantics |
| Worker egress escapes policy | Lease binds exact target/port/path/CIDRs and signed result reports observed peer | Kernel/SDN/firewall enforcement is external and must match the signed policy |
| Worker result is forged or replayed | Workload-key signature binds envelope, identity, lease and one-time grant | Compromised workload signing key undermines authenticity |
| Emergency stop activates during execution | Stop checked before and after provider call; changed state rejects result | Cannot retroactively undo a request already sent; worker platform needs its own kill path |
| Transaction failure leaves partial governance/vault state | Explicit SQLite transactions/rollback; injected-failure regression tests | Filesystem/DB/storage faults outside tested cases still need native recovery |
| Older binary opens newer schema | Version guards reject future DB versions; compatibility manifest documents current/upgradeable versions | Operators must not manually rewrite schema version markers |
| Migration rollback corrupts data | No automatic destructive downgrade; restore verified pre-migration backup | Backup consistency/RPO/RTO are institution responsibilities |
| Package source differs from reviewed release | Wheel/sdist checksums, tag binding, installed-wheel smoke and GitHub/Sigstore provenance | Consumer must actually verify provenance and resolved dependencies |
| Automation declares final compliance/report issuance | Qualified review + signed risk when used + two report approvers; issuance remains external | Downstream systems can ignore contract unless deployment governance prevents it |

## Misuse cases

The following are architectural boundary violations, not feature requests to add
casually:

- general shell/command execution;
- autonomous target discovery or credential attacks;
- production active testing through the built-in runner/worker lease;
- model-generated exploit payload execution;
- embedding passwords/tokens/private keys in proposals or one-time grants;
- weakening RLS/KMS/signature checks to restore availability;
- treating CVSS/ASVS/CycloneDX/regulatory mappings as automatic compliance;
- silently accepting unknown future schemas or mutating old schema semantics;
- using local hash chains or the reference anchor/vault as a WORM/non-repudiation
  guarantee.

## Assumptions

Production-reference use assumes separately managed external identity, database,
KMS/HSM, backup, anchor and isolated-worker environments. Operators are expected
to enforce least privilege, asset/legal authorization, service-account isolation,
key lifecycle, consistent backups, worker egress/sandbox controls, monitoring and
incident response outside the repository.

The repository still supports local/demo paths and simulation. A feature being
present in the reference architecture does not prove a deployment configured it
correctly. v1 readiness therefore also requires explicit independent security,
legal and accessibility review disposition or documented deployment-owner/risk-
acceptance treatment; v0.9.3 does not claim those reviews have occurred.
