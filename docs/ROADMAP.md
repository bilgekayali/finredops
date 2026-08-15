# Roadmap

Roadmap items remain subject to the safety boundary and institutional review.

## v0.1 — governed simulation

- [x] typed scope and closed action catalog;
- [x] digest-bound two-person approval;
- [x] deterministic deny-by-default policy;
- [x] network-free synthetic runner;
- [x] hash-chained audit export and verifier;
- [x] self-contained operations dashboard;
- [x] security boundary, threat model, control mapping, and tests.

## v0.2 — durable assurance

- [x] append-only SQLite snapshot revisions and audit-prefix verification;
- [x] financial-institution policy preflight;
- [x] deterministic evidence minimization and sensitive-data redaction;
- [x] read-only local API with security headers;
- [x] versioned BDDK, current SPK VII-128.10, KVKK and ISO/IEC crosswalk;
- [x] annual bank, vendor source-code and vendor application report templates;
- [x] mandatory coverage, finding ownership and retest-evidence validation;
- [x] JSON schemas and synthetic audit-support report package;

## v0.3 — audit dossier

- [x] human-confirmed BDDK, SPK, KVKK, TSE and ISO applicability matrix;
- [x] TSE TS 13638/T2 public prerequisites and licensed-clause evidence model;
- [x] metadata-only evidence registry and hash-chained custody history;
- [x] finding, severity, retest and control-conclusion report delta;
- [x] deterministic audit dossier and safe offline verifier;
- [x] CLI, read-only API, dashboard, JSON schemas and integrity tests;

## v0.4 — bounded active validation

- [x] simulation remains the default execution mode;
- [x] explicit controlled-runner injection and read-only capability visibility;
- [x] one TLS `HEAD` request to one approved non-production target;
- [x] no redirects, response body, discovery, crawling, port scanning or payloads;
- [x] three-person controlled-action approval and request-rate enforcement;
- [x] pre/post-request kill-switch checks and safe failure receipts;
- [x] HSTS, CSP, MIME, cookie and certificate-expiry draft findings;
- [x] deterministic conversion from validated receipts to report findings;
- [ ] isolated signed worker and institution-owned workload identity;
- [ ] authenticated test-account and authorization-boundary modules;
- [ ] approved source-package SAST/dependency/secret-analysis adapters;
- [ ] independently reviewed production-validation policy overlay;
- [x] qualified tester CLI for false-positive disposition and severity override;

## v0.5 — evidence intake and qualified review

- [x] bounded, uncompressed UTF-8 SARIF 2.1.0 intake;
- [x] deterministic canonical finding fingerprints and duplicate correlation;
- [x] safe repository-relative or opaque artifact references;
- [x] secret/identifier minimization and source-snippet exclusion;
- [x] non-final machine severity/confidence and mandatory human-review state;
- [x] strict JSON contract, digest verification, CLI, synthetic example and tests;
- [x] CycloneDX 1.7 SBOM and vulnerability intake;
- [x] digest-bound qualified-tester disposition and rationale workflow;
- [x] role-separated, evidence-linked and time-bounded business risk acceptance;
- [x] deterministic queue summary with active/expired acceptance state;
- [x] cryptographically signed reviewer identity assertions with provider-neutral trust bundles;
- [x] engagement/intake binding plus review supersession and revocation;
- [x] CVSS 4.0 vector validation with separate financial business impact;
- [x] versioned OWASP ASVS 5.0.0 requirement coverage;
- [x] controlled promotion from confirmed candidates into draft reports;

## v0.6 — end-to-end operator workflow

- [x] one top-level `finredops` command surface for legacy and reviewed-report workflows;
- [x] complete-review `reviewed-report-spec-template` generation;
- [x] explicit `promote-reviewed-report` operator command;
- [x] reproducible `demo-reviewed-report` command for the repository-visible synthetic example;
- [x] fail-closed rejection of unfinished template placeholders;
- [x] no-overwrite protection for generated operator artifacts;
- [x] package and `python -m finredops` entrypoints routed through the operator CLI;
- [x] Python 3.11/3.12/3.13 end-to-end CLI regression coverage;
- [x] signed release artifacts and provenance attestation;
- [x] packaged example inputs for installed-wheel demonstrations;

## v0.6.1 — release integrity and provenance

- [x] wheel and source-distribution build workflow with version-tag binding;
- [x] SHA-256 release manifest plus strict local verification command;
- [x] GitHub/Sigstore artifact provenance using `actions/attest`;
- [x] synthetic engagement, plan and SARIF package data;
- [x] source-checkout-independent `demo-reviewed-report` default;
- [x] clean-wheel smoke test for packaged examples, draft report generation and checksums;
- [x] tag-triggered GitHub Release publication and manual build/attestation mode;
- [x] documentation that separates checksum integrity from provenance verification;

## v0.7 — trust and identity

- [x] externally signed Ed25519 reviewer identity assertions using a configured public-key trust bundle;
- [x] cryptographic binding of reviewer identity to engagement, intake, finding and immutable review digest;
- [x] signed review-governor supersession and revocation without deleting historical decisions;
- [x] current-authoritative-review resolution for trusted report promotion;
- [x] signature-verification evidence exposed through CLI, trust resolution and trusted-promotion outputs;
- [x] OIDC/JWKS adapter for authenticated external identity-provider sessions and claims;
- [x] key-backed report approval and risk-acceptance signatures;

## v0.7.0 — signed review trust and lifecycle

- [x] Ed25519 verification-only trust layer; FinRedOps never stores reviewer private keys;
- [x] short-lived assertion binding to issuer, subject, role, engagement, intake, finding and object digest;
- [x] separate `qualified_tester` and `review_governor` trust roles;
- [x] immutable `supersede` / `revoke` review lifecycle events;
- [x] fail-closed rejection of signature tampering, replay, role mismatch, cycles, branches and orphan review history;
- [x] trusted promotion uses only current authoritative signed reviews and remains draft-only;
- [x] versioned trust-bundle, identity-assertion, lifecycle-event and trust-resolution JSON contracts;
- [x] Python 3.11/3.12/3.13 regression coverage plus installed-wheel verification;
- [x] upstream OIDC/JWKS authentication protocol verification supplied through the v0.7.2 adapter;

## v0.7.1 — key-backed business and report approvals

- [x] dedicated approval trust bundle separated from reviewer trust roots;
- [x] `business_risk_owner` and `report_approver` key roles with Ed25519 verification only;
- [x] risk-acceptance signatures bound to acceptance digest and trusted-review-resolution digest;
- [x] trusted promotion rejects unsigned, extra, replayed or non-authoritative risk acceptance;
- [x] signed risk-acceptance resolution digest carried into trusted-promotion evidence;
- [x] exactly two distinct signed report approvers required for `approved` status;
- [x] report-approval signatures bound to source draft digest and trusted-promotion digest;
- [x] approved report remains `report_issued: false`; delivery/submission stays outside automation;
- [x] versioned approval trust, signature, risk-resolution and report-approval JSON contracts;
- [x] upstream OIDC/JWKS identity-provider authentication and claim binding via v0.7.2;

## v0.7.2 — offline OIDC/JWKS identity binding

- [x] pinned OIDC provider configuration with exact HTTPS issuer and client audience;
- [x] provider-configured asymmetric JWT algorithm allow-list; token headers cannot expand trusted algorithms;
- [x] bounded operator-supplied JWKS with exact `kid`, signing-use and key-operation validation;
- [x] ID-token signature, issuer, audience, `azp`, nonce, expiry, issue-time and not-before validation;
- [x] bounded authentication age, token lifetime and configured ACR requirements;
- [x] configured OIDC role claim mapped only to recognized FinRedOps human roles;
- [x] minimized verification artifact retains token/JWKS/config digests but never the raw ID token;
- [x] exact OIDC `sub` + role binding to signed reviewer/lifecycle or business/report approval objects;
- [x] aggregate workflow resolver fails closed unless every supplied signed identity has one matching OIDC binding;
- [x] no autonomous discovery or JWKS network retrieval in the verification path;
- [x] versioned provider, verification, binding and workflow-resolution JSON contracts;

## v0.8 — tenant and institution key boundaries

- [x] SQLite persistence scopes snapshots by `(institution_id, engagement_id, revision)`;
- [x] audit events are institution-scoped and reject engagement-label mismatch;
- [x] idempotency keys are institution-scoped so identical keys may be used independently by different tenants;
- [x] store handles bind one institution id and do not accept per-operation tenant overrides;
- [x] schema-v1 databases migrate transactionally into the explicit `default` institution;
- [x] provider-neutral institution security context with digest-bound opaque KMS/HSM key references;
- [x] private key material is rejected from institution key-reference configuration;
- [x] CLI exposes institution context validation and tenant-scoped audit verification;
- [x] metadata explicitly distinguishes tenant-scope enforcement from encryption-at-rest verification;
- [x] institution-owned envelope encryption through a reviewed KMS/HSM provider interface;
- [x] KMS/HSM-backed audit-chain and receipt signatures;
- [x] authenticated tenant routing and authorization boundary above the local store;
- [x] database-engine row-level security for the PostgreSQL production persistence backend;
- [x] independent signed change control for tenant policy and service-account mappings;

## v0.8.1 — KMS/HSM envelope encryption and signed evidence

- [x] fresh 256-bit DEK per protected snapshot/audit record;
- [x] AES-256-GCM application-layer encryption with fresh 96-bit nonces;
- [x] AAD binds institution, object identity, key id, provider and key-reference digest;
- [x] provider-neutral `KmsHsmProvider` wrap/unwrap/sign/verify interface;
- [x] concrete AWS KMS adapter using `Encrypt` / `Decrypt` and authenticated encryption context;
- [x] AWS KMS `Sign` / `Verify` on precomputed SHA-256 digests with explicit algorithm allow-list;
- [x] explicit plaintext-to-envelope rewrite for legacy SQLite rows;
- [x] store metadata reports encrypted versus legacy plaintext rows and verified protection state;
- [x] key rotation supports historical `retiring` key references while new writes use the active key;
- [x] disabled historical keys fail closed;
- [x] KMS/HSM-backed audit-chain signatures bind head hash, event count and complete audit digest;
- [x] KMS/HSM-backed execution-receipt signatures bind proposal/evidence/lifecycle digests;
- [x] strict envelope and key-backed-signature JSON schemas plus Python 3.11/3.12/3.13 regression coverage;
- [ ] built-in Azure Key Vault, Google Cloud KMS and PKCS#11 adapters;
- [x] externally anchored/timestamped audit heads via the v0.8.5 provider-neutral boundary;

## v0.8.2 — authenticated tenant routing and authorization

- [x] digest-bound institution routing policy with exact OIDC provider and subject grants;
- [x] closed tenant capability catalog for `store_read`, `store_write`, `audit_verify`, and `crypto_use`;
- [x] role authorization is the exact intersection of verified OIDC roles and institution-granted roles;
- [x] tenant authorization binds source OIDC verification, current routing policy, and current institution context digests;
- [x] cross-institution, cross-provider, cross-subject, stale-policy, stale-context, and capability-escalation replay fail closed;
- [x] authorization expires no later than the verified source ID token;
- [x] source policy/OIDC/context are required again when a stored authorization is used;
- [x] authorized store session derives the institution namespace from verified context instead of request input;
- [x] authenticated store writes require an institution crypto provider so v0.8.1 encryption cannot be bypassed silently;
- [x] CLI policy-template, authorize, verify, and authorized metadata-read workflows;
- [x] strict tenant-routing-policy and tenant-authorization JSON schemas;
- [x] CI boundary prevents token parsing/network capabilities from entering the tenant authorization module;
- [x] database-native row-level security and service-account isolation for the PostgreSQL production persistence backend;
- [x] signed routing-policy bundles with independent configuration-change approval via v0.8.4;

## v0.8.3 — PostgreSQL RLS and service-account isolation

- [x] deterministic PostgreSQL schema and NOLOGIN owner/reader/writer boundary-role contract;
- [x] tenant identity derived from authenticated `session_user` through an administrator-owned role-to-institution registry;
- [x] no client-selected tenant GUC or per-query tenant override in the RLS trust boundary;
- [x] runtime LOGIN roles must be non-superuser, non-`BYPASSRLS`, non-owner service accounts;
- [x] separate read and write group roles with effective privilege verification;
- [x] `ENABLE ROW LEVEL SECURITY` plus `FORCE ROW LEVEL SECURITY` on snapshots, audit events and idempotency records;
- [x] tenant-bound SELECT and write-only INSERT policies with no runtime UPDATE/DELETE grants;
- [x] live catalog verification of role attributes, membership, registry mapping, contract digest, RLS state, policies and privileges;
- [x] application `AuthorizedTenantSession` bridge independently matches the database-resolved institution and access mode;
- [x] PostgreSQL persistence requires v0.8.1 institution-owned envelope encryption for protected payloads;
- [x] PostgreSQL runtime assessment and installation-contract JSON schemas plus operator CLI;
- [x] live PostgreSQL 17 CI verifies cross-tenant denial, reader/write separation and encrypted persistence;
- [x] signed routing-policy and service-account mapping changes with independent approval via v0.8.4;

## v0.8.4 — signed configuration change control

- [x] dedicated configuration-change trust bundle separated from reviewer, risk-owner and report-approval roots;
- [x] trust keys pin issuer, subject, role, Ed25519 public key and validity window;
- [x] one public key cannot be reused under multiple change-control trust identities;
- [x] exact change request binds institution, operation, object, prior/target state digests, context, requester, rationale and approval window;
- [x] exactly two signatures required: one `configuration_governor` and one `security_governor`;
- [x] approvers must use distinct key identities, public-key material and trust-pinned subjects;
- [x] approved change package records the exact trust-bundle digest and reproducible approval-time resolution;
- [x] tenant authorization/verification CLI requires a package covering the exact routing-policy and institution-context digests;
- [x] PostgreSQL mapping/disable SQL CLI requires a package covering the exact role, institution, access/state and RLS-contract digest;
- [x] create/update/disable transitions fail closed when prior/target state semantics are incomplete or stale;
- [x] versioned trust, request, signature, resolution, package and PostgreSQL mapping-intent JSON contracts;
- [x] change-control implementation remains verification-only and stores no approver private keys;

## Path to v1.0

FinRedOps will not use `1.0.0` as a cosmetic version bump. v1 is the first
production-reference release after the following security and operating gates are
implemented, tested, documented and reviewed.

### v0.8.5 — immutable external audit anchoring

- [x] publish institution-signed audit-head commitments through a provider-neutral external anchoring boundary;
- [x] bind anchor receipt identity plus institution, engagement, audit head, event count, anchor timestamp and exact source/signature digests;
- [x] verify signed anchor receipts offline under a trust root independent from the local database and institution KMS/HSM keys;
- [x] fail closed on reordered, continuity-missing, duplicate, backwards-time, disabled-key and cross-institution receipts when the required continuity state is supplied;
- [x] keep anchoring independent from report issuance and active security-testing authority;
- [x] provide a pinned-HTTPS client adapter and a separately operated signed append-only reference authority;
- [x] explicitly do not claim that the reference SQLite authority is physical WORM storage, a Byzantine transparency service, RFC 6962 compatibility or Rekor protocol compatibility.

### v0.9.0 — evidence vault lifecycle

- [x] institution-scoped encrypted evidence-vault interface;
- [x] retention schedules and immutable legal-hold state derived from append-only custody;
- [x] lifecycle eligibility separated from physical storage disposition;
- [x] custody events for ingest, access, export, hold, release, retention extension, disposition approval and restore;
- [x] recovery/restore semantics that preserve tenant, encryption and custody boundaries;
- [x] dedicated offline/non-destructive vault CI boundary and strict artifact schemas.

### v0.9.1 — assurance completeness

- [x] CycloneDX 1.7 SBOM and vulnerability intake;
- [x] CVSS 4.0 vector parsing/validation separated from financial business impact;
- [x] versioned OWASP ASVS 5.0.0 requirement coverage;
- [x] deterministic linkage of these evidence sources into qualified human review and audit dossiers;
- [x] keep regulatory applicability human-confirmed and non-certifying.

### v0.9.2 — isolated workload execution

- [ ] isolated signed worker with institution-owned workload identity;
- [ ] authenticated one-time test-account / authorization-boundary modules;
- [ ] strict egress allowlisting and workload-to-engagement binding;
- [ ] signed worker receipts and emergency-stop verification;
- [ ] active capability remains bounded, non-production and separately approved.

### v0.9.3 — release-candidate hardening

- [ ] upgrade/downgrade and migration tests for persisted schemas and security artifacts;
- [ ] failure-recovery and partial-transaction runbooks;
- [ ] backup/restore boundary review for encrypted tenant persistence and evidence lifecycle;
- [ ] updated threat model covering the complete production reference architecture;
- [ ] dependency, packaging and release-provenance security review;
- [ ] operator deployment, key-rotation, incident and disaster-recovery runbooks.

### v1.0.0 — production-ready reference release gate

v1.0.0 is cut only when all preceding release gates are complete and the release
candidate additionally has:

- [ ] documented public API and JSON-schema compatibility/versioning policy;
- [ ] end-to-end production reference deployment using authenticated identity, tenant routing, PostgreSQL RLS, institution-owned cryptography, change control, audit anchoring and evidence lifecycle;
- [ ] reproducible release checksums plus repository/build provenance verification;
- [ ] supported upgrade path from the final v0.9.x release with rollback/failure guidance;
- [ ] independent security review checklist closed or explicitly risk-accepted;
- [ ] independent legal and accessibility review checklist closed or explicitly scoped as deployment-owner responsibilities;
- [ ] explicit v1 non-claims preserving the governed/non-autonomous testing boundary.

## Platform hardening

- [x] signed identities using an authenticated external identity-provider protocol;
- [x] institution-scoped persistence namespace and cross-tenant collision isolation baseline;
- [x] institution-owned encryption/signing key-reference contract with no secret material;
- [x] institution-owned envelope encryption through KMS/HSM;
- [x] key-backed audit and receipt signatures;
- [x] authenticated application-layer tenant routing and capability authorization;
- [x] PostgreSQL database-engine RLS and service-account production boundary;
- [x] policy bundle signatures and independent change approval;
- [x] independent external audit anchoring contract with signed receipt-chain verification;
- [x] encrypted evidence-vault lifecycle with retention, legal hold and recovery boundaries;
- [ ] independent legal, accessibility and security review.

## Later — separately reviewed advanced modules

Any additional active module needs a separate threat model, legal and control
review, signed workloads, strict egress allowlisting, one-time test identities,
isolated workers, bounded rate and tested emergency stop. Exploit payload
generation, arbitrary commands and autonomous target discovery remain out of
scope for built-in runners.