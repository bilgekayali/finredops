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
- [ ] CycloneDX 1.7 SBOM and vulnerability intake;
- [x] digest-bound qualified-tester disposition and rationale workflow;
- [x] role-separated, evidence-linked and time-bounded business risk acceptance;
- [x] deterministic queue summary with active/expired acceptance state;
- [x] cryptographically signed reviewer identity assertions with provider-neutral trust bundles;
- [x] engagement/intake binding plus review supersession and revocation;
- [ ] CVSS 4.0 vector validation with separate financial business impact;
- [ ] versioned OWASP ASVS 5.0.0 requirement coverage;
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
- [ ] OIDC/JWKS adapter for authenticated external identity-provider sessions and claims;
- [ ] key-backed report approval and risk-acceptance signatures;

## v0.7.0 — signed review trust and lifecycle

- [x] Ed25519 verification-only trust layer; FinRedOps never stores reviewer private keys;
- [x] short-lived assertion binding to issuer, subject, role, engagement, intake, finding and object digest;
- [x] separate `qualified_tester` and `review_governor` trust roles;
- [x] immutable `supersede` / `revoke` review lifecycle events;
- [x] fail-closed rejection of signature tampering, replay, role mismatch, cycles, branches and orphan review history;
- [x] trusted promotion uses only current authoritative signed reviews and remains draft-only;
- [x] versioned trust-bundle, identity-assertion, lifecycle-event and trust-resolution JSON contracts;
- [x] Python 3.11/3.12/3.13 regression coverage plus installed-wheel verification;
- [ ] upstream OIDC/JWKS/SAML authentication protocol verification;
- [ ] signed business risk acceptance and final report approvals;

## Platform hardening

- [ ] signed identities using an authenticated external identity-provider protocol;
- [ ] tenant isolation and institution-owned encryption keys;
- [ ] key-backed approval and receipt signatures;
- [ ] immutable external audit anchoring;
- [ ] evidence-vault integration, retention, legal hold and deletion policy;
- [ ] policy bundle signatures and independent change approval;
- [ ] independent legal, accessibility and security review.

## Later — separately reviewed advanced modules

Any additional active module needs a separate threat model, legal and control
review, signed workloads, strict egress allowlisting, one-time test identities,
isolated workers, bounded rate and tested emergency stop. Exploit payload
generation, arbitrary commands and autonomous target discovery remain out of
scope for built-in runners.
