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
- [ ] authenticated and cryptographically signed reviewer identities;
- [ ] engagement/authorization binding plus review supersession and revocation;
- [ ] CVSS 4.0 vector validation with separate financial business impact;
- [ ] versioned OWASP ASVS 5.0.0 requirement coverage;
- [ ] controlled promotion from confirmed candidates into draft reports;

## Platform hardening

- [ ] signed identities using an external identity provider;
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
