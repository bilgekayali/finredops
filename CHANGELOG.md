# Changelog

All notable changes to FinRedOps are documented here.

## [Unreleased]

## [0.5.1] - 2026-08-12

### Added

- Digest-bound qualified-tester decisions for confirmed, false-positive,
  duplicate and not-applicable machine-finding candidates.
- Final human severity with mandatory rationale for machine-severity overrides,
  opaque validation evidence and assessment-applicable control mapping for
  confirmed findings.
- Separate business-risk-owner acceptance bound to the exact confirmed review,
  with approval evidence, compensating controls and 1–366 day expiry.
- Deterministic review queue summary, strict validation commands, JSON schemas,
  end-to-end CLI workflow and focused integrity tests.

### Security

- Machine candidates remain immutable and cannot become report findings or
  regulatory conclusions through this workflow.
- Non-confirmed decisions cannot carry report conclusions; duplicates must point
  directly to a confirmed primary candidate.
- Tester and risk owner must differ, expired acceptance returns to confirmed
  state, and every decision document is intake- and content-digest bound.
- Identity, qualification and approval claims are not cryptographically signed;
  institution-owned IAM, PKI, trusted time and immutable storage remain required.

## [0.5.0] - 2026-08-12

### Added

- Bounded SARIF 2.1.0 importer with deterministic canonical finding records.
- Stable source-tool/rule fingerprinting, duplicate correlation, non-final
  machine severity/confidence and mandatory qualified-human review state.
- Strict finding-intake JSON contract, source/batch digests, CLI import and
  validation commands, synthetic SARIF example and focused tests.

### Security

- Import accepts uncompressed UTF-8 JSON only and enforces file, run, result,
  rule, tag, position and stored-text limits.
- Artifact URIs are never dereferenced; absolute, external and traversal paths
  become opaque digests, embedded source snippets are ignored and likely secrets
  or regulated identifiers are minimized.
- Raw SARIF is not embedded and imported results cannot become final report
  findings or regulatory conclusions without a separate human workflow.

## [0.4.0] - 2026-08-12

### Added

- Explicitly enabled controlled-validation runner for one bounded TLS `HEAD`
  request to one approved non-production target.
- Deterministic HSTS, CSP, MIME-sniffing, cookie-attribute and certificate-expiry
  observations normalized into human-review draft findings.
- Three-person proposal approval for controlled actions: business owner, control
  team and execution approver, all digest-bound and distinct.
- Request-rate enforcement, pre/post-request kill-switch checks, safe operational
  failure receipts and draft-report finding conversion.
- Read-only execution-capability endpoint and dashboard states for simulation,
  active validation, failure and cancellation.

### Security

- The default service and demo remain simulation-only; network access requires
  explicit construction and injection of the controlled runner.
- The active transport resolves once, rejects unsafe address classes, requires
  TLS 1.2+, follows no redirects, collects no response body and caps headers,
  timeout and requests.
- Production active validation, exploit payloads, credential attacks, arbitrary
  commands, target discovery, crawling, port scanning and attack chaining remain
  absent.

## [0.3.0] - 2026-08-12

### Added

- Human-confirmed, tri-state BDDK/SPK/KVKK/TSE/ISO applicability assessment.
- TSE TS 13638/T2 public qualification/process references and the current TSE
  Sızma Testi Kapsamı link, with licensed-text evidence requirements.
- Metadata-only evidence manifest with immutable content digests, retention
  metadata and append-only chain-of-custody events.
- Report revision delta for new, missing, closed, reopened, severity, retest and
  control-conclusion changes.
- Deterministic audit dossier builder and safe offline ZIP verifier.
- CLI/API/dashboard integration, four new JSON schemas and focused integrity tests.

### Security

- Regulatory-submission packaging fails closed without current profiles,
  human-confirmed applicability, issued/two-person-approved reports, complete
  evidence locators and intact audit/custody chains.
- Audit dossiers contain metadata and opaque evidence references only. Live
  execution, exploit delivery, credential attacks and arbitrary commands remain absent.

## [0.2.0] - 2026-08-12

### Added

- Transactional SQLite snapshot revisions, idempotency records, and exact-prefix
  audit-chain persistence.
- Financial-institution engagement preflight and versioned policy profile.
- Deterministic evidence guard for likely secrets, e-mail addresses, valid IBANs,
  and payment-card identifiers.
- Read-only local API with OpenAPI metadata, ETags, and strict security headers.
- Source-linked Turkish control profile covering BDDK, current SPK VII-128.10,
  KVKK, and mapped ISO/IEC 27001:2022 objectives.
- Audit-support report model for annual bank penetration testing, vendor source
  review, vendor application testing, and remediation verification.
- Mandatory coverage, control conclusion, finding ownership, retest evidence,
  and two-person issue-approval validation.
- JSON schemas, regulatory crosswalk, report templates, and enhanced assurance
  dashboard.

### Security

- Built-in runner remains synthetic and network-free.
- Reports store opaque evidence references instead of raw evidence and cannot be
  marked issued without distinct human approvals.

## [0.1.0] - 2026-08-09

### Added

- Governance-first engagement and scope models.
- Deny-by-default policy engine with exact-target and time-window enforcement.
- Proposal-digest binding and two-person approval controls.
- Closed action catalog with simulation-only execution.
- Tamper-evident SHA-256 audit chain.
- Self-contained visual operations dashboard and synthetic demo.
- Control mapping for DORA/TIBER-EU, NIST SP 800-115, NIST AI RMF, and PCI DSS.
- Threat model, safety boundary, roadmap, and automated test suite.
