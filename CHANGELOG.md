# Changelog

All notable changes to FinRedOps are documented here.

## [Unreleased]

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
