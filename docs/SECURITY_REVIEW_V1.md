# v1 security review checklist

Status: **repository release-gate checklist closed**, subject to the explicit limitations below.

This checklist is not a claim that an external consultancy performed a penetration test or certification. The v1 repository gate combines an independent static-analysis engine (GitHub CodeQL), the existing dedicated trust-boundary workflows, regression tests, threat-model review and explicit deployment-owner controls. A production institution should still commission its own independent assessment appropriate to its risk and regulatory obligations.

## Authorization and execution

- [x] AI output remains proposal-only and cannot authorize execution.
- [x] built-in action catalog remains closed; no generic shell or arbitrary command field.
- [x] simulation remains default.
- [x] built-in active validation remains non-production and approval gated.
- [x] isolated-worker lease binds proposal, identity, one-time account, egress and emergency-stop state.
- [x] production active testing and autonomous target discovery remain explicit non-claims.

## Identity and tenant isolation

- [x] OIDC/JWKS verification pins provider/client/algorithm policy and performs no verifier-side discovery.
- [x] signed reviewer/business/report/change-control roles use separated trust roots and exact object digests.
- [x] tenant routing requires exact subject/provider-config binding and closed capabilities.
- [x] PostgreSQL runtime tenant derives from authenticated `session_user`, not request-selected tenant state.
- [x] production RLS contract requires `ENABLE` + `FORCE ROW LEVEL SECURITY` and rejects superuser/`BYPASSRLS`/unsafe `SET ROLE` paths.

## Cryptography and evidence

- [x] protected application payloads use fresh AES-256-GCM DEKs wrapped by institution-owned KMS/HSM references.
- [x] audit and receipt signatures bind exact canonical digests.
- [x] external anchor uses a separate trust root and verifies receipt-chain continuity offline.
- [x] evidence vault is envelope encrypted, institution bound and append-only at the application API.
- [x] retention only moves forward; legal holds derive from custody history.
- [x] deletion approval does not claim physical sanitization.

## Persistence and recovery

- [x] known SQLite schema migrations are transactional.
- [x] future/unknown schema versions fail closed in governance, vault, reference-anchor and one-time-grant stores.
- [x] injected partial-transaction failure is covered by regression tests.
- [x] backup/restore and no-destructive-downgrade runbooks are documented.
- [x] v0.9.3 is the only supported direct pre-v1 upgrade baseline.

## Supply chain and release

- [x] package builds are clean-wheel smoke tested.
- [x] release tag must match package version.
- [x] SHA-256 release manifest is generated and locally verifiable.
- [x] GitHub/Sigstore artifact provenance is generated for release artifacts.
- [x] CycloneDX 1.7, CVSS 4.0 and ASVS 5.0.0 boundaries remain version pinned.
- [x] GitHub CodeQL v4 `security-extended` analysis is enabled for Python on pushes, PRs and a weekly schedule.
- [x] domain-specific CI continues to guard OIDC/network separation, tenant auth, PostgreSQL, audit anchoring, evidence vault, assurance, isolated worker and release-candidate compatibility.

## Residual risks / deployment responsibilities

The repository release gate does **not** independently prove:

- correctness of an institution's OIDC, cloud IAM, KMS key policy, PostgreSQL firewall or secret-management configuration;
- physical WORM storage or media sanitization;
- kernel/container/VM isolation or SDN/firewall enforcement for an external worker;
- external anchor Byzantine resistance, witnessing or public transparency;
- legal/regulatory applicability or certification;
- availability, capacity, disaster-recovery RTO/RPO or operational staffing of a real deployment;
- absence of all vulnerabilities.

## Independence statement

GitHub CodeQL is an analysis engine independent of the FinRedOps implementation logic, and its workflow is part of the v1 repository gate. **No external human security audit, penetration test or certification is claimed by FinRedOps 1.0.0.** Deployment owners should treat that external review as an institution-specific production assurance activity rather than infer it from the version number.
