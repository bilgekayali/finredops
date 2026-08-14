# Release-candidate security review

This is the repository-maintainer review checklist for FinRedOps v0.9.3. It is
not an independent third-party assessment, legal opinion, penetration-test
certificate or compliance certification.

## Dependency surface

Core runtime dependencies remain deliberately small:

- `cryptography>=49,<50` for AES-GCM and public-key primitives;
- `PyJWT[crypto]>=2.13,<3` for offline OIDC/JWT verification;
- `cvss>=3.6,<4` for CVSS 4.0 vector calculation/validation.

Optional integrations are isolated:

- `boto3>=1.35,<2` only for the AWS KMS adapter;
- `psycopg[binary]>=3.2,<4` only for the PostgreSQL backend.

The candidate must build/install in a clean environment using only declared
runtime dependencies. Package smoke CI exercises installed-wheel examples rather
than relying only on the source checkout.

Dependency ranges are compatibility constraints, not a declaration that every
future version in range is free from vulnerabilities. Release operators must
review the resolved lock/environment, current vulnerability advisories and
institution software-supply-chain policy when producing a deployment.

## Capability review

The safe default remains simulation. The only built-in bounded active action is
`http.security_posture.validate`. Network/process capabilities are kept in named
adapters and guarded with CI import boundaries. In particular, simulation,
OIDC verification, tenant authorization, change-control verification,
assurance intake and isolated-workload control-plane modules must not silently
acquire generic network/process execution.

The v0.9.2 isolated worker is a provider boundary rather than an embedded remote
shell. A deployment can implement a separately reviewed worker, but the built-in
lease still refuses production, autonomous discovery and arbitrary command
capability.

## Cryptography and key custody

FinRedOps does not generate or export institution KMS/HSM private keys. Envelope
encryption uses fresh AES-256-GCM DEKs and provider-wrapped keys. Key-backed
audit/receipt/workload signatures are verified against institution context.
Reviewer, approval, change-control and anchor trust roots remain purpose-
separated.

Reviewers must verify that deployment IAM/key policies, key rotation, disabled/
retiring key handling, backup-key availability and operator separation match the
institution design. Repository tests cannot prove a cloud/HSM policy is correct.

## Persistence and recovery

Governance schema v3 is current; v1/v2 upgrades are tested. Evidence vault,
reference anchor and one-time-grant ledgers are versioned at schema v1. Unknown
future schemas fail closed. Automatic destructive downgrade is not supported.

The candidate includes injected-failure tests for transaction rollback and a
closed-file backup/reopen test for governance and encrypted evidence-vault state.
These tests establish application behavior under the covered scenarios; they do
not validate a production database, cloud snapshot, storage-array or backup
service.

## Release provenance

The existing release workflow binds the package version to the release tag,
builds wheel/sdist, generates SHA-256 checksums, smoke-tests the installed wheel
and creates GitHub/Sigstore build provenance. Consumers must verify both checksum
integrity and provenance; one is not a substitute for the other.

A release candidate must not be promoted if version metadata, tag, checksum
manifest and attestation subject disagree.

## Security-artifact compatibility

Versioned JSON artifacts remain strict contracts. Unknown schema versions are not
silently reinterpreted. The v0.9.3 compatibility manifest lists the security
artifact schema identifiers that form the current release boundary. A future
format change must use a new schema version and a reviewed migration/compatibility
policy rather than changing old semantics in place.

## Open deployment-owner controls

The repository does not independently prove or operate:

- privileged cloud/DB/KMS/HSM administration separation;
- worker VM/container/kernel isolation and egress enforcement;
- external IdP lifecycle and HR identity proofing;
- WORM/evidence-vault physical immutability;
- anchor independence/witnessing beyond the configured provider;
- backup RPO/RTO and geographic resilience;
- DLP/malware scanning of institution evidence;
- asset ownership, legal testing authority or regulatory applicability;
- independent penetration testing, legal review or accessibility review.

Those items remain external review/deployment gates for the v1 production
reference decision.
