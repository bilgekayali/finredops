# Security Policy

## Project boundary

FinRedOps is an authorization and evidence control plane for security testing.
The v0.1 runner is simulation-only. The project does not contain exploit
payloads, credential attacks, persistence mechanisms, arbitrary shell
execution, port scanning, or autonomous target discovery.

Use FinRedOps only for systems you own or are explicitly authorized to test.
An engagement record, software approval, or demonstration is not a substitute
for written authorization, legal review, operational change approval, or the
rules of engagement required by the relevant institution.

## Reporting a vulnerability

Do not disclose security vulnerabilities in a public issue. Use GitHub private
vulnerability reporting when it is enabled for this repository. Include:

- the affected version and component;
- the security impact and preconditions;
- a minimal, non-destructive reproduction;
- suggested mitigations, if available.

Do not include credentials, customer data, production identifiers, or active
exploit payloads in a report.

## Supported versions

Until the first stable release, only the latest commit on `main` is supported.

