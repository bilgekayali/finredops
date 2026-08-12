# Threat model

## Assets to protect

- authorization intent and scope;
- approval identity, role, decision, digest, and validity window;
- action proposals and policy outcomes;
- evidence integrity and audit continuity;
- institution and customer data that must never enter this prototype.

## Principal threats and v0.3 mitigations

| Threat | Mitigation | Residual limitation |
|---|---|---|
| Prompt injection adds a dangerous action | Strict schema and closed catalog | External model gateway still needs content controls |
| Model smuggles executable text | Scalar parameters plus forbidden-key checks; no interpreter | Semantic inspection of all values is not implemented |
| Proposal changes after approval | Approval binds to canonical SHA-256 digest | SHA-256 digest is not a digital signature |
| Requester self-approves | Role separation and distinct-actor rules | Demo identities are strings, not authenticated principals |
| Stale approval is replayed | Subject digest and expiry checks | Durable replay ledger is future work |
| Target escapes scope | Exact canonical hostname/IP/CIDR match; exclusions win | Asset ownership verification is external |
| Unsupported action runs | Policy denies unsupported or controlled actions | Live adapters are intentionally absent |
| Activity continues during an incident | Emergency stop plus paused state | Distributed kill-switch propagation is future work |
| Audit history is edited | Previous-hash chain and verifier | A privileged actor could replace the whole unanchored log |
| Stored audit history is forked | SQLite accepts only an exact extension of the persisted prefix | External immutable anchoring is not yet implemented |
| Sensitive data enters evidence | Deterministic secret/identifier redaction before receipt creation | Institution-owned DLP and encrypted evidence vault remain external |
| Broad or production-unsafe scope is approved | Versioned institution preflight blocks breadth, risk, contact, rate, and TTL violations | Asset ownership and legal authority remain external |
| A stale regulation is treated as current | Versioned, dated, source-linked control registry and applicability notes | Legal/compliance must revalidate every engagement |
| Legal or standards scope is inferred automatically | Tri-state, human-confirmed BDDK/SPK/KVKK/TSE/ISO applicability | Authorized reviewers can still make an incorrect decision |
| Raw evidence leaks through the dossier | Approved opaque URI schemes and metadata-only ZIP contract | The institution-owned vault remains outside this prototype |
| Evidence metadata is rewritten | Content digest plus append-only custody hash chain | Hashes are not external signatures or immutable timestamps |
| A report revision hides regression | Stable-ID delta lists missing, reopened, new and worsened records | Reviewers must preserve stable identifiers |
| A bundle is altered or path-crafted | Exact manifest, size/digest checks, path traversal/symlink/encryption rejection | External PKI signing is not implemented |
| Automation declares its own report final | Issued/approved reports require two distinct human approval records | Demo identities are not cryptographically authenticated |
| Dashboard injects HTML | Contextual HTML escaping and CSP | Production UI security review is still required |

## Misuse cases

FinRedOps must not be extended by adding a general shell action, accepting raw
model tool calls, silently expanding CIDRs, discovering targets, embedding
credentials in proposals, or treating a model score as authorization. Such a
change violates the project boundary even if guarded by a prompt.

## Assumptions

The demo runs locally, contains synthetic data, and is operated by a trusted
developer. Its API is read-only but unauthenticated. It does not provide
authenticated identities, multi-tenancy, high availability, institution-owned
key management, evidence-vault controls, or regulatory record retention.
