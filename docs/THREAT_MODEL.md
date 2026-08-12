# Threat model

## Assets to protect

- authorization intent and scope;
- approval identity, role, decision, digest, and validity window;
- action proposals and policy outcomes;
- evidence integrity and audit continuity;
- institution and customer data that must never enter this prototype.

## Principal threats and v0.1 mitigations

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
| Dashboard injects HTML | Contextual HTML escaping and CSP | Production UI security review is still required |

## Misuse cases

FinRedOps must not be extended by adding a general shell action, accepting raw
model tool calls, silently expanding CIDRs, discovering targets, embedding
credentials in proposals, or treating a model score as authorization. Such a
change violates the project boundary even if guarded by a prompt.

## Assumptions

The demo runs locally, contains synthetic data, and is operated by a trusted
developer. It does not provide authentication, multi-tenancy, high
availability, or regulatory record retention.
