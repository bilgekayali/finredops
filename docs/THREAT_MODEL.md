# Threat model

## Assets to protect

- authorization intent and scope;
- approval identity, role, decision, digest, and validity window;
- action proposals and policy outcomes;
- evidence integrity and audit continuity;
- institution and customer data that must never enter this prototype.

## Principal threats and v0.5 mitigations

| Threat | Mitigation | Residual limitation |
|---|---|---|
| Prompt injection adds a dangerous action | Strict schema and closed catalog | External model gateway still needs content controls |
| Model smuggles executable text | Scalar parameters plus forbidden-key checks; no interpreter | Semantic inspection of all values is not implemented |
| Proposal changes after approval | Approval binds to canonical SHA-256 digest | SHA-256 digest is not a digital signature |
| Requester self-approves | Role separation and distinct-actor rules | Demo identities are strings, not authenticated principals |
| Stale approval is replayed | Subject digest and expiry checks | Durable replay ledger is future work |
| Target escapes scope | Exact canonical hostname/IP/CIDR match; exclusions win | Asset ownership verification is external |
| Unsupported action runs | Policy denies unknown/reserved actions and requires explicit runner injection for the one controlled action | Institution-specific adapters remain external |
| Active request escapes target | Exact scope, exclusions, one-time DNS resolution, unsafe-address denial, no redirects | Asset ownership and DNS control remain external |
| Active validation affects service | One HEAD request, 1–5 second timeout, engagement rate ceiling, non-production restriction and kill-switch checks | Distributed stop propagation and service-side behavior remain external |
| Response leaks sensitive data | No response body; cookie values and redirect locations are not persisted; peer address is digested | Headers can still contain unexpected sensitive values before minimization |
| Malformed SARIF exhausts the intake process | Uncompressed UTF-8 only; file, run, result, rule, tag, position and stored-text limits; invalid structures fail closed | A production service still needs process/memory quotas and malware controls |
| SARIF artifact URI leaks a workstation path or triggers retrieval | No URI dereference; only safe repository-relative paths survive; absolute, external and traversal locations become opaque digests | Reviewers need vault access to correlate opaque locations with raw evidence |
| Scanner output carries secrets or source snippets | Sensitive text is minimized; embedded snippets/fixes/flows are ignored; raw SARIF is not embedded | Institution DLP and evidence-vault controls remain authoritative |
| Scanner result is treated as a confirmed vulnerability | Imported severity is explicitly non-final, capped at high and fixed to pending human review | Qualified testers can still make an incorrect disposition |
| Duplicate scanner output inflates risk counts | Stable tool/rule fingerprints and deterministic occurrence merging | Poor source fingerprints can still reduce correlation quality |
| Canonical intake is altered after import | Source and batch SHA-256 digests plus strict round-trip validation | Digests are not external signatures or immutable timestamps |
| A reviewer decision is copied to a changed finding | Review ID and digest bind the exact batch digest and candidate fingerprint | Reviewer identity and time are asserted strings, not authenticated claims |
| Machine severity silently becomes final severity | Confirmed reviews require an explicit human severity; every change needs a substantive override rationale | The reviewer can still make an incorrect severity decision |
| A false positive carries hidden report conclusions | Non-confirmed dispositions reject final severity, impact, recommendation and control conclusions | Free-text rationale still requires human quality review |
| Duplicate disposition hides an unresolved finding | A duplicate must point directly to a confirmed primary candidate; chains and self-reference fail closed | Cross-batch duplicate correlation remains external |
| Tester accepts the risk they assessed | Risk acceptance requires a distinct business-risk-owner identity, approval evidence, compensating controls and expiry | String identities are not authenticated and organizational conflicts need external IAM policy |
| Expired risk acceptance remains reported as active | Summary evaluation returns an expired acceptance to confirmed state | Operational reminders and renewal workflow remain external |
| A review queue is treated as a final report | Summary records audit-support-only and `report_promotion_performed: false` | A downstream consumer can ignore the stated contract |
| Operational failure becomes a false finding | Failure receipts carry safe codes and no vulnerability | Human reviewers must still assess incomplete coverage |
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
developer. The default demo remains simulation-only and its API is read-only but
unauthenticated. Explicit active validation is limited to approved non-production
targets. SARIF import and review read local files but perform no scanner execution,
artifact retrieval or report promotion. The project does not provide
authenticated identities, multi-tenancy, high availability, institution-owned
key management, evidence-vault controls, or regulatory record retention.
