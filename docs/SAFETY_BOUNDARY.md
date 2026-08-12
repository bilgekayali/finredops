# Safety boundary

## Included

- structured engagement and asset scope;
- exact allowlists plus explicit exclusions;
- time-limited, digest-bound approval records;
- separation of requester, owner, control, approval, and operator roles;
- closed evidence-review action catalog;
- deterministic synthetic simulation;
- explicitly enabled, non-production bounded validation using one TLS `HEAD`
  request, no redirects and no response-body collection;
- deterministic draft findings for HSTS, CSP, MIME-sniffing, cookie attributes
  and certificate expiry, all requiring qualified human validation;
- three-distinct-person approval and request-rate enforcement for controlled actions;
- policy denials, emergency pause, evidence receipts, and audit verification;
- institution-policy preflight and durable SQLite revisions;
- deterministic redaction of likely secrets and regulated identifiers;
- bounded SARIF 2.1.0 intake that emits deduplicated pending-review candidates,
  never final findings or automatic control conclusions;
- digest-bound qualified-tester dispositions with evidence-linked rationale and
  explicit severity override, without automatic report promotion;
- separate, time-bounded business-owner risk acceptance with compensating
  controls and expired-state visibility;
- source-linked regulatory crosswalk and audit-support report templates;
- human-confirmed BDDK/SPK/KVKK/TSE/ISO applicability decisions;
- metadata-only evidence manifest, chain of custody, report delta and
  deterministic offline-verifiable review dossier;
- a local, read-only GET/HEAD API with no mutation endpoint;
- reserved `.test` examples that do not identify a real institution.

## Deliberately excluded

- exploit payload generation or delivery;
- vulnerability payloads or proof-of-concept weaponization;
- credential guessing, phishing, persistence, evasion, or lateral movement;
- autonomous target discovery, port scanning, crawling, or fingerprinting;
- arbitrary shell, script, SQL, URL, or model-generated tool execution;
- response-body collection or processing of real customer data;
- production active validation;
- bypass instructions for authorization, monitoring, or safety controls.

The planning schema has no command field. The policy recursively rejects common
command-, payload-, and secret-bearing parameter names. The simulation runner
contains no network or process-execution API. The separately injected active
runner contains one fixed TLS transport and no process-execution interface.

Availability or resilience controls that could affect a service, including
denial-of-service exercises, are evidence-only coordination records. Social
engineering is likewise outside the built-in runner. FinRedOps may record an
institution-approved external activity and its evidence; it does not perform it.

## Authorized-use requirement

Software controls do not establish legal authority. Any real security test
needs institution-approved written authorization, rules of engagement, legal
and risk review, named emergency contacts, data-handling terms, third-party
coordination, and tested stop procedures.

## Evidence statement

Default-demo receipts are generated from bundled fixtures and include
`simulation: true` and a disclaimer. Controlled receipts contain bounded response
metadata and draft findings; they are not an assurance opinion, final
penetration-test result or certification until a qualified human validates the
scope, evidence, severity, impact and conclusion.

Imported SARIF remains untrusted evidence. FinRedOps records its digest and a
minimized candidate view, but it does not execute the producing tool, fetch
artifact URIs, embed source snippets or determine that the observation is valid.
The v0.5.1 review record captures an asserted human decision but does not
authenticate the reviewer, verify their qualification or provide a digital
signature. Those controls remain institution-owned integration requirements.

Regulatory reports are audit-support drafts. BDDK/SPK applicability, TSE
TS 13638/T2 scope and delivery deadlines require authorized human confirmation;
TSE and ISO objectives require authorized/licensed standards; `approved` and
`issued` reports require two distinct human approvals. The review ZIP embeds
metadata and opaque locators only, never raw evidence.
