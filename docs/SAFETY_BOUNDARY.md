# Safety boundary

## Included

- structured engagement and asset scope;
- exact allowlists plus explicit exclusions;
- time-limited, digest-bound approval records;
- separation of requester, owner, control, approval, and operator roles;
- closed evidence-review action catalog;
- deterministic synthetic simulation;
- policy denials, emergency pause, evidence receipts, and audit verification;
- institution-policy preflight and durable SQLite revisions;
- deterministic redaction of likely secrets and regulated identifiers;
- source-linked regulatory crosswalk and audit-support report templates;
- a local, read-only GET/HEAD API with no mutation endpoint;
- reserved `.test` examples that do not identify a real institution.

## Deliberately excluded

- exploit generation or delivery;
- vulnerability payloads or proof-of-concept weaponization;
- credential guessing, phishing, persistence, evasion, or lateral movement;
- autonomous target discovery, port scanning, crawling, or fingerprinting;
- arbitrary shell, script, SQL, URL, or model-generated tool execution;
- collection from live systems or processing of real customer data;
- bypass instructions for authorization, monitoring, or safety controls.

The planning schema has no command field. The policy recursively rejects common
command-, payload-, and secret-bearing parameter names. The runner contains no
network or process-execution API.

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

Every built-in receipt is generated from a bundled fixture and includes
`simulation: true` and a disclaimer. It must not be represented as a finding,
assurance opinion, penetration-test result, or certification.

Regulatory reports are audit-support drafts. BDDK/SPK applicability and delivery
deadlines require legal/compliance confirmation; ISO objectives require the
institution's licensed standard; `approved` and `issued` reports require two
distinct human approvals.
