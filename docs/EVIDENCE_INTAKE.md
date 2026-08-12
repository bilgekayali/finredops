# Machine finding intake

FinRedOps v0.5 accepts bounded SARIF 2.1.0 as untrusted evidence and produces a
deterministic queue of canonical finding candidates. Import does **not** confirm
a vulnerability, assign final business severity, establish a regulatory gap or
add a finding to an issued report.

SARIF 2.1.0 is the OASIS standard format for static-analysis results. The
implementation uses only documented result, rule, location, level, property and
fingerprint fields. It performs no network access and never dereferences an
artifact URI. See the
[OASIS SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html).

## Import and verify

```bash
python -m finredops import-sarif examples/synthetic_sast.sarif.json \
  --output demo-output/finding-intake.json
python -m finredops validate-intake demo-output/finding-intake.json
```

The output records the source SHA-256 digest, size, tool identity, run/result
counts, duplicate count, redaction count and opaque source evidence locator.
Each candidate contains:

- a FinRedOps identifier derived from its canonical fingerprint;
- source tool and rule identity;
- non-final machine severity and confidence;
- a minimized message and safe repository-relative or opaque artifact reference;
- a stable evidence reference and occurrence count;
- taxonomy tags copied as untrusted labels;
- `pending_review` and `human_validation_required: true`.

Machine severity is deliberately capped at `high`. SARIF `error`, `warning`,
`note` and `none` levels are transport-level tool classifications, not a complete
CVSS or business-risk decision. A qualified tester must examine the source
evidence, reproduce or validate the condition, assess exploitability and impact,
remove false positives and assign control mappings. v0.5.1 records that decision
in a separate digest-bound workflow described in
[Qualified finding review](FINDING_REVIEW.md). It still does not approve report
language or promote a candidate into a report.

## Deterministic fingerprinting

When a result contains bounded SARIF `partialFingerprints` or `fingerprints`,
FinRedOps combines them with the normalized tool and rule identity. This keeps a
candidate stable when a line moves. If the source tool provides no fingerprint,
FinRedOps falls back to the safe artifact reference, starting line and minimized
message. Duplicate candidates are merged deterministically, retain the highest
machine severity/confidence and record an occurrence count.

Fingerprints support correlation; they are not signatures or proof that a tool
result is correct. The source SARIF file must remain in the institution-owned
evidence vault under its recorded digest.

## Intake security boundary

The importer fails closed on unsupported SARIF versions, malformed structures,
invalid rule references and invalid positions. Built-in limits are:

| Boundary | Limit |
|---|---:|
| Input | Uncompressed UTF-8 JSON only |
| File size | 10 MB |
| Canonical intake validation | 40 MB |
| Runs | 50 |
| Results | 20,000 |
| Rules per run | 20,000 |
| Tags per finding | 64 |
| Stored message | 1,000 characters |
| JSON nesting | 64 levels |
| JSON structure | 250,000 nodes |

The importer:

- does not execute scanner content or import Python modules from the input;
- performs no archive extraction, URI fetch, source checkout or network call;
- ignores embedded source snippets, fixes, graphs, code flows and attachments;
- replaces absolute, external, traversal and malformed artifact locations with
  opaque `artifact-digest://` references;
- minimizes likely secrets, bearer tokens, e-mail addresses, valid IBANs and
  payment-card identifiers;
- embeds no raw SARIF, source code or customer evidence in the canonical batch;
- binds the exported document to a deterministic batch digest.

The importer is a defensive parser, not a malware-analysis sandbox. Scanner
execution and raw evidence storage must occur in isolated institution-managed
systems with their own authentication, malware controls, encryption, retention,
legal hold and deletion policies.

## Deliberately deferred

The current v0.5 slice does not include CycloneDX intake, CVSS 4.0 calculation,
ASVS mapping, report promotion, authenticated reviewer identities, key-backed
signatures or scanner execution. These require separate typed workflows,
permissions, audit events and tests; they must not be inferred from SARIF fields
alone.
