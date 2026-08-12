# Qualified finding review and disposition

FinRedOps v0.5.1 turns an immutable machine-finding candidate into a separate,
digest-bound qualified-tester decision. It does not edit the SARIF intake,
authenticate a person, sign a record or promote a candidate into a regulatory
report.

## Decision model

Each candidate can have one active review in a generated queue summary:

| Disposition | Meaning | Required conclusion fields |
|---|---|---|
| `confirmed` | A qualified tester validated the condition | final severity, impact, recommendation, evidence and control references |
| `false_positive` | The observed condition is not present or not valid | rationale and validation evidence only |
| `duplicate` | The candidate refers to an already confirmed primary candidate | rationale, evidence and direct primary finding ID |
| `not_applicable` | The rule does not apply to the tested component or agreed scope | rationale and validation evidence only |

The source tool's severity and confidence remain machine observations. A
confirmed review assigns a human severity. If it differs from machine severity,
a substantive `severity_override_reason` is mandatory. A non-confirmed decision
cannot carry final impact, recommendation, severity or control conclusions.

The review binds the exact intake batch digest, candidate fingerprint, reviewer
identity string, qualification-evidence locator, review time and decision
content. Control references must exist in the built-in, source-linked Türkiye
financial assurance profile, whose ID and digest are also bound into the
decision, and must apply to the selected annual-bank, vendor-source, vendor-app
or remediation assessment type. Changing any bound field changes the derived
review ID and digest.
These SHA-256 values provide tamper evidence, not an authenticated identity,
trusted timestamp or digital signature.

## Qualified-tester workflow

First create and fill a draft. The `machine_context` block is read-only context;
finalization rejects it if it no longer matches the intake candidate.

```bash
python -m finredops finding-review-template \
  --intake demo-output/finding-intake.json \
  --finding-id FRX-SARIF-REPLACE-WITH-CANDIDATE-ID \
  --assessment-type vendor_source_code_review \
  --output review-draft.json

# A qualified tester fills the draft after reviewing retained evidence.
python -m finredops finalize-finding-review \
  --intake demo-output/finding-intake.json \
  --draft review-draft.json \
  --output review.json

python -m finredops validate-finding-review \
  --intake demo-output/finding-intake.json \
  --review review.json
```

Evidence fields accept opaque `evidence://`, `attachment://` or
`qualification-evidence://` locators only. They must point to records governed
by the institution's evidence vault and access, retention and legal-hold rules.
No source, exploit payload, credential, customer record or raw validation output
belongs in the review JSON. Likely e-mail addresses, bearer tokens, valid IBANs
and payment-card identifiers fail closed rather than being stored in the
decision record.

## Separate risk acceptance

Risk acceptance is an optional overlay on a `confirmed` review. It is not a
finding disposition, closure decision or test-team approval. A named
`business_risk_owner`, different from the qualified tester, must record:

- the exact confirmed review digest;
- an accountable rationale and approval-evidence locator;
- at least one compensating control;
- an approval time after the review; and
- an expiry date between 1 and 366 days after approval.

```bash
python -m finredops risk-acceptance-template \
  --intake demo-output/finding-intake.json \
  --review review.json \
  --output risk-acceptance-draft.json

# The accountable business risk owner fills the draft.
python -m finredops finalize-risk-acceptance \
  --intake demo-output/finding-intake.json \
  --review review.json \
  --draft risk-acceptance-draft.json \
  --output risk-acceptance.json

python -m finredops validate-risk-acceptance \
  --intake demo-output/finding-intake.json \
  --review review.json \
  --acceptance risk-acceptance.json
```

An active acceptance produces the queue outcome `accepted_risk`. On the day
after expiry, the queue returns the finding to `confirmed` and records an
`expired` acceptance so the overdue decision remains visible.

## Deterministic review queue

Pass each active review and acceptance explicitly. Omitting a candidate leaves
it `pending_review`; supplying multiple active decisions for the same candidate
fails closed.

```bash
python -m finredops build-review-summary \
  --intake demo-output/finding-intake.json \
  --assessment-type vendor_source_code_review \
  --review review.json \
  --acceptance risk-acceptance.json \
  --as-of 2026-08-14T00:00:00Z \
  --output review-summary.json

python -m finredops validate-review-summary \
  --intake demo-output/finding-intake.json \
  --summary review-summary.json \
  --review review.json \
  --acceptance risk-acceptance.json
```

The summary covers the exact candidate set, separates pending, confirmed,
false-positive, duplicate, not-applicable, accepted and expired states, and is
bound to the intake digest. Summary validation reconstructs the queue from every
supplied review and acceptance, so a populated state cannot be verified without
its source decision record. It always records
`report_promotion_performed: false`. Controlled promotion into a draft report,
external identity authentication, key-backed signatures, review supersession
and immutable timestamping remain separate future workflows.

## Operational controls still required

Before institutional use, integrate authenticated workforce identities,
authorization records, qualification validity checks, evidence-vault access,
maker-checker rules, revocation/supersession, trusted timestamps, digital
signatures and append-only storage. A `qualification-evidence://` locator and
`human_review_asserted: true` are claims for offline verification; this
prototype does not prove them.
