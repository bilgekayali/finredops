# v0.6 Operator Workflow

FinRedOps v0.6 exposes the reviewed-finding workflow through the same top-level
`finredops` command used by the existing governance, evidence, reporting and
verification commands.

The operator workflow remains fail-closed. It does **not** run a scanner, contact
a target, authenticate a reviewer, approve a report, establish compliance, or
issue a report.

## End-to-end flow

```text
SARIF 2.1.0
    ↓
canonical finding intake
    ↓
qualified tester review for every candidate
    ↓
complete review summary
    ↓
reviewed-report specification
    ↓
explicit promotion boundary
    ↓
validated draft report + promotion manifest
    ↓
human report approval outside automation
```

## 1. Import scanner evidence

```bash
finredops import-sarif examples/synthetic_sast.sarif.json \
  --output work/finding-intake.json
finredops validate-intake work/finding-intake.json
```

Imported results remain non-final candidates. Machine severity is not a final
security conclusion.

## 2. Review every candidate

Create and complete one qualified-tester review for each canonical candidate:

```bash
finredops finding-review-template \
  --intake work/finding-intake.json \
  --finding-id FRX-SARIF-REPLACE-ME \
  --assessment-type vendor_source_code_review \
  --output work/review-draft.json

finredops finalize-finding-review \
  --intake work/finding-intake.json \
  --draft work/review-draft.json \
  --output work/review.json
```

Repeat until every candidate has a disposition. A report cannot be promoted if
a candidate is omitted or remains pending.

## 3. Build and verify the review summary

```bash
finredops build-review-summary \
  --intake work/finding-intake.json \
  --assessment-type vendor_source_code_review \
  --review work/review-1.json \
  --review work/review-2.json \
  --as-of 2026-08-12T12:15:00Z \
  --output work/review-summary.json
```

The summary is audit-support evidence. It does not itself create report
findings.

## 4. Create a promotion specification

```bash
finredops reviewed-report-spec-template \
  --intake work/finding-intake.json \
  --assessment-type vendor_source_code_review \
  --review work/review-1.json \
  --review work/review-2.json \
  --output work/reviewed-report-spec.json
```

The command requires a complete review set and pre-populates affected repository
artifacts for confirmed findings. The operator must replace all `TODO` and
`YYYY-MM-DD` placeholders with accountable assessment metadata, including:

- report identity and title;
- organization and assessment period;
- rules-of-engagement reference;
- in-scope and excluded assets;
- tester organization, lead tester and qualifications;
- independence declaration;
- executive summary and limitations;
- remediation owner and due date for each promoted finding.

FinRedOps refuses to promote an unfinished template.

## 5. Promote confirmed reviews into a draft report

```bash
finredops promote-reviewed-report \
  --intake work/finding-intake.json \
  --review work/review-1.json \
  --review work/review-2.json \
  --spec work/reviewed-report-spec.json \
  --output-dir work/reviewed-report
```

Optional business risk acceptances may be supplied with repeated
`--acceptance` arguments. Each acceptance must remain bound to its exact
confirmed review and satisfy the role-separation and expiry rules.

The output directory contains:

```text
regulatory-report.json
regulatory-report.md
promotion-manifest.json
```

The report is always `draft`. The promotion manifest records the intake digest,
review-summary digest, promoted finding IDs, report digest, and explicit claims
that automatic conformance inference and automatic issuance did not occur.

Existing operator outputs are never overwritten by these v0.6 commands.

## 6. Validate and render independently

```bash
finredops validate-report work/reviewed-report/regulatory-report.json
finredops render-report work/reviewed-report/regulatory-report.json \
  --output work/reviewed-report/verified-report.md
```

A structurally valid draft remains `ready_for_issue: false` until the separate
human-approval requirements in the reporting model are satisfied.

## Reproduce the repository example

The complete synthetic workflow can be regenerated with one command:

```bash
finredops demo-reviewed-report \
  --sarif examples/synthetic_sast.sarif.json \
  --output-dir demo-output/reviewed
```

This produces canonical intake, two finalized synthetic reviews, one promoted
finding, a draft JSON/Markdown report, and a promotion manifest. No live target
is contacted.

The repository-visible reference output is
[`EXAMPLE_SECURITY_REPORT.md`](../EXAMPLE_SECURITY_REPORT.md).

## Trust boundary

The operator CLI is orchestration, not authority. It intentionally does not:

- infer that an unreported control conforms;
- promote pending, false-positive, duplicate or not-applicable candidates;
- infer asset ownership or remediation deadlines;
- supply report approvals;
- sign reviewer identity or evidence;
- issue a final report;
- create a regulatory submission;
- expand the bounded active-validation capability.

See [Reviewed report promotion](REVIEWED_REPORT_PROMOTION.md),
[Qualified finding review](FINDING_REVIEW.md), and
[Safety boundary](SAFETY_BOUNDARY.md) for the underlying contracts.
