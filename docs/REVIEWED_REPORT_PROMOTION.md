# Reviewed finding promotion

FinRedOps keeps machine evidence intake, qualified finding disposition, and report issuance as separate trust boundaries. The reviewed-report promotion module provides an explicit bridge from a **complete** set of finalized qualified reviews into a **draft** assessment report.

It does not execute a scanner, contact a target, authenticate a reviewer, infer compliance from the absence of findings, sign a report, or issue a regulatory submission.

## Trust boundary

The promotion step requires:

1. one immutable `finredops.finding-intake.v1` batch;
2. exactly one completed qualified review for every candidate in that batch;
3. optional risk-acceptance records bound to confirmed reviews;
4. a human-supplied reviewed-report specification containing report metadata plus affected assets, remediation owner, and due date for every promoted finding.

Only `confirmed` findings, including confirmed findings with an active separate risk acceptance, become report findings. `false_positive`, `duplicate`, and `not_applicable` decisions remain represented in the review summary and promotion manifest but are not report findings.

The resulting report is always `draft`, has no human report approvals, and therefore cannot be `ready_for_issue` until the existing reporting approval boundary is satisfied.

## Synthetic end-to-end example

The repository includes a credential-free demonstration that starts from the bundled SARIF fixture and performs the complete safe chain:

```bash
python -m finredops.promotion demo \
  --sarif examples/synthetic_sast.sarif.json \
  --output-dir demo-output/reviewed

python -m finredops validate-report \
  demo-output/reviewed/regulatory-report.json
```

The synthetic workflow creates:

- `finding-intake.json` — canonical bounded SARIF intake;
- `reviews/*.json` — two synthetic qualified-review records;
- `regulatory-report.json` — promoted draft report;
- `regulatory-report.md` — rendered human-readable report;
- `promotion-manifest.json` — digest-bound traceability from intake/review summary to report.

The demo marks one normalized candidate `confirmed` and one `false_positive`. This is invented demonstration evidence and is not a real tester attestation.

## Building from finalized review files

Use the `build` command with a canonical intake, every finalized review for that batch, optional finalized risk acceptances, and a reviewed-report specification:

```bash
python -m finredops.promotion build \
  --intake finding-intake.json \
  --review review-a.json \
  --review review-b.json \
  --spec reviewed-report-spec.json \
  --output-dir reviewed-report
```

Risk acceptance files may be added with repeated `--acceptance` arguments.

The specification uses schema identifier `finredops.reviewed-report-spec.v1` and includes normal report metadata plus `finding_metadata` keyed by the exact confirmed finding IDs:

```json
{
  "schema_version": "finredops.reviewed-report-spec.v1",
  "report_id": "FRX-RPT-EXAMPLE-001",
  "title": "Reviewed source-code security report",
  "assessment_type": "vendor_source_code_review",
  "organization": "Example Institution",
  "period_start": "2026-08-12",
  "period_end": "2026-08-12",
  "issued_at": "2026-08-12T12:15:00Z",
  "classification": "RESTRICTED",
  "rules_of_engagement_ref": "attachment://ENGAGEMENT/approved-roe",
  "in_scope_assets": ["source-repository"],
  "excluded_assets": ["production-systems"],
  "tester_organization": "Independent Test Team",
  "lead_tester": "Qualified Tester",
  "independence_declaration": "Recorded by the accountable test organization.",
  "tester_qualifications": ["qualification-evidence://person/tester/current"],
  "methodology": ["SARIF intake", "qualified review", "evidence-based validation"],
  "executive_summary": "Qualified review of machine-generated candidates was completed.",
  "limitations": ["No production target was contacted by this promotion step."],
  "finding_metadata": {
    "FRX-SARIF-EXACT-CONFIRMED-ID": {
      "affected_assets": ["repo://src/example.py"],
      "owner": "Application Security Owner",
      "due_date": "2026-09-30"
    }
  }
}
```

`finding_metadata` must cover **exactly** the confirmed/promotable finding set. Missing or extra entries fail closed.

## Control conclusions

For controls referenced by confirmed findings, the promotion step records `partial` and links the reviewed evidence. For every other applicable control it records `not_tested`; it never treats “no confirmed finding” as proof of conformance.

This preserves a critical assurance rule: scanner silence is not compliance evidence.

## CI artifacts

The GitHub Actions workflow generates and validates both the original synthetic annual-bank demo and the reviewed-finding promotion demo. On successful jobs it uploads the verified Markdown report, audit dossier, reviewed report, promotion manifest, intake, and finalized synthetic reviews as workflow artifacts for inspection.
