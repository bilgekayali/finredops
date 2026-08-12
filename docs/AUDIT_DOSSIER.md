# Deterministic audit dossier

The v0.3 dossier is a deterministic, metadata-only ZIP for human review and
controlled hand-off. Identical inputs and `created_at` produce identical bytes.

| Entry | Purpose |
|---|---|
| `manifest.json` | File hashes, sizes, profile/report/evidence/audit bindings and readiness result |
| `applicability.json` | Human-confirmed authority and standards scope |
| `audit.jsonl` | Governance event hash chain |
| `evidence-manifest.json` | Opaque evidence metadata and custody chain |
| `regulatory-crosswalk.json` | Source-linked control, conclusion, evidence and finding map |
| `report.json` / `report.md` | Machine and human views of the same report |
| `report-delta.json` | Optional baseline-to-current remediation delta |
| `README.txt` | Package boundary and review notice |

The verifier does not extract the archive. It rejects unsafe paths, duplicate
paths, symbolic links, encrypted entries, excess sizes/counts, undeclared files,
digest mismatches, invalid embedded documents, broken chains and raw-evidence
claims.

```bash
python -m finredops build-bundle \
  --report regulatory-report.json \
  --applicability applicability.json \
  --evidence-manifest evidence-manifest.json \
  --audit audit.jsonl \
  --output audit-dossier.zip \
  --purpose human_review \
  --created-at 2026-08-12T10:00:00Z

python -m finredops verify-bundle audit-dossier.zip
```

`regulatory_submission` is a strict package purpose, not a certification. It is
blocked unless the report uses the current profile, is `issued`, has two distinct
human approvals, the applicability decision is fully human-confirmed, every
report evidence URI exists in the manifest, both hash chains verify and report
conclusions reconcile with applicability. v0.3 does not attach or verify an
external PKI signature, so an institution must apply its own signing and secure
delivery process after offline verification.
