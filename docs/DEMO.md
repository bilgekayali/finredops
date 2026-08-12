# Demo guide

The demo shows the governance lifecycle without contacting a target.

```bash
python -m pip install -e .
python -m finredops demo --output demo-output
python -m finredops verify-audit demo-output/audit.jsonl
python -m finredops validate-applicability demo-output/applicability.json
python -m finredops validate-evidence-manifest demo-output/evidence-manifest.json
python -m finredops verify-bundle demo-output/audit-dossier.zip
python -m finredops verify-store demo-output/finredops.db FRX-DEMO-2026-001
python -m finredops serve
```

Expected result:

- the engagement is active after business-owner and control-team approval;
- three evidence-only/passive catalog actions complete against fixtures;
- controlled vulnerability validation is denied despite having approvals;
- every proposal, approval, decision, and receipt is hash-chained;
- the engagement passes the regulated-financial institution preflight;
- the SQLite store preserves snapshot revisions and the exact audit prefix;
- likely sensitive values are minimized before immutable evidence creation;
- a source-linked BDDK/SPK/KVKK/TSE/ISO crosswalk and annual-bank report draft are generated;
- human-confirmed applicability and a metadata-only evidence custody chain are generated;
- a deterministic review dossier verifies offline and remains blocked for
  regulatory submission until issuance gates are met;
- the local API accepts GET/HEAD only and rejects mutation methods;
- changing a line in `audit.jsonl` causes verification to fail.

All actors, assets, controls, and evidence references are invented. The
`example.test` namespace is reserved for documentation and testing.

The generated regulatory report is deliberately marked as an audit-support
draft. It is not a real finding set, regulator submission, legal opinion,
independent assurance statement, TSE conformity statement, or ISO certification.
