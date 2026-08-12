# Demo guide

The demo shows the governance lifecycle without contacting a target.

```bash
python -m pip install -e .
python -m finredops demo --output demo-output
python -m finredops verify-audit demo-output/audit.jsonl
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
- a source-linked BDDK/SPK/KVKK/ISO crosswalk and annual-bank report draft are generated;
- the local API accepts GET/HEAD only and rejects mutation methods;
- changing a line in `audit.jsonl` causes verification to fail.

All actors, assets, controls, and evidence references are invented. The
`example.test` namespace is reserved for documentation and testing.

The generated regulatory report is deliberately marked as an audit-support
draft. It is not a real finding set, regulator submission, legal opinion,
independent assurance statement, or ISO certification.
