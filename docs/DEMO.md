# Demo guide

The demo shows the governance lifecycle without contacting a target.

```bash
python -m pip install -e .
python -m finredops demo --output demo-output
python -m finredops verify-audit demo-output/audit.jsonl
python -m finredops serve
```

Expected result:

- the engagement is active after business-owner and control-team approval;
- three evidence-only/passive catalog actions complete against fixtures;
- controlled vulnerability validation is denied despite having approvals;
- every proposal, approval, decision, and receipt is hash-chained;
- changing a line in `audit.jsonl` causes verification to fail.

All actors, assets, controls, and evidence references are invented. The
`example.test` namespace is reserved for documentation and testing.
