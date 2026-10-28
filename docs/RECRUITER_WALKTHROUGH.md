# Two-minute reviewer walkthrough — FinRedOps

**Audience:** CISO, Head of Cyber Security, security architecture and governance reviewers.

**In one sentence:** This reference project illustrates how AI-assisted security testing proposals can remain inside explicit human approval, authorised scope and deterministic policy boundaries.

## 1. Observe the control boundary (30 seconds)

An AI system may propose a typed action. That proposal is **not authority** to run anything. Scope, approvals, allowed actions and security policy must independently permit it. Start with the [core control model](../README.md#core-control-model) and [safety boundaries](SAFETY_BOUNDARY.md).

## 2. Run an offline synthetic demonstration (60 seconds)

From the repository root, with Python 3.11+ available:

```bash
python -m pip install -e .
finredops export-examples --output-dir finredops-examples
finredops validate-engagement finredops-examples/synthetic_engagement.json
finredops validate-plan finredops-examples/synthetic_ai_plan.json --engagement finredops-examples/synthetic_engagement.json
finredops demo-reviewed-report --output-dir demo-output/reviewed
finredops validate-report demo-output/reviewed/regulatory-report.json
```

These commands are **documented examples**; they have not been run as part of this portfolio-description update. They are designed to use local synthetic data and not contact a live assessment target.

## 3. Inspect what counts as evidence (30 seconds)

Review [the example security report](../EXAMPLE_SECURITY_REPORT.md), [operator workflow](OPERATOR_WORKFLOW.md), [source implementation](../src/) and [tests](../tests/). Look for explicit scope, approval roles, denial paths, evidence custody and separately governed report issuance.

## What this does *not* demonstrate

This is not a live penetration test, autonomous exploit system, production deployment, independent external security assessment or compliance certification. The project's `production-reference` label describes a software/reference boundary—not production adoption by any institution.

[Back to repository README](../README.md)
