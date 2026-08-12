# Regulatory applicability

FinRedOps does not infer legal or standards applicability from an institution
name or type. v0.3 records an explicit tri-state decision for each authority:

| Value | Meaning | Delivery behavior |
|---|---|---|
| `true` | Authorized reviewer confirmed the authority/standard is in scope | Mapped controls are `applicable` |
| `false` | Reviewer marked it out of scope with rationale and exceptions | Mapped controls are `not_applicable` and must reconcile with the report |
| `null` | Scope has not been confirmed | Mapped controls are `requires_confirmation`; audit delivery fails closed |

The context covers BDDK, SPK, personal-data/KVKK scope, TSE TS 13638/T2 and
ISO/IEC 27001. It also records the institution type, test type, outsourcing,
internet exposure, criticality, rationale, exceptions, reviewer and timestamp.
Institution type produces warnings where useful but never replaces a legal or
contractual applicability decision.

For TSE, the reviewer must separately decide whether TS 13638/T2 and the current
TSE Sızma Testi Kapsamı form part of the engagement. The licensed standard
identifier/revision and a human-reviewed clause matrix remain external evidence;
FinRedOps stores only their opaque locators and digests.

```bash
python -m finredops validate-applicability applicability.json
```

A successful structural check is not a legal opinion. `ready_for_audit=true`
means only that every tri-state field is resolved and a named human confirmation
with a timezone-aware timestamp is present.
