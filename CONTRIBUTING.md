# Contributing

FinRedOps welcomes focused contributions that strengthen authorization,
evidence integrity, safety, and operational governance.

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m finredops demo --output demo-output
python -m finredops verify-bundle demo-output/audit-dossier.zip
```

The core has no runtime dependency outside the Python standard library.

## Contribution boundary

Suitable contributions include policy rules, audit controls, safe synthetic
scenarios, bounded non-destructive validators, defensive evidence parsers, control mappings, and dashboard
improvements. Do not submit:

- exploit payloads or malware;
- credential attacks or phishing automation;
- arbitrary command execution;
- target discovery outside an approved scope;
- logic designed to bypass authorization, rate, or kill-switch controls.
- response-body collection or active production testing in built-in runners;

Every behavior change should include tests. Documentation must distinguish
implemented controls from future design goals and must not claim regulatory
certification.

Changes to regulatory mappings must cite an official source, record a review
date, avoid reproducing licensed standards and include an applicability or
validation test. Changes to evidence/bundle formats must preserve strict schema,
size/path limits, metadata-only packaging and offline tamper detection.
Controlled validators must use a closed action, exact target scope, explicit
enablement, non-production tests, deterministic evidence minimization, bounded
requests, no redirects, no payloads and failure-path tests.
