# Contributing

FinRedOps welcomes focused contributions that strengthen authorization,
evidence integrity, safety, and operational governance.

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m finredops demo --output demo-output
```

The core has no runtime dependency outside the Python standard library.

## Contribution boundary

Suitable contributions include policy rules, audit controls, safe synthetic
scenarios, defensive evidence parsers, control mappings, and dashboard
improvements. Do not submit:

- exploit payloads or malware;
- credential attacks or phishing automation;
- arbitrary command execution;
- target discovery outside an approved scope;
- logic designed to bypass authorization, rate, or kill-switch controls.

Every behavior change should include tests. Documentation must distinguish
implemented controls from future design goals and must not claim regulatory
certification.

