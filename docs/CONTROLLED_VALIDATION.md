# Controlled active validation

FinRedOps v0.4 adds an optional, bounded proof-of-exposure runner. It is a
governed active-validation primitive, not a general-purpose exploit framework
and not an autonomous penetration tester.

## Methodology position

The workflow separates professional judgement from machine execution:

1. authorized humans approve the rules of engagement, exact assets, exclusions,
   time window, emergency contacts and rate ceiling;
2. an AI or human proposes a typed catalog action as untrusted JSON;
3. deterministic policy verifies scope, parameters, expiry, separation of duties,
   production restrictions and the kill switch;
4. the runner performs one bounded observation;
5. deterministic rules create evidence-linked draft findings;
6. a qualified tester validates severity, business impact, false positives,
   regulatory mapping and remediation language before report issue.

This sequence is informed by [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final),
the public [TSE Bilişim Teknolojileri Sızma Testleri](https://www.tse.org.tr/sizma-testleri/)
scope, and versioned [OWASP WSTG 4.2](https://owasp.org/www-project-web-security-testing-guide/v42/)
test objectives. Public [OffSec OSCP+ domains](https://help.offsec.com/hc/en-us/articles/37192004980628-Authoritative-References-List-OSCP)
inform the distinction between identification, validation and documentation;
they do not make the software or its output OSCP-certified. CEH, OSCP and TSE
personnel qualifications belong to named human testers and must be evidenced in
the engagement dossier.

TS 13638/T2 is licensed. FinRedOps cites TSE's public pages but does not reproduce
the standard or invent clause numbers. An authorized copy, revision record and
human-reviewed clause matrix remain required for a TSE-aligned delivery.

## Implemented action

| Property | v0.4 behavior |
|---|---|
| Action | `http.security_posture.validate` |
| Target | One exact approved hostname or IP |
| Environment | Lab, development or test; production is denied |
| Network activity | One TLS-protected `HEAD` request |
| TLS | Certificate and hostname verification; TLS 1.2 minimum |
| DNS | Resolve once; loopback, link-local, multicast, unspecified and reserved addresses denied |
| Redirects | Recorded as present, never followed |
| Response body | Never read or retained |
| Limits | One request, 1–5 second timeout, 64 KiB maximum response headers |
| Required proposal data | Institution change/rules-of-engagement reference |
| Human approvals | Business owner, control team and execution approver; three distinct actors |
| Findings | HSTS, CSP, MIME-sniffing, cookie attributes and certificate expiry |
| Output | Sanitized immutable receipt plus draft report findings |

The engine records only response metadata. It never stores cookie values,
redirect URLs, response bodies or raw certificates. A peer address is represented
by a digest in the receipt.

## Explicit enablement

The default service has no outbound target access. An integrator must explicitly
construct the network transport and inject it into the control plane:

```python
from finredops.service import FinRedOpsService
from finredops.validation import ControlledValidationRunner

runner = ControlledValidationRunner.for_authorized_network()
service = FinRedOpsService(controlled_runner=runner)
```

An institution can pass a hardened `ssl.SSLContext` containing its private trust
roots. The transport refuses contexts that disable hostname checks or certificate
verification and always enforces a TLS 1.2 minimum.

This does not bypass the normal state machine. The engagement must still pass
institution preflight, receive two engagement approvals, include the exact
controlled action, and receive three proposal approvals. The read-only API cannot
enable or invoke network access.

The reserved `.test` proposal in
[`examples/synthetic_controlled_plan.json`](../examples/synthetic_controlled_plan.json)
is provided only for schema and policy validation. It is not executed by the
default demo.

## Finding boundary

Generated findings are deliberately drafts. Each contains:

- a deterministic identifier and rule identifier;
- affected approved asset;
- calibrated severity, summary, impact and recommendation;
- opaque evidence references;
- source-linked common KVKK/TSE control references;
- method references and `human_validation_required: true`.

One response cannot establish full application security. Authentication,
authorization, business logic, APIs, mobile clients, source code, dependency
risk and multi-step attack paths require separately authorized modules and human
testing. An operational failure is recorded as a failed receipt, never converted
into a vulnerability.

## Deliberately absent

- exploit payload generation or delivery;
- credential attacks, phishing or session takeover;
- autonomous discovery, crawling, port scanning or attack chaining;
- shell, subprocess, script or arbitrary URL execution;
- response-body collection or customer-data processing;
- production active validation;
- denial-of-service, persistence, evasion, privilege escalation or lateral movement.

More invasive modules should be isolated, independently threat-modelled and
approved by the institution before they are considered for a future release.
