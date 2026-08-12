# Control mapping

This is a design cross-reference, not a statement of compliance, audit
readiness, or legal interpretation. Each institution must establish its own
applicable requirements and obtain independent review.

| FinRedOps design element | Reference concept | Demonstrated artifact |
|---|---|---|
| Documented engagement and exact scope | NIST SP 800-115 planning; TIBER-EU scope specification | `Engagement`, scope lock panel |
| Control-team and owner separation | DORA/TLPT and TIBER-EU governance themes | digest-bound role approvals |
| Controlled action authorization | Rules of engagement and risk management | `PolicyEngine.evaluate` |
| Time window and stop condition | Test execution control and risk containment | window checks, emergency pause |
| Evidence and reporting trail | Test documentation and traceability | receipt plus JSONL audit chain |
| AI proposal treated as untrusted | NIST AI RMF govern/map/measure/manage themes | guarded planning gateway |
| Known techniques represented as typed plans | MITRE ATT&CK emulation planning concept | closed action catalog (no techniques executed) |

Primary references:

- [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final)
- [DORA Regulation (EU) 2022/2554](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX%3A32022R2554)
- [Delegated Regulation (EU) 2025/1190](https://eur-lex.europa.eu/eli/reg_del/2025/1190/oj/eng)
- [ECB TIBER-EU](https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [MITRE ATT&CK adversary emulation plans](https://attack.mitre.org/resources/adversary-emulation-plans/)
