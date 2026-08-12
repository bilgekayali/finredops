# Regulatory and security assurance baseline

FinRedOps is designed for governed security-testing and assurance workflows in
regulated financial institutions. Its analysis model is intentionally broader
than one regulation or one penetration-testing standard.

The project distinguishes three levels of support:

- **Implemented crosswalk / applicability** — FinRedOps has versioned control or
  applicability structures that can be linked to findings and report conclusions.
- **Methodology / analysis baseline** — the framework informs testing, evidence,
  governance, resilience, privacy, or reporting design, but FinRedOps does not
  claim a complete machine-readable crosswalk to every clause.
- **Roadmap coverage** — the framework is already used as a reference, while a
  deeper versioned requirement model is still planned.

None of these labels means certification, legal compliance, regulatory approval,
or an independent audit opinion.

## Coverage matrix

| Framework / authority | FinRedOps use | Current status |
|---|---|---|
| **BDDK — Bankaların Bilgi Sistemleri ve Elektronik Bankacılık Hizmetleri Hakkında Yönetmelik** | Turkish banking information-systems governance, security testing, evidence and reporting context | **Implemented crosswalk / applicability** |
| **BDDK — Bilgi Sistemlerine İlişkin Sızma Testleri Hakkında Genelge 2012/1** | Penetration-testing scope and audit-support reporting baseline for banks | **Implemented crosswalk / regulatory baseline** |
| **SPK VII-128.10 — Bilgi Sistemleri Yönetimine İlişkin Usul ve Esaslar Tebliği** | Capital-markets information-systems governance and security assurance context | **Implemented crosswalk / applicability** |
| **KVKK 6698, especially Article 12 and Personal Data Security guidance** | Personal-data security, technical/organizational safeguards, evidence minimization and reporting | **Implemented crosswalk / applicability** |
| **TSE penetration-testing framework and TS 13638/T2 prerequisites** | Turkish penetration-testing provider and assurance prerequisites | **Implemented public-prerequisite mapping; licensed clause text is not reproduced** |
| **ISO/IEC 27001:2022 and ISO/IEC 27002:2022** | ISMS/control assurance, control mapping and evidence-oriented reporting | **Implemented standards applicability / mapping support; no certification claim** |
| **NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment** | Planning tests, conducting examinations, analyzing findings and documenting mitigation | **Methodology / analysis baseline** |
| **NIST AI RMF Generative AI Profile** | AI-governance boundaries, human oversight, traceability and risk treatment for AI-assisted workflows | **Methodology / governance baseline** |
| **OWASP ASVS 5.0** | Application-security verification requirements and finding/control tagging | **Analysis baseline today; deeper versioned requirement coverage is on the roadmap** |
| **GDPR — Regulation (EU) 2016/679** | Privacy/security analysis, data minimization, confidentiality/integrity and evidence-handling context | **Methodology / privacy baseline; explicit clause-level crosswalk is not claimed** |
| **DORA — Regulation (EU) 2022/2554** | ICT risk management, operational resilience and threat-led penetration-testing context | **Methodology / financial-resilience baseline** |
| **Commission Delegated Regulation (EU) 2025/1190** | DORA threat-led penetration-testing implementation context | **Methodology / TLPT baseline** |
| **ECB TIBER-EU** | Threat-intelligence-led testing governance, control, evidence and human accountability | **Methodology / TLPT baseline** |
| **MITRE ATT&CK** | Adversary-behavior taxonomy and controlled emulation planning reference | **Methodology / threat-model baseline** |
| **OASIS SARIF 2.1.0** | Machine finding intake, canonicalization and human-review queue | **Implemented bounded intake** |

## What "analysis against" means in FinRedOps

FinRedOps does not simply attach framework names to a final report. The intended
assurance chain is:

```text
security evidence
    -> bounded normalization
    -> qualified human disposition
    -> technical and business impact
    -> control / requirement references
    -> applicability decision
    -> draft regulatory assurance conclusion
    -> independent human approval
```

Where an implemented crosswalk exists, findings and conclusions can be linked to
versioned control identifiers and human-confirmed applicability. Where a framework
is currently a methodology baseline, it shapes assessment scope, testing rigor,
evidence handling, review, resilience, privacy, or reporting without pretending
that every legal or standard clause has been encoded.

## Turkish financial-sector assurance

The strongest structured regulatory support currently focuses on the Turkish
financial sector:

- BDDK banking information-systems requirements and penetration-testing context;
- SPK VII-128.10 information-systems governance;
- KVKK security obligations and personal-data security guidance;
- TSE penetration-testing public prerequisites and licensed-standard evidence
  boundaries;
- ISO/IEC 27001/27002 applicability and control-oriented assurance.

See [Türkiye regulatory mapping](TURKEY_REGULATORY_MAPPING.md) and
[Applicability](APPLICABILITY.md) for the detailed model.

## International testing, resilience and privacy baselines

FinRedOps additionally uses international frameworks to keep the assessment model
portable beyond one regulator:

- **NIST SP 800-115** for technical security-testing and assessment methodology;
- **OWASP ASVS** for application-security verification requirements;
- **GDPR** for EU personal-data protection and security context;
- **DORA** and its TLPT-related delegated regulation for EU financial-sector
  digital operational resilience;
- **TIBER-EU** for intelligence-led testing governance;
- **NIST AI RMF** for AI-assisted workflow governance;
- **MITRE ATT&CK** for adversary-behavior taxonomy;
- **SARIF 2.1.0** for bounded machine-result interchange.

## Reference sources

- [BDDK Bankaların Bilgi Sistemleri ve Elektronik Bankacılık Hizmetleri Hakkında Yönetmelik](https://www.resmigazete.gov.tr/eskiler/2020/03/20200315-10.htm)
- [BDDK Bilgi Sistemlerine İlişkin Sızma Testleri Hakkında Genelge 2012/1](https://www.bddk.org.tr/Mevzuat/DokumanGetir/915)
- [SPK Bilgi Sistemleri Yönetimine İlişkin Usul ve Esaslar Tebliği VII-128.10](https://www.resmigazete.gov.tr/eskiler/2025/03/20250313-8.htm)
- [KVKK 6698 sayılı Kanun Madde 12](https://www.kvkk.gov.tr/Icerik/2097/Kanun-doc)
- [KVKK Personal Data Security Guide](https://www.kvkk.gov.tr/SharedFolderServer/CMSFiles/7512d0d4-f345-41cb-bc5b-8d5cf125e3a1.pdf)
- [TSE Bilişim Teknolojileri Sızma Testleri](https://www.tse.org.tr/sizma-testleri/)
- [TSE Sızma Testi Belgelendirmesi / TS 13638/T2 prerequisites](https://www.tse.org.tr/sizma-testi-belgelendirmesi/)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
- [ISO/IEC 27002:2022](https://www.iso.org/standard/75652.html)
- [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [GDPR — Regulation (EU) 2016/679](https://eur-lex.europa.eu/eli/reg/2016/679/oj)
- [DORA — Regulation (EU) 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj)
- [Commission Delegated Regulation (EU) 2025/1190](https://eur-lex.europa.eu/eli/reg_del/2025/1190/oj/eng)
- [ECB TIBER-EU framework](https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html)
- [MITRE ATT&CK adversary emulation plans](https://attack.mitre.org/resources/adversary-emulation-plans/)
- [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)

## Limits

FinRedOps provides audit-support structures, traceability, deterministic checks,
and human-review boundaries. It does **not** establish that an institution is
compliant with BDDK, SPK, KVKK, GDPR, DORA, TSE or ISO requirements; does not
replace licensed standards; does not provide legal advice; and does not issue an
independent audit, certification or regulatory acceptance decision.
