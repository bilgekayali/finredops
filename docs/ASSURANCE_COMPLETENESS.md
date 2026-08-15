# Assurance completeness — v0.9.1

FinRedOps v0.9.1 adds version-pinned assurance evidence boundaries for supply-chain metadata, technical vulnerability severity, and application-security verification coverage. These artifacts are inputs to qualified human review; they are not autonomous report conclusions and do not certify compliance.

## CycloneDX 1.7 intake

`finredops.supply_chain` accepts bounded UTF-8 CycloneDX JSON with `bomFormat` exactly `CycloneDX`, `specVersion` exactly `1.7`, bounded structural complexity and object counts, unique component `bom-ref` values, and affected-component references that resolve to known normalized components. Optional `CVSSv4` ratings are validated by the CVSS 4.0 boundary.

The normalized batch records the source SHA-256 and byte size, does not embed the raw source, requires human review, and never infers regulatory applicability. This is a deliberately bounded FinRedOps intake contract, not a claim that FinRedOps implements every CycloneDX 1.7 schema feature.

## CVSS 4.0 validation

`finredops.cvss40` accepts only CVSS 4.0 vectors and uses the pinned `cvss>=3.6,<4` dependency. It verifies the vector-derived score, FIRST qualitative severity band, and optional published score/severity assertions.

The artifact explicitly states `technical_severity_only=true` and `financial_business_impact_inferred=false`. CVSS does not replace qualified human severity, business-impact analysis, risk acceptance, or institution-specific decisions.

## OWASP ASVS 5.0.0 coverage

`finredops.asvs_coverage` uses versioned requirement references of the form `v5.0.0-x.y.z` and a digest-bound external source reference. FinRedOps intentionally does not copy ASVS requirement text into its catalog artifact.

Coverage states are `covered`, `partial`, `not_covered`, or `not_applicable`. Covered or partial requirements require evidence references. Not-covered and not-applicable requirements cannot claim evidence. Coverage artifacts state `compliance_certified=false` and `regulatory_applicability_inferred=false`.

## Deterministic qualified-review linkage

The assurance modules do not directly promote findings or issue reports. CycloneDX and ASVS evidence references may be added by a qualified tester to `QualifiedFindingReview.validation_evidence_refs`; the existing reviewed-report promotion path carries those validated references into draft finding evidence, and audit dossiers retain the governed report metadata without embedding raw evidence.

No new bypass around qualified review, report approval, tenant authorization, evidence custody, or report issuance is introduced.

## Trust and non-claims

v0.9.1 does not claim that parsing makes CycloneDX content safe, that every CycloneDX extension is normalized, that CVSS is financial or regulatory risk, that ASVS coverage proves compliance, that absence of findings proves conformance, or that FinRedOps autonomously chooses regulatory applicability.

The v0.9.1 assurance core is offline. CI rejects network/process capabilities in the CVSS, CycloneDX, and ASVS core modules and pins supported versions to CycloneDX 1.7, CVSS 4.0, and ASVS 5.0.0.
