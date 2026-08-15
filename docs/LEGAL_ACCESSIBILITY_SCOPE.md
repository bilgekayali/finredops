# v1 legal and accessibility scope

FinRedOps 1.0.0 closes the repository release gate by making legal and accessibility responsibilities explicit. It does **not** convert the project into legal advice, a regulatory certification product, or a universally WCAG-conformant hosted service.

## Legal / regulatory scope

FinRedOps provides structured mappings and audit-support evidence for BDDK, SPK, KVKK, TSE/TS 13638/T2, ISO/IEC 27001/27002, GDPR, DORA, TIBER-EU and related security baselines. Applicability remains human confirmed.

A deployment owner is responsible for:

- determining which laws, regulations, contractual obligations and sector rules actually apply;
- obtaining authorization for security testing and confirming target ownership/scope;
- approving retention periods, legal holds, data residency, cross-border transfer and final evidence disposition;
- deciding whether a report can be issued, transmitted or submitted;
- assessing regulated outsourcing/cloud-provider obligations and local supervisory expectations;
- obtaining legal counsel where required.

The repository does not provide a legal opinion and does not assert that use of FinRedOps establishes compliance.

## Accessibility scope

The repository includes a self-contained operational dashboard and machine-readable CLI/JSON workflows. FinRedOps 1.0.0 does not claim universal WCAG conformance for every downstream deployment, theme, browser, assistive technology or organization-specific UI wrapper.

Deployment owners operating a user-facing interface are responsible for accessibility acceptance appropriate to their jurisdiction and user population, including where applicable:

- keyboard-only operation and focus visibility;
- semantic landmarks/headings and accessible names;
- contrast and non-color-only status communication;
- zoom/reflow and responsive behavior;
- screen-reader behavior and meaningful error/status announcements;
- accessible authentication and timeout handling added by the deployment;
- testing with representative assistive technologies and browsers;
- documented remediation/exception process.

FinRedOps CLI and versioned JSON artifacts provide a non-visual automation surface but are not themselves a substitute for accessibility testing of a deployed UI.

## Release-gate disposition

For v1.0.0 the legal/accessibility repository gate is closed by **explicit scoping**: applicability, formal legal review and deployed-UI accessibility acceptance are deployment-owner responsibilities. FinRedOps makes no certification claim in these domains.
