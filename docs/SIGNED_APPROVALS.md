# Signed business and report approvals

FinRedOps v0.7.1 extends the verification-only trust model from qualified finding reviews to business risk acceptance and final human report approval.

The design goal is narrow: **FinRedOps verifies signatures; it does not mint credentials, hold private keys, or decide who is authorized.**

## Separation of duties

Reviewer trust and approval trust use separate public-key bundles.

```text
reviewer-trust-bundle
  qualified_tester
  review_governor

approval-trust-bundle
  business_risk_owner
  report_approver
```

A qualified-tester key cannot authorize business risk acceptance. A business-risk-owner key cannot approve a report unless it is separately trusted for `report_approver`.

## Risk acceptance

A finalized `RiskAcceptance` is already bound to:

- intake batch and digest;
- finding fingerprint;
- current review id and review digest;
- accountable business-risk owner;
- approval time and expiry;
- approval evidence reference;
- rationale and compensating controls.

v0.7.1 adds an external Ed25519 signature over an approval envelope containing:

```text
subject = accepted_by
purpose = risk_acceptance
role = business_risk_owner
engagement_id
object_id = acceptance_id
object_digest = acceptance_digest
context_digest = trusted-review-resolution digest
issued_at / expires_at
```

The context binding prevents an otherwise valid acceptance signature from being replayed against a different trusted review history.

`promote-trusted-reviewed-report` therefore behaves as follows:

- no risk acceptance supplied: no approval trust bundle is needed;
- risk acceptance supplied: every acceptance must have exactly one valid signed approval record;
- extra, missing, expired, replayed, role-mismatched, or tampered signatures fail closed;
- the acceptance must still reference the current authoritative review.

When signed risk acceptance is used, trusted promotion also emits:

```text
signed-risk-acceptance-resolution.json
```

and binds its digest into `trusted-promotion-manifest.json`.

## Report approval

Trusted report promotion still produces an untouched `draft` report. v0.7.1 does not silently alter that boundary.

Two distinct authorized people must sign the exact trusted draft report digest. Each signature is also bound to the `trusted_promotion_digest`:

```text
purpose = report_approval
role = report_approver
engagement_id
object_id = report_id
object_digest = trusted draft report digest
context_digest = trusted_promotion_digest
```

`approve-trusted-report` requires exactly two signatures from two distinct subjects. It verifies both against the dedicated approval trust bundle and then deterministically derives an `approved` report whose `human_approvals` contain the two verified signature ids.

Outputs:

```text
approved-regulatory-report.json
approved-regulatory-report.md
signed-report-approval.json
```

The approved report can become `ready_for_issue: true` under the existing structural report rules, but **FinRedOps still does not issue or submit it**. The signed approval manifest always records `report_issued: false`.

## CLI flow

### 1. Produce a risk-acceptance signing request

```bash
finredops risk-acceptance-signature-request \
  --intake work/finding-intake.json \
  --review work/current-review.json \
  --acceptance work/risk-acceptance.json \
  --trust-resolution work/trust-resolution.json \
  --engagement-id FRX-ENGAGEMENT-001 \
  --issuer bank-approval-idp \
  --key-id risk-owner-2026 \
  --issued-at 2026-08-13T10:00:00Z \
  --expires-at 2026-08-13T12:00:00Z \
  --output work/risk-signing-request.json
```

The external signer signs the canonical request bytes. FinRedOps then attaches the returned base64url Ed25519 signature:

```bash
finredops finalize-approval-signature \
  --request work/risk-signing-request.json \
  --signature BASE64URL_SIGNATURE \
  --output work/risk-signature.json
```

### 2. Promote with signed risk acceptance

```bash
finredops promote-trusted-reviewed-report \
  ...review trust arguments... \
  --acceptance work/risk-acceptance.json \
  --acceptance-signature work/risk-signature.json \
  --approval-trust-bundle work/approval-trust-bundle.json \
  --spec work/reviewed-report-spec.json \
  --output-dir work/trusted-report
```

### 3. Produce two report-approval signing requests

```bash
finredops report-approval-signature-request \
  --report work/trusted-report/regulatory-report.json \
  --trusted-promotion-manifest work/trusted-report/trusted-promotion-manifest.json \
  --engagement-id FRX-ENGAGEMENT-001 \
  --subject approver:risk-committee \
  --issuer bank-approval-idp \
  --key-id report-approver-1 \
  --issued-at 2026-08-13T10:30:00Z \
  --expires-at 2026-08-13T12:00:00Z \
  --output work/report-approval-request-1.json
```

Repeat for a second distinct approver, finalize both signatures, and run:

```bash
finredops approve-trusted-report \
  --report work/trusted-report/regulatory-report.json \
  --trusted-promotion-manifest work/trusted-report/trusted-promotion-manifest.json \
  --approval-signature work/report-approval-1.json \
  --approval-signature work/report-approval-2.json \
  --approval-trust-bundle work/approval-trust-bundle.json \
  --engagement-id FRX-ENGAGEMENT-001 \
  --as-of 2026-08-13T11:00:00Z \
  --output-dir work/approved-report
```

## What this does not claim

v0.7.1 does not provide:

- OIDC/JWKS or SAML session authentication;
- MFA or device-posture validation;
- institution directory authorization lookup;
- HSM/KMS private-key custody;
- legal or regulatory acceptance;
- report delivery to a regulator;
- automatic report issuance.

OIDC/JWKS identity-provider verification remains the next trust milestone.
