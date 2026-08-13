# Reviewer trust, identity binding and lifecycle

FinRedOps v0.7 introduces a verification-only trust layer for qualified finding reviews. The objective is to answer not only **whether a review document changed**, but also **which externally asserted human identity authorized it, for which engagement and intake, and whether that review is still authoritative**.

## Trust boundary

FinRedOps does **not** mint identity credentials and does not hold reviewer private keys. An external identity authority signs a short-lived assertion with Ed25519. FinRedOps receives only:

- a public-key trust bundle;
- an immutable review or lifecycle event;
- the externally signed identity assertion;
- the engagement identifier and deterministic verification time.

The assertion is cryptographically bound to:

```text
issuer + subject + role
        + engagement_id
        + intake batch_id + batch_digest
        + finding_id
        + immutable object_id + object_digest
        + issued_at + expires_at
```

For a finding review, the protected object is the immutable `FRX-REV-*` review and its full digest. For a lifecycle event, the protected object is the immutable `FRX-RLC-*` event and its digest.

## Roles

Two trust-layer roles exist in v0.7:

- `qualified_tester` — signs the identity assertion bound to a finding review. The signed subject must exactly match the review's `reviewer_id`.
- `review_governor` — signs lifecycle changes such as supersession or revocation. The signed subject must exactly match the lifecycle event's `actor_id`.

A trust key explicitly lists the roles it may assert. A key authorized only for `qualified_tester` cannot authorize lifecycle governance.

## Trust bundle

A trust bundle contains public Ed25519 keys and validity windows. It is deliberately verifier-side data; private key material is out of scope.

```json
{
  "schema_version": "finredops.reviewer-trust-bundle.v1",
  "bundle_id": "bank-review-trust-2026",
  "keys": [
    {
      "issuer": "idp.example-bank.test",
      "key_id": "reviewer-key-2026",
      "algorithm": "Ed25519",
      "public_key": "BASE64URL_RAW_32_BYTE_PUBLIC_KEY",
      "roles": ["qualified_tester", "review_governor"],
      "not_before": "2026-01-01T00:00:00Z",
      "not_after": "2026-12-31T23:59:59Z"
    }
  ]
}
```

## External signing flow

Create a signing request for a finalized review:

```bash
finredops identity-assertion-request \
  --intake work/finding-intake.json \
  --review work/review.json \
  --engagement-id FRX-ENGAGEMENT-001 \
  --issuer idp.example-bank.test \
  --key-id reviewer-key-2026 \
  --issued-at 2026-08-13T09:00:00Z \
  --expires-at 2026-08-13T10:00:00Z \
  --output work/review-signing-request.json
```

The external authority signs the canonical UTF-8 JSON representation of that request with sorted keys and no insignificant whitespace. FinRedOps does not perform that private-key operation.

Attach the returned base64url Ed25519 signature:

```bash
finredops finalize-identity-assertion \
  --request work/review-signing-request.json \
  --signature BASE64URL_ED25519_SIGNATURE \
  --output work/review-identity-assertion.json
```

Finalization validates the document shape and derived assertion identifier. Cryptographic verification occurs only when a trust bundle and protected review/event are supplied.

## Supersession and revocation

Review documents are never edited or deleted to change a decision. Instead, an immutable lifecycle event records the transition.

### Supersede

```text
Review A (historical)
        |
        | signed supersede event
        v
Review B (current authoritative)
```

### Revoke

```text
Review A (historical)
        |
        | signed revoke event
        v
NO CURRENT AUTHORITATIVE REVIEW
```

A revoked finding blocks trusted report promotion until a new review history establishes a valid authoritative replacement.

Create and finalize a lifecycle event:

```bash
finredops review-lifecycle-template \
  --intake work/finding-intake.json \
  --prior-review work/review-a.json \
  --replacement-review work/review-b.json \
  --action supersede \
  --actor-id review-governor:security \
  --output work/lifecycle-draft.json

# Fill event_at and reason, then:
finredops finalize-review-lifecycle \
  --draft work/lifecycle-draft.json \
  --output work/lifecycle-event.json
```

The lifecycle event then receives its own external `review_governor` identity assertion using `identity-assertion-request --lifecycle-event ...`.

## Fail-closed lifecycle resolution

`verify-review-trust` verifies every supplied review and lifecycle signature before resolving authority:

```bash
finredops verify-review-trust \
  --intake work/finding-intake.json \
  --review work/review-a.json \
  --review work/review-b.json \
  --lifecycle-event work/lifecycle-event.json \
  --identity-assertion work/review-a.assertion.json \
  --identity-assertion work/review-b.assertion.json \
  --identity-assertion work/lifecycle.assertion.json \
  --trust-bundle trust/reviewer-trust.json \
  --engagement-id FRX-ENGAGEMENT-001 \
  --as-of 2026-08-13T10:30:00Z
```

Resolution fails closed on:

- missing or duplicate assertions;
- unknown trust keys;
- invalid Ed25519 signatures;
- role mismatch;
- reviewer/actor subject mismatch;
- engagement replay;
- intake, finding or object digest mismatch;
- assertion/key validity failure;
- multiple lifecycle transitions from one review;
- multiple predecessors, cycles, orphan reviews or parallel heads;
- non-monotonic supersession chronology.

## Trusted report promotion

`promote-trusted-reviewed-report` uses the same verification layer and passes only the resolved current authoritative reviews into the existing draft-report promotion boundary.

```bash
finredops promote-trusted-reviewed-report \
  --intake work/finding-intake.json \
  --review work/review-a.json \
  --review work/review-b.json \
  --lifecycle-event work/lifecycle-event.json \
  --identity-assertion work/review-a.assertion.json \
  --identity-assertion work/review-b.assertion.json \
  --identity-assertion work/lifecycle.assertion.json \
  --trust-bundle trust/reviewer-trust.json \
  --engagement-id FRX-ENGAGEMENT-001 \
  --as-of 2026-08-13T10:30:00Z \
  --spec work/reviewed-report-spec.json \
  --output-dir work/trusted-report
```

Outputs include the normal draft report and promotion manifest plus:

- `trust-resolution.json` — authoritative review IDs, verified assertion IDs, lifecycle IDs and trust-bundle digest;
- `trusted-promotion-manifest.json` — binds the trust resolution to the generated draft report and base promotion digest.

Report issuance remains outside this automation. `ready_for_issue` stays false until the separate report-approval model is satisfied.

## Current limitation: no OIDC/JWKS protocol adapter yet

v0.7 verifies a provider-neutral FinRedOps identity assertion against configured Ed25519 public keys. It deliberately reports `external_idp_protocol_verified: false` because this release does **not** yet validate OIDC ID tokens, OAuth access tokens, JWKS discovery, SAML assertions, device posture, MFA claims, or an institutional directory session.

That distinction matters: a valid FinRedOps signature proves possession of a trusted external signing key and exact binding to the reviewed object. It does not by itself prove a particular upstream authentication protocol was performed.

OIDC/JWKS integration remains a subsequent trust-layer milestone.

## Cryptographic scope

v0.7 cryptographically authenticates review and lifecycle identity assertions. It does not yet add key-backed signatures to business risk acceptance or final report approvals. Those remain separate roadmap items.
