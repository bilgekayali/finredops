# OIDC / JWKS identity verification

FinRedOps v0.7.2 adds an **offline, verification-only OpenID Connect identity adapter** for signed human decisions.

The adapter does not replace the existing reviewer or approval signatures. It answers a separate question:

> Which authenticated external IdP session and claims were bound to the human subject and FinRedOps role that signed this decision?

## Trust boundary

FinRedOps accepts three operator-supplied inputs:

1. a pinned OIDC provider configuration;
2. a bounded JWKS document exported from the configured OpenID Provider;
3. one compact ID token obtained from the external authentication flow.

FinRedOps does **not**:

- fetch `.well-known/openid-configuration`;
- fetch or refresh JWKS over the network;
- retain the raw ID token in verification artifacts;
- store IdP client secrets, signing private keys, refresh tokens, access tokens, or reviewer/approval private keys;
- infer authorization from authentication alone;
- treat an OIDC token as a substitute for the Ed25519 reviewer, lifecycle, risk-acceptance, or report-approval signature;
- validate SAML, device posture, endpoint compliance, access-token introspection, or regulator submission.

Keeping network retrieval outside the verifier preserves deterministic offline replay and avoids turning issuer-controlled URLs into an implicit network capability.

## Pinned provider configuration

`finredops.oidc-provider.v1` fixes the identity assumptions that must not be taken from an attacker-controlled token header or payload:

- exact HTTPS `issuer`;
- exact `client_id` / ID-token audience;
- asymmetric signature algorithm allow-list;
- configured role claim name;
- accepted ACR values;
- maximum authentication age;
- maximum token lifetime;
- bounded clock skew.

Example:

```json
{
  "schema_version": "finredops.oidc-provider.v1",
  "provider_id": "bank-workforce-idp",
  "issuer": "https://idp.example-bank.test",
  "client_id": "finredops-assurance",
  "allowed_algorithms": ["RS256"],
  "role_claim": "roles",
  "required_acr": ["urn:example:mfa"],
  "max_auth_age_seconds": 3600,
  "max_token_lifetime_seconds": 3600,
  "clock_skew_seconds": 60
}
```

Generate a template:

```bash
finredops oidc-provider-template --output trust/oidc-provider.json
```

## ID-token verification

```bash
finredops verify-oidc-id-token \
  --provider-config trust/oidc-provider.json \
  --jwks trust/idp-jwks.json \
  --id-token work/id-token.jwt \
  --expected-nonce "$OIDC_NONCE" \
  --as-of 2026-08-13T08:00:00Z \
  --output work/oidc-verification.json
```

The verifier fails closed unless all configured checks succeed, including:

- JWT compact structure and bounded size;
- exact `kid` selection from the supplied JWKS;
- asymmetric key requirement;
- provider-pinned `alg` allow-list;
- JWK `use` / `key_ops` / optional `alg` compatibility;
- cryptographic signature verification;
- exact issuer match;
- exact configured audience, with `azp` validation when present;
- required `exp`, `iat`, `auth_time`, `acr`, `nonce`, `sub`, and `aud` claims;
- nonce equality with the authentication transaction;
- expiry, not-before, issue time, authentication age, and maximum token lifetime;
- configured ACR requirement;
- at least one recognized FinRedOps role in the configured role claim.

The resulting `finredops.oidc-identity-verification.v1` artifact contains only minimized verification metadata and SHA-256 digests. `raw_id_token_retained` is always `false`.

## Bind the IdP identity to a FinRedOps signature

OIDC authentication proves an IdP statement about a subject. FinRedOps decision signatures prove integrity and authorization context for a specific assurance decision. v0.7.2 keeps those claims separate and binds them explicitly.

For a reviewer/lifecycle identity assertion:

```bash
finredops bind-oidc-identity \
  --verification work/oidc-verification.json \
  --identity-assertion work/reviewer.assertion.json \
  --as-of 2026-08-13T08:00:00Z \
  --output work/reviewer.oidc-binding.json
```

For a business-risk or report-approval signature:

```bash
finredops bind-oidc-identity \
  --verification work/oidc-verification.json \
  --approval-signature work/report-approval.json \
  --as-of 2026-08-13T08:00:00Z \
  --output work/report-approval.oidc-binding.json
```

Binding requires exact equality of the OIDC `sub` and the signed FinRedOps `subject`, and the signed FinRedOps role must be present in the verified OIDC role claim.

## Exact workflow coverage

A workflow can contain several independently signed human objects. The aggregate resolver requires one valid OIDC binding for every supplied reviewer/approval signature and rejects missing, duplicate, extra, altered, or cross-engagement bindings.

```bash
finredops verify-oidc-workflow-bindings \
  --binding work/reviewer.oidc-binding.json \
  --binding work/report-approval.oidc-binding.json \
  --identity-assertion work/reviewer.assertion.json \
  --approval-signature work/report-approval.json \
  --engagement-id FRX-ENGAGEMENT-001 \
  --output work/oidc-workflow-resolution.json
```

A successful `finredops.oidc-workflow-resolution.v1` records:

- `external_idp_protocol_verified: true`;
- `exact_binding_coverage: true`;
- the protected signature IDs;
- OIDC verification IDs;
- subjects and FinRedOps roles;
- a deterministic resolution digest.

This artifact should be retained alongside the trusted-review, signed-risk-acceptance, and signed-report-approval evidence for the assessment.

## Security rationale

The implementation follows the OpenID Connect ID-token validation model and RFC/JWT/JWK separation of responsibilities. In particular, accepted algorithms come from the pinned provider configuration, not from the token itself. The JWKS input is treated as evidence supplied through an authorized operational process rather than as a URL that FinRedOps autonomously retrieves.

Primary references:

- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 7517 — JSON Web Key (JWK): https://www.rfc-editor.org/rfc/rfc7517
- RFC 7519 — JSON Web Token (JWT): https://www.rfc-editor.org/rfc/rfc7519
- RFC 8725 — JWT Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725
- PyJWT documentation: https://pyjwt.readthedocs.io/

## Remaining identity hardening

v0.7.2 does not claim complete enterprise identity governance. Later hardening can add separately reviewed adapters for:

- controlled OIDC discovery/JWKS refresh with explicit egress policy;
- IdP federation metadata and key-rotation workflows;
- device posture and conditional-access evidence;
- HSM/KMS-backed decision signing keys;
- tenant-specific identity policy and external audit anchoring.
