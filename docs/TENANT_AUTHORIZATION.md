# Authenticated tenant routing and authorization

FinRedOps v0.8.2 adds an authenticated application-layer routing boundary above
the institution-scoped SQLite store. It consumes the minimized OIDC verification
artifact introduced in v0.7.2; it does **not** parse raw tokens, perform OIDC
discovery, retrieve JWKS, or accept a caller-supplied `institution_id` as proof of
authority.

## Trust chain

The routing decision is derived from four independently digest-bound inputs:

1. a previously verified `finredops.oidc-identity-verification.v1` artifact;
2. an institution routing policy containing exact subject grants;
3. the current institution security context;
4. a requested bounded capability set.

The policy binds one exact `oidc_provider_id` **and its
`provider_config_digest`** to one `institution_id`. Pinning the provider
configuration means an IdP policy change (for example issuer, client audience,
algorithm allow-list, ACR requirement, or another provider-config field) cannot
silently inherit a routing grant merely because the human-readable provider id
stayed the same. Each grant names one exact OIDC `sub`, the FinRedOps roles that
subject may use in the institution, and a closed capability set:

- `store_read`
- `store_write`
- `audit_verify`
- `crypto_use`

Wildcards and implicit membership are intentionally unsupported.

## Authorization artifact

`authorize-tenant-route` produces `finredops.tenant-authorization.v1`. The
artifact binds:

- institution id and current institution-context digest;
- routing policy id and policy digest (which includes the exact OIDC provider-config digest);
- OIDC verification id and verification digest;
- provider id and exact subject;
- the intersection of OIDC roles and policy-granted roles;
- the exact requested capability subset;
- authorization time and the source ID-token expiry.

The artifact records both `external_idp_protocol_verified: true` and
`tenant_route_authorized: true`. Those markers are assertions of the verified
technical workflow only; they are not regulatory or legal approval.

A stored authorization is never trusted by itself. `verify-tenant-authorization`
and `AuthorizedTenantSession.create()` require the source OIDC verification,
current routing policy, and current institution context again. Policy changes,
context changes, provider or provider-configuration changes, subject changes,
expired identity, role changes, or capability escalation therefore fail closed.

## Store boundary

`AuthorizedTenantSession.open_store()` derives the store's institution id from
the verified authorization/context rather than a request parameter. Read access
requires `store_read`. Write access requires `store_write` **and** a configured
institution cryptographic provider, so the authenticated routing layer cannot
silently bypass the v0.8.1 envelope-encryption path and create plaintext writes.

`authorized-tenant-store-metadata` demonstrates this route for metadata-only
reads without requiring a KMS unwrap operation.

## Example workflow

Create a policy template from an institution context and a verified OIDC
identity:

```bash
finredops tenant-routing-policy-template \
  --institution-context institution-security-context.json \
  --oidc-verification oidc-verification.json \
  --output tenant-routing-policy.json
```

The generated policy uses a bounded digest-derived policy id, pins the current
OIDC provider configuration, and is intentionally conservative (`store_read` and
`audit_verify`). Review it under the institution's configuration-change process
before granting broader capabilities.

Authorize a bounded route:

```bash
finredops authorize-tenant-route \
  --policy tenant-routing-policy.json \
  --institution-context institution-security-context.json \
  --oidc-verification oidc-verification.json \
  --capability store_read \
  --capability audit_verify \
  --as-of 2026-08-13T10:00:00Z \
  --output tenant-authorization.json
```

Revalidate it later against the current sources:

```bash
finredops verify-tenant-authorization \
  --authorization tenant-authorization.json \
  --policy tenant-routing-policy.json \
  --institution-context institution-security-context.json \
  --oidc-verification oidc-verification.json \
  --as-of 2026-08-13T10:15:00Z
```

Read the exact institution store namespace through the authorization boundary:

```bash
finredops authorized-tenant-store-metadata finredops.db \
  --authorization tenant-authorization.json \
  --policy tenant-routing-policy.json \
  --institution-context institution-security-context.json \
  --oidc-verification oidc-verification.json \
  --as-of 2026-08-13T10:15:00Z
```

## Fail-closed behavior

Authorization is rejected when any of the following occurs:

- OIDC provider id does not exactly match the institution policy;
- OIDC provider-config digest does not exactly match the pinned policy value;
- OIDC subject has no exact active grant;
- OIDC role claims do not intersect the policy grant;
- requested capability exceeds the grant;
- OIDC verification or authorization has expired;
- authorization predates source verification;
- institution context or routing policy digest changed;
- authorization document or policy document was modified without recomputing its digest;
- authorization is replayed with another institution context;
- a write store is requested without the institution crypto provider.

## Security boundaries and non-claims

v0.8.2 is an **application authorization boundary**, not a database security
feature. Direct code that deliberately bypasses `AuthorizedTenantSession` can
still instantiate the low-level SQLite store; production deployment should
restrict that API at service boundaries and add a persistence engine with native
row-level security.

v0.8.2 does not provide:

- database-engine row-level security;
- network/API gateway authentication by itself;
- IdP discovery or remote JWKS refresh;
- SCIM/group synchronization or wildcard tenant membership;
- automatic routing-policy approval/signing;
- KMS IAM/key-policy validation;
- regulator acceptance, certification, or legal applicability decisions.

The next production persistence milestone remains database-native RLS plus an
independently reviewed service boundary. Policy-bundle signatures and independent
configuration-change approval also remain platform-hardening work.
