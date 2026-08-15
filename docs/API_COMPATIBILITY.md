# v1 API and JSON-schema compatibility policy

FinRedOps 1.x treats the **operator CLI and versioned JSON artifact contracts** as the public compatibility surface. Internal Python modules remain implementation detail unless this document explicitly promotes a symbol in a later release.

## Semantic-versioning rule

Within major version 1:

- an existing stable CLI command is not removed, renamed, or repurposed;
- existing required command arguments do not silently change meaning;
- a versioned JSON artifact keeps its `schema_version` discriminator semantics;
- a consumer that accepted a valid v1 artifact must not be forced to accept a silently incompatible meaning under the same discriminator;
- a breaking CLI or schema-contract change requires a new major FinRedOps version or a new artifact discriminator that can coexist with the old contract.

Additive functionality may introduce new CLI commands or new independently versioned artifact types in a minor release. Existing commands may gain optional arguments only when omission preserves prior behavior. Error text is not a stable machine interface; callers must use documented exit status and artifact contracts rather than parse prose messages.

## Stable v1 CLI surface

The authoritative machine-readable list is `finredops.v1_release.STABLE_CLI_COMMANDS`. It covers the trust, approval, OIDC, change-control, tenant, PostgreSQL, anchor, report-promotion and release-integrity operator paths required by the v1 reference architecture.

Commands outside that list remain supported repository functionality but are not promised the same within-major compatibility guarantee. The project may promote additional commands into the stable list in a backward-compatible v1.x release.

## JSON artifact compatibility

Every stable artifact uses an explicit discriminator such as `finredops.tenant-authorization.v1`. The discriminator, not the filename alone, is the compatibility boundary.

For an existing stable discriminator in v1.x:

- removing or renaming a required property is breaking;
- changing a property's type, security meaning, identity binding, digest semantics, or authorization effect is breaking;
- weakening a `const`, cryptographic binding, role separation, fail-closed condition, or tenant boundary is breaking and prohibited under the same discriminator;
- making an optional property newly required is breaking;
- adding a new optional property is allowed only when existing validators and producers can safely ignore its absence and the schema's `additionalProperties` policy is intentionally revised under review;
- a security-significant semantic expansion should normally use a new artifact discriminator even when JSON shape alone could remain compatible.

FinRedOps intentionally uses many schemas with `additionalProperties: false`. Therefore an apparently additive property can still be wire-incompatible for strict consumers; such a change must be treated as a compatibility decision, not assumed safe.

## Python import surface

The package version (`finredops.__version__`) is public. Other Python modules are primarily the implementation/reference-library surface and are **not** promised stable across all v1.x releases. Integrators requiring a long-lived machine boundary should prefer the CLI and versioned JSON artifacts.

## Security beats silent compatibility

A compatibility promise never requires preserving a known unsafe behavior. If a vulnerability demands an incompatible fix, FinRedOps may fail closed and ship the fix with an explicit security advisory and migration guidance. It will not silently preserve an insecure authorization, cryptographic, tenant, evidence, or execution behavior merely to avoid a version change.

## Deprecation

When feasible, a planned breaking change is first documented as deprecated in a prior minor release. Security fixes and externally imposed protocol changes may require a shorter path. Deprecated behavior is not removed within v1 unless the project documents why continued support would violate a safety or security boundary.

## Upgrade baseline

The supported direct pre-v1 upgrade baseline for 1.0.0 is **0.9.3**. See `UPGRADE_TO_V1.md`. Earlier installations should first move through the documented v0.9.x migration path rather than skipping persisted-schema and trust-boundary transitions.
