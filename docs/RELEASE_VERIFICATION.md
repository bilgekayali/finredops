# v1 release verification

FinRedOps release integrity uses two separate checks that must not be conflated: **artifact byte integrity** and **build provenance**.

## 1. Version/tag binding

A tagged release is accepted by the release workflow only when the tag is exactly `vMAJOR.MINOR.PATCH` and matches `pyproject.toml`. For v1.0.0 the release tag must therefore be `v1.0.0`.

## 2. Build and installed-wheel smoke

The release workflow builds both wheel and source distribution, installs the wheel into a clean virtual environment and exercises the stable operator surface plus packaged synthetic examples. A source checkout is not used as the runtime import path for that smoke test.

## 3. SHA-256 manifest

The workflow generates `dist/CHECKSUMS.sha256` over the wheel and source distribution. Consumers can reproduce the byte-integrity check with:

```bash
finredops verify-release-checksums \
  --manifest CHECKSUMS.sha256 \
  --directory .
```

This proves that local files match the supplied manifest; it does not prove who built them.

## 4. Build provenance

The release workflow uses GitHub artifact attestations / Sigstore-backed provenance for the release artifacts. Consumers should independently verify the downloaded artifact against the FinRedOps repository identity with GitHub's attestation verification mechanism.

For example, after downloading the wheel:

```bash
gh attestation verify finredops-1.0.0-py3-none-any.whl \
  --repo bilgekayali/finredops
```

Provenance verification and checksum verification answer different questions and both should be retained in release evidence.

## 5. Repository release evidence

For a production deployment, retain:

- the exact Git commit/tag;
- wheel/source distribution;
- `CHECKSUMS.sha256`;
- successful provenance-verification output;
- release workflow run identifier;
- v1 release-gate CI result;
- deployment's validated production-reference profile digest;
- upgrade/rollback record when moving from v0.9.3.

## Non-claims

A valid checksum/provenance chain does not establish runtime configuration correctness, absence of vulnerabilities, legal compliance, target authorization or institution IAM/KMS policy correctness. It establishes artifact integrity/origin evidence for the release pipeline.
