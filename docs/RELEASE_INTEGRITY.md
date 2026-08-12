# FinRedOps release integrity and provenance

FinRedOps v0.6.1 separates three questions that are often conflated:

1. **Can the installed package reproduce the documented synthetic workflow?**
2. **Do downloaded release bytes still match the published SHA-256 manifest?**
3. **Were those release bytes built by the expected GitHub Actions workflow from this repository?**

The release process answers these independently. A checksum is not a provenance
claim, and a provenance attestation is useful only when a consumer verifies it.

## Release artifacts

The release workflow builds:

- `finredops-<version>-py3-none-any.whl`;
- `finredops-<version>.tar.gz`;
- `CHECKSUMS.sha256`.

The wheel includes the synthetic engagement, AI plan, and SARIF fixture as package
data. They can be exported after installing the wheel without a source checkout:

```bash
finredops export-examples --output-dir finredops-examples
```

The reviewed-report demo also defaults to the packaged SARIF fixture:

```bash
finredops demo-reviewed-report --output-dir reviewed-demo
finredops validate-report reviewed-demo/regulatory-report.json
```

An explicit SARIF path remains supported with `--sarif`.

## Local checksum verification

Download the wheel/source distribution and `CHECKSUMS.sha256` into one directory,
then run:

```bash
finredops verify-release-checksums \
  --manifest ./CHECKSUMS.sha256 \
  --directory .
```

The verifier accepts only basename subjects, rejects path traversal and duplicate
manifest entries, and checks every listed artifact with SHA-256.

A successful result proves only that the local bytes match the supplied checksum
manifest. It intentionally reports `provenance_verified: false` because a checksum
manifest cannot establish who built the artifacts or which workflow produced them.

## GitHub/Sigstore provenance verification

The release workflow uses GitHub artifact attestations with the permissions:

```yaml
permissions:
  contents: write
  id-token: write
  attestations: write
```

and generates provenance with:

```yaml
- name: Generate GitHub/Sigstore build provenance
  uses: actions/attest@v4
  with:
    subject-path: "dist/*"
```

For a downloaded release artifact, verify the GitHub attestation separately:

```bash
gh attestation verify finredops-0.6.1-py3-none-any.whl \
  --repo bilgekayali/finredops
```

Repeat verification for the source distribution or checksum manifest when those
artifacts are part of the trust decision.

For public repositories, GitHub artifact attestations use Sigstore-backed signing
and bind the subject digest to GitHub Actions provenance such as repository,
workflow, commit SHA, and triggering event. Consumers should verify the attestation
rather than treating its mere existence as a security guarantee.

## Tag and package-version binding

A tag-triggered release must use `vMAJOR.MINOR.PATCH`. Before building, the workflow
reads `[project].version` from `pyproject.toml` and fails if the tag version does not
match it. A tag therefore cannot silently publish a differently versioned wheel.

Manual `workflow_dispatch` runs build, smoke-test, checksum, and attest artifacts
but do not create a GitHub Release. Only a version-tag event invokes `gh release
create`.

## Clean-wheel smoke test

CI and the release workflow install the built wheel into a fresh virtual
environment and verify that the installed package can:

1. export all bundled synthetic inputs;
2. validate the synthetic engagement and plan;
3. run `demo-reviewed-report` without a repository-relative SARIF path;
4. validate the resulting draft report;
5. verify the generated release checksum manifest.

This catches package-data omissions that editable installs can hide.

## Security boundaries

Release provenance does **not**:

- authenticate qualified testers or report approvers;
- sign review decisions or report approvals;
- establish regulatory compliance or report issuance;
- replace independent verification of release artifacts;
- make a compromised consumer environment trustworthy.

Reviewer identity, engagement binding, review supersession/revocation, and
key-backed approval signatures remain separate roadmap items.
