# Isolated workload execution

FinRedOps v0.9.2 adds a provider boundary for separately operated, isolated
workers without turning the control plane into a shell, process launcher, target
discovery engine, or general-purpose network client. The built-in active
capability remains the existing `http.security_posture.validate` action: one
approved TLS `HEAD` request to one approved non-production target, with no
redirect following, response-body collection, crawling, exploit payloads, or
arbitrary commands.

The design is identity-centric. It is informed by NIST zero-trust workload
identity principles and by SPIFFE's separation between workload identity and
network location, but FinRedOps does **not** claim SPIFFE conformance and does
not implement the SPIFFE Workload API or SVID formats.

## Trust and execution flow

1. An institution security context contains an opaque, institution-owned
   `workload_identity` KMS/HSM key reference. The private key never enters a
   FinRedOps artifact.
2. A separately operated worker deployment produces a short-lived
   `WorkloadIdentityAttestation`. The artifact binds institution, worker and
   deployment identifiers, the runtime image digest, a deployment isolation
   evidence digest, and the exact network-policy digest. Its lifetime is at most
   one hour.
3. A one-time test-account grant binds only an account identifier and an opaque
   account-reference digest to one engagement, proposal, action and target. It
   contains no credential material and expires within one hour.
4. The execution egress rule binds the current bounded action to an exact target,
   port, path, peer CIDR set and one-request limit.
5. The current emergency-stop state is bound by institution, engagement and a
   monotonically supplied generation number.
6. FinRedOps creates a maximum-15-minute `WorkloadExecutionLease` only when the
   engagement is approved and in-window, the deterministic policy decision
   allows the exact proposal, the target is in non-production scope, the account
   grant matches the proposal, the egress policy matches the controlled action,
   and the emergency stop is clear.
7. The one-time grant is atomically consumed before the external worker is
   invoked. A failed worker call therefore does not make the grant reusable.
8. The external worker returns a typed execution envelope plus a signature made
   under the institution workload-identity key. Verification binds the returned
   execution to the worker identity, lease, one-time grant, egress rule,
   emergency-stop state and observed peer address.
9. FinRedOps checks emergency-stop state again after the call. A state change or
   stop activation causes the result to be rejected for promotion even if the
   external operation already occurred.

## Fail-closed properties

The v0.9.2 control-plane modules do not import socket/network clients or process
execution libraries. CI also rejects dynamic `exec`/`eval`-style execution in
this boundary. The external worker is an injected provider; the repository does
not silently gain a generic remote-execution surface.

A built-in execution lease cannot set any of these values to true:

- `production_allowed`;
- `autonomous_discovery_allowed`;
- `arbitrary_command_allowed`.

The request limit is exactly one. The workload identity must be valid at
execution time, and the lease cannot outlive the identity, test-account grant or
engagement window. Cross-institution, cross-engagement, stale-policy,
stale-emergency-stop, changed-network-policy, changed-proposal and replayed
test-account artifacts fail closed.

`SQLiteOneTimeGrantLedger` records one irreversible consumption row per
`(institution_id, grant_digest)` using an atomic transaction. It exposes no
update/delete workflow. This is an application-level replay boundary, not a
claim of physical WORM storage.

## Egress and isolation boundary

FinRedOps verifies that the signed worker result reports one observed peer
address within the approved CIDR set and that the workload identity is bound to
the exact egress-policy digest. This provides cryptographic traceability between
the approved policy and returned evidence.

It does **not** prove that a host firewall, Kubernetes NetworkPolicy, service
mesh, cloud security group, hypervisor, container runtime or kernel actually
enforced that policy. A production deployment must enforce the same policy in a
separately administered worker environment and provide trustworthy isolation
and network-policy evidence. The signed `isolation_evidence_digest` establishes
integrity of the referenced evidence; it does not independently prove the
sandbox or its configuration.

Likewise, FinRedOps does not provision credentials. The one-time grant contains
no password, token, cookie, private key or secret. A deployment-specific worker
may resolve an opaque account reference through an institution-controlled
credential mechanism, but that resolver and its access policy are outside this
repository's built-in control plane.

## Emergency stop semantics

The emergency-stop state is checked before invocation and again after the
external provider returns. If it is already active, no worker call is made. If
it changes during execution, the returned result is rejected for promotion.

This is a fail-closed control and evidence-integrity boundary, not a rollback
mechanism. FinRedOps cannot retroactively undo a request that a separately
operated worker already sent. Production worker deployments therefore need their
own independently tested kill/termination control and should make the same stop
state available to the worker before any network action.

## Signed worker receipts

A worker receipt signature binds:

- institution and worker identity;
- execution identifier;
- complete execution-envelope digest;
- workload-identity digest;
- execution-lease digest;
- institution workload key id/provider/reference digest;
- signing time and signing algorithm.

The corresponding execution envelope binds the `ExecutionReceipt`, account grant,
egress rule, emergency-stop state and observed peer address. A changed envelope,
changed peer, changed lease or changed identity cannot reuse the original
signature.

## Explicit non-claims

v0.9.2 does not claim that:

- FinRedOps creates or independently attests a secure VM/container/sandbox;
- a signed isolation-evidence digest proves the underlying isolation is correct;
- FinRedOps implements or conforms to SPIFFE/SPIRE;
- an application-level egress check replaces kernel/SDN/cloud network controls;
- the one-time grant provisions or contains test-account credentials;
- emergency stop can undo a request already sent by an external worker;
- active validation is permitted against production systems;
- autonomous discovery, arbitrary commands, exploit generation or credential
  attacks are enabled;
- a signed worker result establishes regulatory compliance, legal applicability,
  certification or final report approval.

Deployment owners remain responsible for the worker runtime, isolation control,
network enforcement, workload-key IAM/policy, credential resolver, monitoring,
emergency termination and independent security review.
