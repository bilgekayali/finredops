"""Fail-closed execution lease for an externally isolated worker.

This module deliberately has no network, shell, subprocess, credential-fetching,
or target-discovery capability. It validates a closed execution request and
verifies the signed result returned by a separately operated worker provider.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from .crypto_provider import KmsHsmProvider
from .institution import InstitutionSecurityContext
from .models import (
    ActionProposal,
    Engagement,
    EngagementStatus,
    Environment,
    ExecutionReceipt,
    PolicyDecision,
    canonical_target,
    ensure_aware,
    sha256_digest,
    to_primitive,
)
from .validation import CONTROLLED_HTTP_ACTION, validate_controlled_parameters
from .workload_identity import (
    WorkerReceiptSignature,
    WorkloadIdentityAttestation,
    verify_worker_receipt_signature,
    verify_workload_identity_attestation,
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,199}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/\-]*$")
_SCHEMA_GRANT = "finredops.one-time-test-account-grant.v1"
_SCHEMA_STOP = "finredops.emergency-stop-state.v1"
_SCHEMA_LEASE = "finredops.workload-execution-lease.v1"
_SCHEMA_ENVELOPE = "finredops.worker-execution-envelope.v1"


class WorkloadExecutionError(ValueError):
    """Raised when the isolated-worker boundary rejects an execution."""


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise WorkloadExecutionError(f"{name} must be a bounded identifier.")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise WorkloadExecutionError(f"{name} must be a lowercase SHA-256 digest.")
    return value


@dataclass(frozen=True, slots=True)
class EgressRule:
    action_id: str
    target: str
    port: int
    path: str
    peer_cidrs: tuple[str, ...]
    request_limit: int = 1

    def __post_init__(self) -> None:
        if self.action_id != CONTROLLED_HTTP_ACTION:
            raise WorkloadExecutionError("Built-in workload egress accepts only the bounded HTTP action.")
        object.__setattr__(self, "target", canonical_target(self.target))
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise WorkloadExecutionError("Egress port must be between 1 and 65535.")
        if not isinstance(self.path, str) or not _SAFE_PATH.fullmatch(self.path) or len(self.path) > 1024:
            raise WorkloadExecutionError("Egress path must be one bounded absolute HTTP path.")
        if self.request_limit != 1:
            raise WorkloadExecutionError("The built-in isolated workload permits exactly one request.")
        if not self.peer_cidrs or len(self.peer_cidrs) > 32:
            raise WorkloadExecutionError("Egress policy requires one to 32 peer network entries.")
        normalized: list[str] = []
        for value in self.peer_cidrs:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise WorkloadExecutionError("Egress peer network is invalid.") from exc
            if network.is_multicast or network.is_unspecified:
                raise WorkloadExecutionError("Unsafe egress peer network class is not permitted.")
            normalized.append(str(network))
        object.__setattr__(self, "peer_cidrs", tuple(sorted(set(normalized))))

    def digest(self) -> str:
        return sha256_digest(self)

    def allows_peer(self, peer_address: str) -> bool:
        try:
            peer = ipaddress.ip_address(peer_address)
        except ValueError:
            return False
        return any(peer in ipaddress.ip_network(value, strict=False) for value in self.peer_cidrs)


@dataclass(frozen=True, slots=True)
class EmergencyStopState:
    institution_id: str
    engagement_id: str
    generation: int
    stopped: bool
    reason: str
    changed_at: datetime
    schema_version: str = _SCHEMA_STOP

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA_STOP:
            raise WorkloadExecutionError("Unsupported emergency-stop schema.")
        _identifier(self.institution_id, "institution_id")
        _identifier(self.engagement_id, "engagement_id")
        if isinstance(self.generation, bool) or not isinstance(self.generation, int) or self.generation < 1:
            raise WorkloadExecutionError("Emergency-stop generation must be a positive integer.")
        if not isinstance(self.stopped, bool):
            raise WorkloadExecutionError("Emergency-stop state must be boolean.")
        if not isinstance(self.reason, str) or not self.reason.strip() or len(self.reason) > 512:
            raise WorkloadExecutionError("Emergency-stop reason must be bounded text.")
        object.__setattr__(self, "changed_at", ensure_aware(self.changed_at))
        object.__setattr__(self, "reason", self.reason.strip())

    def digest(self) -> str:
        return sha256_digest(self)

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self), "state_digest": self.digest()}


@dataclass(frozen=True, slots=True)
class OneTimeTestAccountGrant:
    grant_id: str
    institution_id: str
    engagement_id: str
    account_id: str
    account_reference_digest: str
    proposal_digest: str
    action_id: str
    target: str
    issued_at: datetime
    expires_at: datetime
    max_uses: int = 1
    credential_material_embedded: bool = False
    schema_version: str = _SCHEMA_GRANT

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA_GRANT:
            raise WorkloadExecutionError("Unsupported test-account grant schema.")
        for value, name in (
            (self.grant_id, "grant_id"),
            (self.institution_id, "institution_id"),
            (self.engagement_id, "engagement_id"),
            (self.account_id, "account_id"),
        ):
            _identifier(value, name)
        _digest(self.account_reference_digest, "account_reference_digest")
        _digest(self.proposal_digest, "proposal_digest")
        if self.action_id != CONTROLLED_HTTP_ACTION:
            raise WorkloadExecutionError("Test-account grant may authorize only the bounded HTTP action.")
        object.__setattr__(self, "target", canonical_target(self.target))
        issued = ensure_aware(self.issued_at)
        expires = ensure_aware(self.expires_at)
        if expires <= issued or (expires - issued).total_seconds() > 3_600:
            raise WorkloadExecutionError("Test-account grant lifetime must be positive and at most one hour.")
        if self.max_uses != 1:
            raise WorkloadExecutionError("Test-account grants are strictly one-time.")
        if self.credential_material_embedded is not False:
            raise WorkloadExecutionError("Credential material cannot be embedded in a grant artifact.")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)

    def digest(self) -> str:
        return sha256_digest(self)

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self), "grant_digest": self.digest()}


@dataclass(frozen=True, slots=True)
class WorkloadExecutionLease:
    lease_id: str
    institution_id: str
    engagement_id: str
    proposal_id: str
    proposal_digest: str
    workload_identity_digest: str
    test_account_grant_digest: str
    egress_rule_digest: str
    emergency_stop_generation: int
    issued_at: datetime
    expires_at: datetime
    request_limit: int = 1
    production_allowed: bool = False
    autonomous_discovery_allowed: bool = False
    arbitrary_command_allowed: bool = False
    schema_version: str = _SCHEMA_LEASE

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA_LEASE:
            raise WorkloadExecutionError("Unsupported workload execution lease schema.")
        for value, name in (
            (self.lease_id, "lease_id"),
            (self.institution_id, "institution_id"),
            (self.engagement_id, "engagement_id"),
            (self.proposal_id, "proposal_id"),
        ):
            _identifier(value, name)
        for value, name in (
            (self.proposal_digest, "proposal_digest"),
            (self.workload_identity_digest, "workload_identity_digest"),
            (self.test_account_grant_digest, "test_account_grant_digest"),
            (self.egress_rule_digest, "egress_rule_digest"),
        ):
            _digest(value, name)
        if isinstance(self.emergency_stop_generation, bool) or not isinstance(self.emergency_stop_generation, int) or self.emergency_stop_generation < 1:
            raise WorkloadExecutionError("Lease emergency-stop generation must be positive.")
        issued = ensure_aware(self.issued_at)
        expires = ensure_aware(self.expires_at)
        if expires <= issued or (expires - issued).total_seconds() > 900:
            raise WorkloadExecutionError("Execution lease lifetime must be positive and at most 15 minutes.")
        if self.request_limit != 1:
            raise WorkloadExecutionError("Execution lease must remain single-request.")
        if self.production_allowed or self.autonomous_discovery_allowed or self.arbitrary_command_allowed:
            raise WorkloadExecutionError("Execution lease cannot expand the built-in active boundary.")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "expires_at", expires)

    def digest(self) -> str:
        return sha256_digest(self)

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self), "lease_digest": self.digest()}


@dataclass(frozen=True, slots=True)
class WorkerExecutionEnvelope:
    institution_id: str
    worker_id: str
    deployment_id: str
    execution_id: str
    workload_identity_digest: str
    lease_digest: str
    test_account_grant_digest: str
    egress_rule_digest: str
    emergency_stop_state_digest: str
    observed_peer_address: str
    request_count: int
    account_grant_consumed: bool
    receipt: ExecutionReceipt
    schema_version: str = _SCHEMA_ENVELOPE

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA_ENVELOPE:
            raise WorkloadExecutionError("Unsupported worker execution envelope schema.")
        for value, name in (
            (self.institution_id, "institution_id"),
            (self.worker_id, "worker_id"),
            (self.deployment_id, "deployment_id"),
            (self.execution_id, "execution_id"),
        ):
            _identifier(value, name)
        for value, name in (
            (self.workload_identity_digest, "workload_identity_digest"),
            (self.lease_digest, "lease_digest"),
            (self.test_account_grant_digest, "test_account_grant_digest"),
            (self.egress_rule_digest, "egress_rule_digest"),
            (self.emergency_stop_state_digest, "emergency_stop_state_digest"),
        ):
            _digest(value, name)
        try:
            ipaddress.ip_address(self.observed_peer_address)
        except ValueError as exc:
            raise WorkloadExecutionError("Worker must report the exact observed peer address.") from exc
        if self.request_count != 1 or self.account_grant_consumed is not True:
            raise WorkloadExecutionError("Worker envelope must prove one request and consumed one-time grant.")
        if self.receipt.execution_id != self.execution_id:
            raise WorkloadExecutionError("Worker envelope execution id does not match receipt.")

    def core(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "institution_id": self.institution_id,
            "worker_id": self.worker_id,
            "deployment_id": self.deployment_id,
            "execution_id": self.execution_id,
            "workload_identity_digest": self.workload_identity_digest,
            "lease_digest": self.lease_digest,
            "test_account_grant_digest": self.test_account_grant_digest,
            "egress_rule_digest": self.egress_rule_digest,
            "emergency_stop_state_digest": self.emergency_stop_state_digest,
            "observed_peer_address": self.observed_peer_address,
            "request_count": self.request_count,
            "account_grant_consumed": self.account_grant_consumed,
            "receipt": to_primitive(self.receipt),
        }

    def digest(self) -> str:
        return sha256_digest(self.core())

    def as_dict(self) -> dict[str, Any]:
        return {**self.core(), "envelope_digest": self.digest()}


@dataclass(frozen=True, slots=True)
class WorkerExecutionRequest:
    proposal: ActionProposal
    engagement: Engagement
    lease: WorkloadExecutionLease
    identity: WorkloadIdentityAttestation
    test_account: OneTimeTestAccountGrant
    egress_rule: EgressRule
    emergency_stop: EmergencyStopState


@runtime_checkable
class OneTimeGrantLedger(Protocol):
    def consume_once(
        self,
        *,
        institution_id: str,
        grant_digest: str,
        lease_id: str,
        consumed_at: datetime,
    ) -> bool: ...


@runtime_checkable
class IsolatedWorkerProvider(Protocol):
    worker_id: str
    deployment_id: str
    isolation_profile: str

    def execute(
        self,
        request: WorkerExecutionRequest,
    ) -> tuple[WorkerExecutionEnvelope, WorkerReceiptSignature]: ...


def network_policy_digest(rule: EgressRule) -> str:
    return sha256_digest({"schema_version": "finredops.worker-network-policy.v1", "egress": to_primitive(rule)})


def build_execution_lease(
    *,
    institution_context: InstitutionSecurityContext,
    proposal: ActionProposal,
    engagement: Engagement,
    policy_decision: PolicyDecision,
    identity: WorkloadIdentityAttestation,
    test_account: OneTimeTestAccountGrant,
    egress_rule: EgressRule,
    emergency_stop: EmergencyStopState,
    issued_at: datetime,
    expires_at: datetime,
) -> WorkloadExecutionLease:
    issued = ensure_aware(issued_at)
    expires = ensure_aware(expires_at)
    _validate_execution_inputs(
        institution_context=institution_context,
        proposal=proposal,
        engagement=engagement,
        policy_decision=policy_decision,
        identity=identity,
        test_account=test_account,
        egress_rule=egress_rule,
        emergency_stop=emergency_stop,
        as_of=issued,
    )
    if expires > min(identity.expires_at, test_account.expires_at, engagement.window_end):
        raise WorkloadExecutionError("Execution lease cannot outlive identity, account grant, or engagement window.")
    seed = {
        "institution_id": institution_context.institution_id,
        "proposal_digest": proposal.digest(),
        "identity_digest": identity.digest(),
        "grant_digest": test_account.digest(),
        "egress_digest": egress_rule.digest(),
        "stop_generation": emergency_stop.generation,
        "issued_at": issued,
        "expires_at": expires,
    }
    return WorkloadExecutionLease(
        lease_id="LEASE-" + sha256_digest(seed)[:24].upper(),
        institution_id=institution_context.institution_id,
        engagement_id=engagement.engagement_id,
        proposal_id=proposal.proposal_id,
        proposal_digest=proposal.digest(),
        workload_identity_digest=identity.digest(),
        test_account_grant_digest=test_account.digest(),
        egress_rule_digest=egress_rule.digest(),
        emergency_stop_generation=emergency_stop.generation,
        issued_at=issued,
        expires_at=expires,
    )


def verify_execution_lease(
    lease: WorkloadExecutionLease,
    *,
    institution_context: InstitutionSecurityContext,
    proposal: ActionProposal,
    engagement: Engagement,
    policy_decision: PolicyDecision,
    identity: WorkloadIdentityAttestation,
    test_account: OneTimeTestAccountGrant,
    egress_rule: EgressRule,
    emergency_stop: EmergencyStopState,
    as_of: datetime,
) -> bool:
    now = ensure_aware(as_of)
    try:
        _validate_execution_inputs(
            institution_context=institution_context,
            proposal=proposal,
            engagement=engagement,
            policy_decision=policy_decision,
            identity=identity,
            test_account=test_account,
            egress_rule=egress_rule,
            emergency_stop=emergency_stop,
            as_of=now,
        )
    except (ValueError, PermissionError):
        return False
    return (
        lease.institution_id == institution_context.institution_id
        and lease.engagement_id == engagement.engagement_id
        and lease.proposal_id == proposal.proposal_id
        and lease.proposal_digest == proposal.digest()
        and lease.workload_identity_digest == identity.digest()
        and lease.test_account_grant_digest == test_account.digest()
        and lease.egress_rule_digest == egress_rule.digest()
        and lease.emergency_stop_generation == emergency_stop.generation
        and lease.issued_at <= now < lease.expires_at
        and lease.expires_at <= min(identity.expires_at, test_account.expires_at, engagement.window_end)
    )


def execute_with_isolated_worker(
    *,
    institution_context: InstitutionSecurityContext,
    crypto_provider: KmsHsmProvider,
    worker_provider: IsolatedWorkerProvider,
    grant_ledger: OneTimeGrantLedger,
    proposal: ActionProposal,
    engagement: Engagement,
    policy_decision: PolicyDecision,
    identity: WorkloadIdentityAttestation,
    test_account: OneTimeTestAccountGrant,
    egress_rule: EgressRule,
    lease: WorkloadExecutionLease,
    emergency_stop_supplier: Callable[[], EmergencyStopState],
    now: datetime,
) -> tuple[WorkerExecutionEnvelope, WorkerReceiptSignature]:
    current = ensure_aware(now)
    stop_before = emergency_stop_supplier()
    if not verify_workload_identity_attestation(
        identity,
        institution_context=institution_context,
        provider=crypto_provider,
        as_of=current,
    ):
        raise WorkloadExecutionError("Workload identity verification failed.")
    if (
        worker_provider.worker_id != identity.worker_id
        or worker_provider.deployment_id != identity.deployment_id
        or worker_provider.isolation_profile != identity.isolation_profile
    ):
        raise WorkloadExecutionError("Worker provider does not match the signed workload identity.")
    if not verify_execution_lease(
        lease,
        institution_context=institution_context,
        proposal=proposal,
        engagement=engagement,
        policy_decision=policy_decision,
        identity=identity,
        test_account=test_account,
        egress_rule=egress_rule,
        emergency_stop=stop_before,
        as_of=current,
    ):
        raise WorkloadExecutionError("Execution lease verification failed.")
    if not grant_ledger.consume_once(
        institution_id=institution_context.institution_id,
        grant_digest=test_account.digest(),
        lease_id=lease.lease_id,
        consumed_at=current,
    ):
        raise WorkloadExecutionError("One-time test account grant was already consumed.")

    envelope, signature = worker_provider.execute(
        WorkerExecutionRequest(
            proposal=proposal,
            engagement=engagement,
            lease=lease,
            identity=identity,
            test_account=test_account,
            egress_rule=egress_rule,
            emergency_stop=stop_before,
        )
    )
    stop_after = emergency_stop_supplier()
    if stop_after.digest() != stop_before.digest() or stop_after.stopped:
        raise WorkloadExecutionError("Emergency-stop state changed during execution; result is not trusted for promotion.")
    if not verify_signed_worker_result(
        envelope,
        signature,
        institution_context=institution_context,
        crypto_provider=crypto_provider,
        identity=identity,
        test_account=test_account,
        egress_rule=egress_rule,
        lease=lease,
        emergency_stop=stop_before,
    ):
        raise WorkloadExecutionError("Signed worker result failed verification.")
    return envelope, signature


def verify_signed_worker_result(
    envelope: WorkerExecutionEnvelope,
    signature: WorkerReceiptSignature,
    *,
    institution_context: InstitutionSecurityContext,
    crypto_provider: KmsHsmProvider,
    identity: WorkloadIdentityAttestation,
    test_account: OneTimeTestAccountGrant,
    egress_rule: EgressRule,
    lease: WorkloadExecutionLease,
    emergency_stop: EmergencyStopState,
) -> bool:
    if (
        envelope.institution_id != institution_context.institution_id
        or envelope.worker_id != identity.worker_id
        or envelope.deployment_id != identity.deployment_id
        or envelope.workload_identity_digest != identity.digest()
        or envelope.lease_digest != lease.digest()
        or envelope.test_account_grant_digest != test_account.digest()
        or envelope.egress_rule_digest != egress_rule.digest()
        or envelope.emergency_stop_state_digest != emergency_stop.digest()
        or not egress_rule.allows_peer(envelope.observed_peer_address)
        or envelope.receipt.proposal_id != lease.proposal_id
        or envelope.receipt.proposal_digest != lease.proposal_digest
        or envelope.receipt.started_at < lease.issued_at
        or envelope.receipt.finished_at > lease.expires_at
    ):
        return False
    return verify_worker_receipt_signature(
        signature,
        institution_context=institution_context,
        provider=crypto_provider,
        identity=identity,
        execution_id=envelope.execution_id,
        execution_envelope_digest=envelope.digest(),
        lease_digest=lease.digest(),
    )


def _validate_execution_inputs(
    *,
    institution_context: InstitutionSecurityContext,
    proposal: ActionProposal,
    engagement: Engagement,
    policy_decision: PolicyDecision,
    identity: WorkloadIdentityAttestation,
    test_account: OneTimeTestAccountGrant,
    egress_rule: EgressRule,
    emergency_stop: EmergencyStopState,
    as_of: datetime,
) -> None:
    now = ensure_aware(as_of)
    if engagement.status != EngagementStatus.APPROVED:
        raise PermissionError("Isolated execution requires an approved engagement.")
    if not engagement.window_start <= now < engagement.window_end:
        raise PermissionError("Isolated execution is outside the engagement window.")
    if proposal.engagement_id != engagement.engagement_id:
        raise PermissionError("Proposal is bound to another engagement.")
    if proposal.action_id != CONTROLLED_HTTP_ACTION or proposal.action_id not in engagement.allowed_actions:
        raise PermissionError("Only the approved bounded HTTP action can use the built-in worker boundary.")
    if not policy_decision.allowed or policy_decision.proposal_digest != proposal.digest():
        raise PermissionError("A matching allow policy decision is required.")
    if identity.institution_id != institution_context.institution_id:
        raise PermissionError("Workload identity is bound to another institution.")
    if network_policy_digest(egress_rule) != identity.network_policy_digest:
        raise PermissionError("Signed workload identity is bound to another egress network policy.")
    if test_account.institution_id != institution_context.institution_id:
        raise PermissionError("Test-account grant is bound to another institution.")
    if test_account.engagement_id != engagement.engagement_id:
        raise PermissionError("Test-account grant is bound to another engagement.")
    if test_account.proposal_digest != proposal.digest():
        raise PermissionError("Test-account grant is bound to another proposal.")
    if test_account.action_id != proposal.action_id or test_account.target != proposal.target:
        raise PermissionError("Test-account grant action/target does not match proposal.")
    if not test_account.issued_at <= now < test_account.expires_at:
        raise PermissionError("Test-account grant is not currently valid.")
    if emergency_stop.institution_id != institution_context.institution_id or emergency_stop.engagement_id != engagement.engagement_id:
        raise PermissionError("Emergency-stop state is bound to another institution or engagement.")
    if emergency_stop.stopped:
        raise PermissionError("Emergency stop is active.")
    matches = tuple(asset for asset in engagement.assets if asset.contains(proposal.target))
    if not matches or any(asset.contains(proposal.target) for asset in engagement.excluded_assets):
        raise PermissionError("Proposal target is not in exact approved scope.")
    if any(asset.environment == Environment.PRODUCTION for asset in matches):
        raise PermissionError("Built-in isolated workload execution refuses production targets.")
    port, path, _timeout, _change = validate_controlled_parameters(proposal.parameters)
    if (
        egress_rule.action_id != proposal.action_id
        or egress_rule.target != proposal.target
        or egress_rule.port != port
        or egress_rule.path != path
    ):
        raise PermissionError("Egress rule does not exactly match the approved controlled action.")
