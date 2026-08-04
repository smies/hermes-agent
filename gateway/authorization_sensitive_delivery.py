"""Parent-process bridge from durable authorization to sensitive delivery.

This module deliberately contains no workflow engine or persistence.  The
gateway-owned :class:`AuthorizationTaskStore` remains the sole state machine
and one-shot send authority.  The bridge only translates one already-claimed,
typed work item into an in-memory grant after the store's exact send-start CAS,
then translates one exact live receipt into the existing terminal transition.
"""

from __future__ import annotations

import secrets
import threading
import time
import weakref

from gateway.authorization_contracts import (
    AuthorizationTask,
    AuthorizationTaskWorkItem,
    ClaimIdentity,
    DeliveryAcceptanceEvidence,
    MutationResult,
    PdpDecisionEvidence,
    TrustedAuthorizationBinding,
)
from gateway.authorization_tasks import AuthorizationTaskStore
from gateway.config import Platform
from gateway.sensitive_delivery import (
    SensitiveDeliveryAcceptanceStatus,
    SensitiveDeliveryAccountObservation,
    SensitiveDeliveryAttempt,
    SensitiveDeliveryAuthorizationProvenance,
    SensitiveDeliveryDestination,
    SensitiveDeliveryErrorCode,
    SensitiveDeliveryHostAuthority,
    SensitiveDeliveryOutcome,
    SensitiveDeliveryReceipt,
    SensitiveDeliverySendGrant,
    _NoCopyOrPickle,
)


class AuthorizationSensitiveDeliveryBridge(_NoCopyOrPickle):
    """Exact parent-owned adapter for one accepted authorization claim."""

    __slots__ = (
        "_store", "binding", "claim", "task", "authority", "provenance",
        "destination", "binding_digest", "request_key_version",
        "_wall_clock_us", "_issued",
        "_lock", "_send_transition_attempted", "_finish_attempted",
        "_prepared_observation", "_private_read_authorized",
        "_send_start_conflict", "_consumed_attempt",
        "__weakref__",
    )

    def __init__(
        self,
        *,
        store: AuthorizationTaskStore,
        binding: TrustedAuthorizationBinding,
        claim: ClaimIdentity,
        host_authority: SensitiveDeliveryHostAuthority,
        wall_clock_us=None,
    ) -> None:
        if type(store) is not AuthorizationTaskStore:
            raise TypeError("bridge requires the exact authorization task store")
        if type(binding) is not TrustedAuthorizationBinding:
            raise TypeError("bridge requires an exact trusted authorization binding")
        if type(claim) is not ClaimIdentity:
            raise TypeError("bridge requires an exact accepted claim identity")
        if type(host_authority) is not SensitiveDeliveryHostAuthority:
            raise TypeError("bridge requires the exact sensitive host authority")
        clock = wall_clock_us or (lambda: time.time_ns() // 1000)
        current_us = clock()
        if type(current_us) is not int or current_us <= 0:
            raise ValueError("bridge wall clock must return positive integer microseconds")
        work_item = store.load_task_work_item(binding.task_id, now_us=current_us)
        if (
            type(work_item) is not AuthorizationTaskWorkItem
            or work_item.binding != binding
        ):
            raise ValueError("sensitive delivery requires the exact task work item")
        task = work_item.task
        if type(task) is not AuthorizationTask or task.status != "claimed":
            raise ValueError("sensitive delivery requires an already-claimed task")
        if task.claim_generation != claim.generation:
            raise ValueError("accepted claim generation does not match the task")
        try:
            platform = Platform(binding.delivery_platform)
        except ValueError as exc:
            raise ValueError("delivery platform is not a supported exact platform") from exc
        binding_digest = work_item.binding_digest
        provenance = host_authority._authorize_verified(
            correlation_id=binding.correlation_id,
            authorization_task_id=binding.task_id,
            operation_id=binding.operation,
            resource_type=binding.resource_type,
            resource_id=binding.resource_id,
            binding_digest=binding_digest,
            request_digest=task.request_digest,
            request_key_version=work_item.key_version,
            policy_namespace=binding.policy_identity,
            policy_version=binding.policy_version,
            policy_hash=binding.policy_hash,
            decision_model_id=binding.model_identity,
            worker_profile=claim.owner_profile,
            worker_agent=claim.owner_agent,
            worker_account=claim.owner_account,
            claim_nonce=claim.nonce,
            claim_generation=claim.generation,
        )
        destination = SensitiveDeliveryDestination(
            authorization_task_id=binding.task_id,
            operation_id=binding.operation,
            profile=binding.delivery_profile,
            platform=platform,
            account_binding_token=binding.delivery_account_binding,
            chat_id=binding.delivery_chat,
            thread_id=binding.delivery_thread or None,
        )
        self._store = store
        self.binding = binding
        self.claim = claim
        self.task = task
        self.authority = host_authority
        self.provenance = provenance
        self.destination = destination
        self.binding_digest = binding_digest
        self.request_key_version = work_item.key_version
        self._wall_clock_us = clock
        self._issued = {}
        self._lock = threading.Lock()
        self._send_transition_attempted = False
        self._finish_attempted = False
        self._prepared_observation = None
        self._private_read_authorized = False
        self._send_start_conflict = False
        self._consumed_attempt = None

    def __repr__(self) -> str:
        return "<AuthorizationSensitiveDeliveryBridge redacted>"

    __str__ = __repr__

    def now_us(self) -> int:
        value = self._wall_clock_us()
        if type(value) is not int or value <= 0:
            raise ValueError("bridge wall clock must return positive integer microseconds")
        return value

    def record_send_started(
        self,
        observation: SensitiveDeliveryAccountObservation,
        *,
        now_us: int,
    ) -> SensitiveDeliverySendGrant | None:
        """Perform the sole durable send-start transition and mint on success.

        An exception, an unapplied result, or an idempotent already-started
        result is deliberately indistinguishable to the router: none receives
        send authority.
        """
        if type(observation) is not SensitiveDeliveryAccountObservation:
            return None
        with self._lock:
            if (
                self._send_transition_attempted
                or self._finish_attempted
                or observation is not self._prepared_observation
                or not self._private_read_authorized
            ):
                return None
            self._send_transition_attempted = True
        try:
            result = self._store.record_send_started(
                self.binding.task_id,
                self.binding,
                self.claim,
                now_us=now_us,
            )
        except BaseException:
            return None
        if type(result) is not MutationResult or not result.applied or result.idempotent:
            with self._lock:
                self._send_start_conflict = True
            return None
        if (
            type(result.task) is not AuthorizationTask
            or result.task.status != "claimed"
            or result.task.send_started_at_us != now_us
            or result.task.request_digest != self.task.request_digest
            or result.task.claim_generation != self.claim.generation
        ):
            return None
        grant = object.__new__(SensitiveDeliverySendGrant)
        values = {
            "grant_id": secrets.token_hex(32),
            "attempt_id": "delivery-" + secrets.token_hex(16),
            "authorization_task_id": self.binding.task_id,
            "correlation_id": self.binding.correlation_id,
            "operation_id": self.binding.operation,
            "resource_type": self.binding.resource_type,
            "resource_id": self.binding.resource_id,
            "binding_digest": self.binding_digest,
            "request_digest": self.task.request_digest,
            "request_key_version": self.request_key_version,
            "worker_profile": self.claim.owner_profile,
            "worker_agent": self.claim.owner_agent,
            "worker_account": self.claim.owner_account,
            "claim_nonce": self.claim.nonce,
            "claim_generation": self.claim.generation,
            "send_started_us": now_us,
            "observation_id": observation.observation_id,
        }
        for name, value in values.items():
            object.__setattr__(grant, name, value)
        grant_key = id(grant)

        def forget(dead_ref, *, bridge_ref=weakref.ref(self), key=grant_key):
            bridge = bridge_ref()
            if bridge is not None:
                with bridge._lock:
                    current = bridge._issued.get(key)
                    if current is not None and current[0] is dead_ref:
                        bridge._issued.pop(key, None)

        issued_ref = weakref.ref(grant, forget)
        with self._lock:
            self._issued[grant_key] = (issued_ref, observation, False)
        return grant

    def accept_prepared_observation(
        self, observation: SensitiveDeliveryAccountObservation
    ) -> bool:
        """Fence the exact observation that preceded the private read."""
        if type(observation) is not SensitiveDeliveryAccountObservation:
            return False
        with self._lock:
            if self._prepared_observation is not None or self._finish_attempted:
                return False
            self._prepared_observation = observation
            return True

    def authorize_private_read(
        self,
        evidence: PdpDecisionEvidence,
        *,
        now_us: int,
    ) -> bool:
        """Consume the accepted second PDP check after live preparation."""
        if type(evidence) is not PdpDecisionEvidence:
            return False
        with self._lock:
            if (
                self._prepared_observation is None
                or self._private_read_authorized
                or self._send_transition_attempted
                or self._finish_attempted
            ):
                return False
        try:
            result = self._store.authorize_private_read(
                self.binding.task_id,
                self.binding,
                self.claim,
                evidence,
                now_us=now_us,
            )
        except BaseException:
            return False
        if type(result) is not MutationResult or not result.applied:
            return False
        with self._lock:
            if self._send_transition_attempted or self._finish_attempted:
                return False
            self._private_read_authorized = True
        return True

    def consume_send_grant(
        self,
        grant: SensitiveDeliverySendGrant,
        observation: SensitiveDeliveryAccountObservation,
        attempt: SensitiveDeliveryAttempt,
    ) -> bool:
        """Consume one exact live grant immediately before transport spawn."""
        if (
            type(grant) is not SensitiveDeliverySendGrant
            or type(observation) is not SensitiveDeliveryAccountObservation
            or type(attempt) is not SensitiveDeliveryAttempt
        ):
            return False
        with self._lock:
            issued = self._issued.get(id(grant))
            if (
                issued is None
                or issued[0]() is not grant
                or issued[1] is not observation
                or issued[2]
            ):
                return False
            expected = (
                grant.attempt_id, grant.authorization_task_id, grant.correlation_id,
                grant.operation_id, grant.resource_type, grant.resource_id,
                grant.binding_digest, grant.request_digest, grant.request_key_version,
                grant.worker_profile, grant.worker_agent, grant.worker_account,
                grant.claim_nonce, grant.claim_generation, grant.send_started_us,
                grant.observation_id,
            )
            actual = (
                attempt.attempt_id, attempt.authorization_task_id,
                attempt.correlation_id, attempt.operation_id, attempt.resource_type,
                attempt.resource_id, attempt.binding_digest, attempt.request_digest,
                attempt.request_key_version, attempt.worker_profile,
                attempt.worker_agent, attempt.worker_account, attempt.claim_nonce,
                attempt.claim_generation, attempt.send_started_us,
                attempt.account_observation_id,
            )
            if actual != expected:
                return False
            self._issued[id(grant)] = (issued[0], issued[1], True)
            self._consumed_attempt = attempt
            return True

    def finish_receipt(self, receipt: SensitiveDeliveryReceipt, *, now_us: int) -> bool:
        """Verify and durably consume the claim exactly once."""
        with self._lock:
            if self._finish_attempted:
                return False
            self._finish_attempted = True
            # Another exact worker already owns the durable send-start.  This
            # bridge has no authority to send or to close that worker's claim.
            if self._send_start_conflict:
                return True
        accepted = False
        evidence = None
        receipt_code = "internal_failure"
        if (
            type(receipt) is SensitiveDeliveryReceipt
            and self.authority.verify_receipt(receipt)
            and receipt.provenance is self.provenance
            and receipt.destination is self.destination
        ):
            if (
                receipt.outcome is SensitiveDeliveryOutcome.ACCEPTED
                and receipt.acceptance_status
                is SensitiveDeliveryAcceptanceStatus.ACCEPTED
                and type(receipt.attempt) is SensitiveDeliveryAttempt
                and receipt.attempt is self._consumed_attempt
                and receipt.provider_message_id is not None
                and receipt.acceptance_observed_us is not None
            ):
                attempt = receipt.attempt
                evidence = DeliveryAcceptanceEvidence(
                    task_id=self.binding.task_id,
                    correlation_id=self.binding.correlation_id,
                    operation=self.binding.operation,
                    request_digest=self.task.request_digest,
                    request_key_version=self.request_key_version,
                    policy_version=self.binding.policy_version,
                    policy_hash=self.binding.policy_hash,
                    worker_profile=self.claim.owner_profile,
                    worker_agent=self.claim.owner_agent,
                    worker_account=self.claim.owner_account,
                    claim_nonce=self.claim.nonce,
                    claim_generation=self.claim.generation,
                    delivery_profile=self.binding.delivery_profile,
                    delivery_platform=self.binding.delivery_platform,
                    delivery_account=self.binding.delivery_account,
                    delivery_chat=self.binding.delivery_chat,
                    delivery_thread=self.binding.delivery_thread,
                    transport_implementation=attempt.transport_implementation_id,
                    runtime_identity=attempt.runtime_instance_token,
                    account_binding=attempt.account_binding_token,
                    connection_epoch=attempt.connection_epoch,
                    provider_message_id=receipt.provider_message_id,
                    status="provider_accepted",
                    accepted_at_us=receipt.acceptance_observed_us,
                )
                accepted = True
                receipt_code = "provider_accepted"
            elif receipt.error_code is SensitiveDeliveryErrorCode.TRANSPORT_REJECTED:
                receipt_code = "provider_rejected"
            elif receipt.error_code is SensitiveDeliveryErrorCode.TIMEOUT:
                receipt_code = "provider_timeout"
            elif receipt.error_code is SensitiveDeliveryErrorCode.INPUT_LIMIT:
                receipt_code = "render_failed"
        try:
            result = self._store.finish(
                self.binding.task_id,
                self.binding,
                self.claim,
                now_us=now_us,
                outcome="consumed" if accepted else "failed_consumed",
                receipt_code=receipt_code,
                evidence=evidence,
            )
        except BaseException:
            return False
        return (
            type(result) is MutationResult
            and result.applied
            and not result.idempotent
            and result.task is not None
            and result.task.status == ("consumed" if accepted else "failed_consumed")
        )


__all__ = ["AuthorizationSensitiveDeliveryBridge"]
