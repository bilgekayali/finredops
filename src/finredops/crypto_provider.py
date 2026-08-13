"""Provider-neutral KMS/HSM cryptographic operation boundary.

FinRedOps never asks a provider to export a KEK or signing private key.  The
control plane supplies opaque institution-owned key references and receives only
wrapped data keys, signatures, or plaintext DEKs returned for an authorized
unwrap operation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol, runtime_checkable


class CryptoProviderError(RuntimeError):
    """Raised when a KMS/HSM operation is unavailable or returns invalid data."""


def validate_provider_context(context: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(context, Mapping) or not context:
        raise CryptoProviderError("Provider context must be a non-empty mapping.")
    normalized: dict[str, str] = {}
    for key, value in context.items():
        if (
            not isinstance(key, str)
            or not key
            or len(key) > 128
            or not isinstance(value, str)
            or not value
            or len(value) > 512
        ):
            raise CryptoProviderError(
                "Provider context keys and values must be bounded non-empty strings."
            )
        normalized[key] = value
    return normalized


@dataclass(frozen=True, slots=True)
class WrappedDataKey:
    ciphertext: bytes
    algorithm: str

    def __post_init__(self) -> None:
        if not isinstance(self.ciphertext, bytes) or not self.ciphertext:
            raise CryptoProviderError("Wrapped data key ciphertext is required.")
        if not isinstance(self.algorithm, str) or not self.algorithm.strip():
            raise CryptoProviderError("Wrapped data key algorithm is required.")


@dataclass(frozen=True, slots=True)
class ProviderSignature:
    signature: bytes
    algorithm: str

    def __post_init__(self) -> None:
        if not isinstance(self.signature, bytes) or not self.signature:
            raise CryptoProviderError("Provider signature bytes are required.")
        if not isinstance(self.algorithm, str) or not self.algorithm.strip():
            raise CryptoProviderError("Provider signature algorithm is required.")


@runtime_checkable
class KmsHsmProvider(Protocol):
    """Minimal provider contract needed by FinRedOps.

    Concrete implementations may use a cloud KMS, PKCS#11 HSM, external HSM
    gateway, or another institution-approved cryptographic service.  A provider
    implementation is responsible for authenticating to that service and
    enforcing the institution's authorization policy.
    """

    provider_name: str

    def wrap_data_key(
        self,
        key_ref: str,
        plaintext_key: bytes,
        *,
        context: Mapping[str, str],
    ) -> WrappedDataKey: ...

    def unwrap_data_key(
        self,
        key_ref: str,
        wrapped_key: WrappedDataKey,
        *,
        context: Mapping[str, str],
    ) -> bytes: ...

    def sign_digest(self, key_ref: str, digest: bytes) -> ProviderSignature: ...

    def verify_digest(
        self,
        key_ref: str,
        digest: bytes,
        signature: ProviderSignature,
    ) -> bool: ...
