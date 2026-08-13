"""AWS KMS implementation of the provider-neutral FinRedOps crypto boundary.

The adapter uses customer-managed KMS key references supplied by the institution.
It never requests export of a KMS key.  Only a 32-byte per-object DEK is sent to
KMS for wrapping/unwrapping, and only a SHA-256 digest is sent for signing.
"""

from __future__ import annotations

from typing import Any, Mapping

from .crypto_provider import (
    CryptoProviderError,
    ProviderSignature,
    WrappedDataKey,
    validate_provider_context,
)

_WRAP_ALGORITHM = "AWS_KMS_ENCRYPT"
_SHA256_SIGNING_ALGORITHMS = frozenset(
    {
        "ECDSA_SHA_256",
        "RSASSA_PSS_SHA_256",
        "RSASSA_PKCS1_V1_5_SHA_256",
    }
)


class AwsKmsProvider:
    """Use AWS KMS Encrypt/Decrypt and Sign/Verify through a boto3-compatible client."""

    provider_name = "aws_kms"

    def __init__(
        self,
        client: Any,
        *,
        signing_algorithms: Mapping[str, str] | None = None,
    ) -> None:
        if client is None:
            raise CryptoProviderError("An AWS KMS client is required.")
        self._client = client
        self._signing_algorithms = dict(signing_algorithms or {})
        for key_ref, algorithm in self._signing_algorithms.items():
            if not isinstance(key_ref, str) or not key_ref:
                raise CryptoProviderError("AWS KMS signing key references must be non-empty.")
            if algorithm not in _SHA256_SIGNING_ALGORITHMS:
                raise CryptoProviderError(
                    "AWS KMS signing algorithms must use an explicitly supported SHA-256 mode."
                )

    @classmethod
    def from_default_session(
        cls,
        *,
        signing_algorithms: Mapping[str, str] | None = None,
        region_name: str | None = None,
    ) -> "AwsKmsProvider":
        """Create the adapter from the caller's normal boto3 credential chain."""

        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - optional dependency path
            raise CryptoProviderError(
                "AWS KMS support requires the optional 'aws-kms' dependency."
            ) from exc
        return cls(
            boto3.client("kms", region_name=region_name),
            signing_algorithms=signing_algorithms,
        )

    def wrap_data_key(
        self,
        key_ref: str,
        plaintext_key: bytes,
        *,
        context: Mapping[str, str],
    ) -> WrappedDataKey:
        if not isinstance(plaintext_key, bytes) or len(plaintext_key) != 32:
            raise CryptoProviderError("FinRedOps envelope DEKs must be exactly 32 bytes.")
        encryption_context = validate_provider_context(context)
        try:
            response = self._client.encrypt(
                KeyId=key_ref,
                Plaintext=plaintext_key,
                EncryptionContext=encryption_context,
            )
            ciphertext = response["CiphertextBlob"]
        except Exception as exc:  # provider SDK exceptions are intentionally wrapped
            raise CryptoProviderError("AWS KMS failed to wrap the data key.") from exc
        if not isinstance(ciphertext, (bytes, bytearray)) or not ciphertext:
            raise CryptoProviderError("AWS KMS returned an invalid wrapped data key.")
        return WrappedDataKey(bytes(ciphertext), _WRAP_ALGORITHM)

    def unwrap_data_key(
        self,
        key_ref: str,
        wrapped_key: WrappedDataKey,
        *,
        context: Mapping[str, str],
    ) -> bytes:
        if wrapped_key.algorithm != _WRAP_ALGORITHM:
            raise CryptoProviderError("Wrapped data key algorithm does not match AWS KMS.")
        encryption_context = validate_provider_context(context)
        try:
            response = self._client.decrypt(
                KeyId=key_ref,
                CiphertextBlob=wrapped_key.ciphertext,
                EncryptionContext=encryption_context,
            )
            plaintext = response["Plaintext"]
        except Exception as exc:
            raise CryptoProviderError("AWS KMS failed to unwrap the data key.") from exc
        if not isinstance(plaintext, (bytes, bytearray)) or len(plaintext) != 32:
            raise CryptoProviderError("AWS KMS returned an invalid plaintext data key.")
        return bytes(plaintext)

    def _signing_algorithm(self, key_ref: str) -> str:
        algorithm = self._signing_algorithms.get(key_ref)
        if algorithm is None:
            raise CryptoProviderError(
                "No explicit SHA-256 signing algorithm is configured for this AWS KMS key."
            )
        return algorithm

    def sign_digest(self, key_ref: str, digest: bytes) -> ProviderSignature:
        if not isinstance(digest, bytes) or len(digest) != 32:
            raise CryptoProviderError("AWS KMS signing requires a 32-byte SHA-256 digest.")
        algorithm = self._signing_algorithm(key_ref)
        try:
            response = self._client.sign(
                KeyId=key_ref,
                Message=digest,
                MessageType="DIGEST",
                SigningAlgorithm=algorithm,
            )
            signature = response["Signature"]
        except Exception as exc:
            raise CryptoProviderError("AWS KMS failed to sign the digest.") from exc
        if not isinstance(signature, (bytes, bytearray)) or not signature:
            raise CryptoProviderError("AWS KMS returned an invalid signature.")
        returned_algorithm = response.get("SigningAlgorithm", algorithm)
        if returned_algorithm != algorithm:
            raise CryptoProviderError("AWS KMS returned an unexpected signing algorithm.")
        return ProviderSignature(bytes(signature), algorithm)

    def verify_digest(
        self,
        key_ref: str,
        digest: bytes,
        signature: ProviderSignature,
    ) -> bool:
        if not isinstance(digest, bytes) or len(digest) != 32:
            raise CryptoProviderError("AWS KMS verification requires a 32-byte SHA-256 digest.")
        algorithm = self._signing_algorithm(key_ref)
        if signature.algorithm != algorithm:
            return False
        try:
            response = self._client.verify(
                KeyId=key_ref,
                Message=digest,
                MessageType="DIGEST",
                Signature=signature.signature,
                SigningAlgorithm=algorithm,
            )
        except Exception as exc:
            raise CryptoProviderError("AWS KMS failed to verify the digest signature.") from exc
        return response.get("SignatureValid") is True
