"""Cryptographic utilities: Ed25519 verification and RFC 8785 content hashing."""

from __future__ import annotations

import hashlib
from typing import Any

import canonicaljson
import nacl.signing


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        public_key: 32-byte Ed25519 public key.
        message: The signed message bytes.
        signature: 64-byte Ed25519 signature.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        verify_key = nacl.signing.VerifyKey(public_key)
        verify_key.verify(message, signature)
        return True
    except nacl.exceptions.BadSignatureError:
        return False


def compute_content_hash(obj: Any) -> str:
    """Compute the SHA-256 hex digest of the RFC 8785 canonical JSON encoding.

    Args:
        obj: Any JSON-serializable value.

    Returns:
        Hex-encoded SHA-256 hash string.
    """
    canonical = canonicaljson.encode_canonical_json(obj)
    return hashlib.sha256(canonical).hexdigest()


def verify_attestation_signature(
    attestation_json: str,
    signature_b64: str,
    public_key_b64: str,
) -> bool:
    """Verify an attestation's Ed25519 signature.

    Args:
        attestation_json: The canonical JSON string that was signed.
        signature_b64: Base64-encoded Ed25519 signature.
        public_key_b64: Base64-encoded Ed25519 public key.

    Returns:
        True if the signature is valid.
    """
    import base64

    public_key = base64.b64decode(public_key_b64)
    signature = base64.b64decode(signature_b64)
    message = attestation_json.encode("utf-8")
    return verify_ed25519(public_key, message, signature)


def verify_content_hash(obj: Any, expected_hash: str) -> bool:
    """Verify that a JSON object matches an expected content hash.

    Args:
        obj: The JSON-serializable object.
        expected_hash: The expected hex SHA-256 hash.

    Returns:
        True if the computed hash matches.
    """
    return compute_content_hash(obj) == expected_hash
