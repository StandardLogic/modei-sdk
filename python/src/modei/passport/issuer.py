"""PassportIssuer — construct and sign self-issued v2 envelopes.

Spec §11.1, §3.1. Delegation issuance lives in ``delegation.py`` (C19.5);
this module only handles ``issuer.type = 'self'``.

Signing input (unambiguous per backend parity):
  1. Build canonical v2 envelope dict.
  2. RFC 8785 canonicalize via ``canonicalize_strict`` → UTF-8 bytes.
  3. Sign with Ed25519 over the full canonical bytes.
  4. Return the envelope and the detached base64 signature.

The signature is never embedded in the envelope — it's returned alongside
and threaded through request bodies that carry ``{passport_json,
signature}``. Matches backend ``signPassport`` at
``src/app/api/gates/[gate_id]/passports/issue/route.ts:76``.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import nacl.signing

from .agent_id import derive_self_agent_id
from .canonical import canonicalize_strict
from .credentials import AgentCredentials
from .envelope import (
    Envelope,
    EnvelopeIssuer,
    PassportIdentity,
    PassportPermission,
    PassportProvenance,
    SignedPassport,
)

# Backend parity: canonical byte-length cap per spec §2.1.
MAX_CANONICAL_ENVELOPE_BYTES = 64 * 1024

# Timestamp format:
#   ISO 8601 UTC with millisecond precision and 'Z' suffix.
#   Example: "2026-04-22T00:00:00.000Z"
# Matches backend ``new Date().toISOString()`` exactly. Pinning this format
# is critical for cross-SDK canonical byte parity with the backend. A future
# change to microsecond precision (or a different suffix) would break
# signature verification against envelopes issued under the old format. Do
# not "improve" this without a coordinated cross-SDK + backend migration.
_TIMESTAMP_FORMAT_ISO_MS_Z = "iso-ms-Z"  # documentation anchor


def _format_iso_ms_z(ts: datetime) -> str:
    # datetime → "YYYY-MM-DDTHH:MM:SS.mmmZ". Truncate microsecond → millisecond.
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    else:
        ts = ts.astimezone(timezone.utc)
    ms = ts.microsecond // 1000
    return f"{ts.strftime('%Y-%m-%dT%H:%M:%S')}.{ms:03d}Z"


def _hex_sha256_b64_pubkey(public_key_b64: str) -> str:
    pk_bytes = base64.b64decode(public_key_b64, validate=True)
    return hashlib.sha256(pk_bytes).hexdigest()


class PassportIssuer:
    """Self-issue and sign v2 passport envelopes.

    Args:
        credentials: Agent keypair. The private key never leaves the object.
        identity_claim: String that populates ``identity.agent_name`` in
            every issued envelope. At L0 this is unverified display text;
            at L0.5 (deferred) it becomes DNS-verifiable. Optional.

            If ``identity_claim is None``, the issued envelope has
            ``identity.agent_name = None``. Such envelopes are LOCALLY
            valid and can be used on the inline path, but
            ``POST /api/passports/register`` REJECTS them server-side
            (the route requires a non-empty agent_name). Self-issued
            passports that will be registered must pass a non-None
            ``identity_claim``.
    """

    def __init__(
        self,
        credentials: AgentCredentials,
        identity_claim: Optional[str] = None,
    ) -> None:
        self._credentials = credentials
        self._identity_claim = identity_claim
        self._signing_key = nacl.signing.SigningKey(credentials.private_key_bytes)

    def self_issue(
        self,
        permissions: list[dict[str, Any]],
        expires_in: timedelta,
        delegation_authority: bool = False,
        verification_evidence: Optional[list[Any]] = None,
    ) -> SignedPassport:
        """Construct a v2 self-issued envelope and return it with its signature.

        Args:
            permissions: List of ``{permission_key, constraints}`` dicts.
                ``constraints`` must be present on every entry (may be empty
                dict). No default fill-in.
            expires_in: Duration from now until envelope expiration.
            delegation_authority: ``True`` allows this envelope to be a
                delegation parent. Default ``False``.
            verification_evidence: L0.5 reserved field; default ``[]``.

        Returns:
            :class:`SignedPassport` — a ``NamedTuple(envelope, signature)``.
            Tuple-unpack is supported: ``env, sig = issuer.self_issue(...)``.

        Raises:
            ValueError: canonical envelope exceeds the 64KB per-envelope
                spec §2.1 cap (caller bug, not recoverable).
        """
        creds = self._credentials
        pubkey_b64 = creds.public_key_b64

        issued_at_dt = datetime.now(timezone.utc)
        expires_at_dt = issued_at_dt + expires_in

        envelope = Envelope(
            schema_version=2,
            passport_id=f"pp_self_{uuid.uuid4().hex}",
            identity=PassportIdentity(
                agent_id=derive_self_agent_id(pubkey_b64),
                agent_name=self._identity_claim,
                public_key=pubkey_b64,
            ),
            permissions=[
                PassportPermission(
                    permission_key=p["permission_key"],
                    constraints=p.get("constraints", {}),
                )
                for p in permissions
            ],
            provenance=PassportProvenance(
                issuer=EnvelopeIssuer(
                    type="self",
                    id="self:" + _hex_sha256_b64_pubkey(pubkey_b64),
                    key_id="self",
                ),
                gate_id=None,
                catalog_content_hash=None,
                catalog_version=None,
                delegation_chain=None,
                issued_at=_format_iso_ms_z(issued_at_dt),
                expires_at=_format_iso_ms_z(expires_at_dt),
            ),
            delegation_authority=delegation_authority,
            verification_evidence=verification_evidence if verification_evidence is not None else [],
        )

        signature_b64 = self._sign_envelope(envelope)
        return SignedPassport(envelope=envelope, signature=signature_b64)

    def _sign_envelope(self, envelope: Envelope) -> str:
        canonical_bytes = canonicalize_strict(envelope.model_dump(mode="json"))
        if len(canonical_bytes) > MAX_CANONICAL_ENVELOPE_BYTES:
            raise ValueError(
                f"envelope_too_large: canonical envelope is "
                f"{len(canonical_bytes)} bytes, max {MAX_CANONICAL_ENVELOPE_BYTES}"
            )
        signature_bytes = self._signing_key.sign(canonical_bytes).signature
        return base64.b64encode(signature_bytes).decode("ascii")
