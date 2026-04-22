"""Pydantic v2 models for the v2 passport envelope (spec §3.1).

Mirror of backend ``src/lib/passports/types.ts``. Structural validation
parity with ``assertCanonicalEnvelope`` (backend ``verify.ts``) is a
release invariant — any field that backend rejects when missing is
required here (no default). Construction ergonomics live in
``PassportIssuer.self_issue()`` / ``DelegationBuilder.sign()`` (C19.4,
C19.5), not at model level.

NAMING DEVIATION FROM BACKEND: Backend TypeScript exports a struct named
``PassportIssuer`` for ``provenance.issuer``. This SDK reserves that name
for the public sign-and-issue class (spec §11.1, C19.4). The envelope
submodel is therefore renamed ``EnvelopeIssuer``. All other envelope
submodels keep their backend names.

All models set ``model_config = ConfigDict(extra='forbid')`` so unknown
fields raise ``ValidationError`` — backend treats unknown envelope fields
as ``invalid_envelope_shape``. Parity matters.
"""

from __future__ import annotations

from typing import Any, Literal, NamedTuple, Optional

from pydantic import BaseModel, ConfigDict, Field

IssuerType = Literal["gate", "platform", "self", "delegate"]


class EnvelopeIssuer(BaseModel):
    """``provenance.issuer`` — renamed from backend ``PassportIssuer``."""

    model_config = ConfigDict(extra="forbid")

    type: IssuerType
    id: str = Field(min_length=1)
    key_id: str = Field(min_length=1)


class PassportIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    agent_name: Optional[str]
    public_key: str


class PassportPermission(BaseModel):
    model_config = ConfigDict(extra="forbid")

    permission_key: str
    constraints: dict[str, Any]


class DelegationChainEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passport_json: "Envelope"
    signature: str = Field(min_length=1)


class PassportProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer: EnvelopeIssuer
    gate_id: Optional[str]
    catalog_content_hash: Optional[str]
    catalog_version: Optional[int]
    delegation_chain: Optional[list[DelegationChainEntry]]
    issued_at: str
    expires_at: str


class Envelope(BaseModel):
    """v2 canonical passport envelope (spec §3.1).

    Every field required. ``verification_evidence`` has no default — the
    SDK issuer populates ``[]`` at construction time. A missing key on
    parse is a shape violation, matching backend behavior.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[2]
    passport_id: str = Field(min_length=1)
    identity: PassportIdentity
    permissions: list[PassportPermission]
    provenance: PassportProvenance
    delegation_authority: bool
    verification_evidence: list[Any]


# Pydantic v2 forward-ref resolution for the recursive DelegationChainEntry.
DelegationChainEntry.model_rebuild()


class SignedPassport(NamedTuple):
    """An envelope bundled with its detached Ed25519 signature.

    Returned by :meth:`PassportIssuer.self_issue` and consumed by
    :class:`DelegationBuilder`. Spec §11.1 names this wrapper ``Passport``;
    the SDK uses ``SignedPassport`` because ``modei.Passport`` is already
    exported as a REST-shape model by ``modei-python@1.0.0``.

    As a ``NamedTuple``, instances unpack like a plain tuple:

    .. code-block:: python

        signed = issuer.self_issue(...)
        envelope, signature = signed      # tuple unpack
        signed.envelope                   # field access
        signed.signature                  # field access
    """

    envelope: "Envelope"
    signature: str
