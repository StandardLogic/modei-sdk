"""DelegationBuilder — construct a child envelope from a parent.

Spec §11.1 lines 482–530, §3.3 (chain invariants), §3.4 (subset
permissions), §3.5 (constraint tightening).

Usage:

.. code-block:: python

    parent_signed = parent_issuer.self_issue(
        permissions=[{"permission_key": "flights:book",
                      "constraints": {"max_per_action_cost": 500}}],
        expires_in=timedelta(days=30),
        delegation_authority=True,
    )

    child_signed = (
        DelegationBuilder(parent=parent_signed, parent_credentials=parent_creds)
        .authorize(child_credentials=child_creds)
        .with_permissions([
            {"permission_key": "flights:book",
             "constraints": {"max_per_action_cost": 200}},
        ])
        .with_expiry(expires_in=timedelta(days=7))
        .sign()
    )

Pre-sign validation at :meth:`sign`:
    * Parent must have ``delegation_authority=True``
      (:class:`DelegationAuthorityMissingError`).
    * Resulting chain length must be ≤ 5
      (:class:`DelegationChainTooDeepError`).
    * Every adjacent pair in the proposed full chain — including
      (parent, leaf) — must satisfy the subset permissions and
      constraint tightening rules, plus leaf expiry must not extend
      any ancestor's (:class:`DelegationSubsetError`).

All three exceptions subclass :class:`DelegationError`, which subclasses
:class:`ValueError` so a broad ``except ValueError`` still catches them.

Expiry clamp (spec §11.1 line 530): ``with_expiry(expires_in=...)``
computes ``now + expires_in`` then clamps to ``min(requested,
parent.expires_at, chain[*].expires_at)``. The clamp is silent. Use
:attr:`effective_expires_at` and :attr:`expiry_was_clamped` to
introspect after calling ``with_expiry``.
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import nacl.signing

from ._subset import enforce_subset_permissions, is_expiry_non_extending
from .agent_id import derive_self_agent_id
from .canonical import canonicalize_strict
from .credentials import AgentCredentials
from .envelope import (
    DelegationChainEntry,
    Envelope,
    EnvelopeIssuer,
    PassportIdentity,
    PassportPermission,
    PassportProvenance,
    SignedPassport,
)
from .issuer import MAX_CANONICAL_ENVELOPE_BYTES, _format_iso_ms_z

MAX_DELEGATION_DEPTH = 5  # spec §3.3


# ---------------------------------------------------------------------------
# exceptions
# ---------------------------------------------------------------------------


class DelegationError(ValueError):
    """Base class for pre-sign delegation failures. Subclasses ``ValueError``
    so a broad ``except ValueError`` matches — mirrors spec §11.1 example."""


class DelegationSubsetError(DelegationError):
    """Child permission/constraint violates the §3.4/§3.5 subset rule."""

    def __init__(
        self,
        *,
        permission_key: Optional[str],
        dimension: Optional[str],
        ancestor_value: Any,
        descendant_value: Any,
        detail: str,
    ) -> None:
        self.permission_key = permission_key
        self.dimension = dimension
        self.ancestor_value = ancestor_value
        self.descendant_value = descendant_value
        self.detail = detail
        super().__init__(detail)


class DelegationChainTooDeepError(DelegationError):
    """Proposed chain length exceeds spec §3.3 max of 5."""

    def __init__(self, chain_length: int, max_depth: int = MAX_DELEGATION_DEPTH) -> None:
        self.chain_length = chain_length
        self.max_depth = max_depth
        super().__init__(
            f"delegation_chain_too_deep: proposed chain length {chain_length} "
            f"exceeds max {max_depth}"
        )


class DelegationAuthorityMissingError(DelegationError):
    """Parent envelope lacks ``delegation_authority=True``."""

    def __init__(self) -> None:
        super().__init__(
            "delegation_authority_missing: parent envelope has "
            "delegation_authority=False; cannot delegate from it"
        )


# ---------------------------------------------------------------------------
# builder
# ---------------------------------------------------------------------------


_UNSET = object()  # sentinel for "user hasn't called the setter"


class DelegationBuilder:
    """Fluent builder for a delegated v2 passport envelope."""

    def __init__(
        self,
        parent: SignedPassport,
        parent_credentials: AgentCredentials,
    ) -> None:
        if parent_credentials.public_key_b64 != parent.envelope.identity.public_key:
            raise DelegationError(
                "parent_credentials public key does not match "
                "parent.envelope.identity.public_key"
            )

        self._parent_envelope: Envelope = parent.envelope
        self._parent_signature: str = parent.signature
        # parent_credentials is stored for defensive symmetry even though we
        # don't use it to sign (the parent's signature is already on hand).
        # It documents which identity authorized the delegation.
        self._parent_credentials: AgentCredentials = parent_credentials

        self._child_credentials: Optional[AgentCredentials] = None
        self._child_permissions: Any = _UNSET
        self._child_expires_in: Optional[timedelta] = None
        self._child_identity_claim: Optional[str] = None
        self._child_delegation_authority: bool = False
        self._child_verification_evidence: list[Any] = []

        self._effective_expires_at_dt: Optional[datetime] = None
        self._expiry_was_clamped: bool = False

    # ----- fluent setters -------------------------------------------------

    def authorize(self, child_credentials: AgentCredentials) -> "DelegationBuilder":
        """Bind the child keypair. Required before :meth:`sign`."""
        self._child_credentials = child_credentials
        return self

    def with_permissions(self, permissions: list[dict[str, Any]]) -> "DelegationBuilder":
        """Set child permissions. Required before :meth:`sign`.

        Caller writes the subset by hand — SDK does not auto-attenuate
        (deferred to v1.2 per spec §14). Pre-sign validation at
        :meth:`sign` checks the subset against the entire parent chain.
        """
        self._child_permissions = permissions
        return self

    def with_expiry(self, expires_in: timedelta) -> "DelegationBuilder":
        """Set child expiration. Clamps to the most restrictive ancestor
        expiry so the child can never extend beyond the chain's minimum.
        """
        self._child_expires_in = expires_in
        # Compute effective expiry + clamp flag now so caller can introspect
        # BEFORE sign().
        requested_dt = datetime.now(timezone.utc) + expires_in
        ancestor_expiries = [self._parse_z_ms(self._parent_envelope.provenance.expires_at)]
        for entry in self._parent_envelope.provenance.delegation_chain or []:
            ancestor_expiries.append(
                self._parse_z_ms(entry.passport_json.provenance.expires_at)
            )
        min_ancestor_expiry = min(ancestor_expiries)
        effective = min(requested_dt, min_ancestor_expiry)
        self._effective_expires_at_dt = effective
        self._expiry_was_clamped = effective < requested_dt
        return self

    def with_identity_claim(self, identity_claim: Optional[str]) -> "DelegationBuilder":
        self._child_identity_claim = identity_claim
        return self

    def with_delegation_authority(self, value: bool) -> "DelegationBuilder":
        self._child_delegation_authority = value
        return self

    def with_verification_evidence(self, evidence: list[Any]) -> "DelegationBuilder":
        self._child_verification_evidence = evidence
        return self

    # ----- introspection --------------------------------------------------

    @property
    def effective_expires_at(self) -> Optional[datetime]:
        """The clamped ``expires_at`` after :meth:`with_expiry`. ``None`` if
        ``with_expiry`` has not been called."""
        return self._effective_expires_at_dt

    @property
    def expiry_was_clamped(self) -> bool:
        """``True`` if :meth:`with_expiry`'s requested value was clamped
        down to an ancestor's expiry. ``False`` before ``with_expiry`` or
        if no clamp applied."""
        return self._expiry_was_clamped

    # ----- sign -----------------------------------------------------------

    def sign(self) -> SignedPassport:
        """Validate + construct + sign the child envelope.

        Raises:
            DelegationError: ``authorize`` or ``with_permissions`` not called.
            DelegationAuthorityMissingError: parent lacks delegation_authority.
            DelegationChainTooDeepError: resulting chain length > 5.
            DelegationSubsetError: any pair violates subset/constraint rules.
            ValueError: canonical envelope > 64KB (caller bug).
        """
        if self._child_credentials is None:
            raise DelegationError(
                "authorize(child_credentials) must be called before sign()"
            )
        if self._child_permissions is _UNSET:
            raise DelegationError(
                "with_permissions(...) must be called before sign(). "
                "To inherit parent's permissions verbatim, pass them "
                "explicitly: .with_permissions(parent.envelope.permissions)"
            )

        if self._parent_envelope.delegation_authority is not True:
            raise DelegationAuthorityMissingError()

        # Build the proposed chain: parent's own chain (if any) + the parent itself.
        parent_chain = self._parent_envelope.provenance.delegation_chain or []
        proposed_chain: list[DelegationChainEntry] = list(parent_chain) + [
            DelegationChainEntry(
                passport_json=self._parent_envelope,
                signature=self._parent_signature,
            )
        ]
        if len(proposed_chain) > MAX_DELEGATION_DEPTH:
            raise DelegationChainTooDeepError(len(proposed_chain))

        # Issued-at / expires-at. If with_expiry() wasn't called, default to
        # the most-restrictive ancestor expiry (same as parent.expires_at in
        # the common case). This keeps the "delegate inherits expiry" default
        # safe — never extends.
        issued_at_dt = datetime.now(timezone.utc)
        if self._effective_expires_at_dt is None:
            ancestor_expiries = [self._parse_z_ms(self._parent_envelope.provenance.expires_at)]
            for entry in parent_chain:
                ancestor_expiries.append(
                    self._parse_z_ms(entry.passport_json.provenance.expires_at)
                )
            self._effective_expires_at_dt = min(ancestor_expiries)
        expires_at_dt = self._effective_expires_at_dt

        # issuer.id references the chain ROOT's passport_id per backend
        # agent_id.ts:75-77. The root is chain[0].
        root = proposed_chain[0].passport_json
        # issuer.key_id inherits from parent per spec §3.1 table.
        parent_key_id = self._parent_envelope.provenance.issuer.key_id

        # gate_id / catalog_* inherit from root if root is gate, else None.
        if root.provenance.issuer.type == "gate":
            inherited_gate_id = root.provenance.gate_id
            inherited_catalog_hash = root.provenance.catalog_content_hash
            inherited_catalog_version = root.provenance.catalog_version
        else:
            inherited_gate_id = None
            inherited_catalog_hash = None
            inherited_catalog_version = None

        child_creds = self._child_credentials
        child = Envelope(
            schema_version=2,
            passport_id=f"pp_delegate_{uuid.uuid4().hex}",
            identity=PassportIdentity(
                agent_id=derive_self_agent_id(child_creds.public_key_b64),
                agent_name=self._child_identity_claim,
                public_key=child_creds.public_key_b64,
            ),
            permissions=[
                PassportPermission(
                    permission_key=p["permission_key"],
                    constraints=p.get("constraints", {}),
                )
                for p in self._child_permissions
            ],
            provenance=PassportProvenance(
                issuer=EnvelopeIssuer(
                    type="delegate",
                    id="delegate:" + root.passport_id,
                    key_id=parent_key_id,
                ),
                gate_id=inherited_gate_id,
                catalog_content_hash=inherited_catalog_hash,
                catalog_version=inherited_catalog_version,
                delegation_chain=proposed_chain,
                issued_at=_format_iso_ms_z(issued_at_dt),
                expires_at=_format_iso_ms_z(expires_at_dt),
            ),
            delegation_authority=self._child_delegation_authority,
            verification_evidence=list(self._child_verification_evidence),
        )

        # Pre-sign walk: every adjacent pair + (last_ancestor, leaf).
        # Inner pairs were validated at their own sign-time — walking them
        # again is redundant for well-formed inputs but guarantees pre-sign
        # verdict == verify-time verdict for any input, at negligible cost.
        for i in range(len(proposed_chain) - 1):
            self._check_pair(proposed_chain[i].passport_json, proposed_chain[i + 1].passport_json)
        last_ancestor = proposed_chain[-1].passport_json
        self._check_pair(last_ancestor, child)

        # Signature: child is signed by the last chain entry's private key
        # (i.e., parent_credentials).
        canonical_bytes = canonicalize_strict(child.model_dump(mode="json"))
        if len(canonical_bytes) > MAX_CANONICAL_ENVELOPE_BYTES:
            raise ValueError(
                f"envelope_too_large: canonical envelope is {len(canonical_bytes)} "
                f"bytes, max {MAX_CANONICAL_ENVELOPE_BYTES}"
            )
        signing_key = nacl.signing.SigningKey(self._parent_credentials.private_key_bytes)
        signature_b64 = base64.b64encode(signing_key.sign(canonical_bytes).signature).decode(
            "ascii"
        )
        return SignedPassport(envelope=child, signature=signature_b64)

    # ----- internals ------------------------------------------------------

    @staticmethod
    def _parse_z_ms(s: str) -> datetime:
        """Parse an ISO 8601 UTC millisecond Z-suffixed timestamp."""
        if not s.endswith("Z"):
            raise ValueError(f"expected Z-suffixed UTC timestamp, got {s!r}")
        return datetime.fromisoformat(s[:-1]).replace(tzinfo=timezone.utc)

    @staticmethod
    def _check_pair(ancestor: Envelope, descendant: Envelope) -> None:
        subset = enforce_subset_permissions(ancestor, descendant)
        if not subset.ok:
            # Parse detail to populate structured fields on the exception.
            # Best-effort parse: the detail is canonically formatted by
            # enforce_subset_permissions ("descendant permission 'x' not
            # present in ancestor" or "permission 'x': <dimension-specific>").
            permission_key: Optional[str] = None
            dimension: Optional[str] = None
            detail_text = subset.detail or ""
            if detail_text.startswith("descendant permission "):
                # "descendant permission 'x' not present in ancestor"
                start = detail_text.find("'")
                end = detail_text.find("'", start + 1)
                if start != -1 and end != -1:
                    permission_key = detail_text[start + 1 : end]
            elif detail_text.startswith("permission '"):
                end = detail_text.find("'", len("permission '"))
                if end != -1:
                    permission_key = detail_text[len("permission '") : end]
                # dimension extraction: "... constraint 'dim' absent ..." or
                # "... 'dim' descendant=... > ancestor=..."
                for marker in ("constraint '", "'"):
                    idx = detail_text.find(marker, end)
                    if idx == -1:
                        continue
                    inner_start = idx + len(marker)
                    inner_end = detail_text.find("'", inner_start)
                    if inner_end != -1:
                        dimension = detail_text[inner_start:inner_end]
                        break
            raise DelegationSubsetError(
                permission_key=permission_key,
                dimension=dimension,
                ancestor_value=None,  # full ancestor/descendant values not parsed back
                descendant_value=None,
                detail=detail_text,
            )
        if not is_expiry_non_extending(ancestor, descendant):
            raise DelegationSubsetError(
                permission_key=None,
                dimension="expires_at",
                ancestor_value=ancestor.provenance.expires_at,
                descendant_value=descendant.provenance.expires_at,
                detail=(
                    f"expiry_extension: descendant.expires_at "
                    f"{descendant.provenance.expires_at!r} > ancestor.expires_at "
                    f"{ancestor.provenance.expires_at!r}"
                ),
            )
