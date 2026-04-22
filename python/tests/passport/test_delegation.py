"""C19.5 tests — DelegationBuilder.

14 tests. Covers pre-sign subset validation (spec §13 rows 13a/b/c),
chain construction, expiry clamp, depth boundary, and cross-backend
byte-parity for a deterministic 2-link fixture.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import Any

import nacl.signing
import pytest

from modei.passport.canonical import canonicalize_strict
from modei.passport.credentials import AgentCredentials
from modei.passport.delegation import (
    DelegationAuthorityMissingError,
    DelegationBuilder,
    DelegationChainTooDeepError,
    DelegationError,
    DelegationSubsetError,
)
from modei.passport.envelope import (
    DelegationChainEntry,
    Envelope,
    EnvelopeIssuer,
    PassportIdentity,
    PassportPermission,
    PassportProvenance,
    SignedPassport,
)
from modei.passport.issuer import PassportIssuer, _format_iso_ms_z
from modei.passport.tier import TrustTier
from modei.passport.verifier import PassportVerifier


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _issue_self(
    creds: AgentCredentials,
    *,
    permissions: Any = None,
    expires_in: timedelta = timedelta(days=30),
    delegation_authority: bool = True,
) -> SignedPassport:
    issuer = PassportIssuer(creds, identity_claim="parent@dev.local")
    return issuer.self_issue(
        permissions=permissions or [{"permission_key": "api:read", "constraints": {}}],
        expires_in=expires_in,
        delegation_authority=delegation_authority,
    )


# ---------------------------------------------------------------------------
# 1–2. state-machine errors
# ---------------------------------------------------------------------------


def test_authorize_required_before_sign() -> None:
    parent_creds = AgentCredentials.generate()
    parent_signed = _issue_self(parent_creds)
    builder = DelegationBuilder(parent=parent_signed, parent_credentials=parent_creds)
    builder.with_permissions([{"permission_key": "api:read", "constraints": {}}])
    with pytest.raises(DelegationError, match="authorize"):
        builder.sign()


def test_with_permissions_required_before_sign() -> None:
    parent_creds = AgentCredentials.generate()
    parent_signed = _issue_self(parent_creds)
    child_creds = AgentCredentials.generate()
    builder = (
        DelegationBuilder(parent=parent_signed, parent_credentials=parent_creds)
        .authorize(child_credentials=child_creds)
    )
    with pytest.raises(DelegationError, match="with_permissions"):
        builder.sign()


# ---------------------------------------------------------------------------
# 3. round-trip — self→delegate verifier accepts
# ---------------------------------------------------------------------------


def test_simple_self_to_delegate_round_trip_verifier_accepts() -> None:
    """Spec §13 row 10 via construction path: parent self-issued, child
    delegated, verifier accepts → valid, tier=L0."""
    parent_creds = AgentCredentials.generate()
    parent_signed = _issue_self(parent_creds)
    child_creds = AgentCredentials.generate()

    child_signed = (
        DelegationBuilder(parent=parent_signed, parent_credentials=parent_creds)
        .authorize(child_credentials=child_creds)
        .with_permissions([{"permission_key": "api:read", "constraints": {}}])
        .sign()
    )

    assert child_signed.envelope.provenance.issuer.type == "delegate"
    assert child_signed.envelope.provenance.issuer.id == (
        "delegate:" + parent_signed.envelope.passport_id
    )

    result = PassportVerifier().verify(child_signed.envelope, child_signed.signature)
    assert result.valid is True, f"unexpected BLOCK: {result.reason_code} {result.detail}"
    assert result.tier == TrustTier.L0


# ---------------------------------------------------------------------------
# 4–7. subset violations (spec §13 rows 13a, 13b)
# ---------------------------------------------------------------------------


def test_subset_violation_permission_added() -> None:
    """Spec §13 row 13a: child has a permission_key not in parent."""
    parent_creds = AgentCredentials.generate()
    parent_signed = _issue_self(
        parent_creds,
        permissions=[{"permission_key": "api:read", "constraints": {}}],
    )
    child_creds = AgentCredentials.generate()
    builder = (
        DelegationBuilder(parent=parent_signed, parent_credentials=parent_creds)
        .authorize(child_credentials=child_creds)
        .with_permissions([{"permission_key": "api:write", "constraints": {}}])
    )
    with pytest.raises(DelegationSubsetError) as exc_info:
        builder.sign()
    assert "api:write" in str(exc_info.value)
    assert exc_info.value.permission_key == "api:write"


def test_subset_violation_constraint_loosened_numeric() -> None:
    """Spec §13 row 13b: child loosens a numeric constraint."""
    parent_creds = AgentCredentials.generate()
    parent_signed = _issue_self(
        parent_creds,
        permissions=[
            {"permission_key": "api:read", "constraints": {"max_per_action_cost": 500}}
        ],
    )
    child_creds = AgentCredentials.generate()
    builder = (
        DelegationBuilder(parent=parent_signed, parent_credentials=parent_creds)
        .authorize(child_credentials=child_creds)
        .with_permissions(
            [{"permission_key": "api:read", "constraints": {"max_per_action_cost": 1000}}]
        )
    )
    with pytest.raises(DelegationSubsetError) as exc_info:
        builder.sign()
    msg = str(exc_info.value)
    assert "max_per_action_cost" in msg
    assert "1000" in msg and "500" in msg


def test_subset_violation_constraint_loosened_list() -> None:
    parent_creds = AgentCredentials.generate()
    parent_signed = _issue_self(
        parent_creds,
        permissions=[
            {
                "permission_key": "api:read",
                "constraints": {"allowed_domains": ["a.com", "b.com"]},
            }
        ],
    )
    child_creds = AgentCredentials.generate()
    builder = (
        DelegationBuilder(parent=parent_signed, parent_credentials=parent_creds)
        .authorize(child_credentials=child_creds)
        .with_permissions(
            [
                {
                    "permission_key": "api:read",
                    "constraints": {"allowed_domains": ["a.com", "c.com"]},  # c.com not in parent
                }
            ]
        )
    )
    with pytest.raises(DelegationSubsetError) as exc_info:
        builder.sign()
    assert "allowed_domains" in str(exc_info.value)
    assert "c.com" in str(exc_info.value)


def test_subset_violation_constraint_added_to_absent_dimension() -> None:
    """Parent has no constraint on a dimension; child tries to add one."""
    parent_creds = AgentCredentials.generate()
    parent_signed = _issue_self(
        parent_creds,
        permissions=[{"permission_key": "api:read", "constraints": {}}],  # no constraints
    )
    child_creds = AgentCredentials.generate()
    builder = (
        DelegationBuilder(parent=parent_signed, parent_credentials=parent_creds)
        .authorize(child_credentials=child_creds)
        .with_permissions(
            [{"permission_key": "api:read", "constraints": {"max_per_action_cost": 100}}]
        )
    )
    with pytest.raises(DelegationSubsetError) as exc_info:
        builder.sign()
    assert "max_per_action_cost" in str(exc_info.value)
    assert "absent in ancestor" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 8–9. expiry clamp (spec §13 row 13c)
# ---------------------------------------------------------------------------


def test_expiry_clamp_basic() -> None:
    """Parent expires in 7d; child asks for 30d → child clamped to parent's expires_at.

    effective_expires_at reflects the clamp; expiry_was_clamped is True.
    """
    parent_creds = AgentCredentials.generate()
    parent_signed = _issue_self(parent_creds, expires_in=timedelta(days=7))

    child_creds = AgentCredentials.generate()
    builder = (
        DelegationBuilder(parent=parent_signed, parent_credentials=parent_creds)
        .authorize(child_credentials=child_creds)
        .with_permissions([{"permission_key": "api:read", "constraints": {}}])
        .with_expiry(expires_in=timedelta(days=30))
    )
    assert builder.expiry_was_clamped is True
    # Effective expiry == parent's expiry (clamped).
    parent_expires_dt = DelegationBuilder._parse_z_ms(
        parent_signed.envelope.provenance.expires_at
    )
    assert builder.effective_expires_at == parent_expires_dt

    child_signed = builder.sign()
    assert child_signed.envelope.provenance.expires_at == parent_signed.envelope.provenance.expires_at


def test_expiry_clamp_transitive_across_chain() -> None:
    """3-link chain; middle link is most restrictive → leaf clamped to it."""
    # Manually construct a 2-link chain (root + middle) by hand, since
    # DelegationBuilder produces 1-link chains at a time.
    root_creds = AgentCredentials.generate()
    middle_creds = AgentCredentials.generate()

    now = datetime.now(timezone.utc)
    # Root has the loosest expiry; middle tightens; leaf will be clamped
    # to middle's expiry.
    root_expires = _format_iso_ms_z(now + timedelta(days=30))
    middle_expires = _format_iso_ms_z(now + timedelta(days=3))

    root_issuer = PassportIssuer(root_creds, identity_claim="root@x.y")
    root_signed = root_issuer.self_issue(
        permissions=[{"permission_key": "api:read", "constraints": {}}],
        expires_in=timedelta(days=30),
        delegation_authority=True,
    )
    # Override root's expiry by reconstructing the envelope + signature.
    root_env = root_signed.envelope.model_copy(
        update={
            "provenance": root_signed.envelope.provenance.model_copy(
                update={"expires_at": root_expires}
            )
        }
    )
    root_sig = base64.b64encode(
        nacl.signing.SigningKey(root_creds.private_key_bytes)
        .sign(canonicalize_strict(root_env.model_dump(mode="json")))
        .signature
    ).decode("ascii")
    root_signed_clean = SignedPassport(envelope=root_env, signature=root_sig)

    # Middle: delegated from root, tightened expiry.
    middle_builder = (
        DelegationBuilder(parent=root_signed_clean, parent_credentials=root_creds)
        .authorize(child_credentials=middle_creds)
        .with_permissions([{"permission_key": "api:read", "constraints": {}}])
        .with_expiry(expires_in=timedelta(days=3))
        .with_delegation_authority(True)
    )
    middle_signed = middle_builder.sign()

    # Leaf: asks for 10 days, should clamp to middle's 3 days.
    leaf_creds = AgentCredentials.generate()
    leaf_builder = (
        DelegationBuilder(parent=middle_signed, parent_credentials=middle_creds)
        .authorize(child_credentials=leaf_creds)
        .with_permissions([{"permission_key": "api:read", "constraints": {}}])
        .with_expiry(expires_in=timedelta(days=10))
    )
    assert leaf_builder.expiry_was_clamped is True
    middle_expires_dt = DelegationBuilder._parse_z_ms(
        middle_signed.envelope.provenance.expires_at
    )
    assert leaf_builder.effective_expires_at == middle_expires_dt

    leaf_signed = leaf_builder.sign()
    result = PassportVerifier().verify(leaf_signed.envelope, leaf_signed.signature)
    assert result.valid is True, f"unexpected BLOCK: {result.reason_code} {result.detail}"


# ---------------------------------------------------------------------------
# 10. parent without delegation_authority
# ---------------------------------------------------------------------------


def test_parent_without_delegation_authority_raises() -> None:
    parent_creds = AgentCredentials.generate()
    parent_signed = _issue_self(parent_creds, delegation_authority=False)
    child_creds = AgentCredentials.generate()
    builder = (
        DelegationBuilder(parent=parent_signed, parent_credentials=parent_creds)
        .authorize(child_credentials=child_creds)
        .with_permissions([{"permission_key": "api:read", "constraints": {}}])
    )
    with pytest.raises(DelegationAuthorityMissingError):
        builder.sign()


# ---------------------------------------------------------------------------
# 11–12. chain depth boundary
# ---------------------------------------------------------------------------


def _build_deep_chain(target_depth: int) -> tuple[SignedPassport, AgentCredentials]:
    """Build a delegated SignedPassport whose delegation_chain has exactly
    ``target_depth`` entries (1 ≤ target_depth ≤ 5). Returns (leaf_signed,
    leaf_private_credentials)."""
    # Start with a self-rooted parent. Each iteration delegates down one level
    # keeping delegation_authority=True until we hit target_depth.
    root_creds = AgentCredentials.generate()
    current_signed = _issue_self(root_creds)
    current_creds = root_creds

    # Depth after first delegation = 1. Each subsequent delegation adds 1.
    for _ in range(target_depth):
        next_creds = AgentCredentials.generate()
        current_signed = (
            DelegationBuilder(parent=current_signed, parent_credentials=current_creds)
            .authorize(child_credentials=next_creds)
            .with_permissions([{"permission_key": "api:read", "constraints": {}}])
            .with_delegation_authority(True)
            .sign()
        )
        current_creds = next_creds
    return current_signed, current_creds


def test_chain_depth_boundary_5_permits() -> None:
    """Build a 4-link chain parent; delegating adds +1 → 5-link child (OK)."""
    parent_signed, parent_creds = _build_deep_chain(target_depth=4)
    assert len(parent_signed.envelope.provenance.delegation_chain) == 4

    child_creds = AgentCredentials.generate()
    child_signed = (
        DelegationBuilder(parent=parent_signed, parent_credentials=parent_creds)
        .authorize(child_credentials=child_creds)
        .with_permissions([{"permission_key": "api:read", "constraints": {}}])
        .sign()
    )
    assert len(child_signed.envelope.provenance.delegation_chain) == 5

    result = PassportVerifier().verify(child_signed.envelope, child_signed.signature)
    assert result.valid is True, f"unexpected BLOCK: {result.reason_code} {result.detail}"


def test_chain_depth_boundary_6_rejects_presign() -> None:
    """5-link parent → would make 6-link child; pre-sign raises."""
    parent_signed, parent_creds = _build_deep_chain(target_depth=5)
    assert len(parent_signed.envelope.provenance.delegation_chain) == 5

    child_creds = AgentCredentials.generate()
    builder = (
        DelegationBuilder(parent=parent_signed, parent_credentials=parent_creds)
        .authorize(child_credentials=child_creds)
        .with_permissions([{"permission_key": "api:read", "constraints": {}}])
    )
    with pytest.raises(DelegationChainTooDeepError) as exc_info:
        builder.sign()
    assert exc_info.value.chain_length == 6


# ---------------------------------------------------------------------------
# 13. issuer.id structural correctness
# ---------------------------------------------------------------------------


def test_delegated_issuer_id_references_chain_root() -> None:
    """Even in a multi-link chain, child.issuer.id references chain[0]
    (root) passport_id, not the immediate parent's."""
    parent_signed, parent_creds = _build_deep_chain(target_depth=3)
    root_passport_id = parent_signed.envelope.provenance.delegation_chain[0].passport_json.passport_id

    child_creds = AgentCredentials.generate()
    child_signed = (
        DelegationBuilder(parent=parent_signed, parent_credentials=parent_creds)
        .authorize(child_credentials=child_creds)
        .with_permissions([{"permission_key": "api:read", "constraints": {}}])
        .sign()
    )
    assert child_signed.envelope.provenance.issuer.id == "delegate:" + root_passport_id
    # parent.passport_id is NOT the root here (depth-3 chain) — confirm.
    assert parent_signed.envelope.passport_id != root_passport_id


# ---------------------------------------------------------------------------
# 14. cross-backend byte parity (delegation fixture)
# ---------------------------------------------------------------------------
#
# Ground truth generated 2026-04-22 via
# ``~/Projects/modei/scripts/sdk_parity_fixture.ts`` (delegation section).
# Deterministic seeds: root = 32 zero bytes, leaf = bytes(range(32)).
# Backend verifyPassportWithChain returned {"valid": true, "tier": "L0"}.
#
# If this test fails, STOP. Canonicalizer or signer drifted from backend.
# Release-blocker per spec §11.2 and §13 row 23/26.

FX_ROOT_PUB_B64 = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
FX_ROOT_PRIV_SEED = bytes(32)
FX_LEAF_PUB_B64 = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
FX_LEAF_PRIV_SEED = bytes(range(32))
FX_ROOT_AGENT_ID = "agent_self_E545QOZLVJFyIIjZoNdBYo_IJuCUddNB"
FX_LEAF_AGENT_ID = "agent_self_Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3"
FX_ISSUED_AT = "2026-04-22T00:00:00.000Z"
FX_EXPIRES_AT = "2026-05-22T00:00:00.000Z"

# Hex constants are single contiguous string literals (no concatenation,
# no line wrapping). Regenerated 2026-04-22 from the tsx fixture script
# output — do NOT hand-edit. Any mismatch against backend means the
# canonicalizer or the envelope field mapping drifted.
FX_ROOT_CANONICAL_HEX = "7b2264656c65676174696f6e5f617574686f72697479223a747275652c226964656e74697479223a7b226167656e745f6964223a226167656e745f73656c665f45353435514f5a4c564a467949496a5a6f4e6442596f5f494a75435564644e42222c226167656e745f6e616d65223a22726f6f74406465762e6c6f63616c222c227075626c69635f6b6579223a224f326f6e764d3632704331696f366a514b6d384e6332557946586364346b4f6d4f7342496f59745a32696b3d227d2c2270617373706f72745f6964223a2270705f73656c665f666978747572655f726f6f74222c227065726d697373696f6e73223a5b7b22636f6e73747261696e7473223a7b7d2c227065726d697373696f6e5f6b6579223a226170693a72656164227d5d2c2270726f76656e616e6365223a7b22636174616c6f675f636f6e74656e745f68617368223a6e756c6c2c22636174616c6f675f76657273696f6e223a6e756c6c2c2264656c65676174696f6e5f636861696e223a6e756c6c2c22657870697265735f6174223a22323032362d30352d32325430303a30303a30302e3030305a222c22676174655f6964223a6e756c6c2c226973737565645f6174223a22323032362d30342d32325430303a30303a30302e3030305a222c22697373756572223a7b226964223a2273656c663a31333965333934306536346235343931373232303838643961306437343136323866633832366530393437356433343161373830616364653363346238303730222c226b65795f6964223a2273656c66222c2274797065223a2273656c66227d7d2c22736368656d615f76657273696f6e223a322c22766572696669636174696f6e5f65766964656e6365223a5b5d7d"
FX_LEAF_CANONICAL_HEX = "7b2264656c65676174696f6e5f617574686f72697479223a66616c73652c226964656e74697479223a7b226167656e745f6964223a226167656e745f73656c665f566b64617031526a52307743686439647679764b747a326d555457494f656d33222c226167656e745f6e616d65223a226c656166406465762e6c6f63616c222c227075626c69635f6b6579223a2241364548762f504f454c3464634e3059353076416d57666b316a436270513166486479475a424a564d62673d227d2c2270617373706f72745f6964223a2270705f64656c65676174655f666978747572655f6c656166222c227065726d697373696f6e73223a5b7b22636f6e73747261696e7473223a7b7d2c227065726d697373696f6e5f6b6579223a226170693a72656164227d5d2c2270726f76656e616e6365223a7b22636174616c6f675f636f6e74656e745f68617368223a6e756c6c2c22636174616c6f675f76657273696f6e223a6e756c6c2c2264656c65676174696f6e5f636861696e223a5b7b2270617373706f72745f6a736f6e223a7b2264656c65676174696f6e5f617574686f72697479223a747275652c226964656e74697479223a7b226167656e745f6964223a226167656e745f73656c665f45353435514f5a4c564a467949496a5a6f4e6442596f5f494a75435564644e42222c226167656e745f6e616d65223a22726f6f74406465762e6c6f63616c222c227075626c69635f6b6579223a224f326f6e764d3632704331696f366a514b6d384e6332557946586364346b4f6d4f7342496f59745a32696b3d227d2c2270617373706f72745f6964223a2270705f73656c665f666978747572655f726f6f74222c227065726d697373696f6e73223a5b7b22636f6e73747261696e7473223a7b7d2c227065726d697373696f6e5f6b6579223a226170693a72656164227d5d2c2270726f76656e616e6365223a7b22636174616c6f675f636f6e74656e745f68617368223a6e756c6c2c22636174616c6f675f76657273696f6e223a6e756c6c2c2264656c65676174696f6e5f636861696e223a6e756c6c2c22657870697265735f6174223a22323032362d30352d32325430303a30303a30302e3030305a222c22676174655f6964223a6e756c6c2c226973737565645f6174223a22323032362d30342d32325430303a30303a30302e3030305a222c22697373756572223a7b226964223a2273656c663a31333965333934306536346235343931373232303838643961306437343136323866633832366530393437356433343161373830616364653363346238303730222c226b65795f6964223a2273656c66222c2274797065223a2273656c66227d7d2c22736368656d615f76657273696f6e223a322c22766572696669636174696f6e5f65766964656e6365223a5b5d7d2c227369676e6174757265223a225044336d544957792b58716d756138346f745a4b354f48654b77742f4d67316f736b49524268334378515949495531464e355776612f524154665a3449434d544e66764a6972537053724438377439347465665342673d3d227d5d2c22657870697265735f6174223a22323032362d30352d32325430303a30303a30302e3030305a222c22676174655f6964223a6e756c6c2c226973737565645f6174223a22323032362d30342d32325430303a30303a30302e3030305a222c22697373756572223a7b226964223a2264656c65676174653a70705f73656c665f666978747572655f726f6f74222c226b65795f6964223a2273656c66222c2274797065223a2264656c6567617465227d7d2c22736368656d615f76657273696f6e223a322c22766572696669636174696f6e5f65766964656e6365223a5b5d7d"
FX_ROOT_SIGNATURE_B64 = "PD3mTIWy+Xqmua84otZK5OHeKwt/Mg1oskIRBh3CxQYIIU1FN5Wva/RATfZ4ICMTNfvJirSpSrD87t94tefSBg=="


def _build_fixture_root() -> Envelope:
    """Construct the root envelope per the tsx fixture script."""
    import hashlib

    pk_bytes = base64.b64decode(FX_ROOT_PUB_B64)
    return Envelope(
        schema_version=2,
        passport_id="pp_self_fixture_root",
        identity=PassportIdentity(
            agent_id=FX_ROOT_AGENT_ID,
            agent_name="root@dev.local",
            public_key=FX_ROOT_PUB_B64,
        ),
        permissions=[PassportPermission(permission_key="api:read", constraints={})],
        provenance=PassportProvenance(
            issuer=EnvelopeIssuer(
                type="self",
                id="self:" + hashlib.sha256(pk_bytes).hexdigest(),
                key_id="self",
            ),
            gate_id=None,
            catalog_content_hash=None,
            catalog_version=None,
            delegation_chain=None,
            issued_at=FX_ISSUED_AT,
            expires_at=FX_EXPIRES_AT,
        ),
        delegation_authority=True,
        verification_evidence=[],
    )


def _build_fixture_leaf(root: Envelope, root_signature: str) -> Envelope:
    return Envelope(
        schema_version=2,
        passport_id="pp_delegate_fixture_leaf",
        identity=PassportIdentity(
            agent_id=FX_LEAF_AGENT_ID,
            agent_name="leaf@dev.local",
            public_key=FX_LEAF_PUB_B64,
        ),
        permissions=[PassportPermission(permission_key="api:read", constraints={})],
        provenance=PassportProvenance(
            issuer=EnvelopeIssuer(
                type="delegate", id="delegate:pp_self_fixture_root", key_id="self"
            ),
            gate_id=None,
            catalog_content_hash=None,
            catalog_version=None,
            delegation_chain=[
                DelegationChainEntry(passport_json=root, signature=root_signature),
            ],
            issued_at=FX_ISSUED_AT,
            expires_at=FX_EXPIRES_AT,
        ),
        delegation_authority=False,
        verification_evidence=[],
    )


FX_LEAF_SIGNATURE_B64 = (
    "q6SVXu7fc0Qt9+IyQAib+T8W2d3veWh6PiCJLQjlJcAdfTMMzAJYd/vpOZ6p98q/crjrLa+vq9pR+Phi/YDTBQ=="
)


def test_delegation_cross_backend_byte_parity() -> None:
    """Backend ground-truth byte equality for root + leaf canonical bytes
    AND signatures. The tsx script ran backend verifyPassportWithChain and
    confirmed {"valid": true, "tier": "L0"} for this fixture; SDK verifier
    here must produce the same verdict.
    """
    root = _build_fixture_root()
    root_canonical = canonicalize_strict(root.model_dump(mode="json"))
    # Canonical-bytes assertion runs BEFORE the signature assertion: on
    # failure, diff shows which envelope bytes drifted — diagnosable.
    # The signature assertion alone would only tell us the signature
    # differs, with no clue why.
    assert root_canonical.hex() == FX_ROOT_CANONICAL_HEX, (
        "root canonical bytes diverged from backend — release blocker"
    )
    root_sig_b64 = base64.b64encode(
        nacl.signing.SigningKey(FX_ROOT_PRIV_SEED).sign(root_canonical).signature
    ).decode("ascii")
    assert root_sig_b64 == FX_ROOT_SIGNATURE_B64, (
        "root signature diverged from backend — release blocker"
    )

    leaf = _build_fixture_leaf(root, root_sig_b64)
    leaf_canonical = canonicalize_strict(leaf.model_dump(mode="json"))
    assert leaf_canonical.hex() == FX_LEAF_CANONICAL_HEX, (
        "leaf canonical bytes diverged from backend — release blocker"
    )
    leaf_sig_b64 = base64.b64encode(
        nacl.signing.SigningKey(FX_ROOT_PRIV_SEED).sign(leaf_canonical).signature
    ).decode("ascii")
    assert leaf_sig_b64 == FX_LEAF_SIGNATURE_B64, (
        "leaf signature diverged from backend — release blocker"
    )

    # SDK verifier agrees with backend's chain_verify = {valid:true, tier:L0}.
    result = PassportVerifier().verify(leaf, leaf_sig_b64)
    assert result.valid is True
    assert result.tier == TrustTier.L0


# ---------------------------------------------------------------------------
# extra: parent_credentials public-key mismatch detection
# ---------------------------------------------------------------------------


def test_parent_credentials_mismatch_raises() -> None:
    parent_creds = AgentCredentials.generate()
    wrong_creds = AgentCredentials.generate()  # different keypair
    parent_signed = _issue_self(parent_creds)
    with pytest.raises(DelegationError, match="parent_credentials public key"):
        DelegationBuilder(parent=parent_signed, parent_credentials=wrong_creds)
