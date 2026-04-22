"""Subset-permissions + constraints-tightening + expiry-non-extension.

Private module: shared by ``verifier.py`` (verify-time enforcement) and
``delegation.py`` (pre-sign validation). The pre-sign verdict MUST match
the verify-time verdict for identical inputs — that's the whole point
of pre-sign (fail fast locally rather than at the wire).

Mirror of backend ``src/lib/passports/chain.ts`` lines 285–446:
``enforceSubsetPermissions``, ``enforceConstraintsTightening``,
``checkDimension``, ``deepEqual``.

Exposed names used by verifier.py and delegation.py:
    enforce_subset_permissions(ancestor, descendant) -> SubsetCheck
    is_expiry_non_extending(ancestor, descendant) -> bool
"""

from __future__ import annotations

from typing import Any, NamedTuple, Optional

from .envelope import Envelope

_NUMERIC_TIGHTEN = frozenset(
    {
        "max_per_action_cost",
        "max_daily_cost",
        "max_total_cost",
        "rate_limit_per_minute",
        "rate_limit_per_hour",
    }
)
_SET_INCLUDE = frozenset({"allowed_domains", "allowed_paths", "allowed_models"})


class SubsetCheck(NamedTuple):
    ok: bool
    detail: Optional[str]  # None when ok

    @classmethod
    def passed(cls) -> "SubsetCheck":
        return cls(ok=True, detail=None)

    @classmethod
    def failed(cls, detail: str) -> "SubsetCheck":
        return cls(ok=False, detail=detail)


def deep_equal(a: Any, b: Any) -> bool:
    """Structural equality. Matches backend ``deepEqual`` semantics
    (Python's `==` is already structural for dict/list)."""
    return a == b


def check_constraint_dimension(
    dim: str, ancestor_val: Any, descendant_val: Any
) -> SubsetCheck:
    """Return ``SubsetCheck.passed()`` if descendant tightens-or-equals
    ancestor; otherwise a failure with the spec-required detail message.
    """
    if dim in _NUMERIC_TIGHTEN:
        if not isinstance(ancestor_val, (int, float)) or isinstance(ancestor_val, bool):
            return SubsetCheck.failed(f"'{dim}' must be numeric on both sides")
        if not isinstance(descendant_val, (int, float)) or isinstance(descendant_val, bool):
            return SubsetCheck.failed(f"'{dim}' must be numeric on both sides")
        if descendant_val > ancestor_val:
            return SubsetCheck.failed(
                f"'{dim}' descendant={descendant_val} > ancestor={ancestor_val}"
            )
        return SubsetCheck.passed()

    if dim in _SET_INCLUDE:
        if not isinstance(ancestor_val, list) or not isinstance(descendant_val, list):
            return SubsetCheck.failed(f"'{dim}' must be an array on both sides")
        anc_set = set(ancestor_val)
        for v in descendant_val:
            if v not in anc_set:
                return SubsetCheck.failed(
                    f"'{dim}' descendant entry {v!r} not in ancestor"
                )
        return SubsetCheck.passed()

    # operating_hours and unknown dimensions fall back to deep-equality.
    if not deep_equal(ancestor_val, descendant_val):
        if dim == "operating_hours":
            return SubsetCheck.failed(
                "'operating_hours' descendant differs from ancestor "
                "(deep-equality required)"
            )
        return SubsetCheck.failed(
            f"unknown constraint dimension '{dim}' must match ancestor exactly"
        )
    return SubsetCheck.passed()


def enforce_subset_permissions(
    ancestor: Envelope, descendant: Envelope
) -> SubsetCheck:
    """Pairwise subset check: for every descendant permission, the ancestor
    must have a matching ``permission_key`` AND every constraint dimension
    in the descendant must tighten-or-equal the ancestor's value for that
    dimension. Dimensions absent in the descendant are inherited
    (§3.5); dimensions absent in the ancestor cannot be added by the
    descendant.
    """
    ancestor_by_key = {p.permission_key: p for p in ancestor.permissions}
    for desc_perm in descendant.permissions:
        anc_perm = ancestor_by_key.get(desc_perm.permission_key)
        if anc_perm is None:
            return SubsetCheck.failed(
                f"descendant permission {desc_perm.permission_key!r} "
                "not present in ancestor"
            )
        for dim, desc_val in desc_perm.constraints.items():
            if dim not in anc_perm.constraints:
                return SubsetCheck.failed(
                    f"permission '{desc_perm.permission_key}': constraint '{dim}' "
                    "absent in ancestor; descendant cannot add it"
                )
            check = check_constraint_dimension(dim, anc_perm.constraints[dim], desc_val)
            if not check.ok:
                return SubsetCheck.failed(
                    f"permission '{desc_perm.permission_key}': {check.detail}"
                )
    return SubsetCheck.passed()


def is_expiry_non_extending(ancestor: Envelope, descendant: Envelope) -> bool:
    """True if ``descendant.expires_at <= ancestor.expires_at``.

    Compares the ISO 8601 Z-suffixed millisecond strings lexicographically,
    which is sound for this format (same result as chronological compare).
    """
    return descendant.provenance.expires_at <= ancestor.provenance.expires_at
