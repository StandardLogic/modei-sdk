"""Synchronous Modus client using httpx."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from ._http import (
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT,
    _build_headers,
    _clean_params,
    _parse_response,
)
from .types import (
    AnonymousPolicy,
    Attestation,
    AttestationRecord,
    CatalogCreate,
    CheckResult,
    ConsumeRequest,
    ConsumeResult,
    ConstraintTemplate,
    ConstraintType,
    CumulativeState,
    DiscoveryQuery,
    DiscoveryResult,
    EnforceRequest,
    EnforceResult,
    EnforcementAttestation,
    Gate,
    GateCreate,
    GateUpdate,
    Passport,
    PassportIssue,
    PublishResult,
    PublishedCatalog,
    ReissueResult,
    SLAComplianceReport,
    SettlementRequest,
    SettlementSummary,
    VerifyResult,
)


class ModusClient:
    """Synchronous client for the Modus REST API.

    Args:
        api_key: Modus API key (e.g. ``mod_live_xxx``).
        base_url: API base URL. Defaults to ``https://modustrust.ai``.
        timeout: Request timeout in seconds. Defaults to 30.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self._base_url,
            headers=_build_headers(api_key),
            timeout=timeout,
        )

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> ModusClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # -- internal helpers ---------------------------------------------------

    def _get(self, path: str, params: Optional[dict[str, Any]] = None) -> Any:
        resp = self._client.get(path, params=_clean_params(params))
        return _parse_response(resp)

    def _post(self, path: str, json: Optional[Any] = None) -> Any:
        resp = self._client.post(path, json=json)
        return _parse_response(resp)

    def _patch(self, path: str, json: Optional[Any] = None) -> Any:
        resp = self._client.patch(path, json=json)
        return _parse_response(resp)

    def _put(self, path: str, json: Optional[Any] = None) -> Any:
        resp = self._client.put(path, json=json)
        return _parse_response(resp)

    def _delete(self, path: str) -> Any:
        resp = self._client.delete(path)
        return _parse_response(resp)

    # ======================================================================
    # Gates
    # ======================================================================

    def list_gates(self) -> list[dict[str, Any]]:
        """List all gates you own."""
        return self._get("/api/gates")

    def get_gate(self, gate_id: str) -> dict[str, Any]:
        """Get details for a specific gate."""
        return self._get(f"/api/gates/{gate_id}")

    def create_gate(
        self,
        *,
        name: str,
        gate_id: str,
        profile: str = "L1",
        description: Optional[str] = None,
        allow_self_issued: Optional[bool] = None,
    ) -> dict[str, Any]:
        """Create a new gate."""
        body = GateCreate(
            name=name,
            gate_id=gate_id,
            profile=profile,  # type: ignore[arg-type]
            description=description,
            allow_self_issued=allow_self_issued,
        )
        return self._post("/api/gates", json=body.model_dump(exclude_none=True))

    def update_gate(self, gate_id: str, **kwargs: Any) -> dict[str, Any]:
        """Update settings for an existing gate."""
        body = GateUpdate(**kwargs)
        return self._patch(f"/api/gates/{gate_id}", json=body.model_dump(exclude_none=True))

    def delete_gate(self, gate_id: str) -> dict[str, Any]:
        """Delete (archive) a gate."""
        return self._delete(f"/api/gates/{gate_id}")

    # ======================================================================
    # Passports
    # ======================================================================

    def list_passports(self, gate_id: str) -> list[dict[str, Any]]:
        """List all active passports for a gate."""
        return self._get(f"/api/gates/{gate_id}/passports")

    def get_passport(self, gate_id: str, passport_id: str) -> dict[str, Any]:
        """Get details for a specific passport."""
        return self._get(f"/api/gates/{gate_id}/passports/{passport_id}")

    def issue_passport(
        self,
        gate_id: str,
        *,
        agent_id: str,
        permissions: list[str],
        agent_name: Optional[str] = None,
        agent_public_key: Optional[str] = None,
        constraints: Optional[dict[str, Any]] = None,
        expires_in_seconds: Optional[int] = None,
        expires_in: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Issue a new passport to an agent."""
        body = PassportIssue(
            agent_id=agent_id,
            permissions=permissions,
            agent_name=agent_name,
            agent_public_key=agent_public_key,
            constraints=constraints,
            expires_in_seconds=expires_in_seconds,
            expires_in=expires_in,
            metadata=metadata,
        )
        return self._post(
            f"/api/gates/{gate_id}/passports",
            json=body.model_dump(exclude_none=True),
        )

    def revoke_passport(self, gate_id: str, passport_id: str) -> dict[str, Any]:
        """Revoke a passport immediately."""
        return self._delete(f"/api/gates/{gate_id}/passports/{passport_id}")

    def reissue_passport(
        self,
        passport_id: str,
        *,
        accept_catalog_version: Optional[int] = None,
    ) -> dict[str, Any]:
        """Re-issue a passport pinned to a newer catalog version."""
        body: dict[str, Any] = {}
        if accept_catalog_version is not None:
            body["accept_catalog_version"] = accept_catalog_version
        return self._post(f"/api/passports/{passport_id}/reissue", json=body)

    # ======================================================================
    # Attestations
    # ======================================================================

    def list_attestations(
        self,
        gate_id: str,
        *,
        passport_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        permission: Optional[str] = None,
        since: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """List attestations (audit log) for a gate."""
        return self._get(
            f"/api/gates/{gate_id}/attestations",
            params={
                "passport_id": passport_id,
                "agent_id": agent_id,
                "permission": permission,
                "since": since,
                "limit": limit,
            },
        )

    def record_attestation(
        self, gate_id: str, **kwargs: Any
    ) -> dict[str, Any]:
        """Record a new attestation."""
        return self._post(f"/api/gates/{gate_id}/attestations", json=kwargs)

    # ======================================================================
    # Permission Catalog
    # ======================================================================

    def get_catalog(self, gate_id: str) -> dict[str, Any]:
        """Get the active draft catalog for a gate."""
        return self._get(f"/api/gates/{gate_id}/catalog")

    def create_catalog(self, gate_id: str, **kwargs: Any) -> dict[str, Any]:
        """Create or update the permission catalog for a gate."""
        return self._post(f"/api/gates/{gate_id}/catalog", json=kwargs)

    def publish_catalog(
        self,
        gate_id: str,
        *,
        change_summary: Optional[str] = None,
        effective_at: Optional[str] = None,
    ) -> dict[str, Any]:
        """Build, sign, and atomically publish a catalog snapshot."""
        body: dict[str, Any] = {}
        if change_summary is not None:
            body["change_summary"] = change_summary
        if effective_at is not None:
            body["effective_at"] = effective_at
        return self._post(f"/api/gates/{gate_id}/catalog/publish", json=body)

    def list_catalog_versions(self, gate_id: str) -> list[dict[str, Any]]:
        """List all published catalog versions (metadata only)."""
        return self._get(f"/api/gates/{gate_id}/catalog/versions")

    def get_catalog_version(self, gate_id: str, version: int) -> dict[str, Any]:
        """Get a specific published catalog version."""
        return self._get(f"/api/gates/{gate_id}/catalog/{version}")

    def get_catalog_impact(self, gate_id: str) -> dict[str, Any]:
        """Get impact analysis for pending catalog changes."""
        return self._get(f"/api/gates/{gate_id}/catalog/impact")

    # ======================================================================
    # Gate Check (Authorization)
    # ======================================================================

    def check_gate(
        self,
        gate_id: str,
        *,
        action: str,
        passport_id: Optional[str] = None,
        target: Optional[str] = None,
    ) -> dict[str, Any]:
        """Test a passport against a gate."""
        body: dict[str, Any] = {"action": action}
        if passport_id is not None:
            body["passport_id"] = passport_id
        if target is not None:
            body["target"] = target
        return self._post(f"/api/gates/{gate_id}/check", json=body)

    # ======================================================================
    # Constraints
    # ======================================================================

    def get_constraints(self, passport_id: str) -> dict[str, Any]:
        """Get constraints for a passport."""
        return self._get(f"/api/passports/{passport_id}/constraints")

    def set_constraints(
        self, passport_id: str, constraints: dict[str, Any]
    ) -> dict[str, Any]:
        """Set constraints on a passport."""
        return self._put(f"/api/passports/{passport_id}/constraints", json=constraints)

    def list_constraint_types(
        self, *, category: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """List available constraint type definitions."""
        return self._get("/api/constraints/types", params={"category": category})

    def list_constraint_templates(
        self, *, category: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """List system and user constraint templates."""
        return self._get("/api/constraint-templates", params={"category": category})

    def apply_constraint_template(
        self, passport_id: str, template_slug: str
    ) -> dict[str, Any]:
        """Apply a constraint template to a passport."""
        return self._post(
            f"/api/passports/{passport_id}/constraints",
            json={"template_slug": template_slug},
        )

    def create_constraint_template(self, **kwargs: Any) -> dict[str, Any]:
        """Create a user constraint template."""
        return self._post("/api/constraint-templates", json=kwargs)

    # ======================================================================
    # Enforcement (CEL)
    # ======================================================================

    def enforce_action(
        self,
        *,
        passport_id: str,
        action: str,
        target: Optional[str] = None,
        cost_cents: Optional[int] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Evaluate constraints and record an enforcement attestation."""
        body = EnforceRequest(
            passport_id=passport_id,
            action=action,
            target=target,
            cost_cents=cost_cents,
            metadata=metadata,
        )
        return self._post("/api/enforce", json=body.model_dump(exclude_none=True))

    def list_enforcement_attestations(
        self,
        passport_id: str,
        *,
        decision: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """List enforcement attestations for a passport."""
        return self._get(
            f"/api/passports/{passport_id}/enforcement",
            params={"decision": decision, "limit": limit},
        )

    def get_enforcement_attestation(self, attestation_id: str) -> dict[str, Any]:
        """Get a single enforcement attestation by ID."""
        return self._get(f"/api/enforcement/{attestation_id}")

    def verify_enforcement_attestation(self, attestation_id: str) -> dict[str, Any]:
        """Verify the cryptographic signature of an enforcement attestation."""
        return self._post(f"/api/enforcement/{attestation_id}/verify")

    # ======================================================================
    # Anonymous Access
    # ======================================================================

    def get_anonymous_policy(self, gate_id: str) -> dict[str, Any]:
        """Get the anonymous access policy for a gate."""
        return self._get(f"/api/gates/{gate_id}/anonymous-policy")

    def set_anonymous_policy(
        self, gate_id: str, **kwargs: Any
    ) -> dict[str, Any]:
        """Configure anonymous access policy on a gate."""
        return self._put(f"/api/gates/{gate_id}/anonymous-policy", json=kwargs)

    def get_anonymous_log(self, gate_id: str) -> list[dict[str, Any]]:
        """Get the anonymous access audit log for a gate."""
        return self._get(f"/api/gates/{gate_id}/anonymous-log")

    # ======================================================================
    # Cumulative State
    # ======================================================================

    def get_cumulative_state(self, passport_id: str) -> dict[str, Any]:
        """Get spending and rate limit state for a passport."""
        return self._get(f"/api/passports/{passport_id}/state")

    def reset_cumulative_state(
        self,
        passport_id: str,
        *,
        window_type: Optional[str] = None,
    ) -> dict[str, Any]:
        """Reset cumulative spending and rate counters."""
        body: dict[str, Any] = {}
        if window_type is not None:
            body["window_type"] = window_type
        return self._post(f"/api/passports/{passport_id}/state/reset", json=body)

    # ======================================================================
    # Commerce: Consumption Attestations
    # ======================================================================

    def issue_consumption_attestation(
        self,
        *,
        passport_id: str,
        gate_id: str,
        action: str,
        outcome: str,
        quantity: int = 1,
        agent_pop: Optional[dict[str, Any]] = None,
        request_payload_hash: Optional[str] = None,
        response_payload_hash: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Issue a consumption attestation (bilateral metering)."""
        body: dict[str, Any] = {
            "passport_id": passport_id,
            "gate_id": gate_id,
            "action": action,
            "outcome": outcome,
            "quantity": quantity,
        }
        if agent_pop is not None:
            body["agent_pop"] = agent_pop
        if request_payload_hash is not None:
            body["request_payload_hash"] = request_payload_hash
        if response_payload_hash is not None:
            body["response_payload_hash"] = response_payload_hash
        if metadata is not None:
            body["metadata"] = metadata
        return self._post("/api/consume", json=body)

    # ======================================================================
    # Commerce: Discovery
    # ======================================================================

    def discover_services(
        self,
        capability: str,
        *,
        max_price_cents: Optional[int] = None,
        min_uptime_bp: Optional[int] = None,
        max_response_time_ms: Optional[int] = None,
        pricing_model: Optional[str] = None,
        sort: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Discover services by capability (public, no auth required)."""
        return self._get(
            "/api/discover",
            params={
                "capability": capability,
                "max_price_cents": max_price_cents,
                "min_uptime_bp": min_uptime_bp,
                "max_response_time_ms": max_response_time_ms,
                "pricing_model": pricing_model,
                "sort": sort,
                "limit": limit,
                "offset": offset,
            },
        )

    # ======================================================================
    # Commerce: Settlement & Billing
    # ======================================================================

    def generate_settlement(
        self,
        *,
        gate_id: str,
        period_type: str,
        period_start: str,
        period_end: str,
        agent_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Generate a billing settlement for a period."""
        body = SettlementRequest(
            gate_id=gate_id,
            period_type=period_type,  # type: ignore[arg-type]
            period_start=period_start,
            period_end=period_end,
            agent_id=agent_id,
        )
        return self._post("/api/billing", json=body.model_dump(exclude_none=True))

    def list_settlements(
        self,
        *,
        gate_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        period_type: Optional[str] = None,
        status: Optional[str] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List settlement summaries."""
        return self._get(
            "/api/billing",
            params={
                "gate_id": gate_id,
                "agent_id": agent_id,
                "period_type": period_type,
                "status": status,
                "from": from_date,
                "to": to_date,
                "limit": limit,
                "offset": offset,
            },
        )

    def get_settlement(self, settlement_id: str) -> dict[str, Any]:
        """Get a settlement by ID."""
        return self._get(f"/api/billing/{settlement_id}")

    def update_settlement_status(
        self, settlement_id: str, status: str
    ) -> dict[str, Any]:
        """Transition a settlement to a new status."""
        return self._post(f"/api/billing/{settlement_id}/status", json={"status": status})

    # ======================================================================
    # Commerce: SLA Compliance
    # ======================================================================

    def get_sla_compliance(
        self,
        gate_id: str,
        *,
        period_start: str,
        period_end: str,
        permission_key: Optional[str] = None,
    ) -> dict[str, Any]:
        """Get SLA compliance metrics for a gate."""
        return self._get(
            f"/api/gates/{gate_id}/sla",
            params={
                "period_start": period_start,
                "period_end": period_end,
                "permission_key": permission_key,
            },
        )

    # ======================================================================
    # Dry-Run Authorization
    # ======================================================================

    def authorize_dry_run(
        self,
        *,
        gate_id: str,
        passport: dict[str, Any],
        requested_permission: str,
        requested_constraints: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Test authorization without executing."""
        body: dict[str, Any] = {
            "gate_id": gate_id,
            "passport": passport,
            "requested_permission": requested_permission,
        }
        if requested_constraints is not None:
            body["requested_constraints"] = requested_constraints
        return self._post("/api/authorize/dry-run", json=body)

    # ======================================================================
    # API Keys
    # ======================================================================

    def list_api_keys(self) -> list[dict[str, Any]]:
        """List your API keys."""
        return self._get("/api/users/api-keys")

    def create_api_key(
        self,
        *,
        name: str,
        scopes: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Create a new API key."""
        body: dict[str, Any] = {"name": name}
        if scopes is not None:
            body["scopes"] = scopes
        return self._post("/api/users/api-keys", json=body)

    def revoke_api_key(self, key_id: str) -> dict[str, Any]:
        """Revoke an API key."""
        return self._delete(f"/api/users/api-keys/{key_id}")
