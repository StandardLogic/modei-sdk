"""Pydantic v2 models for the Modei API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


class Gate(BaseModel):
    gate_id: str
    name: str
    description: Optional[str] = None
    profile: Literal["L1", "L2", "L3"] = "L1"
    allow_self_issued: bool = False
    is_discoverable: bool = False
    current_catalog_version: int = 0
    created_at: Optional[str] = None
    deleted_at: Optional[str] = None


class GateCreate(BaseModel):
    name: str
    gate_id: str
    description: Optional[str] = None
    profile: Literal["L1", "L2", "L3"] = "L1"
    allow_self_issued: Optional[bool] = None


class GateUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    profile: Optional[Literal["L1", "L2", "L3"]] = None
    allow_self_issued: Optional[bool] = None
    is_discoverable: Optional[bool] = None


# ---------------------------------------------------------------------------
# Passports
# ---------------------------------------------------------------------------


class Passport(BaseModel):
    passport_id: str
    gate_id: str
    agent_id: str
    agent_name: Optional[str] = None
    issuer_id: Optional[str] = None
    permissions: list[str] = Field(default_factory=list)
    constraints: Optional[dict[str, Any]] = None
    passport_json: Optional[str] = None
    signature: Optional[str] = None
    public_key: Optional[str] = None
    expires_at: Optional[str] = None
    revoked_at: Optional[str] = None
    created_at: Optional[str] = None
    catalog_version: Optional[int] = None
    catalog_content_hash: Optional[str] = None


class PassportIssue(BaseModel):
    agent_id: str
    agent_name: Optional[str] = None
    agent_public_key: Optional[str] = None
    permissions: list[str]
    constraints: Optional[dict[str, Any]] = None
    expires_in_seconds: Optional[int] = None
    expires_in: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Issuers
# ---------------------------------------------------------------------------


class Issuer(BaseModel):
    issuer_id: str
    name: str
    description: Optional[str] = None
    public_key: Optional[str] = None
    created_at: Optional[str] = None
    revoked_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Attestations
# ---------------------------------------------------------------------------


class Attestation(BaseModel):
    id: str
    gate_id: str
    passport_id: Optional[str] = None
    agent_id: Optional[str] = None
    action: Optional[str] = None
    target: Optional[str] = None
    decision: Optional[str] = None
    reason_code: Optional[str] = None
    signature: Optional[str] = None
    attestation_json: Optional[str] = None
    created_at: Optional[str] = None


class AttestationRecord(BaseModel):
    passport_id: str
    agent_id: str
    permission: str
    tool_name: str
    result: Literal["allowed", "denied"]
    denial_code: Optional[str] = None
    input_hash: Optional[str] = None
    output_hash: Optional[str] = None
    constraints_used: Optional[dict[str, Any]] = None
    execution_ms: Optional[int] = None
    metadata: Optional[dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Permission Catalog
# ---------------------------------------------------------------------------


class CatalogPermission(BaseModel):
    permission_key: str
    display_name: str
    description: str
    risk_level: Literal["low", "medium", "high", "critical"] = "low"
    min_trust_level: Literal[1, 2, 3] = 1
    constraints: Optional[dict[str, Any]] = None


class CatalogCreate(BaseModel):
    version: Optional[str] = None
    catalog_name: Optional[str] = None
    description: Optional[str] = None
    permissions: list[CatalogPermission]
    is_active: bool = True


class CatalogSnapshot(BaseModel):
    gate_id: str
    version: int = 0
    published_at: Optional[str] = None
    permissions: list[dict[str, Any]] = Field(default_factory=list)


class PublishedCatalog(BaseModel):
    gate_id: str
    version: int
    catalog_snapshot: Optional[dict[str, Any]] = None
    content_hash: Optional[str] = None
    signature: Optional[str] = None
    signing_key_id: Optional[str] = None
    effective_at: Optional[str] = None
    change_summary: Optional[str] = None
    changes: Optional[list[dict[str, Any]]] = None
    has_breaking_changes: bool = False
    created_at: Optional[str] = None


class PublishResult(BaseModel):
    version: int
    content_hash: str
    signature: str
    changes: list[dict[str, Any]] = Field(default_factory=list)
    has_breaking_changes: bool = False


# ---------------------------------------------------------------------------
# Constraints & Templates
# ---------------------------------------------------------------------------


class ConstraintType(BaseModel):
    constraint_key: str
    namespace: Optional[str] = None
    name: str
    description: Optional[str] = None
    value_type: str
    unit: Optional[str] = None
    category: str
    evaluation_order: int = 0
    is_system: bool = True


class ConstraintTemplate(BaseModel):
    slug: str
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    icon: Optional[str] = None
    constraints: dict[str, Any] = Field(default_factory=dict)
    is_system: bool = False


# ---------------------------------------------------------------------------
# Enforcement (CEL)
# ---------------------------------------------------------------------------


class EnforceRequest(BaseModel):
    passport_id: str
    action: str
    target: Optional[str] = None
    cost_cents: Optional[int] = None
    metadata: Optional[dict[str, Any]] = None


class EnforceResult(BaseModel):
    decision: Literal["PERMIT", "BLOCK", "SUSPEND"]
    evaluations: list[dict[str, Any]] = Field(default_factory=list)
    blocked_by: Optional[str] = None
    block_reason: Optional[str] = None
    cumulative_cost: Optional[int] = None
    attestation_id: Optional[str] = None
    sequence_number: Optional[int] = None


class EnforcementAttestation(BaseModel):
    id: str
    passport_id: str
    gate_id: str
    action: str
    target: Optional[str] = None
    decision: str
    constraint_evaluations: Optional[list[dict[str, Any]]] = None
    signature: Optional[str] = None
    attestation_json: Optional[str] = None
    sequence_number: Optional[int] = None
    created_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Anonymous Access
# ---------------------------------------------------------------------------


class AnonymousPolicy(BaseModel):
    enabled: bool = False
    allowed_actions: list[str] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)
    rate_limit_per_minute: int = 5
    rate_limit_per_hour: int = 50
    read_only: bool = True
    upgrade_message: Optional[str] = None
    upgrade_url: Optional[str] = None


# ---------------------------------------------------------------------------
# Cumulative State
# ---------------------------------------------------------------------------


class CumulativeState(BaseModel):
    id: Optional[str] = None
    passport_id: str
    window_type: str
    window_start: Optional[str] = None
    cost_cumulative_cents: int = 0
    action_counts: dict[str, int] = Field(default_factory=dict)
    rate_windows: dict[str, list[str]] = Field(default_factory=dict)
    sequence_number: int = 0
    last_attestation_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Commerce: Consumption Attestations
# ---------------------------------------------------------------------------


class AgentPoP(BaseModel):
    """Agent proof-of-possession for billable consumption attestations."""

    signature: str
    public_key: str
    timestamp: int  # Unix milliseconds
    nonce: str
    catalog_content_hash: str
    request_payload_hash: Optional[str] = None


class ConsumeRequest(BaseModel):
    passport_id: str
    gate_id: str
    action: str
    outcome: Literal["success", "error", "timeout", "partial"]
    quantity: int = 1
    agent_pop: Optional[AgentPoP] = None
    request_payload_hash: Optional[str] = None
    response_payload_hash: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class ConsumeResult(BaseModel):
    attestation_id: str
    cost_cents: str  # Decimal string
    platform_fee_cents: str  # Decimal string
    currency: str = "USD"
    pricing_model: Optional[str] = None
    catalog_version: Optional[int] = None
    catalog_content_hash: Optional[str] = None
    signature: Optional[str] = None


# ---------------------------------------------------------------------------
# Commerce: Discovery
# ---------------------------------------------------------------------------


class DiscoveryResult(BaseModel):
    gate_id: str
    gate_name: Optional[str] = None
    permission_key: str
    pricing_model: Optional[str] = None
    price_cents: Optional[int] = None
    currency: str = "USD"
    uptime_basis_points: Optional[int] = None
    response_time_ms: Optional[int] = None
    platform_fee_basis_points: Optional[int] = None
    catalog_version: Optional[int] = None
    catalog_content_hash: Optional[str] = None
    catalog_signature: Optional[str] = None
    signing_key_id: Optional[str] = None
    security_profile: Optional[str] = None


class DiscoveryQuery(BaseModel):
    capability: str
    max_price_cents: Optional[int] = None
    min_uptime_bp: Optional[int] = None
    max_response_time_ms: Optional[int] = None
    pricing_model: Optional[str] = None
    sort: Optional[str] = None
    limit: int = 20
    offset: int = 0


# ---------------------------------------------------------------------------
# Commerce: Settlement & Billing
# ---------------------------------------------------------------------------


class SettlementRequest(BaseModel):
    gate_id: str
    period_type: Literal["daily", "weekly", "monthly"]
    period_start: str  # YYYY-MM-DD
    period_end: str  # YYYY-MM-DD
    agent_id: Optional[str] = None


class SettlementSummary(BaseModel):
    id: str
    settlement_run_id: Optional[str] = None
    gate_id: str
    agent_id: Optional[str] = None
    period_type: str
    period_start: str
    period_end: str
    total_cost_cents: int = 0
    total_platform_fee_cents: int = 0
    total_transactions: int = 0
    verified_count: int = 0
    excluded_count: int = 0
    currency: str = "USD"
    permission_breakdown: Optional[dict[str, Any]] = None
    outcome_breakdown: Optional[dict[str, Any]] = None
    content_hash: Optional[str] = None
    status: str = "pending"
    created_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Commerce: SLA
# ---------------------------------------------------------------------------


class SLAMetric(BaseModel):
    permission_key: str
    total_requests: int = 0
    success_count: int = 0
    error_count: int = 0
    timeout_count: int = 0
    partial_count: int = 0
    uptime_basis_points: int = 0
    sla_uptime_bp: Optional[int] = None
    compliant: bool = True


class SLAComplianceReport(BaseModel):
    gate_id: str
    period_start: str
    period_end: str
    metrics: list[SLAMetric] = Field(default_factory=list)
    overall_uptime_bp: int = 0
    overall_compliant: bool = True


# ---------------------------------------------------------------------------
# Gate Check
# ---------------------------------------------------------------------------


class CheckResult(BaseModel):
    allowed: bool
    decision: Optional[str] = None
    reason_code: Optional[str] = None
    access_mode: Optional[str] = None
    attestation_id: Optional[str] = None
    checks: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Passport Reissue
# ---------------------------------------------------------------------------


class ReissueResult(BaseModel):
    passport_id: str
    passport_json: Optional[str] = None
    signature: Optional[str] = None
    public_key: Optional[str] = None
    expires_at: Optional[str] = None
    catalog_version: Optional[int] = None
    catalog_content_hash: Optional[str] = None
    revoked_passport_id: Optional[str] = None
    terms_changed: bool = False
    has_breaking_changes: bool = False
    changes: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


class VerifyResult(BaseModel):
    valid: bool
    reason: Optional[str] = None
    signing_key_id: Optional[str] = None
