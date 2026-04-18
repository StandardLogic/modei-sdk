"""Modei Python SDK — trust infrastructure for AI agents."""

from .async_client import AsyncModeiClient
from .client import ModeiClient
from .crypto import (
    compute_content_hash,
    verify_attestation_signature,
    verify_content_hash,
    verify_ed25519,
)
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    NotFoundError,
    ModeiError,
    RateLimitError,
    ValidationError,
)
from .types import (
    AgentPoP,
    AnonymousPolicy,
    Attestation,
    AttestationRecord,
    CatalogCreate,
    CatalogPermission,
    CatalogSnapshot,
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
    Issuer,
    Passport,
    PassportIssue,
    PublishedCatalog,
    PublishResult,
    ReissueResult,
    SettlementRequest,
    SettlementSummary,
    SLAComplianceReport,
    SLAMetric,
    VerifyResult,
)

__all__ = [
    # Clients
    "ModeiClient",
    "AsyncModeiClient",
    # Exceptions
    "ModeiError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "RateLimitError",
    "ValidationError",
    "ConflictError",
    # Crypto
    "verify_ed25519",
    "compute_content_hash",
    "verify_attestation_signature",
    "verify_content_hash",
    # Types — Gates
    "Gate",
    "GateCreate",
    "GateUpdate",
    # Types — Passports
    "Passport",
    "PassportIssue",
    # Types — Issuers
    "Issuer",
    # Types — Attestations
    "Attestation",
    "AttestationRecord",
    # Types — Catalog
    "CatalogPermission",
    "CatalogCreate",
    "CatalogSnapshot",
    "PublishedCatalog",
    "PublishResult",
    # Types — Constraints
    "ConstraintType",
    "ConstraintTemplate",
    # Types — Enforcement
    "EnforceRequest",
    "EnforceResult",
    "EnforcementAttestation",
    # Types — Anonymous
    "AnonymousPolicy",
    # Types — State
    "CumulativeState",
    # Types — Commerce
    "AgentPoP",
    "ConsumeRequest",
    "ConsumeResult",
    "DiscoveryResult",
    "DiscoveryQuery",
    "SettlementRequest",
    "SettlementSummary",
    "SLAMetric",
    "SLAComplianceReport",
    # Types — Check & Verify
    "CheckResult",
    "ReissueResult",
    "VerifyResult",
]

__version__ = "1.1.0"
