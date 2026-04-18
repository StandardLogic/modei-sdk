"""Typed exceptions for the Modei SDK."""

from __future__ import annotations

from typing import Any, Optional


class ModeiError(Exception):
    """Base exception for all Modei SDK errors."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        body: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class AuthenticationError(ModeiError):
    """Raised when the API key is invalid or missing (HTTP 401)."""


class AuthorizationError(ModeiError):
    """Raised when the API key lacks required scopes (HTTP 403)."""


class NotFoundError(ModeiError):
    """Raised when the requested resource does not exist (HTTP 404)."""


class RateLimitError(ModeiError):
    """Raised when rate limits are exceeded (HTTP 429)."""

    def __init__(
        self,
        message: str,
        retry_after: Optional[float] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class ValidationError(ModeiError):
    """Raised when request parameters fail validation (HTTP 400/422)."""


class ConflictError(ModeiError):
    """Raised on resource conflicts like duplicate nonces (HTTP 409)."""
