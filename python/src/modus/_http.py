"""Low-level HTTP transport shared by sync and async clients."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    NotFoundError,
    ModusError,
    RateLimitError,
    ValidationError,
)

DEFAULT_BASE_URL = "https://modustrust.ai"
DEFAULT_TIMEOUT = 30.0


def _raise_for_status(response: httpx.Response) -> None:
    """Map HTTP error status codes to typed exceptions."""
    if response.is_success:
        return

    try:
        body = response.json()
        message = body.get("message") or body.get("error") or f"API error: {response.status_code}"
    except Exception:
        body = None
        message = f"API error: {response.status_code} {response.reason_phrase}"

    kwargs: dict[str, Any] = {"status_code": response.status_code, "body": body}

    if response.status_code == 401:
        raise AuthenticationError(message, **kwargs)
    if response.status_code == 403:
        raise AuthorizationError(message, **kwargs)
    if response.status_code == 404:
        raise NotFoundError(message, **kwargs)
    if response.status_code == 409:
        raise ConflictError(message, **kwargs)
    if response.status_code == 429:
        retry_after = response.headers.get("retry-after")
        raise RateLimitError(
            message,
            retry_after=float(retry_after) if retry_after else None,
            **kwargs,
        )
    if response.status_code in (400, 422):
        raise ValidationError(message, **kwargs)

    raise ModusError(message, **kwargs)


def _parse_response(response: httpx.Response) -> Any:
    """Parse a successful HTTP response, handling 204 No Content."""
    _raise_for_status(response)
    if response.status_code == 204:
        return {}
    if not response.content:
        return {}
    return response.json()


def _build_headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


def _clean_params(params: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Remove None values from query params."""
    if params is None:
        return None
    return {k: v for k, v in params.items() if v is not None}
