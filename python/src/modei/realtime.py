"""
Modei Realtime Adapter (Python)

Handles Supabase Realtime connection for agent presence and verification.
This module is opt-in: install with `pip install modei-sdk[realtime]`.

Features:
- Exchange passport for short-lived Realtime JWT
- Track Presence with agent/passport metadata
- Respond to verify.request broadcasts with signed nonce
- Token refresh every 4 minutes
- Cleanup on exit
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx

try:
    from nacl.signing import SigningKey
    from supabase import create_client, Client as SupabaseClient
except ImportError:
    raise ImportError(
        "Realtime support requires additional dependencies. "
        "Install with: pip install modei-sdk[realtime]"
    )

VERSION = "1.2.0"


@dataclass
class RealtimeConfig:
    """Configuration for Realtime connection."""
    enabled: bool = False
    supabase_url: str = ""
    token_endpoint: str = ""


@dataclass
class AgentCredentials:
    """Agent passport credentials for Realtime auth."""
    agent_id: str = ""
    passport_id: str = ""
    passport_fingerprint: str = ""
    private_key_base64: str = ""  # Ed25519 private key (base64)
    public_key_base64: str = ""   # Ed25519 public key (base64)


def compute_fingerprint(public_key_base64: str) -> str:
    """Compute SHA-256 fingerprint of the passport public key."""
    import base64
    pub_bytes = base64.b64decode(public_key_base64)
    digest = hashlib.sha256(pub_bytes).hexdigest()
    return f"sha256:{digest}"


class RealtimeAdapter:
    """
    Manages Supabase Realtime connection for agent presence and verification.

    Usage::

        config = RealtimeConfig(
            enabled=True,
            supabase_url="https://xyz.supabase.co",
            token_endpoint="https://modeitrust.ai/api/auth/realtime-token",
        )
        credentials = AgentCredentials(
            agent_id="agent_abc123",
            passport_id="pass_xyz",
            passport_fingerprint=compute_fingerprint(public_key_b64),
            private_key_base64="...",
            public_key_base64="...",
        )
        adapter = RealtimeAdapter(config, credentials, api_key="mod_live_...")
        await adapter.connect()
    """

    def __init__(
        self,
        config: RealtimeConfig,
        credentials: AgentCredentials,
        api_key: str,
    ):
        self.config = config
        self.credentials = credentials
        self.api_key = api_key
        self._supabase: Optional[SupabaseClient] = None
        self._channel: Any = None
        self._refresh_task: Optional[asyncio.Task] = None
        self._started_at: str = ""

    async def _exchange_for_token(self) -> str:
        """Exchange passport proof for a short-lived Realtime JWT."""
        import base64

        challenge = os.urandom(32).hex()
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Sign the challenge with the passport private key
        private_key_bytes = base64.b64decode(self.credentials.private_key_base64)
        signing_key = SigningKey(private_key_bytes)
        signed = signing_key.sign(challenge.encode("utf-8"))
        signature_hex = signed.signature.hex()

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.config.token_endpoint,
                json={
                    "agent_id": self.credentials.agent_id,
                    "passport_id": self.credentials.passport_id,
                    "challenge": challenge,
                    "signature": signature_hex,
                    "timestamp": timestamp,
                },
            )
            response.raise_for_status()
            data = response.json()
            return data["token"]

    def _sign_nonce(self, nonce: str) -> str:
        """Sign a nonce with the passport private key."""
        import base64

        private_key_bytes = base64.b64decode(self.credentials.private_key_base64)
        signing_key = SigningKey(private_key_bytes)
        signed = signing_key.sign(nonce.encode("utf-8"))
        return signed.signature.hex()

    async def connect(self) -> None:
        """Connect to Supabase Realtime and track Presence."""
        self._started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Step 1: Exchange passport for Realtime token
        token = await self._exchange_for_token()

        # Step 2: Create Supabase client with the token
        self._supabase = create_client(self.config.supabase_url, token)

        # Step 3: Join channel and track Presence
        channel_name = f"agent:{self.credentials.agent_id}"
        self._channel = self._supabase.channel(channel_name)

        # Listen for verify.request broadcasts
        self._channel.on_broadcast(
            event="verify.request",
            callback=self._handle_verify_request,
        )

        # Subscribe and track presence
        await self._channel.subscribe()
        await self._channel.track({
            "agent_id": self.credentials.agent_id,
            "passport_id": self.credentials.passport_id,
            "passport_fingerprint": self.credentials.passport_fingerprint,
            "sdk": "modei-sdk",
            "sdk_version": VERSION,
            "runtime": "python",
            "env": os.environ.get("MODEI_ENV", "development"),
            "started_at": self._started_at,
        })

        # Step 4: Start token refresh loop
        self._refresh_task = asyncio.create_task(self._refresh_loop())

        # Step 5: Register cleanup handlers
        for sig in (signal.SIGTERM, signal.SIGINT):
            asyncio.get_event_loop().add_signal_handler(sig, self.disconnect)

    async def _refresh_loop(self) -> None:
        """Refresh the Realtime token every 4 minutes."""
        while True:
            await asyncio.sleep(4 * 60)
            try:
                new_token = await self._exchange_for_token()
                if self._supabase:
                    self._supabase.realtime.set_auth(new_token)
            except Exception as e:
                print(f"[modei-realtime] Token refresh failed: {e}", flush=True)

    def _handle_verify_request(self, payload: dict) -> None:
        """Handle verify.request broadcast by signing the nonce."""
        try:
            nonce = payload.get("payload", {}).get("nonce", "")
            if not nonce:
                return

            signature = self._sign_nonce(nonce)

            if self._channel:
                self._channel.send_broadcast(
                    event="verify.response",
                    data={
                        "nonce": nonce,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "uptime_seconds": int(time.monotonic()),
                        "passport_fingerprint": self.credentials.passport_fingerprint,
                        "sdk_version": f"modei-sdk@{VERSION}",
                        "signature": signature,
                    },
                )
        except Exception as e:
            print(f"[modei-realtime] Failed to respond to verify challenge: {e}", flush=True)

    def disconnect(self) -> None:
        """Disconnect from Realtime and clean up."""
        if self._refresh_task:
            self._refresh_task.cancel()
            self._refresh_task = None

        if self._channel:
            try:
                self._channel.untrack()
                self._channel.unsubscribe()
            except Exception:
                pass
            self._channel = None

        if self._supabase:
            try:
                self._supabase.remove_all_channels()
            except Exception:
                pass
            self._supabase = None


async def send_heartbeat(
    api_url: str,
    api_key: str,
    agent_id: str,
    passport_id: str,
    sdk_version: str = VERSION,
    runtime: str = "python",
    env: str = "development",
) -> bool:
    """Send a one-time startup heartbeat to the Modei API."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{api_url}/api/agents/{agent_id}/heartbeat",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "passport_id": passport_id,
                    "sdk": "modei-sdk",
                    "sdk_version": sdk_version,
                    "runtime": runtime,
                    "env": env,
                    "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
            )
            return response.is_success
        except Exception:
            return False
