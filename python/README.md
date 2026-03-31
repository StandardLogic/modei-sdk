# modus-sdk

[![PyPI version](https://img.shields.io/pypi/v/modus-sdk)](https://pypi.org/project/modus-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Python SDK for the [Modus](https://modustrust.ai) REST API. Manage agent passports, gates, and enforcement policies programmatically.

The MCP server (for Claude Desktop, Cursor, etc.) is the separate TypeScript package: [modus-mcp on npm](https://www.npmjs.com/package/modus-mcp).

---

## Installation

```bash
pip install modus-sdk
```

---

## Usage

```python
from modus import ModusClient

client = ModusClient(api_key="mod_live_xxx")

# List all gates
gates = client.list_gates()

# Create a gate
gate = client.create_gate(name="My API", gate_id="gate_my-api")

# Issue a passport
passport = client.issue_passport(
    "gate_my-api",
    agent_id="agent-001",
    permissions=["read", "write"],
    expires_in="7d",
)

# Check authorization
result = client.check_gate("gate_my-api", action="read", passport_id=passport["passport_id"])
print(result["allowed"])  # True

# Enforce with constraints
enforcement = client.enforce_action(
    passport_id=passport["passport_id"],
    action="write",
    cost_cents=500,
)
print(enforcement["decision"])  # "PERMIT"

client.close()
```

---

## Async Usage

```python
import asyncio
from modus import AsyncModusClient

async def main():
    async with AsyncModusClient(api_key="mod_live_xxx") as client:
        gates = await client.list_gates()
        for gate in gates:
            passports = await client.list_passports(gate["gate_id"])
            print(f"{gate['name']}: {len(passports)} passports")

asyncio.run(main())
```

Both clients support context managers for automatic cleanup:

```python
with ModusClient(api_key="mod_live_xxx") as client:
    gates = client.list_gates()
```

---

## API Coverage

### Gates

```python
client.list_gates()
client.get_gate("gate_my-api")
client.create_gate(name="My API", gate_id="gate_my-api")
client.update_gate("gate_my-api", name="Updated Name")
client.delete_gate("gate_my-api")
```

### Passports

```python
client.list_passports("gate_my-api")
client.get_passport("gate_my-api", "pp_xxx")
client.issue_passport("gate_my-api", agent_id="agent-001", permissions=["read"])
client.revoke_passport("gate_my-api", "pp_xxx")
client.reissue_passport("pp_xxx", accept_catalog_version=2)
```

### Attestations

```python
client.list_attestations("gate_my-api", limit=50)
client.record_attestation("gate_my-api", passport_id="pp_xxx", permission="read", tool_name="search", result="allowed")
```

### Permission Catalog

```python
client.get_catalog("gate_my-api")
client.create_catalog("gate_my-api", permissions=[...])
client.publish_catalog("gate_my-api", change_summary="Added search permission")
client.list_catalog_versions("gate_my-api")
client.get_catalog_version("gate_my-api", version=1)
client.get_catalog_impact("gate_my-api")
```

### Gate Check

```python
client.check_gate("gate_my-api", action="read", passport_id="pp_xxx")
client.authorize_dry_run(gate_id="gate_my-api", passport={"..."}, requested_permission="read")
```

### Constraints

```python
client.get_constraints("pp_xxx")
client.set_constraints("pp_xxx", {"read": {"core:rate:max_per_minute": 100}})
client.list_constraint_types(category="cost")
client.list_constraint_templates(category="security")
client.apply_constraint_template("pp_xxx", "conservative-agent")
client.create_constraint_template(slug="my-template", name="My Template", constraints={...})
```

### Enforcement (CEL)

```python
client.enforce_action(passport_id="pp_xxx", action="write", cost_cents=500)
client.list_enforcement_attestations("pp_xxx", decision="BLOCK")
client.get_enforcement_attestation("enf_xxx")
client.verify_enforcement_attestation("enf_xxx")
```

### Anonymous Access

```python
client.get_anonymous_policy("gate_my-api")
client.set_anonymous_policy("gate_my-api", enabled=True, allowed_actions=["read"])
client.get_anonymous_log("gate_my-api")
```

### Commerce

```python
client.discover_services("flights:search", max_price_cents=100, sort="price_asc")
client.issue_consumption_attestation(passport_id="pp_xxx", gate_id="gate_my-api", action="flights:search", outcome="success")
client.generate_settlement(gate_id="gate_my-api", period_type="monthly", period_start="2025-01-01", period_end="2025-01-31")
client.list_settlements(gate_id="gate_my-api", status="pending")
client.get_settlement("stl_xxx")
client.update_settlement_status("stl_xxx", "invoiced")
client.get_sla_compliance("gate_my-api", period_start="2025-01-01", period_end="2025-01-31")
```

### Cumulative State

```python
client.get_cumulative_state("pp_xxx")
client.reset_cumulative_state("pp_xxx", window_type="daily")
```

### API Keys

```python
client.list_api_keys()
client.create_api_key(name="My Key", scopes=["gates:read", "passports:write"])
client.revoke_api_key("key_xxx")
```

---

## Cryptographic Verification

Local verification utilities for Ed25519 signatures and RFC 8785 content hashing:

```python
from modus import verify_attestation_signature, verify_content_hash, compute_content_hash

valid = verify_attestation_signature(
    attestation_json='{"gate_id":"gate_my-api",...}',
    signature_b64="base64-sig...",
    public_key_b64="base64-key...",
)

matches = verify_content_hash(catalog_snapshot, expected_hash)
hash_hex = compute_content_hash({"key": "value"})
```

---

## Error Handling

```python
from modus import (
    ModusError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    ValidationError,
    ConflictError,
)

try:
    client.get_gate("gate_nonexistent")
except NotFoundError as e:
    print(f"Not found: {e}")
    print(f"Status: {e.status_code}")  # 404
except RateLimitError as e:
    print(f"Rate limited, retry after: {e.retry_after}s")
except ModusError as e:
    print(f"API error: {e} (HTTP {e.status_code})")
```

| Exception | HTTP Status |
|-----------|-------------|
| `AuthenticationError` | 401 |
| `AuthorizationError` | 403 |
| `NotFoundError` | 404 |
| `ConflictError` | 409 |
| `ValidationError` | 400, 422 |
| `RateLimitError` | 429 |
| `ModusError` | All other errors |

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MODUS_API_KEY` | Yes | — | Your Modus API key |
| `MODUS_API_URL` | No | `https://modustrust.ai` | API base URL (override for local dev) |

You can also pass these directly to the client:

```python
client = ModusClient(api_key="mod_live_xxx", base_url="http://localhost:3000")
```

---

## Documentation

Full documentation at [modustrust.ai/docs](https://modustrust.ai/docs)

---

## License

MIT — [Standard Logic Co.](https://standardlogic.ai)
