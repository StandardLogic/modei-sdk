# modus-mcp

<!-- mcp-name: io.github.standardlogic/modus-manage -->

[![npm version](https://img.shields.io/npm/v/modus-mcp)](https://www.npmjs.com/package/modus-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-green)](https://modelcontextprotocol.io)

MCP server for managing [Modus](https://modustrust.ai) agent governance infrastructure — passports, gates, constraints, enforcement, and audit — directly from Claude, Cursor, or any MCP client.

---

## What is Modus?

[Modus](https://modustrust.ai) is the trust layer for AI agents. It has two sides:

**Gates** protect your tools, APIs, and MCP servers. A Gate is a verification checkpoint — you define a permission catalog of what's allowed, and incoming agent requests are checked against it locally, with no network round-trip. Every decision produces a signed attestation for a tamper-evident audit trail.

**Passports** are signed credentials that agents carry. Each passport specifies who issued it, what the agent is allowed to do, and under what constraints — scoped to specific actions, resources, and time windows.

This MCP server lets you manage both sides conversationally from any MCP client.


---

## Prerequisites

- A **Modus account** — sign up at the [Modus Dashboard](https://modustrust.ai)
- **Claude Desktop**, **Claude Code**, **Cursor**, or any MCP-compatible client
- An **API key** — generate one from the dashboard

---

## Quick Start

### Connect with API Key (Claude Desktop, any MCP client)

Add Modus to your MCP configuration:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "modus": {
      "command": "npx",
      "args": ["modus-mcp"],
      "env": {
        "MODUS_API_KEY": "mod_live_xxxxxxxx"
      }
    }
  }
}
```

### Add to Claude Code

```bash
claude mcp add modus \
  --scope user \
  -- npx modus-mcp \
  --env MODUS_API_KEY=mod_live_xxxxxxxx
```

Restart your client and you're ready to go.

---

## Available Tools (45)

### Gates (5)

| Tool | Description |
|------|-------------|
| `list_gates` | List all gates you own |
| `get_gate` | Get details for a specific gate |
| `create_gate` | Create a new gate with a trust profile (L1/L2/L3) |
| `update_gate` | Update settings for an existing gate |
| `delete_gate` | Delete (archive) a gate |

### Passports (5)

| Tool | Description |
|------|-------------|
| `list_passports` | List all active passports for a gate |
| `get_passport` | Get details for a specific passport |
| `issue_passport` | Issue a new passport to an agent with permissions and constraints |
| `revoke_passport` | Revoke a passport immediately |
| `reissue_passport` | Re-issue a passport pinned to a newer catalog version |

### Attestations (2)

| Tool | Description |
|------|-------------|
| `list_attestations` | List attestations (audit log) for a gate with filters |
| `record_attestation` | Record a new attestation |

### Permission Catalog (6)

| Tool | Description |
|------|-------------|
| `get_catalog` | Get the active draft catalog for a gate |
| `create_catalog` | Create or update the permission catalog |
| `publish_catalog` | Build, sign, and atomically publish a catalog snapshot |
| `list_catalog_versions` | List all published catalog versions |
| `get_catalog_version` | Get a specific published catalog version |
| `get_catalog_impact` | Get impact analysis for pending catalog changes |

### Gate Check (2)

| Tool | Description |
|------|-------------|
| `check_gate` | Test a passport against a gate (allow/deny preview) |
| `authorize_dry_run` | Test authorization without executing |

### Constraints & Templates (6)

| Tool | Description |
|------|-------------|
| `get_constraints` | Get constraints for a passport |
| `set_constraints` | Set constraints on a passport |
| `list_constraint_types` | List available constraint type definitions |
| `list_constraint_templates` | List system and user constraint templates |
| `apply_constraint_template` | Apply a constraint template to a passport |
| `create_constraint_template` | Create a user constraint template |

### Enforcement — CEL (4)

| Tool | Description |
|------|-------------|
| `enforce_action` | Evaluate constraints and record an enforcement attestation |
| `list_enforcement_attestations` | List enforcement attestations for a passport |
| `get_enforcement_attestation` | Get a single enforcement attestation by ID |
| `verify_enforcement_attestation` | Verify the cryptographic signature of an enforcement attestation |

### Anonymous Access (3)

| Tool | Description |
|------|-------------|
| `get_anonymous_policy` | Get the anonymous access policy for a gate |
| `set_anonymous_policy` | Configure anonymous access policy |
| `get_anonymous_log` | Get the anonymous access audit log |

### Cumulative State (2)

| Tool | Description |
|------|-------------|
| `get_cumulative_state` | Get spending and rate limit state for a passport |
| `reset_cumulative_state` | Reset cumulative spending and rate counters |

### Commerce (7)

| Tool | Description |
|------|-------------|
| `discover_services` | Discover services by capability |
| `issue_consumption_attestation` | Issue a consumption attestation (bilateral metering) |
| `generate_settlement` | Generate a billing settlement for a period |
| `list_settlements` | List settlement summaries |
| `get_settlement` | Get a settlement by ID |
| `update_settlement_status` | Transition a settlement to a new status |
| `get_sla_compliance` | Get SLA compliance metrics for a gate |

### API Keys (3)

| Tool | Description |
|------|-------------|
| `list_api_keys` | List your API keys |
| `create_api_key` | Create a new API key with optional scopes |
| `revoke_api_key` | Revoke an API key |

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MODUS_API_KEY` | Yes | — | Your Modus API key (`mod_live_*` or `mod_test_*`) |
| `MODUS_API_URL` | No | `https://modustrust.ai` | API base URL (override for local dev) |

---

## Local Development

For local testing against a development dashboard:

```json
{
  "mcpServers": {
    "modus": {
      "command": "npx",
      "args": ["modus-mcp"],
      "env": {
        "MODUS_API_URL": "http://localhost:3000",
        "MODUS_API_KEY": "mod_test_xxxxxxxx"
      }
    }
  }
}
```

---

## Troubleshooting

**Server doesn't appear in Claude Desktop**
Make sure you've restarted Claude Desktop after editing the config file. Check for JSON syntax errors in your config.

**"Invalid API key" error**
Verify your key starts with `mod_live_` (production) or `mod_test_` (development) and hasn't been revoked.

**Tools aren't showing up**
Run `npx modus-mcp` directly in your terminal to check for startup errors. Ensure Node.js 18+.

---

## Learn More

- [Modus Dashboard](https://modustrust.ai) — Create your account and manage gates, passports, and API keys
- [Documentation & Guides](https://modustrust.ai)
- [MCP SDK (TypeScript)](https://www.npmjs.com/package/modus-mcp-sdk) · [MCP SDK (Python)](https://pypi.org/project/modus-mcp-sdk/)
- [Management SDK (Python)](https://pypi.org/project/modus-mcp/)
- [Discussions](https://github.com/StandardLogic/modus-mcp/discussions) — Questions and ideas

---

## License

MIT — [Standard Logic Co.](https://standardlogic.ai)

Building the trust infrastructure for AI agents.
