# Modei

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-green)](https://modelcontextprotocol.io)

The trust layer for AI agents. Gates protect your tools. Passports authorize your agents. Everything verified locally.

This repo contains two packages:

| Package | Directory | Published as | Description |
|---------|-----------|-------------|-------------|
| **MCP Server** | [`typescript/`](typescript/) | [`modei-mcp`](https://www.npmjs.com/package/modei-mcp) on npm | MCP server for managing Modei infrastructure from Claude, Cursor, or any MCP client |
| **Python SDK** | [`python/`](python/) | [`modei-sdk`](https://pypi.org/project/modei-sdk/) on PyPI | Python REST API client for managing gates, passports, and enforcement policies |

---

## MCP Server (TypeScript)

[![npm version](https://img.shields.io/npm/v/modei-mcp)](https://www.npmjs.com/package/modei-mcp)

```bash
npx modei-mcp
```

Add to your MCP client config:

```json
{
  "mcpServers": {
    "modei": {
      "command": "npx",
      "args": ["modei-mcp"],
      "env": {
        "MODEI_API_KEY": "mod_live_xxxxxxxx"
      }
    }
  }
}
```

See [`typescript/README.md`](typescript/README.md) for full documentation.

---

## Python SDK

[![PyPI version](https://img.shields.io/pypi/v/modei-sdk)](https://pypi.org/project/modei-sdk/)

```bash
pip install modei-sdk
```

```python
from modei import ModeiClient

client = ModeiClient(api_key="mod_live_xxxxxxxx")
gates = client.list_gates()
```

See [`python/README.md`](python/README.md) for full documentation.

---

## License

MIT — [Standard Logic Co.](https://standardlogic.ai)
