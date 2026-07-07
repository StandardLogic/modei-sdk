# Modei

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-green)](https://modelcontextprotocol.io)

The trust layer for AI agents. Gates protect your tools. Passports authorize your agents. Everything verified locally.

This repo contains three packages:

| Package | Directory | Published as | Description |
|---------|-----------|--------------|-------------|
| **MCP Server** | [`mcp/`](mcp/) | [`modei-mcp`](https://www.npmjs.com/package/modei-mcp) on npm | MCP server for managing Modei infrastructure from Claude, Cursor, or any MCP client |
| **Python SDK** | [`python/`](python/) | [`modei-python`](https://pypi.org/project/modei-python/) on PyPI | Identity and settlement library plus a thin REST client: passport issuance, signing, verification, consumption attestations |
| **TypeScript SDK** | [`typescript/`](typescript/) | [`modei-typescript`](https://www.npmjs.com/package/modei-typescript) on npm | Identity library: self-issued passports, Ed25519 signing, local verification, attenuated delegation |

---

## MCP Server

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
        "MODEI_API_KEY": "mod_xxxxxxxx"
      }
    }
  }
}
```

See [`mcp/README.md`](mcp/README.md) for full documentation.

---

## Python SDK

[![PyPI version](https://img.shields.io/pypi/v/modei-python)](https://pypi.org/project/modei-python/)

```bash
pip install modei-python
```

```python
from modei import ModeiClient

client = ModeiClient(api_key="mod_xxxxxxxx")
gates = client.list_gates()
```

See [`python/README.md`](python/README.md) for full documentation.

---

## TypeScript SDK

[![npm version](https://img.shields.io/npm/v/modei-typescript)](https://www.npmjs.com/package/modei-typescript)

```bash
npm install modei-typescript
```

```ts
import { AgentCredentials, PassportIssuer } from 'modei-typescript';

const creds = AgentCredentials.generate();
const passport = new PassportIssuer(creds, { identityClaim: 'alice@dev.local' })
  .selfIssue({
    permissions: [{ permission_key: 'api:read', constraints: {} }],
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });
```

See [`typescript/README.md`](typescript/README.md) for full documentation.

---

## License

MIT — [Standard Logic Co.](https://standardlogic.ai)
