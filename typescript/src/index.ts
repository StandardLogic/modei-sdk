#!/usr/bin/env node

/**
 * Modei Management MCP Server
 *
 * A thin adapter that exposes Modei Dashboard operations as MCP tools.
 * Enables developers to manage issuers, passports, and gates directly from Claude.
 *
 * Usage:
 *   MODEI_API_KEY=sk_xxx npx modei-mcp
 *   MODEI_API_KEY=mod_xxx npx modei-mcp
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { ApiClient } from './api-client.js';
import { allTools, handleToolCall } from './tools/index.js';
import { createRealtimeAdapter, computeFingerprint, type RealtimeConfig, type AgentCredentials } from './realtime.js';

// Configuration from environment
const MODEI_API_URL = process.env.MODEI_API_URL || 'https://modei.ai';
const MODEI_API_KEY = process.env.MODEI_API_KEY;

// Realtime configuration (opt-in)
const MODEI_REALTIME_ENABLED = process.env.MODEI_REALTIME_ENABLED === 'true';
const MODEI_SUPABASE_URL = process.env.MODEI_SUPABASE_URL;
const MODEI_REALTIME_TOKEN_ENDPOINT = process.env.MODEI_REALTIME_TOKEN_ENDPOINT || `${MODEI_API_URL}/api/auth/realtime-token`;

// Agent/Passport credentials for Realtime + heartbeat
const MODEI_AGENT_ID = process.env.MODEI_AGENT_ID;
const MODEI_PASSPORT_ID = process.env.MODEI_PASSPORT_ID;
const MODEI_PASSPORT_PRIVATE_KEY = process.env.MODEI_PASSPORT_PRIVATE_KEY; // Base64
const MODEI_PASSPORT_PUBLIC_KEY = process.env.MODEI_PASSPORT_PUBLIC_KEY;   // Base64

async function main() {
  // Validate configuration
  if (!MODEI_API_KEY) {
    console.error('Error: MODEI_API_KEY environment variable is required');
    console.error('');
    console.error('Usage:');
    console.error('  MODEI_API_KEY=sk_xxx npx modei-mcp');
    console.error('');
    console.error('Or for local development:');
    console.error('  MODEI_API_KEY=mod_xxx npx modei-mcp');
    process.exit(1);
  }

  // Initialize API client
  const api = new ApiClient({
    baseUrl: MODEI_API_URL,
    apiKey: MODEI_API_KEY,
  });

  // Create MCP server
  const server = new Server(
    {
      name: 'modei',
      version: '1.0.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // Handle list_tools request
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: allTools };
  });

  // Handle call_tool request
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      const result = await handleToolCall(api, name, args || {});

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';

      return {
        content: [
          {
            type: 'text',
            text: `Error: ${message}`,
          },
        ],
        isError: true,
      };
    }
  });

  // Start server with stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Log to stderr (stdout is reserved for MCP protocol)
  console.error(`Modei Management MCP Server started`);
  console.error(`  API URL: ${MODEI_API_URL}`);
  console.error(`  API Key: ${MODEI_API_KEY.slice(0, 10)}...`);

  // ── Startup heartbeat ──────────────────────────────────────────
  if (MODEI_AGENT_ID && MODEI_PASSPORT_ID) {
    try {
      const heartbeatRes = await fetch(`${MODEI_API_URL}/api/agents/${MODEI_AGENT_ID}/heartbeat`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${MODEI_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          passport_id: MODEI_PASSPORT_ID,
          sdk: 'modei-mcp',
          sdk_version: '1.0.0',
          runtime: 'nodejs',
          env: process.env.NODE_ENV || 'development',
          started_at: new Date().toISOString(),
        }),
      });
      if (heartbeatRes.ok) {
        console.error(`  Heartbeat sent for agent ${MODEI_AGENT_ID}`);
      } else {
        console.error(`  Heartbeat failed: ${heartbeatRes.status}`);
      }
    } catch (err) {
      console.error(`  Heartbeat error:`, err);
    }
  }

  // ── Realtime connection (opt-in) ───────────────────────────────
  if (MODEI_REALTIME_ENABLED && MODEI_SUPABASE_URL && MODEI_AGENT_ID && MODEI_PASSPORT_ID && MODEI_PASSPORT_PRIVATE_KEY && MODEI_PASSPORT_PUBLIC_KEY) {
    try {
      const realtimeConfig: RealtimeConfig = {
        enabled: true,
        supabaseUrl: MODEI_SUPABASE_URL,
        tokenEndpoint: MODEI_REALTIME_TOKEN_ENDPOINT,
      };

      const credentials: AgentCredentials = {
        agentId: MODEI_AGENT_ID,
        passportId: MODEI_PASSPORT_ID,
        passportFingerprint: computeFingerprint(MODEI_PASSPORT_PUBLIC_KEY),
        privateKey: MODEI_PASSPORT_PRIVATE_KEY,
        publicKey: MODEI_PASSPORT_PUBLIC_KEY,
      };

      const adapter = createRealtimeAdapter(realtimeConfig, credentials, MODEI_API_KEY);
      await adapter.connect();
      console.error(`  Realtime connected for agent ${MODEI_AGENT_ID}`);
    } catch (err) {
      console.error(`  Realtime connection failed (non-fatal):`, err);
    }
  } else if (MODEI_REALTIME_ENABLED) {
    console.error(`  Realtime enabled but missing required env vars (MODEI_SUPABASE_URL, MODEI_AGENT_ID, MODEI_PASSPORT_ID, MODEI_PASSPORT_PRIVATE_KEY, MODEI_PASSPORT_PUBLIC_KEY)`);
  }
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
