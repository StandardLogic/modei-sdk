/**
 * Comprehensive tests for all 45 MCP tool handlers.
 *
 * Strategy: mock global `fetch` and verify each handler sends
 * the correct HTTP method, URL, headers, body, and query params.
 */

import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import { ApiClient } from '../src/api-client.js';
import { handleToolCall } from '../src/tools/index.js';

const BASE_URL = 'https://modustrust.ai';
const API_KEY = 'mod_test_xxx';

let api: ApiClient;
let fetchMock: Mock;

/** Helper: create a mock Response for successful JSON replies. */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Helper: create a mock error Response. */
function errorResponse(status: number, body: { message?: string; error?: string } = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText: status === 401 ? 'Unauthorized' : status === 404 ? 'Not Found' : 'Error',
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Return the last fetch call's details. */
function lastCall() {
  const [url, init] = fetchMock.mock.calls[fetchMock.mock.calls.length - 1];
  return {
    url: url as string,
    method: (init as RequestInit).method!,
    headers: (init as RequestInit).headers as Record<string, string>,
    body: (init as RequestInit).body ? JSON.parse((init as RequestInit).body as string) : undefined,
  };
}

beforeEach(() => {
  fetchMock = vi.fn().mockResolvedValue(jsonResponse({}));
  vi.stubGlobal('fetch', fetchMock);
  api = new ApiClient({ baseUrl: BASE_URL, apiKey: API_KEY });
});


// ======================================================================
// Authentication
// ======================================================================

describe('Authentication', () => {
  it('includes Bearer token header', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([]));
    await handleToolCall(api, 'list_gates', {});
    expect(lastCall().headers['Authorization']).toBe(`Bearer ${API_KEY}`);
  });

  it('includes Content-Type header', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([]));
    await handleToolCall(api, 'list_gates', {});
    expect(lastCall().headers['Content-Type']).toBe('application/json');
  });
});


// ======================================================================
// Gates (5)
// ======================================================================

describe('Gates', () => {
  it('list_gates — GET /api/gates', async () => {
    const resp = [{ gate_id: 'gate_test-1' }];
    fetchMock.mockResolvedValueOnce(jsonResponse(resp));
    const result = await handleToolCall(api, 'list_gates', {});
    expect(result).toEqual(resp);
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/gates`);
  });

  it('get_gate — GET /api/gates/:id', async () => {
    const resp = { gate_id: 'gate_test-1', name: 'Test' };
    fetchMock.mockResolvedValueOnce(jsonResponse(resp));
    const result = await handleToolCall(api, 'get_gate', { gate_id: 'gate_test-1' });
    expect(result).toEqual(resp);
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/gates/gate_test-1`);
  });

  it('create_gate — POST /api/gates', async () => {
    const resp = { gate_id: 'gate_new', name: 'New' };
    fetchMock.mockResolvedValueOnce(jsonResponse(resp, 201));
    const result = await handleToolCall(api, 'create_gate', {
      name: 'New', gate_id: 'gate_new', profile: 'L1', description: 'A gate',
    });
    expect(result).toEqual(resp);
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/gates`);
    expect(call.body.name).toBe('New');
    expect(call.body.gate_id).toBe('gate_new');
    expect(call.body.profile).toBe('L1');
    expect(call.body.description).toBe('A gate');
  });

  it('update_gate — PATCH /api/gates/:id', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ gate_id: 'gate_test-1' }));
    await handleToolCall(api, 'update_gate', { gate_id: 'gate_test-1', name: 'Updated' });
    const call = lastCall();
    expect(call.method).toBe('PATCH');
    expect(call.url).toBe(`${BASE_URL}/api/gates/gate_test-1`);
    expect(call.body.name).toBe('Updated');
  });

  it('delete_gate — DELETE /api/gates/:id', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ deleted: true }));
    await handleToolCall(api, 'delete_gate', { gate_id: 'gate_test-1' });
    const call = lastCall();
    expect(call.method).toBe('DELETE');
    expect(call.url).toBe(`${BASE_URL}/api/gates/gate_test-1`);
  });
});


// ======================================================================
// Passports (5)
// ======================================================================

describe('Passports', () => {
  it('list_passports — GET /api/gates/:id/passports', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([{ passport_id: 'pp_abc' }]));
    const result = await handleToolCall(api, 'list_passports', { gate_id: 'gate_test-1' });
    expect(result).toEqual([{ passport_id: 'pp_abc' }]);
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/gates/gate_test-1/passports`);
  });

  it('get_passport — GET /api/gates/:id/passports/:pid', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ passport_id: 'pp_abc' }));
    await handleToolCall(api, 'get_passport', { gate_id: 'gate_test-1', passport_id: 'pp_abc' });
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/gates/gate_test-1/passports/pp_abc`);
  });

  it('issue_passport — POST /api/gates/:id/passports with body', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ passport_id: 'pp_new' }, 201));
    await handleToolCall(api, 'issue_passport', {
      gate_id: 'gate_test-1',
      agent_id: 'agent-1',
      permissions: ['read', 'write'],
      agent_name: 'Test Agent',
      constraints: { 'core:cost:max_per_action': 100 },
      expires_in: '24h',
      metadata: { env: 'test' },
    });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/gates/gate_test-1/passports`);
    expect(call.body.agent_id).toBe('agent-1');
    expect(call.body.permissions).toEqual(['read', 'write']);
    expect(call.body.agent_name).toBe('Test Agent');
    expect(call.body.constraints).toEqual({ 'core:cost:max_per_action': 100 });
    expect(call.body.expires_in).toBe('24h');
    expect(call.body.metadata).toEqual({ env: 'test' });
    // gate_id should NOT be in the body — it's in the URL
    expect(call.body.gate_id).toBeUndefined();
  });

  it('revoke_passport — DELETE /api/gates/:id/passports/:pid', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ revoked: true }));
    await handleToolCall(api, 'revoke_passport', { gate_id: 'gate_test-1', passport_id: 'pp_abc' });
    expect(lastCall().method).toBe('DELETE');
    expect(lastCall().url).toBe(`${BASE_URL}/api/gates/gate_test-1/passports/pp_abc`);
  });

  it('reissue_passport — POST /api/passports/:pid/reissue', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ passport_id: 'pp_abc', catalog_version: 3 }));
    await handleToolCall(api, 'reissue_passport', { passport_id: 'pp_abc', accept_catalog_version: 3 });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/passports/pp_abc/reissue`);
    expect(call.body.accept_catalog_version).toBe(3);
  });

  it('reissue_passport — empty body when no version specified', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ passport_id: 'pp_abc' }));
    await handleToolCall(api, 'reissue_passport', { passport_id: 'pp_abc' });
    expect(lastCall().body).toEqual({});
  });
});


// ======================================================================
// Attestations (2)
// ======================================================================

describe('Attestations', () => {
  it('list_attestations — GET /api/gates/:id/attestations', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([{ attestation_id: 'att_1' }]));
    await handleToolCall(api, 'list_attestations', { gate_id: 'gate_test-1' });
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/gates/gate_test-1/attestations`);
  });

  it('list_attestations — includes query params', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([]));
    await handleToolCall(api, 'list_attestations', {
      gate_id: 'gate_test-1',
      passport_id: 'pp_abc',
      agent_id: 'agent-1',
      permission: 'read',
      since: '2024-01-01',
      limit: 10,
    });
    const url = lastCall().url;
    expect(url).toContain('passport_id=pp_abc');
    expect(url).toContain('agent_id=agent-1');
    expect(url).toContain('permission=read');
    expect(url).toContain('since=2024-01-01');
    expect(url).toContain('limit=10');
  });

  it('record_attestation — POST /api/gates/:id/attestations', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ attestation_id: 'att_new' }, 201));
    await handleToolCall(api, 'record_attestation', {
      gate_id: 'gate_test-1',
      passport_id: 'pp_abc',
      agent_id: 'agent-1',
      permission: 'read',
      tool_name: 'search',
      result: 'allowed',
    });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/gates/gate_test-1/attestations`);
    expect(call.body.passport_id).toBe('pp_abc');
    expect(call.body.agent_id).toBe('agent-1');
    expect(call.body.permission).toBe('read');
    expect(call.body.tool_name).toBe('search');
    expect(call.body.result).toBe('allowed');
    expect(call.body.gate_id).toBeUndefined();
  });
});


// ======================================================================
// Permission Catalog (6)
// ======================================================================

describe('Catalogs', () => {
  it('get_catalog — GET /api/gates/:id/catalog', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ permissions: [] }));
    await handleToolCall(api, 'get_catalog', { gate_id: 'gate_test-1' });
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/gates/gate_test-1/catalog`);
  });

  it('create_catalog — POST /api/gates/:id/catalog', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ status: 'saved' }));
    await handleToolCall(api, 'create_catalog', {
      gate_id: 'gate_test-1',
      permissions: [{ permission_key: 'read', display_name: 'Read', description: 'Read access', risk_level: 'low', min_trust_level: 1 }],
    });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/gates/gate_test-1/catalog`);
    expect(call.body.permissions).toHaveLength(1);
    expect(call.body.permissions[0].permission_key).toBe('read');
    expect(call.body.gate_id).toBeUndefined();
  });

  it('publish_catalog — POST /api/gates/:id/catalog/publish', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ version: 1 }));
    await handleToolCall(api, 'publish_catalog', {
      gate_id: 'gate_test-1',
      change_summary: 'Initial publish',
      effective_at: '2024-06-01T00:00:00Z',
    });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/gates/gate_test-1/catalog/publish`);
    expect(call.body.change_summary).toBe('Initial publish');
    expect(call.body.effective_at).toBe('2024-06-01T00:00:00Z');
  });

  it('publish_catalog — empty body when no options', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ version: 2 }));
    await handleToolCall(api, 'publish_catalog', { gate_id: 'gate_test-1' });
    expect(lastCall().body).toEqual({});
  });

  it('list_catalog_versions — GET /api/gates/:id/catalog/versions', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([{ version: 1 }, { version: 2 }]));
    const result = await handleToolCall(api, 'list_catalog_versions', { gate_id: 'gate_test-1' });
    expect(result).toHaveLength(2);
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/gates/gate_test-1/catalog/versions`);
  });

  it('get_catalog_version — GET /api/gates/:id/catalog/:version', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ version: 1, permissions: [] }));
    await handleToolCall(api, 'get_catalog_version', { gate_id: 'gate_test-1', version: 1 });
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/gates/gate_test-1/catalog/1`);
  });

  it('get_catalog_impact — GET /api/gates/:id/catalog/impact', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ affected_passports: 3 }));
    const result = await handleToolCall(api, 'get_catalog_impact', { gate_id: 'gate_test-1' });
    expect((result as { affected_passports: number }).affected_passports).toBe(3);
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/gates/gate_test-1/catalog/impact`);
  });
});


// ======================================================================
// Gate Check (2)
// ======================================================================

describe('Gate Check', () => {
  it('check_gate — POST /api/gates/:id/check', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ decision: 'allow' }));
    await handleToolCall(api, 'check_gate', {
      gate_id: 'gate_test-1',
      action: 'read',
      passport_id: 'pp_abc',
      target: '/docs/secret',
    });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/gates/gate_test-1/check`);
    expect(call.body.action).toBe('read');
    expect(call.body.passport_id).toBe('pp_abc');
    expect(call.body.target).toBe('/docs/secret');
  });

  it('check_gate — minimal (no optional fields in body)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ decision: 'deny' }));
    await handleToolCall(api, 'check_gate', { gate_id: 'gate_test-1', action: 'write' });
    expect(lastCall().body).toEqual({ action: 'write' });
  });

  it('authorize_dry_run — POST /api/authorize/dry-run', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ decision: 'allow' }));
    await handleToolCall(api, 'authorize_dry_run', {
      gate_id: 'gate_test-1',
      passport: { passport_id: 'pp_abc', permissions: ['read'] },
      requested_permission: 'read',
    });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/authorize/dry-run`);
    expect(call.body.gate_id).toBe('gate_test-1');
    expect(call.body.passport.passport_id).toBe('pp_abc');
    expect(call.body.requested_permission).toBe('read');
    expect(call.body.requested_constraints).toBeUndefined();
  });

  it('authorize_dry_run — includes requested_constraints when provided', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ decision: 'deny' }));
    await handleToolCall(api, 'authorize_dry_run', {
      gate_id: 'gate_test-1',
      passport: { passport_id: 'pp_abc' },
      requested_permission: 'write',
      requested_constraints: { 'core:cost:max_per_action': 50 },
    });
    expect(lastCall().body.requested_constraints).toEqual({ 'core:cost:max_per_action': 50 });
  });
});


// ======================================================================
// Constraints & Templates (6)
// ======================================================================

describe('Constraints & Templates', () => {
  it('get_constraints — GET /api/passports/:pid/constraints', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ 'core:rate:max_per_minute': 60 }));
    await handleToolCall(api, 'get_constraints', { passport_id: 'pp_abc' });
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/passports/pp_abc/constraints`);
  });

  it('set_constraints — PUT /api/passports/:pid/constraints', async () => {
    const constraints = { 'core:rate:max_per_minute': 120 };
    fetchMock.mockResolvedValueOnce(jsonResponse({ updated: true }));
    await handleToolCall(api, 'set_constraints', { passport_id: 'pp_abc', constraints });
    const call = lastCall();
    expect(call.method).toBe('PUT');
    expect(call.url).toBe(`${BASE_URL}/api/passports/pp_abc/constraints`);
    expect(call.body).toEqual(constraints);
  });

  it('list_constraint_types — GET /api/constraints/types', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([{ type: 'core:rate:max_per_minute' }]));
    await handleToolCall(api, 'list_constraint_types', {});
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/constraints/types`);
  });

  it('list_constraint_types — with category filter', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([]));
    await handleToolCall(api, 'list_constraint_types', { category: 'cost' });
    expect(lastCall().url).toContain('category=cost');
  });

  it('list_constraint_templates — GET /api/constraint-templates', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([{ slug: 'read-only' }]));
    await handleToolCall(api, 'list_constraint_templates', {});
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/constraint-templates`);
  });

  it('list_constraint_templates — with category filter', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([]));
    await handleToolCall(api, 'list_constraint_templates', { category: 'system' });
    expect(lastCall().url).toContain('category=system');
  });

  it('apply_constraint_template — POST /api/passports/:pid/constraints', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ applied: true }));
    await handleToolCall(api, 'apply_constraint_template', {
      passport_id: 'pp_abc', template_slug: 'conservative-agent',
    });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/passports/pp_abc/constraints`);
    expect(call.body.template_slug).toBe('conservative-agent');
  });

  it('create_constraint_template — POST /api/constraint-templates', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ slug: 'custom' }, 201));
    await handleToolCall(api, 'create_constraint_template', {
      slug: 'custom',
      name: 'Custom Template',
      constraints: { 'core:rate:max_per_minute': 10 },
    });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/constraint-templates`);
    expect(call.body.slug).toBe('custom');
    expect(call.body.name).toBe('Custom Template');
  });
});


// ======================================================================
// Enforcement (4)
// ======================================================================

describe('Enforcement', () => {
  it('enforce_action — POST /api/enforce', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ decision: 'allow', attestation_id: 'enf_1' }));
    await handleToolCall(api, 'enforce_action', {
      passport_id: 'pp_abc',
      action: 'read',
      target: '/docs/file.txt',
      cost_cents: 5,
      metadata: { source: 'test' },
    });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/enforce`);
    expect(call.body.passport_id).toBe('pp_abc');
    expect(call.body.action).toBe('read');
    expect(call.body.target).toBe('/docs/file.txt');
    expect(call.body.cost_cents).toBe(5);
    expect(call.body.metadata).toEqual({ source: 'test' });
  });

  it('enforce_action — minimal (no optional fields)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ decision: 'deny' }));
    await handleToolCall(api, 'enforce_action', { passport_id: 'pp_abc', action: 'write' });
    const call = lastCall();
    expect(call.body.target).toBeUndefined();
    expect(call.body.cost_cents).toBeUndefined();
    expect(call.body.metadata).toBeUndefined();
  });

  it('list_enforcement_attestations — GET /api/passports/:pid/enforcement', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([{ id: 'enf_1' }]));
    await handleToolCall(api, 'list_enforcement_attestations', { passport_id: 'pp_abc' });
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/passports/pp_abc/enforcement`);
  });

  it('list_enforcement_attestations — with filters', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([]));
    await handleToolCall(api, 'list_enforcement_attestations', {
      passport_id: 'pp_abc', decision: 'PERMIT', limit: 5,
    });
    const url = lastCall().url;
    expect(url).toContain('decision=PERMIT');
    expect(url).toContain('limit=5');
  });

  it('get_enforcement_attestation — GET /api/enforcement/:id', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ id: 'enf_1', decision: 'allow' }));
    await handleToolCall(api, 'get_enforcement_attestation', { attestation_id: 'enf_1' });
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/enforcement/enf_1`);
  });

  it('verify_enforcement_attestation — POST /api/enforcement/:id/verify (not GET)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ valid: true }));
    await handleToolCall(api, 'verify_enforcement_attestation', { attestation_id: 'enf_1' });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/enforcement/enf_1/verify`);
  });
});


// ======================================================================
// Anonymous Access (3)
// ======================================================================

describe('Anonymous Access', () => {
  it('get_anonymous_policy — GET /api/gates/:id/anonymous-policy', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ enabled: false }));
    await handleToolCall(api, 'get_anonymous_policy', { gate_id: 'gate_test-1' });
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/gates/gate_test-1/anonymous-policy`);
  });

  it('set_anonymous_policy — PUT /api/gates/:id/anonymous-policy (not POST)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ enabled: true }));
    await handleToolCall(api, 'set_anonymous_policy', {
      gate_id: 'gate_test-1',
      enabled: true,
      allowed_actions: ['read'],
      rate_limit_per_minute: 60,
    });
    const call = lastCall();
    expect(call.method).toBe('PUT');
    expect(call.url).toBe(`${BASE_URL}/api/gates/gate_test-1/anonymous-policy`);
    expect(call.body.enabled).toBe(true);
    expect(call.body.allowed_actions).toEqual(['read']);
    expect(call.body.rate_limit_per_minute).toBe(60);
    // gate_id should NOT be in the body
    expect(call.body.gate_id).toBeUndefined();
  });

  it('get_anonymous_log — GET /api/gates/:id/anonymous-log', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([{ action: 'read' }]));
    await handleToolCall(api, 'get_anonymous_log', { gate_id: 'gate_test-1' });
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/gates/gate_test-1/anonymous-log`);
  });
});


// ======================================================================
// Cumulative State (2)
// ======================================================================

describe('Cumulative State', () => {
  it('get_cumulative_state — GET /api/passports/:pid/state', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ total_cost_cents: 150 }));
    await handleToolCall(api, 'get_cumulative_state', { passport_id: 'pp_abc' });
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/passports/pp_abc/state`);
  });

  it('reset_cumulative_state — POST /api/passports/:pid/state/reset', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ reset: true }));
    await handleToolCall(api, 'reset_cumulative_state', {
      passport_id: 'pp_abc', window_type: 'daily',
    });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/passports/pp_abc/state/reset`);
    expect(call.body.window_type).toBe('daily');
  });

  it('reset_cumulative_state — empty body when no window_type', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ reset: true }));
    await handleToolCall(api, 'reset_cumulative_state', { passport_id: 'pp_abc' });
    expect(lastCall().body).toEqual({});
  });
});


// ======================================================================
// Commerce (7)
// ======================================================================

describe('Commerce — Discovery', () => {
  it('discover_services — GET /api/discover', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ services: [{ gate_id: 'gate_translate' }] }));
    const result = await handleToolCall(api, 'discover_services', { capability: 'translation' });
    expect((result as { services: unknown[] }).services).toHaveLength(1);
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toContain('/api/discover');
    expect(lastCall().url).toContain('capability=translation');
  });

  it('discover_services — with all filters', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ services: [] }));
    await handleToolCall(api, 'discover_services', {
      capability: 'flights:*',
      max_price_cents: 100,
      min_uptime_bp: 9500,
      max_response_time_ms: 200,
      pricing_model: 'per_call',
      sort: 'price_asc',
      limit: 5,
      offset: 10,
    });
    const url = lastCall().url;
    expect(url).toContain('max_price_cents=100');
    expect(url).toContain('min_uptime_bp=9500');
    expect(url).toContain('max_response_time_ms=200');
    expect(url).toContain('pricing_model=per_call');
    expect(url).toContain('sort=price_asc');
    expect(url).toContain('limit=5');
    expect(url).toContain('offset=10');
  });
});

describe('Commerce — Consumption', () => {
  it('issue_consumption_attestation — POST /api/consume', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ attestation_id: 'ca_1' }, 201));
    await handleToolCall(api, 'issue_consumption_attestation', {
      passport_id: 'pp_abc',
      gate_id: 'gate_test-1',
      action: 'translate',
      outcome: 'success',
      quantity: 3,
    });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/consume`);
    expect(call.body.passport_id).toBe('pp_abc');
    expect(call.body.gate_id).toBe('gate_test-1');
    expect(call.body.action).toBe('translate');
    expect(call.body.outcome).toBe('success');
    expect(call.body.quantity).toBe(3);
  });

  it('issue_consumption_attestation — defaults quantity to 1', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ attestation_id: 'ca_2' }, 201));
    await handleToolCall(api, 'issue_consumption_attestation', {
      passport_id: 'pp_abc',
      gate_id: 'gate_test-1',
      action: 'translate',
      outcome: 'success',
    });
    expect(lastCall().body.quantity).toBe(1);
  });

  it('issue_consumption_attestation — optional fields', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ attestation_id: 'ca_3' }, 201));
    await handleToolCall(api, 'issue_consumption_attestation', {
      passport_id: 'pp_abc',
      gate_id: 'gate_test-1',
      action: 'translate',
      outcome: 'success',
      agent_pop: { sig: 'abc' },
      request_payload_hash: 'sha256:req',
      response_payload_hash: 'sha256:resp',
      metadata: { model: 'gpt-4' },
    });
    const body = lastCall().body;
    expect(body.agent_pop).toEqual({ sig: 'abc' });
    expect(body.request_payload_hash).toBe('sha256:req');
    expect(body.response_payload_hash).toBe('sha256:resp');
    expect(body.metadata).toEqual({ model: 'gpt-4' });
  });
});

describe('Commerce — Settlement & Billing', () => {
  it('generate_settlement — POST /api/billing', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ settlement_id: 'stl_1' }, 201));
    await handleToolCall(api, 'generate_settlement', {
      gate_id: 'gate_test-1',
      period_type: 'monthly',
      period_start: '2024-01-01',
      period_end: '2024-01-31',
    });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/billing`);
    expect(call.body.gate_id).toBe('gate_test-1');
    expect(call.body.period_type).toBe('monthly');
    expect(call.body.agent_id).toBeUndefined();
  });

  it('generate_settlement — with agent_id', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ settlement_id: 'stl_2' }, 201));
    await handleToolCall(api, 'generate_settlement', {
      gate_id: 'gate_test-1',
      period_type: 'daily',
      period_start: '2024-06-01',
      period_end: '2024-06-01',
      agent_id: 'agent-1',
    });
    expect(lastCall().body.agent_id).toBe('agent-1');
  });

  it('list_settlements — GET /api/billing', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ settlements: [] }));
    await handleToolCall(api, 'list_settlements', {});
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toContain('/api/billing');
  });

  it('list_settlements — with filters', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ settlements: [] }));
    await handleToolCall(api, 'list_settlements', {
      gate_id: 'gate_test-1',
      status: 'pending',
      from_date: '2024-01-01',
      to_date: '2024-12-31',
      limit: 50,
      offset: 10,
    });
    const url = lastCall().url;
    expect(url).toContain('gate_id=gate_test-1');
    expect(url).toContain('status=pending');
    expect(url).toContain('from=2024-01-01');
    expect(url).toContain('to=2024-12-31');
    expect(url).toContain('limit=50');
    expect(url).toContain('offset=10');
  });

  it('get_settlement — GET /api/billing/:id', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ settlement_id: 'stl_1', status: 'paid' }));
    await handleToolCall(api, 'get_settlement', { settlement_id: 'stl_1' });
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/billing/stl_1`);
  });

  it('update_settlement_status — POST /api/billing/:id/status (not PATCH)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ status: 'paid' }));
    await handleToolCall(api, 'update_settlement_status', {
      settlement_id: 'stl_1', status: 'paid',
    });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/billing/stl_1/status`);
    expect(call.body).toEqual({ status: 'paid' });
  });
});

describe('Commerce — SLA', () => {
  it('get_sla_compliance — GET /api/gates/:id/sla', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ uptime_percent: 99.9 }));
    await handleToolCall(api, 'get_sla_compliance', {
      gate_id: 'gate_test-1',
      period_start: '2024-01-01',
      period_end: '2024-01-31',
    });
    const call = lastCall();
    expect(call.method).toBe('GET');
    expect(call.url).toContain('/api/gates/gate_test-1/sla');
    expect(call.url).toContain('period_start=2024-01-01');
    expect(call.url).toContain('period_end=2024-01-31');
  });

  it('get_sla_compliance — with permission_key', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}));
    await handleToolCall(api, 'get_sla_compliance', {
      gate_id: 'gate_test-1',
      period_start: '2024-01-01',
      period_end: '2024-01-31',
      permission_key: 'translate',
    });
    expect(lastCall().url).toContain('permission_key=translate');
  });
});


// ======================================================================
// API Keys (3)
// ======================================================================

describe('API Keys', () => {
  it('list_api_keys — GET /api/users/api-keys', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([{ id: 'key_1' }]));
    await handleToolCall(api, 'list_api_keys', {});
    expect(lastCall().method).toBe('GET');
    expect(lastCall().url).toBe(`${BASE_URL}/api/users/api-keys`);
  });

  it('create_api_key — POST /api/users/api-keys', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ id: 'key_2' }, 201));
    await handleToolCall(api, 'create_api_key', { name: 'CI Key', scopes: ['gates:read'] });
    const call = lastCall();
    expect(call.method).toBe('POST');
    expect(call.url).toBe(`${BASE_URL}/api/users/api-keys`);
    expect(call.body.name).toBe('CI Key');
    expect(call.body.scopes).toEqual(['gates:read']);
  });

  it('create_api_key — without scopes', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ id: 'key_3' }, 201));
    await handleToolCall(api, 'create_api_key', { name: 'Default Key' });
    expect(lastCall().body).toEqual({ name: 'Default Key' });
  });

  it('revoke_api_key — DELETE /api/users/api-keys/:id', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ revoked: true }));
    await handleToolCall(api, 'revoke_api_key', { key_id: 'key_1' });
    expect(lastCall().method).toBe('DELETE');
    expect(lastCall().url).toBe(`${BASE_URL}/api/users/api-keys/key_1`);
  });
});


// ======================================================================
// Error Handling
// ======================================================================

describe('Error Handling', () => {
  it('throws on 401 with message from JSON body', async () => {
    fetchMock.mockResolvedValueOnce(errorResponse(401, { message: 'Invalid API key' }));
    await expect(handleToolCall(api, 'list_gates', {})).rejects.toThrow('Invalid API key');
  });

  it('throws on 404 with message from JSON body', async () => {
    fetchMock.mockResolvedValueOnce(errorResponse(404, { message: 'Gate not found' }));
    await expect(handleToolCall(api, 'get_gate', { gate_id: 'gate_nope' }))
      .rejects.toThrow('Gate not found');
  });

  it('throws on 500 with fallback message', async () => {
    fetchMock.mockResolvedValueOnce(errorResponse(500, {}));
    await expect(handleToolCall(api, 'list_gates', {})).rejects.toThrow('API error: 500');
  });

  it('throws on unknown tool name', async () => {
    await expect(handleToolCall(api, 'nonexistent_tool', {})).rejects.toThrow('Unknown tool');
  });
});


// ======================================================================
// Tool count sanity check
// ======================================================================

describe('Tool Registry', () => {
  it('exports exactly 45 tools', async () => {
    const { allTools } = await import('../src/tools/index.js');
    expect(allTools).toHaveLength(45);
  });

  it('every tool name has a handler', async () => {
    const { allTools } = await import('../src/tools/index.js');
    for (const tool of allTools) {
      // This will throw "Unknown tool" if handler is missing
      fetchMock.mockResolvedValueOnce(jsonResponse({}));
      // We don't care if it fails on missing args — just that the handler exists
      try {
        await handleToolCall(api, tool.name, {});
      } catch (e) {
        // Acceptable: args validation, API call parsing
        // Not acceptable: "Unknown tool"
        expect((e as Error).message).not.toContain('Unknown tool');
      }
    }
  });
});
