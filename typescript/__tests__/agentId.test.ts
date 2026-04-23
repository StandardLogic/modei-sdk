/**
 * deriveSelfAgentId — mirrors the agent_id section of
 * python/tests/passport/test_envelope_tier_agent_id.py (5 tests, adapted).
 *
 * The Python suite's "rejects invalid base64" test is dropped here: the TS
 * signature takes `Uint8Array` directly, so there is no base64 input to
 * malform. Intentional per C20.2 kickoff.
 *
 * Ground-truth agent_id fixtures were lifted from the backend's
 * `deriveSelfAgentId` via a one-shot `tsx` invocation — the same fixtures
 * Python uses. Cross-SDK byte-parity is a release invariant (backend ↔
 * Python ↔ TS). Any drift is a spec-parity bug — STOP, investigate.
 */

import { describe, expect, it } from 'vitest';

import { SELF_AGENT_ID_PREFIX, deriveSelfAgentId } from '../src/passport/agentId.js';

// 32 zero bytes.
const PK1: Uint8Array = new Uint8Array(32);
const PK1_AGENT_ID = 'agent_self_Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOz';

// Sequential bytes 0..31.
const PK2: Uint8Array = Uint8Array.from({ length: 32 }, (_, i) => i);
const PK2_AGENT_ID = 'agent_self_Yw3NKWbEM2aRElRIu7JbT_QSpJxzLbLI';

describe('deriveSelfAgentId', () => {
  it('matches backend output for zero-filled 32-byte key', () => {
    expect(deriveSelfAgentId(PK1)).toBe(PK1_AGENT_ID);
  });

  it('matches backend output for deterministic 0..31 key', () => {
    expect(deriveSelfAgentId(PK2)).toBe(PK2_AGENT_ID);
  });

  it('always has agent_self_ prefix and length 43', () => {
    const result = deriveSelfAgentId(PK1);
    expect(result.startsWith(SELF_AGENT_ID_PREFIX)).toBe(true);
    expect(SELF_AGENT_ID_PREFIX.length + 32).toBe(43);
    expect(result.length).toBe(43);
  });

  it('does not enforce 32-byte pubkey length (backend parity)', () => {
    // Backend's deriveSelfAgentId does not check pubkey length; signature
    // verification catches length mismatches. Pin current behavior so any
    // future tightening is intentional.
    const shortPubkey = new TextEncoder().encode('short');
    const result = deriveSelfAgentId(shortPubkey);
    expect(result.startsWith(SELF_AGENT_ID_PREFIX)).toBe(true);
    expect(result.length).toBe(43);
  });
});
