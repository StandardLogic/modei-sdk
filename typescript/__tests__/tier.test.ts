/**
 * TrustTier / deriveTier / tierRank — mirrors the tier section of
 * python/tests/passport/test_envelope_tier_agent_id.py (8 tests).
 *
 * The `_minimalEnvelope()` helper builds raw objects and pipes them through
 * `envelopeSchema.parse()`. This doubles as envelope-schema validation — if
 * the helper ever emits an invalid shape, the tier tests fail loudly rather
 * than silently.
 */

import { describe, expect, it } from 'vitest';

import {
  type DelegationChainEntry,
  type Envelope,
  type IssuerType,
  type PassportPermission,
  envelopeSchema,
} from '../src/passport/envelope.js';
import { TrustTier, deriveTier, tierRank } from '../src/passport/tier.js';

// Base64 of 32 zero bytes — shared with the Python suite's PK1 fixture.
const PK1_BASE64 = Buffer.alloc(32).toString('base64');

interface MinimalEnvelopeOptions {
  delegation_chain?: DelegationChainEntry[] | null;
  permissions?: PassportPermission[];
  delegation_authority?: boolean;
  expires_at?: string;
  issued_at?: string;
  passport_id?: string;
}

function minimalEnvelope(issuerType: IssuerType, opts: MinimalEnvelopeOptions = {}): Envelope {
  const raw = {
    schema_version: 2,
    passport_id: opts.passport_id ?? 'pp_test',
    identity: {
      agent_id: 'agent_test',
      agent_name: null,
      public_key: PK1_BASE64,
    },
    permissions: opts.permissions ?? [],
    provenance: {
      issuer: { type: issuerType, id: `${issuerType}:x`, key_id: 'k' },
      gate_id: null,
      catalog_content_hash: null,
      catalog_version: null,
      delegation_chain: opts.delegation_chain ?? null,
      issued_at: opts.issued_at ?? '2026-04-22T00:00:00Z',
      expires_at: opts.expires_at ?? '2026-05-22T00:00:00Z',
    },
    delegation_authority: opts.delegation_authority ?? false,
    verification_evidence: [],
  };
  return envelopeSchema.parse(raw);
}

function delegateChain(rootIssuerType: IssuerType): DelegationChainEntry[] {
  const root = minimalEnvelope(rootIssuerType, { passport_id: 'pp_root' });
  return [{ passport_json: root, signature: 'sig_placeholder' }];
}

describe('deriveTier', () => {
  it('self → L0', () => {
    expect(deriveTier(minimalEnvelope('self'))).toBe(TrustTier.L0);
  });

  it('platform → L1', () => {
    expect(deriveTier(minimalEnvelope('platform'))).toBe(TrustTier.L1);
  });

  it('gate → L2', () => {
    expect(deriveTier(minimalEnvelope('gate'))).toBe(TrustTier.L2);
  });

  it('delegate with self root → L0', () => {
    const leaf = minimalEnvelope('delegate', {
      delegation_chain: delegateChain('self'),
      passport_id: 'pp_leaf',
    });
    expect(deriveTier(leaf)).toBe(TrustTier.L0);
  });

  it('delegate with platform root → L1', () => {
    const leaf = minimalEnvelope('delegate', {
      delegation_chain: delegateChain('platform'),
      passport_id: 'pp_leaf',
    });
    expect(deriveTier(leaf)).toBe(TrustTier.L1);
  });

  it('delegate with gate root → L2', () => {
    const leaf = minimalEnvelope('delegate', {
      delegation_chain: delegateChain('gate'),
      passport_id: 'pp_leaf',
    });
    expect(deriveTier(leaf)).toBe(TrustTier.L2);
  });

  it('delegate with null chain throws', () => {
    const bad = minimalEnvelope('delegate', { delegation_chain: null });
    expect(() => deriveTier(bad)).toThrow(/delegation_chain is null\/empty/);
  });
});

describe('tierRank', () => {
  it('returns 0..4 for L0..L3 and is strictly monotonic', () => {
    expect(tierRank(TrustTier.L0)).toBe(0);
    expect(tierRank(TrustTier.L0_5)).toBe(1);
    expect(tierRank(TrustTier.L1)).toBe(2);
    expect(tierRank(TrustTier.L2)).toBe(3);
    expect(tierRank(TrustTier.L3)).toBe(4);

    const tiers: TrustTier[] = [
      TrustTier.L0,
      TrustTier.L0_5,
      TrustTier.L1,
      TrustTier.L2,
      TrustTier.L3,
    ];
    const ranks = tiers.map(tierRank);
    const sorted = [...ranks].sort((a, b) => a - b);
    expect(ranks).toEqual(sorted);
    expect(new Set(ranks).size).toBe(ranks.length);
  });
});
