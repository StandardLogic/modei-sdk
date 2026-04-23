/**
 * Trust tier enum + derivation.
 *
 * Mirrors backend `src/lib/passports/tier.ts` (`deriveTier`) and
 * `src/lib/passports/inline.ts` (`TIER_ORDER` / `tierRank`), and the Python
 * SDK's `modei.passport.tier`.
 *
 * Tier is NOT a signed envelope field — it is derived from
 * `provenance.issuer.type` at verify time so that any tampering with
 * `issuer.type` invalidates the signature (spec §3.2, §14 A5).
 *
 * Tier ordering is pinned via an explicit rank map, not via enum or string
 * comparison. String comparison works by accident for this alphabet but is
 * not a contract — a future tier like `"L4"` or `"L10"` would break it.
 * Mirror the backend's explicit map.
 *
 * `TrustTier` is a const-object + type union rather than a TS `enum`: clean
 * across ESM/CJS, zero-cost erasure at the type layer, idiomatic TS. Python
 * uses `StrEnum` for the same purpose.
 */

import type { Envelope } from './envelope.js';

export const TrustTier = {
  L0: 'L0',
  L0_5: 'L0.5',
  L1: 'L1',
  L2: 'L2',
  L3: 'L3',
} as const;

export type TrustTier = (typeof TrustTier)[keyof typeof TrustTier];

const TIER_RANK: Record<TrustTier, number> = {
  [TrustTier.L0]: 0,
  [TrustTier.L0_5]: 1,
  [TrustTier.L1]: 2,
  [TrustTier.L2]: 3,
  [TrustTier.L3]: 4,
};

/** Return the integer rank of `tier`. Higher = more trust. */
export function tierRank(tier: TrustTier): number {
  return TIER_RANK[tier];
}

/**
 * Derive the trust tier of a well-formed envelope.
 *
 * Caller contract: `envelope` is structurally valid. The chain verifier
 * (C20.5) validates shape + chain invariants BEFORE calling this. If
 * `issuer.type === 'delegate'` with a null/empty `delegation_chain`, that's
 * a caller bug and we throw rather than silently coerce a tier. Mirrors
 * the backend's `throw new Error`.
 */
export function deriveTier(envelope: Envelope): TrustTier {
  const issuerType = envelope.provenance.issuer.type;

  if (issuerType === 'self') return TrustTier.L0;
  if (issuerType === 'platform') return TrustTier.L1;
  if (issuerType === 'gate') return TrustTier.L2;
  if (issuerType === 'delegate') {
    const chain = envelope.provenance.delegation_chain;
    const root = chain?.[0];
    if (root === undefined) {
      throw new Error(
        "deriveTier: envelope has issuer.type='delegate' but " +
          'delegation_chain is null/empty; chain verification must run ' +
          'before tier derivation',
      );
    }
    return deriveTier(root.passport_json);
  }

  throw new Error(`deriveTier: unknown issuer.type=${JSON.stringify(issuerType)}`);
}
