/**
 * DelegationBuilder tests. Port of Python test_delegation.py — 14 ported
 * tests + 1 single-use .sign() test (TS addition per C20.5 kickoff).
 *
 * Exercises pre-sign validation (Spec §13 rows 13a/b/c), chain construction,
 * expiry clamp, depth boundary, and end-to-end round-trip against
 * PassportVerifier. Cross-backend byte-parity for the delegation fixture
 * is locked in C20.4's verifier.test.ts via manual envelope construction;
 * not duplicated here.
 */

import { describe, expect, it } from 'vitest';

import { AgentCredentials } from '../src/passport/credentials.js';
import { DelegationBuilder } from '../src/passport/delegation.js';
import type { SignedPassport } from '../src/passport/envelope.js';
import {
  DelegationAuthorityMissingError,
  DelegationChainTooDeepError,
  DelegationError,
  DelegationSubsetError,
} from '../src/passport/errors.js';
import { PassportIssuer } from '../src/passport/issuer.js';
import { TrustTier } from '../src/passport/tier.js';
import { PassportVerifier } from '../src/passport/verifier.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function issueSelf(
  creds: AgentCredentials,
  opts: {
    permissions?: Array<{ permission_key: string; constraints?: Record<string, unknown> }>;
    expiresAt?: Date;
    delegationAuthority?: boolean;
  } = {},
): SignedPassport {
  const issuer = new PassportIssuer(creds, { identityClaim: 'parent@dev.local' });
  return issuer.selfIssue({
    permissions: opts.permissions ?? [{ permission_key: 'api:read', constraints: {} }],
    expiresAt: opts.expiresAt ?? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    delegationAuthority: opts.delegationAuthority ?? true,
  });
}

/**
 * Build a delegated SignedPassport whose delegation_chain has exactly
 * `targetDepth` entries (1 ≤ targetDepth ≤ 5). Port of Python's
 * `_build_deep_chain`. Returns the leaf-signed + leaf's credentials.
 */
function buildDeepChain(targetDepth: number): {
  leafSigned: SignedPassport;
  leafCredentials: AgentCredentials;
} {
  const rootCreds = AgentCredentials.generate();
  let currentSigned = issueSelf(rootCreds);
  let currentCreds = rootCreds;

  for (let i = 0; i < targetDepth; i++) {
    const nextCreds = AgentCredentials.generate();
    currentSigned = new DelegationBuilder(currentSigned, currentCreds)
      .authorize(nextCreds)
      .withPermissions([{ permission_key: 'api:read', constraints: {} }])
      .withDelegationAuthority(true)
      .sign();
    currentCreds = nextCreds;
  }

  return { leafSigned: currentSigned, leafCredentials: currentCreds };
}

// ---------------------------------------------------------------------------
// 1-2. state-machine errors
// ---------------------------------------------------------------------------

describe('DelegationBuilder state-machine', () => {
  it('authorize required before sign', () => {
    const parentCreds = AgentCredentials.generate();
    const parentSigned = issueSelf(parentCreds);
    const builder = new DelegationBuilder(parentSigned, parentCreds).withPermissions([
      { permission_key: 'api:read', constraints: {} },
    ]);
    expect(() => builder.sign()).toThrow(/authorize/);
    expect(() => builder.sign()).toThrow(DelegationError);
  });

  it('withPermissions required before sign', () => {
    const parentCreds = AgentCredentials.generate();
    const parentSigned = issueSelf(parentCreds);
    const childCreds = AgentCredentials.generate();
    const builder = new DelegationBuilder(parentSigned, parentCreds).authorize(childCreds);
    expect(() => builder.sign()).toThrow(/withPermissions/);
    expect(() => builder.sign()).toThrow(DelegationError);
  });
});

// ---------------------------------------------------------------------------
// 3. round-trip
// ---------------------------------------------------------------------------

describe('DelegationBuilder round-trip', () => {
  it('simple self→delegate round-trip: verifier accepts {valid:true, L0}', () => {
    const parentCreds = AgentCredentials.generate();
    const parentSigned = issueSelf(parentCreds);
    const childCreds = AgentCredentials.generate();

    const childSigned = new DelegationBuilder(parentSigned, parentCreds)
      .authorize(childCreds)
      .withPermissions([{ permission_key: 'api:read', constraints: {} }])
      .sign();

    expect(childSigned.envelope.provenance.issuer.type).toBe('delegate');
    expect(childSigned.envelope.provenance.issuer.id).toBe(
      'delegate:' + parentSigned.envelope.passport_id,
    );

    const result = new PassportVerifier().verify(childSigned.envelope, childSigned.signature);
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.tier).toBe(TrustTier.L0);
  });
});

// ---------------------------------------------------------------------------
// 4-7. subset violations
// ---------------------------------------------------------------------------

describe('DelegationBuilder subset violations', () => {
  it('permission added: DelegationSubsetError with permissionKey populated', () => {
    const parentCreds = AgentCredentials.generate();
    const parentSigned = issueSelf(parentCreds, {
      permissions: [{ permission_key: 'api:read', constraints: {} }],
    });
    const childCreds = AgentCredentials.generate();
    const builder = new DelegationBuilder(parentSigned, parentCreds)
      .authorize(childCreds)
      .withPermissions([{ permission_key: 'api:write', constraints: {} }]);

    try {
      builder.sign();
      throw new Error('expected DelegationSubsetError');
    } catch (err) {
      expect(err).toBeInstanceOf(DelegationSubsetError);
      const e = err as DelegationSubsetError;
      expect(e.permissionKey).toBe('api:write');
      expect(e.detail).toContain('api:write');
    }
  });

  it('numeric loosen: dimension + detail populated', () => {
    const parentCreds = AgentCredentials.generate();
    const parentSigned = issueSelf(parentCreds, {
      permissions: [{ permission_key: 'api:read', constraints: { max_per_action_cost: 500 } }],
    });
    const childCreds = AgentCredentials.generate();
    const builder = new DelegationBuilder(parentSigned, parentCreds)
      .authorize(childCreds)
      .withPermissions([
        { permission_key: 'api:read', constraints: { max_per_action_cost: 1000 } },
      ]);

    try {
      builder.sign();
      throw new Error('expected DelegationSubsetError');
    } catch (err) {
      expect(err).toBeInstanceOf(DelegationSubsetError);
      const e = err as DelegationSubsetError;
      expect(e.permissionKey).toBe('api:read');
      expect(e.dimension).toBe('max_per_action_cost');
      expect(e.detail).toContain('1000');
      expect(e.detail).toContain('500');
    }
  });

  it('set-include loosen: dimension populated with set-include name', () => {
    const parentCreds = AgentCredentials.generate();
    const parentSigned = issueSelf(parentCreds, {
      permissions: [
        { permission_key: 'api:read', constraints: { allowed_domains: ['a.com', 'b.com'] } },
      ],
    });
    const childCreds = AgentCredentials.generate();
    const builder = new DelegationBuilder(parentSigned, parentCreds)
      .authorize(childCreds)
      .withPermissions([
        { permission_key: 'api:read', constraints: { allowed_domains: ['a.com', 'c.com'] } },
      ]);

    try {
      builder.sign();
      throw new Error('expected DelegationSubsetError');
    } catch (err) {
      expect(err).toBeInstanceOf(DelegationSubsetError);
      const e = err as DelegationSubsetError;
      expect(e.permissionKey).toBe('api:read');
      expect(e.dimension).toBe('allowed_domains');
      expect(e.detail).toContain('c.com');
    }
  });

  it('constraint added to absent dimension: "absent in ancestor" detail', () => {
    const parentCreds = AgentCredentials.generate();
    const parentSigned = issueSelf(parentCreds, {
      permissions: [{ permission_key: 'api:read', constraints: {} }],
    });
    const childCreds = AgentCredentials.generate();
    const builder = new DelegationBuilder(parentSigned, parentCreds)
      .authorize(childCreds)
      .withPermissions([
        { permission_key: 'api:read', constraints: { max_per_action_cost: 100 } },
      ]);

    try {
      builder.sign();
      throw new Error('expected DelegationSubsetError');
    } catch (err) {
      expect(err).toBeInstanceOf(DelegationSubsetError);
      const e = err as DelegationSubsetError;
      expect(e.permissionKey).toBe('api:read');
      expect(e.dimension).toBe('max_per_action_cost');
      expect(e.detail).toContain('absent in ancestor');
    }
  });
});

// ---------------------------------------------------------------------------
// 8-9. expiry clamp
// ---------------------------------------------------------------------------

describe('DelegationBuilder expiry clamp', () => {
  it('clamps to parent expiry when child asks for longer', () => {
    const parentCreds = AgentCredentials.generate();
    const parentSigned = issueSelf(parentCreds, {
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    });
    const childCreds = AgentCredentials.generate();
    const builder = new DelegationBuilder(parentSigned, parentCreds)
      .authorize(childCreds)
      .withPermissions([{ permission_key: 'api:read', constraints: {} }])
      .withExpiry(new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)); // ask for 30

    expect(builder.expiryWasClamped).toBe(true);
    const parentExpires = new Date(parentSigned.envelope.provenance.expires_at);
    expect(builder.effectiveExpiresAt?.getTime()).toBe(parentExpires.getTime());

    const childSigned = builder.sign();
    expect(childSigned.envelope.provenance.expires_at).toBe(
      parentSigned.envelope.provenance.expires_at,
    );
  });

  it('clamps transitively to most-restrictive ancestor across chain', () => {
    // Build root (30d expiry, delegation_authority=true) → middle (3d, authority=true) → leaf (asks 10d, should clamp to 3d).
    const rootCreds = AgentCredentials.generate();
    const rootSigned = issueSelf(rootCreds, {
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      delegationAuthority: true,
    });

    const middleCreds = AgentCredentials.generate();
    const middleSigned = new DelegationBuilder(rootSigned, rootCreds)
      .authorize(middleCreds)
      .withPermissions([{ permission_key: 'api:read', constraints: {} }])
      .withExpiry(new Date(Date.now() + 3 * 24 * 60 * 60 * 1000))
      .withDelegationAuthority(true)
      .sign();

    const leafCreds = AgentCredentials.generate();
    const leafBuilder = new DelegationBuilder(middleSigned, middleCreds)
      .authorize(leafCreds)
      .withPermissions([{ permission_key: 'api:read', constraints: {} }])
      .withExpiry(new Date(Date.now() + 10 * 24 * 60 * 60 * 1000)); // ask 10d

    expect(leafBuilder.expiryWasClamped).toBe(true);
    const middleExpires = new Date(middleSigned.envelope.provenance.expires_at);
    expect(leafBuilder.effectiveExpiresAt?.getTime()).toBe(middleExpires.getTime());

    const leafSigned = leafBuilder.sign();
    const result = new PassportVerifier().verify(leafSigned.envelope, leafSigned.signature);
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 10. delegation_authority missing
// ---------------------------------------------------------------------------

describe('DelegationBuilder authority enforcement', () => {
  it('parent without delegation_authority raises DelegationAuthorityMissingError', () => {
    const parentCreds = AgentCredentials.generate();
    const parentSigned = issueSelf(parentCreds, { delegationAuthority: false });
    const childCreds = AgentCredentials.generate();
    const builder = new DelegationBuilder(parentSigned, parentCreds)
      .authorize(childCreds)
      .withPermissions([{ permission_key: 'api:read', constraints: {} }]);

    expect(() => builder.sign()).toThrow(DelegationAuthorityMissingError);
  });
});

// ---------------------------------------------------------------------------
// 11-12. chain depth boundary
// ---------------------------------------------------------------------------

describe('DelegationBuilder chain depth', () => {
  it('depth-5 permits (4-link parent + 1 delegation = 5-link chain)', () => {
    const { leafSigned: parentSigned, leafCredentials: parentCreds } = buildDeepChain(4);
    expect(parentSigned.envelope.provenance.delegation_chain).toHaveLength(4);

    const childCreds = AgentCredentials.generate();
    const childSigned = new DelegationBuilder(parentSigned, parentCreds)
      .authorize(childCreds)
      .withPermissions([{ permission_key: 'api:read', constraints: {} }])
      .sign();
    expect(childSigned.envelope.provenance.delegation_chain).toHaveLength(5);

    const result = new PassportVerifier().verify(childSigned.envelope, childSigned.signature);
    expect(result.valid).toBe(true);
  });

  it('depth-6 rejects pre-sign with DelegationChainTooDeepError.chainLength=6', () => {
    const { leafSigned: parentSigned, leafCredentials: parentCreds } = buildDeepChain(5);
    expect(parentSigned.envelope.provenance.delegation_chain).toHaveLength(5);

    const childCreds = AgentCredentials.generate();
    const builder = new DelegationBuilder(parentSigned, parentCreds)
      .authorize(childCreds)
      .withPermissions([{ permission_key: 'api:read', constraints: {} }]);

    try {
      builder.sign();
      throw new Error('expected DelegationChainTooDeepError');
    } catch (err) {
      expect(err).toBeInstanceOf(DelegationChainTooDeepError);
      const e = err as DelegationChainTooDeepError;
      expect(e.chainLength).toBe(6);
      expect(e.maxDepth).toBe(5);
    }
  });
});

// ---------------------------------------------------------------------------
// 13. issuer.id structural correctness
// ---------------------------------------------------------------------------

describe('DelegationBuilder issuer.id', () => {
  it('references chain root passport_id, not immediate parent', () => {
    const { leafSigned: parentSigned, leafCredentials: parentCreds } = buildDeepChain(3);
    const chain = parentSigned.envelope.provenance.delegation_chain;
    expect(chain).not.toBeNull();
    const rootPassportId = chain![0]!.passport_json.passport_id;

    const childCreds = AgentCredentials.generate();
    const childSigned = new DelegationBuilder(parentSigned, parentCreds)
      .authorize(childCreds)
      .withPermissions([{ permission_key: 'api:read', constraints: {} }])
      .sign();

    expect(childSigned.envelope.provenance.issuer.id).toBe('delegate:' + rootPassportId);
    // Parent's passport_id is NOT the root here (depth-3 parent).
    expect(parentSigned.envelope.passport_id).not.toBe(rootPassportId);
  });
});

// ---------------------------------------------------------------------------
// 14. parent credentials mismatch
// ---------------------------------------------------------------------------

describe('DelegationBuilder constructor validation', () => {
  it('parent_credentials public-key mismatch raises DelegationError', () => {
    const parentCreds = AgentCredentials.generate();
    const wrongCreds = AgentCredentials.generate();
    const parentSigned = issueSelf(parentCreds);

    expect(() => new DelegationBuilder(parentSigned, wrongCreds)).toThrow(
      /parent_credentials public key/,
    );
    expect(() => new DelegationBuilder(parentSigned, wrongCreds)).toThrow(DelegationError);
  });
});

// ---------------------------------------------------------------------------
// 15. single-use sign() (TS addition, not in Python)
// ---------------------------------------------------------------------------

describe('DelegationBuilder single-use sign', () => {
  it('second call to sign() throws', () => {
    const parentCreds = AgentCredentials.generate();
    const parentSigned = issueSelf(parentCreds);
    const childCreds = AgentCredentials.generate();

    const builder = new DelegationBuilder(parentSigned, parentCreds)
      .authorize(childCreds)
      .withPermissions([{ permission_key: 'api:read', constraints: {} }]);

    builder.sign(); // first call ok
    expect(() => builder.sign()).toThrow(/sign\(\) already called/);
  });
});
