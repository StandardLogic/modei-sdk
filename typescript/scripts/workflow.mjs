// ESM consumer smoke workflow. Imports the full public API surface and runs
// the self-issue → verify → delegate → verify flow against a built tarball.
// Invoked from scripts/smoke-test.sh inside a scratch dir. No devDeps beyond
// the modei-typescript tarball itself.

import assert from 'node:assert/strict';

import {
  AgentCredentials,
  PassportIssuer,
  PassportVerifier,
  DelegationBuilder,
  TrustTier,
  CanonicalizationError,
  ModeiError,
} from 'modei-typescript';

// Subpath import sanity — one import per subpath entry in the exports map.
import { canonicalizeStrict } from 'modei-typescript/passport/canonical';
import { PASSPORT_VERIFY_REASON_CODES } from 'modei-typescript/passport/reasons';
import { envelopeSchema } from 'modei-typescript/passport/envelope';
import { deriveSelfAgentId } from 'modei-typescript/passport/agentId';
import { tierRank } from 'modei-typescript/passport/tier';
import { CREDENTIALS_FORMAT_VERSION } from 'modei-typescript/passport/credentials';
import { DelegationError } from 'modei-typescript/passport/errors';
import { MAX_CANONICAL_ENVELOPE_BYTES } from 'modei-typescript/passport/issuer';
import { MAX_DELEGATION_DEPTH } from 'modei-typescript/passport/verifier';
import { DelegationBuilder as DB2 } from 'modei-typescript/passport/delegation';

assert.equal(typeof canonicalizeStrict, 'function');
assert.ok(PASSPORT_VERIFY_REASON_CODES instanceof Set);
assert.equal(typeof envelopeSchema.parse, 'function');
assert.equal(typeof deriveSelfAgentId, 'function');
assert.equal(typeof tierRank, 'function');
assert.equal(CREDENTIALS_FORMAT_VERSION, 1);
assert.ok(DelegationError.prototype instanceof ModeiError);
assert.equal(MAX_CANONICAL_ENVELOPE_BYTES, 64 * 1024);
assert.equal(MAX_DELEGATION_DEPTH, 5);
assert.equal(DB2, DelegationBuilder);

// Canonicalize smoke — reject non-finite input.
assert.throws(() => canonicalizeStrict({ x: Number.NaN }), CanonicalizationError);

// End-to-end: generate → self-issue → verify → delegate → verify.
const parentCreds = AgentCredentials.generate();
const parent = new PassportIssuer(parentCreds, { identityClaim: 'smoke@dev.local' })
  .selfIssue({
    permissions: [{ permission_key: 'api:read', constraints: {} }],
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    delegationAuthority: true,
  });

const parentVerify = new PassportVerifier().verify(parent.envelope, parent.signature);
assert.ok(parentVerify.valid, `parent verify failed: ${JSON.stringify(parentVerify)}`);
assert.equal(parentVerify.tier, TrustTier.L0);

const childCreds = AgentCredentials.generate();
const child = new DelegationBuilder(parent, parentCreds)
  .authorize(childCreds)
  .withPermissions([{ permission_key: 'api:read', constraints: {} }])
  .withExpiry(new Date(Date.now() + 12 * 60 * 60 * 1000))
  .sign();

const childVerify = new PassportVerifier().verify(child.envelope, child.signature);
assert.ok(childVerify.valid, `child verify failed: ${JSON.stringify(childVerify)}`);
assert.equal(childVerify.tier, TrustTier.L0);

console.log('ESM smoke workflow passed');
