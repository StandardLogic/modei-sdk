// CJS consumer smoke workflow. Logic mirrors workflow.mjs verbatim; only the
// module-system syntax differs. Proves that `require('modei-typescript')`
// works end-to-end from a CJS entrypoint.

const assert = require('node:assert/strict');

const {
  AgentCredentials,
  PassportIssuer,
  PassportVerifier,
  DelegationBuilder,
  TrustTier,
  CanonicalizationError,
  ModeiError,
} = require('modei-typescript');

const { canonicalizeStrict } = require('modei-typescript/passport/canonical');
const { PASSPORT_VERIFY_REASON_CODES } = require('modei-typescript/passport/reasons');
const { envelopeSchema } = require('modei-typescript/passport/envelope');
const { deriveSelfAgentId } = require('modei-typescript/passport/agentId');
const { tierRank } = require('modei-typescript/passport/tier');
const { CREDENTIALS_FORMAT_VERSION } = require('modei-typescript/passport/credentials');
const { DelegationError } = require('modei-typescript/passport/errors');
const { MAX_CANONICAL_ENVELOPE_BYTES } = require('modei-typescript/passport/issuer');
const { MAX_DELEGATION_DEPTH } = require('modei-typescript/passport/verifier');
const { DelegationBuilder: DB2 } = require('modei-typescript/passport/delegation');

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

assert.throws(() => canonicalizeStrict({ x: Number.NaN }), CanonicalizationError);

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

console.log('CJS smoke workflow passed');
