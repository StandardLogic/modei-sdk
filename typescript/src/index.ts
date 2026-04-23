export { canonicalizeStrict, CanonicalizationError } from './passport/canonical.js';
export {
  PASSPORT_VERIFY_REASON_CODES,
  type PassportVerifyReasonCode,
} from './passport/reasons.js';
export { SELF_AGENT_ID_PREFIX, deriveSelfAgentId } from './passport/agentId.js';
export { TrustTier, tierRank, deriveTier } from './passport/tier.js';
export {
  delegationChainEntrySchema,
  envelopeIssuerSchema,
  envelopeSchema,
  issuerTypeSchema,
  passportIdentitySchema,
  passportPermissionSchema,
  passportProvenanceSchema,
  type DelegationChainEntry,
  type Envelope,
  type EnvelopeIssuer,
  type IssuerType,
  type PassportIdentity,
  type PassportPermission,
  type PassportProvenance,
  type SignedPassport,
} from './passport/envelope.js';
