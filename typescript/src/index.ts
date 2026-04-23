export { canonicalizeStrict } from './passport/canonical.js';
export {
  PASSPORT_VERIFY_REASON_CODES,
  type PassportVerifyReasonCode,
} from './passport/reasons.js';
export { SELF_AGENT_ID_PREFIX, deriveSelfAgentId } from './passport/agentId.js';
export {
  AgentCredentials,
  CREDENTIALS_FORMAT_VERSION,
  ENV_PATH_VAR,
  type AgentCredentialsInit,
} from './passport/credentials.js';
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
export {
  CanonicalizationError,
  DelegationAuthorityMissingError,
  DelegationChainTooDeepError,
  DelegationError,
  DelegationSubsetError,
  ModeiError,
  type DelegationSubsetErrorInit,
} from './passport/errors.js';
export {
  MAX_CANONICAL_ENVELOPE_BYTES,
  PassportIssuer,
  signEnvelope,
  type PassportIssuerOptions,
  type SelfIssueOptions,
  type SelfIssuePermission,
} from './passport/issuer.js';
export {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
  MAX_DELEGATION_DEPTH,
  PassportVerifier,
  type ChainVerifyResult,
} from './passport/verifier.js';
export { DelegationBuilder } from './passport/delegation.js';
