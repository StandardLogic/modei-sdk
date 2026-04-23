/**
 * Zod schemas + inferred types for the v2 passport envelope (spec §3.1).
 *
 * Mirror of the backend's `src/lib/passports/types.ts` and the Python SDK's
 * `modei.passport.envelope`. Structural validation parity with the backend's
 * `assertCanonicalEnvelope` (`verify.ts`) is a release invariant — any field
 * that backend rejects when missing is required here (no default).
 * Construction ergonomics live in `PassportIssuer.selfIssue()` and
 * `DelegationBuilder.sign()` (C20.4, C20.5), not at schema level.
 *
 * SNAKE_CASE FIELD NAMES (deliberate deviation from the SDK's camelCase rule).
 * The envelope IS the wire format — it's what gets RFC 8785 canonicalized and
 * Ed25519-signed. Any snake↔camel transformation layer would be a hiding place
 * for signature drift. Every other symbol in this SDK (method parameters,
 * builder options, error field names like `reasonCode`) uses camelCase; the
 * envelope + its submodels + `SignedPassport` are the narrow exception.
 * Matches backend TS types, Python SDK, and the sibling `mcp/` package's
 * REST-shape types.
 *
 * NAMING DEVIATION FROM BACKEND: Backend TypeScript exports a struct named
 * `PassportIssuer` for `provenance.issuer`. This SDK reserves that name for
 * the public sign-and-issue class (spec §11.1, C20.4). The envelope submodel
 * is therefore renamed `EnvelopeIssuer`. All other envelope submodels keep
 * their backend names.
 *
 * All schemas are `.strict()` so unknown fields fail validation — the backend
 * treats unknown envelope fields as `invalid_envelope_shape`. Parity matters.
 */

import { z } from 'zod';

export const issuerTypeSchema = z.enum(['gate', 'platform', 'self', 'delegate']);
export type IssuerType = z.infer<typeof issuerTypeSchema>;

/** `provenance.issuer` — renamed from backend `PassportIssuer`. */
export const envelopeIssuerSchema = z
  .object({
    type: issuerTypeSchema,
    id: z.string().min(1),
    key_id: z.string().min(1),
  })
  .strict();
export type EnvelopeIssuer = z.infer<typeof envelopeIssuerSchema>;

export const passportIdentitySchema = z
  .object({
    agent_id: z.string(),
    agent_name: z.string().nullable(),
    public_key: z.string(),
  })
  .strict();
export type PassportIdentity = z.infer<typeof passportIdentitySchema>;

export const passportPermissionSchema = z
  .object({
    permission_key: z.string(),
    constraints: z.record(z.string(), z.unknown()),
  })
  .strict();
export type PassportPermission = z.infer<typeof passportPermissionSchema>;

// Recursive types need manual declaration — Zod + TS cannot infer a fully
// self-referential type through `z.lazy` alone. Standard Zod escape hatch:
// declare the type as an interface, then annotate the schema explicitly.
export interface DelegationChainEntry {
  passport_json: Envelope;
  signature: string;
}

export interface Envelope {
  schema_version: 2;
  passport_id: string;
  identity: PassportIdentity;
  permissions: PassportPermission[];
  provenance: PassportProvenance;
  delegation_authority: boolean;
  verification_evidence: unknown[];
}

export interface PassportProvenance {
  issuer: EnvelopeIssuer;
  gate_id: string | null;
  catalog_content_hash: string | null;
  catalog_version: number | null;
  delegation_chain: DelegationChainEntry[] | null;
  issued_at: string;
  expires_at: string;
}

export const delegationChainEntrySchema: z.ZodType<DelegationChainEntry> = z.lazy(() =>
  z
    .object({
      passport_json: envelopeSchema,
      signature: z.string().min(1),
    })
    .strict(),
);

export const passportProvenanceSchema: z.ZodType<PassportProvenance> = z
  .object({
    issuer: envelopeIssuerSchema,
    gate_id: z.string().nullable(),
    catalog_content_hash: z.string().nullable(),
    catalog_version: z.number().int().nullable(),
    delegation_chain: z.array(delegationChainEntrySchema).nullable(),
    issued_at: z.string(),
    expires_at: z.string(),
  })
  .strict();

export const envelopeSchema: z.ZodType<Envelope> = z
  .object({
    schema_version: z.literal(2),
    passport_id: z.string().min(1),
    identity: passportIdentitySchema,
    permissions: z.array(passportPermissionSchema),
    provenance: passportProvenanceSchema,
    delegation_authority: z.boolean(),
    verification_evidence: z.array(z.unknown()),
  })
  .strict();

/**
 * An envelope bundled with its detached Ed25519 signature.
 *
 * Returned by `PassportIssuer.selfIssue()` (C20.4) and consumed by
 * `DelegationBuilder` (C20.5). Spec §11.1 names this wrapper `Passport`;
 * the SDK uses `SignedPassport` to avoid collision with REST-shape types.
 */
export interface SignedPassport {
  envelope: Envelope;
  signature: string;
}
