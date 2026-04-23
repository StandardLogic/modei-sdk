/**
 * Self-issued agent_id derivation.
 *
 * Mirrors the backend's `src/lib/passports/agent_id.ts` byte-for-byte:
 *
 *     agent_id = "agent_self_" + base64url(sha256(pubkey_bytes)).slice(0, 32)
 *
 * 32 base64url characters = 192 bits of entropy (spec §14 A9).
 *
 * SIGNATURE DIVERGENCE FROM PYTHON SDK: This function takes raw `Uint8Array`
 * bytes. The Python SDK's `derive_self_agent_id` takes a base64-encoded
 * string. Intentional per C20.2 kickoff — TS has `Uint8Array` natively, so
 * the b64-decode step belongs in the caller when it's needed. Callers
 * holding a base64 string should decode themselves via
 * `Buffer.from(b64, 'base64')`.
 */

import { sha256 } from '@noble/hashes/sha2.js';

export const SELF_AGENT_ID_PREFIX = 'agent_self_';

/**
 * Derive the self-issued `agent_id` from a raw public key.
 *
 * @param publicKey Raw public-key bytes. Typically 32 bytes for Ed25519, but
 *   length is NOT enforced here — signature verification catches length
 *   mismatches. Matches backend parity.
 * @returns `"agent_self_" + base64url(sha256(publicKey)).slice(0, 32)`.
 *   Always 43 characters.
 */
export function deriveSelfAgentId(publicKey: Uint8Array): string {
  const digest = sha256(publicKey);
  const b64url = Buffer.from(digest).toString('base64url');
  return SELF_AGENT_ID_PREFIX + b64url.slice(0, 32);
}
