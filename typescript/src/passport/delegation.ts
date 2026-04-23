/**
 * DelegationBuilder — construct a child envelope from a parent SignedPassport.
 *
 * Port of Python `modei.passport.delegation`. Spec §11.1 lines 482-530,
 * §3.3 (chain invariants), §3.4 (subset permissions), §3.5 (constraint
 * tightening).
 *
 * API shape mirrors the Python SDK verbatim:
 *
 * ```ts
 * new DelegationBuilder(parent, parentCredentials)   // two args
 *   .authorize(childCredentials)                     // full keypair, not agentId
 *   .withPermissions([...])
 *   .withExpiry(expiresAt)                           // absolute Date; clamps to min ancestor
 *   .sign()                                          // no args; parent creds sign child
 * ```
 *
 * Three deviations from the C20.5 kickoff sketch were resolved to Python
 * parity and locked:
 *   1. Two-arg constructor — parent private key needed to sign child.
 *   2. `.authorize(childCredentials: AgentCredentials)` — full keypair so
 *      child's agent_id can be derived from the pubkey. Preserves the
 *      agent_id↔pubkey invariant.
 *   3. `.sign()` takes no args — creds are already bound via constructor + authorize.
 *
 * Single-use `.sign()` — TS addition not in Python. Catches reuse bugs at
 * negligible cost.
 *
 * Pre-sign validation:
 *   * Parent must have `delegation_authority=true` (`DelegationAuthorityMissingError`).
 *   * Proposed chain length ≤ 5 (`DelegationChainTooDeepError`).
 *   * Every adjacent pair in the proposed full chain + (last_ancestor, leaf)
 *     must satisfy subset permissions + constraint tightening + expiry
 *     non-extension (`DelegationSubsetError`).
 *
 * Expiry clamp (spec §11.1): `withExpiry(expiresAt)` computes
 * `min(expiresAt, parent.expires_at, chain[*].expires_at)`. The clamp is
 * silent; use `effectiveExpiresAt` and `expiryWasClamped` to introspect.
 * If `withExpiry` is not called, `sign()` defaults to `min(ancestor expiries)`.
 */

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { randomUUID } from 'node:crypto';

import { deriveSelfAgentId } from './agentId.js';
import type { AgentCredentials } from './credentials.js';
import type {
  DelegationChainEntry,
  Envelope,
  PassportPermission,
  SignedPassport,
} from './envelope.js';
import {
  DelegationAuthorityMissingError,
  DelegationChainTooDeepError,
  DelegationError,
  DelegationSubsetError,
} from './errors.js';
import {
  type SelfIssuePermission,
  signEnvelope,
} from './issuer.js';
import { MAX_DELEGATION_DEPTH } from './verifier.js';
import { enforceSubsetPermissions, isExpiryNonExtending } from './_subset.js';

// sync SHA-512 hook for @noble/ed25519 v3; required before any sign/verify/getPublicKey call.
// Idempotent — earlier-loaded modules may have already set this; reassigning a function
// property is zero-cost and defends against import-order bugs.
ed.hashes.sha512 = sha512;

/**
 * Parse a `SubsetCheck.detail` string into structured fields for
 * `DelegationSubsetError`. Mirrors Python's `str.find` chain at
 * delegation.py:364-399 — regex-based translation, same cases:
 *
 *   A: "descendant permission 'KEY' not present in ancestor"
 *   B: "permission 'KEY': constraint 'DIM' absent in ancestor; ..."
 *   C-H: "permission 'KEY': 'DIM' ..." (first quoted token after the
 *        key's colon is the dimension)
 *
 * Degrades silently if the detail format changes — structured fields go
 * `null`, the full `detail` string is preserved on the error. Same
 * behavior as Python. Unit tests pin the current format.
 */
function parseSubsetDetail(detail: string): {
  permissionKey: string | null;
  dimension: string | null;
} {
  // Case A
  const missing = /^descendant permission '([^']+)' not present in ancestor/.exec(detail);
  if (missing !== null) {
    return { permissionKey: missing[1] ?? null, dimension: null };
  }

  // Cases B-H — extract "permission 'KEY': rest", then dimension from rest.
  const wrap = /^permission '([^']+)': (.*)$/s.exec(detail);
  if (wrap !== null) {
    const permissionKey = wrap[1] ?? null;
    const rest = wrap[2] ?? '';
    // Case B
    const constraintDim = /^constraint '([^']+)'/.exec(rest);
    if (constraintDim !== null) {
      return { permissionKey, dimension: constraintDim[1] ?? null };
    }
    // Cases C-H
    const firstQuoted = /'([^']+)'/.exec(rest);
    if (firstQuoted !== null) {
      return { permissionKey, dimension: firstQuoted[1] ?? null };
    }
    return { permissionKey, dimension: null };
  }

  return { permissionKey: null, dimension: null };
}

/** Fluent builder for a delegated v2 passport envelope. */
export class DelegationBuilder {
  readonly #parentEnvelope: Envelope;
  readonly #parentSignature: string;
  readonly #parentCredentials: AgentCredentials;

  #childCredentials: AgentCredentials | null = null;
  #childPermissions: SelfIssuePermission[] | null = null;
  #childIdentityClaim: string | null = null;
  #childDelegationAuthority = false;
  #childVerificationEvidence: unknown[] = [];

  #effectiveExpiresAt: Date | null = null;
  #expiryWasClamped = false;

  #signed = false;

  constructor(parent: SignedPassport, parentCredentials: AgentCredentials) {
    const parentPubB64 = Buffer.from(parentCredentials.publicKey).toString('base64');
    if (parentPubB64 !== parent.envelope.identity.public_key) {
      throw new DelegationError(
        'parent_credentials public key does not match parent.envelope.identity.public_key',
      );
    }
    this.#parentEnvelope = parent.envelope;
    this.#parentSignature = parent.signature;
    this.#parentCredentials = parentCredentials;
  }

  // ---- fluent setters -----------------------------------------------------

  authorize(childCredentials: AgentCredentials): this {
    this.#childCredentials = childCredentials;
    return this;
  }

  withPermissions(permissions: SelfIssuePermission[]): this {
    this.#childPermissions = permissions;
    return this;
  }

  withExpiry(expiresAt: Date): this {
    const ancestorExpiries = [new Date(this.#parentEnvelope.provenance.expires_at)];
    for (const entry of this.#parentEnvelope.provenance.delegation_chain ?? []) {
      ancestorExpiries.push(new Date(entry.passport_json.provenance.expires_at));
    }
    const minAncestor = new Date(Math.min(...ancestorExpiries.map((d) => d.getTime())));
    const effective = expiresAt.getTime() < minAncestor.getTime() ? expiresAt : minAncestor;
    this.#effectiveExpiresAt = effective;
    this.#expiryWasClamped = effective.getTime() < expiresAt.getTime();
    return this;
  }

  withIdentityClaim(claim: string | null): this {
    this.#childIdentityClaim = claim;
    return this;
  }

  withDelegationAuthority(value: boolean): this {
    this.#childDelegationAuthority = value;
    return this;
  }

  withVerificationEvidence(evidence: unknown[]): this {
    this.#childVerificationEvidence = evidence;
    return this;
  }

  // ---- introspection ------------------------------------------------------

  /** Clamped `expires_at` after `withExpiry()`. `null` before `withExpiry()`. */
  get effectiveExpiresAt(): Date | null {
    return this.#effectiveExpiresAt;
  }

  /** `true` if `withExpiry()`'s requested value was clamped down to an ancestor's expiry. */
  get expiryWasClamped(): boolean {
    return this.#expiryWasClamped;
  }

  // ---- terminal -----------------------------------------------------------

  sign(): SignedPassport {
    if (this.#signed) {
      throw new Error('DelegationBuilder: sign() already called');
    }

    if (this.#childCredentials === null) {
      throw new DelegationError(
        'authorize(childCredentials) must be called before sign()',
      );
    }
    if (this.#childPermissions === null) {
      throw new DelegationError(
        'withPermissions(...) must be called before sign(). ' +
          "To inherit parent's permissions verbatim, pass them explicitly: " +
          '.withPermissions(parent.envelope.permissions)',
      );
    }

    if (this.#parentEnvelope.delegation_authority !== true) {
      throw new DelegationAuthorityMissingError();
    }

    const parentChain = this.#parentEnvelope.provenance.delegation_chain ?? [];
    const proposedChain: DelegationChainEntry[] = [
      ...parentChain,
      { passport_json: this.#parentEnvelope, signature: this.#parentSignature },
    ];
    if (proposedChain.length > MAX_DELEGATION_DEPTH) {
      throw new DelegationChainTooDeepError(proposedChain.length, MAX_DELEGATION_DEPTH);
    }

    // If withExpiry wasn't called, default to inherit most-restrictive ancestor expiry.
    if (this.#effectiveExpiresAt === null) {
      const ancestorExpiries = [new Date(this.#parentEnvelope.provenance.expires_at)];
      for (const entry of parentChain) {
        ancestorExpiries.push(new Date(entry.passport_json.provenance.expires_at));
      }
      this.#effectiveExpiresAt = new Date(
        Math.min(...ancestorExpiries.map((d) => d.getTime())),
      );
    }
    const expiresAtDate = this.#effectiveExpiresAt;

    // issuer.id references the chain ROOT's passport_id, not immediate parent's.
    const root = proposedChain[0];
    if (root === undefined) {
      // Unreachable: proposedChain always has ≥1 entry (the parent itself).
      throw new DelegationError('internal: proposed chain is empty');
    }
    const rootIssuerType = root.passport_json.provenance.issuer.type;

    // Gate inheritance: gate_id + catalog_* only inherit from a gate-rooted chain.
    const inheritedGateId =
      rootIssuerType === 'gate' ? root.passport_json.provenance.gate_id : null;
    const inheritedCatalogHash =
      rootIssuerType === 'gate' ? root.passport_json.provenance.catalog_content_hash : null;
    const inheritedCatalogVersion =
      rootIssuerType === 'gate' ? root.passport_json.provenance.catalog_version : null;

    const childCreds = this.#childCredentials;
    const childPubB64 = Buffer.from(childCreds.publicKey).toString('base64');

    const child: Envelope = {
      schema_version: 2,
      passport_id: `pp_delegate_${randomUUID().replace(/-/g, '')}`,
      identity: {
        agent_id: deriveSelfAgentId(childCreds.publicKey),
        agent_name: this.#childIdentityClaim,
        public_key: childPubB64,
      },
      permissions: this.#childPermissions.map<PassportPermission>((p) => ({
        permission_key: p.permission_key,
        constraints: p.constraints ?? {},
      })),
      provenance: {
        issuer: {
          type: 'delegate',
          id: 'delegate:' + root.passport_json.passport_id,
          key_id: this.#parentEnvelope.provenance.issuer.key_id,
        },
        gate_id: inheritedGateId,
        catalog_content_hash: inheritedCatalogHash,
        catalog_version: inheritedCatalogVersion,
        delegation_chain: proposedChain,
        issued_at: new Date().toISOString(),
        expires_at: expiresAtDate.toISOString(),
      },
      delegation_authority: this.#childDelegationAuthority,
      verification_evidence: [...this.#childVerificationEvidence],
    };

    // Pre-sign walk: every adjacent pair in proposed chain + (last_ancestor, child).
    // Inner pairs were validated at their own sign-time; re-walking is redundant for
    // well-formed inputs but pins pre-sign verdict === verify-time verdict for ANY
    // input at negligible cost. Matches Python.
    for (let i = 0; i < proposedChain.length - 1; i++) {
      checkPair(proposedChain[i]!.passport_json, proposedChain[i + 1]!.passport_json);
    }
    const lastAncestor = proposedChain[proposedChain.length - 1]!.passport_json;
    checkPair(lastAncestor, child);

    // Parent's private key signs the child envelope. Reuses issuer.ts's signEnvelope
    // helper for canonicalize + size-check + ed.sign + base64-encode.
    const signatureB64 = signEnvelope(child, this.#parentCredentials.privateKey);

    this.#signed = true;
    return { envelope: child, signature: signatureB64 };
  }
}

/**
 * Internal: run the subset + expiry checks on one (ancestor, descendant)
 * pair. Raises `DelegationSubsetError` with structured fields on failure.
 *
 * Permission-subset failures: `permissionKey` + `dimension` parsed from the
 * SubsetCheck detail string; `ancestorValue`/`descendantValue` left `null`
 * (parsing arbitrary values out of the detail is too fragile — matches
 * Python's `delegation.py:393-399`).
 *
 * Expiry-extension failures: `dimension = 'expires_at'`,
 * `ancestorValue`/`descendantValue` populated with the raw ISO strings.
 */
function checkPair(ancestor: Envelope, descendant: Envelope): void {
  const subset = enforceSubsetPermissions(ancestor, descendant);
  if (!subset.ok) {
    const detail = subset.detail ?? '';
    const { permissionKey, dimension } = parseSubsetDetail(detail);
    throw new DelegationSubsetError({
      permissionKey,
      dimension,
      ancestorValue: null,
      descendantValue: null,
      detail,
    });
  }
  if (!isExpiryNonExtending(ancestor, descendant)) {
    throw new DelegationSubsetError({
      permissionKey: null,
      dimension: 'expires_at',
      ancestorValue: ancestor.provenance.expires_at,
      descendantValue: descendant.provenance.expires_at,
      detail:
        `expiry_extension: descendant.expires_at ` +
        `'${descendant.provenance.expires_at}' > ancestor.expires_at ` +
        `'${ancestor.provenance.expires_at}'`,
    });
  }
}
