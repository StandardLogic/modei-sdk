# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-rc.1] — 2026-04-22

Release candidate. Install with `npm install modei-typescript@next` (or
`pnpm add modei-typescript@next`). A default `npm install modei-typescript`
will **not** install this version — the `next` dist-tag is explicitly
reserved for RCs via `publishConfig.tag`.

### Added

- **Initial public release.** TypeScript SDK for the Modei platform, providing
  self-issued passport workflows (spec §2) at capability parity with
  [`modei-python@1.1.0a1`](https://pypi.org/project/modei-python/).
- `PassportIssuer` — self-issue and sign v2 envelopes.
- `PassportVerifier` — local Ed25519 signature + delegation chain verification.
  Returns a discriminated-union `ChainVerifyResult` for type-narrowing consumers.
- `AgentCredentials` — file-backed Ed25519 keypair with atomic `0o600` writes,
  `MODEI_CREDENTIALS_PATH` env override, and cross-SDK file-format interop
  with `modei-python`.
- `DelegationBuilder` — fluent API for constructing and signing delegated
  passports; pre-sign subset + expiry validation throws structured errors.
- `Envelope`, `SignedPassport`, `PassportIdentity`, `PassportPermission`,
  `PassportProvenance`, `DelegationChainEntry`, `EnvelopeIssuer`,
  `IssuerType` — Zod-inferred envelope types (snake_case wire format) plus
  matching schemas for runtime validation.
- `TrustTier` (`L0`, `L0.5`, `L1`, `L2`, `L3`), `tierRank`, `deriveTier`.
- `canonicalizeStrict` — RFC 8785 canonicalizer. Rejects non-finite numbers
  with a structured `CanonicalizationError`.
- `deriveSelfAgentId` — `"agent_self_" + base64url(sha256(pubkey))[:32]`
  per spec §14 A9.
- Error taxonomy: `ModeiError` base + `CanonicalizationError`,
  `DelegationError`, `DelegationSubsetError`, `DelegationChainTooDeepError`,
  `DelegationAuthorityMissingError`.
- 23-code `PassportVerifyReasonCode` taxonomy + `PASSPORT_VERIFY_REASON_CODES`
  runtime set.
- **Dual ESM + CJS output** with per-mode `.d.ts` / `.d.cts` conditional
  exports. 11 subpath entries: `.` plus `./passport/{canonical, reasons,
  envelope, agentId, tier, credentials, errors, issuer, verifier, delegation}`.
  Shared chunks via tsup `splitting: true` so `err instanceof ModeiError`
  works regardless of which subpath the error class is imported from.

### Cross-backend parity invariants

Three-way byte-equality (backend ↔ `modei-python` ↔ `modei-typescript`) is
a release invariant. Locked by fixture tests:

- **RFC 8785 canonicalization** — 23-case fixture (20 byte-equal + 3 reject).
- **Ed25519 signature** — self-issued + delegation-chain envelope fixtures;
  canonical-bytes hex + signature base64 match `modei-python` test literals
  verbatim.
- **Credential file format** — a file written by either SDK loads cleanly
  in the other; verified by `__tests__/fixtures/python-written-credential.json`.

### Intentional API divergences from `modei-python`

Documented, not bugs. See module TSDoc for each:

- `PassportIssuer.selfIssue` takes `expiresAt: Date` (absolute). Python
  uses `expires_in: timedelta` (relative). TypeScript has no native duration
  type.
- Shared `ModeiError` base class. Python has no equivalent; errors there
  extend `ValueError` or `Exception` directly.
- `deriveSelfAgentId` takes raw `Uint8Array` bytes. Python takes a base64
  string.

### Dependencies

- `@noble/ed25519@^3.0.0`, `@noble/hashes@^2.0.1` — sync API, wired via
  `ed.hashes.sha512` hook.
- `json-canonicalize@2.0.0` — **exact pin** matching the backend and
  `modei-python`'s `jcs==0.2.1`. Any upgrade is a coordinated cross-stack
  change requiring the RFC 8785 fixture suite to pass.
- `zod@^3.23.0` — runtime validation at envelope + credential-file boundaries.

## [1.0.0] — TBD

Production release. Promotes `1.0.0-rc.1` unchanged pending staging
round-trip sign-off + npm dist-tag move from `next` to `latest`. No API
changes between RC and GA.

[Unreleased]: https://github.com/StandardLogic/modei-sdk/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/StandardLogic/modei-sdk/releases/tag/v1.0.0-rc.1
