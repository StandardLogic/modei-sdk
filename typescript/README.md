# modei-typescript

TypeScript SDK for [Modei](https://modei.ai) — trust infrastructure for
AI agents. Pronounced "Mo-dee".

> **Status:** `1.0.0-rc.1` — release candidate. Install with
> `npm install modei-typescript@next`. Promotes to `1.0.0` at prod cutover.

## Install

```bash
npm install modei-typescript@next
# or
pnpm add modei-typescript@next
```

Requires Node.js ≥ 18. Dual ESM + CJS: both `import` and `require` are
supported with per-mode types.

## Quickstart

```ts
import {
  AgentCredentials,
  PassportIssuer,
  PassportVerifier,
  DelegationBuilder,
} from 'modei-typescript';

// 1. Generate (or load) an agent keypair.
const aliceCreds = AgentCredentials.generate();

// 2. Self-issue a passport.
const alice = new PassportIssuer(aliceCreds, { identityClaim: 'alice@dev.local' })
  .selfIssue({
    permissions: [{ permission_key: 'api:read', constraints: {} }],
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    delegationAuthority: true,
  });

// 3. Verify locally.
const result = new PassportVerifier().verify(alice.envelope, alice.signature);
if (result.valid) {
  console.log('tier:', result.tier); // 'L0'
}

// 4. Delegate to a child agent.
const bobCreds = AgentCredentials.generate();
const bob = new DelegationBuilder(alice, aliceCreds)
  .authorize(bobCreds)
  .withPermissions([{ permission_key: 'api:read', constraints: {} }])
  .withExpiry(new Date(Date.now() + 24 * 60 * 60 * 1000))
  .sign();
```

## Persisting credentials

```ts
import { AgentCredentials } from 'modei-typescript';

const creds = AgentCredentials.loadOrCreate(
  '~/.config/modei/credentials/alice.json',
);
```

Files are written atomically with mode `0o600` on POSIX. Tilde paths are
expanded via `os.homedir()`; parent directories are created as needed. Set
`MODEI_CREDENTIALS_PATH` to override the default path argument. The file
format is byte-compatible with the
[`modei-python`](https://pypi.org/project/modei-python/) SDK — a credential
written by either SDK loads cleanly in the other.

## Error handling

```ts
import {
  ModeiError,
  DelegationSubsetError,
  CanonicalizationError,
} from 'modei-typescript';

try {
  builder.sign();
} catch (err) {
  if (err instanceof DelegationSubsetError) {
    console.error('subset violation:', err.permissionKey, err.dimension);
  } else if (err instanceof ModeiError) {
    console.error('SDK error:', err.message);
  } else {
    throw err;
  }
}
```

Every SDK-thrown error extends `ModeiError`. Specific subclasses:
`CanonicalizationError`, `DelegationError` (+ three subclasses:
`DelegationSubsetError`, `DelegationChainTooDeepError`,
`DelegationAuthorityMissingError`).

## Subpath imports

For tree-shakeability, import specific modules by subpath:

```ts
import { canonicalizeStrict } from 'modei-typescript/passport/canonical';
import { TrustTier } from 'modei-typescript/passport/tier';
import { PASSPORT_VERIFY_REASON_CODES } from 'modei-typescript/passport/reasons';
```

Ten subpaths available: `canonical`, `reasons`, `envelope`, `agentId`,
`tier`, `credentials`, `errors`, `issuer`, `verifier`, `delegation`.

## Cross-language parity

The TypeScript SDK is capability-equivalent with
[`modei-python`](https://pypi.org/project/modei-python/) (`1.0.0-rc.1` ↔
`1.1.0a1`). Cryptographic primitives (RFC 8785 canonicalization, Ed25519
signing, agent-id derivation) are byte-identical across both SDKs and the
Modei backend. Envelopes produced by one SDK verify in the other; credential
files written by one load cleanly in the other.

See [CHANGELOG.md](./CHANGELOG.md) for the complete list of release
invariants and intentional API divergences.

## API reference

Detailed API docs live as TSDoc inline on each module. Your IDE's hover
integration is the primary reference surface.

High-level grouping:

- **Envelope construction:** `PassportIssuer`, `DelegationBuilder`
- **Verification:** `PassportVerifier`, `ChainVerifyResult`
- **Credentials:** `AgentCredentials`
- **Types:** `Envelope`, `SignedPassport`, `TrustTier`, `PassportVerifyReasonCode`
- **Errors:** `ModeiError` + 5 subclasses
- **Utilities:** `canonicalizeStrict`, `deriveSelfAgentId`, `deriveTier`,
  `tierRank`

## License

MIT — see [LICENSE](./LICENSE).
