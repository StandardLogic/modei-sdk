import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/passport/canonical.ts',
    'src/passport/reasons.ts',
    'src/passport/envelope.ts',
    'src/passport/agentId.ts',
    'src/passport/tier.ts',
    'src/passport/credentials.ts',
    'src/passport/errors.ts',
    'src/passport/issuer.ts',
    'src/passport/verifier.ts',
    'src/passport/delegation.ts',
    // _subset.ts is intentionally NOT listed — tsup bundles its code inline
    // into verifier.js / delegation.js so consumers cannot import it directly.
  ],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  target: 'es2022',
  outDir: 'dist',
});
