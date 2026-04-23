import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/passport/canonical.ts',
    'src/passport/reasons.ts',
    'src/passport/envelope.ts',
    'src/passport/agentId.ts',
    'src/passport/tier.ts',
  ],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  target: 'es2022',
  outDir: 'dist',
});
