#!/usr/bin/env bash
# Validate the shape of `npm pack` output. Asserts expected files present +
# forbidden files absent + unpacked size under cap.
#
# Run from typescript/: `pnpm inspect-pack`.
# Expected file count: ~110 (4 root + dist artifacts as of 1.0.0-rc.1).
# tsup splitting: true produces 11 entry files + ~44 shared-chunk files
# (chunks carry shared class definitions so `err instanceof ModeiError`
# works across root + subpath imports). Bounds [80, 150] allow adjustments
# without test churn. Outside this range -> either a new subpath entry
# (update this comment + bound) or an unintended inclusion (investigate).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

# Per-run scratch cache so release smoke is hermetic and sidesteps any
# corrupted state in the dev's global ~/.npm. Cleaned up on exit.
cache_dir="$(mktemp -d -t modei-inspect-cache.XXXXXX)"
trap 'rm -rf "$cache_dir"' EXIT

npm pack --dry-run --json --cache "$cache_dir" 2>/dev/null | node -e '
const data = JSON.parse(require("fs").readFileSync(0, "utf8"));
const entry = data[0];
const files = entry.files.map(f => f.path).sort();
const unpackedSize = entry.unpackedSize;

const required = [
  "package.json",
  "README.md",
  "LICENSE",
  "CHANGELOG.md",
  "dist/index.js",
  "dist/index.cjs",
  "dist/index.d.ts",
  "dist/index.d.cts",
  "dist/passport/issuer.js",
  "dist/passport/verifier.js",
  "dist/passport/delegation.js",
];

const forbidden = [
  "src/",
  "__tests__/",
  ".specs/",
  "scripts/",
  "node_modules/",
  "tsconfig.json",
  "tsconfig.typecheck.json",
  "tsup.config.ts",
  "vitest.config.ts",
  "eslint.config.js",
  ".prettierrc.json",
  ".prettierignore",
  "pnpm-lock.yaml",
  ".gitignore",
];

// Unpacked size cap: 1 MB. Actual as of 1.0.0-rc.1 is ~770 KB (dual ESM+CJS
// code + source maps for 10 modules). Cap has ~250 KB headroom; a drift
// past 1 MB likely means a large accidental inclusion (e.g., node_modules
// leaked in, or a big vendored fixture).
const CAP_BYTES = 1024 * 1024;
const MIN_FILES = 80;
const MAX_FILES = 150;

let fail = false;
for (const r of required) {
  if (!files.includes(r)) { console.error(`MISSING required: ${r}`); fail = true; }
}
for (const f of files) {
  for (const bad of forbidden) {
    if (f === bad || f.startsWith(bad)) {
      console.error(`FORBIDDEN present: ${f}`); fail = true; break;
    }
  }
}
if (unpackedSize > CAP_BYTES) {
  console.error(`unpacked size ${unpackedSize} bytes exceeds cap (${CAP_BYTES})`);
  fail = true;
}
if (files.length < MIN_FILES || files.length > MAX_FILES) {
  console.error(`file count ${files.length} outside expected [${MIN_FILES}, ${MAX_FILES}]`);
  fail = true;
}
if (fail) {
  console.error("\ninspect-pack FAILED. Full file list:");
  for (const f of files) console.error("  " + f);
  process.exit(1);
}
console.log(
  `✅ inspect-pack OK: ${files.length} files, ${Math.round(unpackedSize / 1024)} KB unpacked`,
);
'
