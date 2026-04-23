#!/usr/bin/env bash
# Package-level smoke test. Verifies that a built tarball installs cleanly
# from file: and that both ESM and CJS consumer workflows exercise the full
# public API without crashing.
#
# Run from typescript/: `pnpm smoke`.
# Requires: bash, npm, mktemp, rm. No Windows support (release tooling only).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"  # -> typescript/
cd "$HERE"

echo "==> Building (tsup)…"
pnpm --silent build >/dev/null

# Per-run scratch cache so release smoke is hermetic and sidesteps any
# corrupted state in the dev's global ~/.npm.
cache_dir="$(mktemp -d -t modei-smoke-cache.XXXXXX)"

echo "==> Packing…"
tarball_name="$(npm pack --silent --cache "$cache_dir")"
tarball_abs="$HERE/$tarball_name"

# On any exit path, remove the tarball + scratch cache.
cleanup_artifacts() {
  rm -f "$tarball_abs" 2>/dev/null || true
  rm -rf "$cache_dir" 2>/dev/null || true
}
trap cleanup_artifacts EXIT

scratch="$(mktemp -d -t modei-smoke.XXXXXX)"
leave_scratch() {
  echo "❌ smoke test failed; scratch left at $scratch for inspection" >&2
}
trap 'leave_scratch' ERR

run_flavor() {
  # $1 = flavor name ("esm" | "cjs")
  # $2 = workflow file extension ("mjs" | "cjs")
  # $3 = JSON snippet for consumer package.json (either '"type": "module",' or '')
  local flavor="$1"
  local ext="$2"
  local type_field="$3"
  local dir="$scratch/$flavor"
  mkdir -p "$dir"

  cat > "$dir/package.json" <<EOF
{
  "name": "modei-smoke-${flavor}",
  "private": true,
  ${type_field}
  "dependencies": { "modei-typescript": "file:$tarball_abs" }
}
EOF
  cp "$HERE/scripts/workflow.$ext" "$dir/workflow.$ext"

  echo "==> [$flavor] installing tarball…"
  (cd "$dir" && npm install --silent --no-audit --no-fund --cache "$cache_dir") >/dev/null

  echo "==> [$flavor] running workflow…"
  (cd "$dir" && node "workflow.$ext")
  echo "==> [$flavor] OK"
}

run_flavor esm mjs '"type": "module",'
run_flavor cjs cjs ''

# Success: clean up scratch + tarball. Disarm the ERR trap first so the EXIT
# cleanup runs unimpeded.
trap - ERR
rm -rf "$scratch"
echo "✅ smoke test passed (ESM + CJS)"
