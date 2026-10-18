#!/usr/bin/env bash
# Historical showcase location only: S0 never starts a VM or executes a root.
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/misa-s0.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
export TMPDIR="$work"

if [[ -n ${MISA_PLAN_BIN:-} ]]; then
  tool=$MISA_PLAN_BIN
else
  # Keep build artifacts out of the source tree, and never rewrite Cargo.lock.
  RUSTC_WRAPPER= cargo build --locked --manifest-path "$repo/Cargo.toml" \
    --package misa-cli --bin misa-plan --target-dir "$work/target"
  tool="$work/target/debug/misa-plan"
fi

nix_cmd=(nix --extra-experimental-features 'nix-command flakes')
locked=(--no-update-lock-file --no-write-lock-file)
# path: includes new source files even before their first Git commit.
flake="path:$repo"
for domain in strata plan generation wire; do
  first=$("${nix_cmd[@]}" build "${locked[@]}" --no-link --print-out-paths \
    "$flake#${domain}-fixture")
  second=$("${nix_cmd[@]}" build "${locked[@]}" --no-link --print-out-paths \
    "$flake#${domain}-fixture")
  if [[ "$first" != "$second" ]]; then
    printf 'Nix fixture evaluation changed store identity: %s\n' "$domain" >&2
    exit 1
  fi
  # Repeated locked realization can hit the cache; this is NOT a rebuild proof.
  cmp -- "$first/$domain.json" "$second/$domain.json"
  cp -- "$first/$domain.json" "$work/$domain.json"
done

python3 "$repo/nix/s0.py" --tool "$tool" --fixtures "$repo/fixtures" \
  --strata "$work/strata.json" --plan "$work/plan.json" \
  --generation "$work/generation.json" --nix-wire "$work/wire.json"
