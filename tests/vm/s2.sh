#!/usr/bin/env bash
# S2 acceptance on stock NixOS in a real VM: a Void musl root beside the S1 Debian
# root in one merged lockset and plan. Needs a Nix with KVM available to the builders
# (`system-features = kvm nixos-test`) and network only for the fixed-output fetches
# of the pinned Debian and Void images and Debian packages, before any VM boots.
#
# An oracle VM stage performs the real admissions/imports (its receipts feed the
# immutable plans via import-from-derivation), then the acceptance stage runs
# tests/vm/s2-accept.py. The command fails unless every gate passes.
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
nix --extra-experimental-features 'nix-command flakes' build \
  --no-update-lock-file --no-write-lock-file --no-link --print-build-logs \
  "path:$repo#checks.x86_64-linux.s2"
