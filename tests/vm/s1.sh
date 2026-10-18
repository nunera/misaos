#!/usr/bin/env bash
# S1 acceptance on stock NixOS in a real VM. Needs a Nix with KVM available to the
# builders (`system-features = kvm nixos-test`) and network only for the fixed-output
# fetches of the pinned Debian image and packages, which happen before any VM boots.
#
# Two NixOS VM tests run in sequence during evaluation and build: an oracle stage
# that performs the real image admission/import (its receipts feed the immutable
# strata plans via import-from-derivation), then the acceptance stage whose test
# script is tests/vm/s1-accept.py. The command fails unless every gate passes.
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
nix --extra-experimental-features 'nix-command flakes' build \
  --no-update-lock-file --no-write-lock-file --no-link --print-build-logs \
  "path:$repo#checks.x86_64-linux.s1"
