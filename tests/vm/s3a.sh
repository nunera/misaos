#!/usr/bin/env bash
# S3a acceptance: the first Misa-owned UEFI boot. OVMF and systemd-boot (loader only)
# boot a published BLS entry through a borrowed stage 1 (the not-os adaptation, then
# NixOS's scripted stage 1) into misa-handoff, which verifies the selected
# generation and execs Dinit as PID 1. Needs a Nix with KVM available to the builders
# (`system-features = kvm nixos-test`); the guests have no network.
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
nix --extra-experimental-features 'nix-command flakes' build \
  --no-update-lock-file --no-write-lock-file --no-link --print-build-logs \
  "path:$repo#checks.x86_64-linux.s3a"
