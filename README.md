# MisaOS

Declarative Linux hosts and isolated foreign application roots, following **MisaOS Architecture and Implementation Contract, baseline 1.4**.

**Implemented: S0 — executable wire contracts and Nix/Rust conformance.** This repository currently builds an unprivileged `misa-plan` validator, not a bootable operating system or foreign-application runner. It does not change the machine's bootloader, init, accounts, packages, mounts or services.

## Run it

With Nix and the `nix-command flakes` experimental features enabled:

```sh
nix build --no-update-lock-file --no-write-lock-file .
./result/bin/misa-plan validate fixtures/strata.json --expect strata
./result/bin/misa-plan validate fixtures/plan.json --expect plan
./result/bin/misa-plan validate fixtures/generation.json --expect generation
./result/bin/misa-plan generation-id fixtures/generation-body.json
```

For Rust development:

```sh
nix develop --no-update-lock-file --no-write-lock-file .
cargo run --locked -p misa-cli --bin misa-plan -- validate fixtures/strata.json --expect strata
cargo test --workspace --locked
```

`Cargo.lock` and `flake.lock` are committed. Nixpkgs is pinned to stable `nixos-26.05` revision `6fcc160353f63555b560f25588925133c8f61f2a`. Lock updates are explicit development operations, not a side effect of plan inspection. The Rust workspace requires Rust 1.88 or later; the Nix shell supplies the pinned toolchain.

**Every root, store path, boot image and signing key in `fixtures/` is synthetic.** These files exercise schemas; they do not supply artifacts that can be run, imported or booted. The CLI deliberately reports `validationScope: "schema-and-semantics-only"` and `artifactVerification: "not-performed"`.

## What works

- Three distinct, closed authority domains: `misa.strata/v1`, `misa.plan/v1`, and `misa.generation/v1`. A standalone strata record cannot be accepted as a full-host deployment, even by changing its discriminator.
- Strict JSON decoding before map construction: duplicate and escaped-duplicate keys, invalid UTF-8, lone surrogates, floating-point notation, negative zero, unsafe integers, excessive nesting and oversized input are rejected.
- RFC 8785 JCS canonicalization with Misa's integer-only numeric profile, including UTF-16 property ordering and no Unicode normalization.
- SHA-256 semantic identities and separate raw-input digests. A generation ID hashes the canonical manifest **without** `generationId`; its input must match that computed identity.
- Canonical configured paths; bounded identifiers; full digest syntax; decimal U64 byte counts; sorted, unique set-like arrays. Argument vectors and boot ordering retain their declared order.
- Root/export/grant references, export-name collisions, host path ownership, service graph edges and cycle witnesses, milestone membership, provider conflicts, and system/user dependency separation.
- Structural trust-policy consistency, distinct-key thresholds, boot selector/architecture/kernel/module consistency and explicit refusal of unknown required features or unqualified `leased-gc`.
- Locked Nix plan constructors, CLI packaging, shared byte-level golden vectors and a cross-language showcase. GitHub Actions runs the Rust and Nix checks.

The JSON Schema documents are self-contained. All operation objects reject unknown fields. Open maps exist only where explicitly defined, such as bounded inert annotations and environment declarations. Additional semantic checks run in Rust; JSON Schema alone is not sufficient.

## CLI

| Command | Output |
| --- | --- |
| `misa-plan validate FILE [--expect strata\|plan\|generation]` | JSON receipt with domain, semantic digest, raw digest and validation scope |
| `misa-plan canonicalize FILE [--expect ...]` | Validated record's exact JCS bytes, without an extra newline |
| `misa-plan digest FILE [--expect ...]` | Semantic `sha256:` identity; for generations this is `generationId` |
| `misa-plan generation-id FILE` | Identity of a complete generation body that omits `generationId` |
| `misa-plan jcs FILE` | JCS bytes for arbitrary JSON under Misa's strict numeric/input profile |
| `misa-plan schema strata\|plan\|generation` | Published JSON Schema |

`FILE` may be `-` for standard input. Validation/I/O failures exit 2 and emit `{code, field, message}` JSON on stderr. `field` is a JSON Pointer; strict decoding errors may use the document root (`""`). Usage/help output is handled by Clap. Diagnostics identify fields and constrained service IDs without dumping record contents or secret values.

The parser allows at most 1 MiB per input and 64 nested levels. Integral JSON values are limited to ±9,007,199,254,740,991; larger byte counts use canonical unsigned-decimal strings through U64_MAX. Set-like arrays must already be sorted by their declared identity key. Arrays such as `argv`, `cmdline.template`, `initrd.parts` and `modules.initrdOrder` are ordered sequences, not sets.

## Nix declaration interface

`lib.mkStrataPlan` and `lib.mkHostPlan` accept `{ pkgs; declaration; name ? ...; }` and return schema-only derivations. They fill an absent authority discriminator, reject an incompatible one, serialize with Nix, and validate/canonicalize with Rust at build time.

```nix
misa.lib.mkStrataPlan {
  inherit pkgs;
  declaration = builtins.fromJSON (builtins.readFile ./my-strata.json);
}
```

Outputs contain `strata.json` or `plan.json`, plus `receipt.json` and `digest.txt`. They are not NixOS modules and grant no activation authority. The checked-in fixture outputs are `strata-fixture`, `plan-fixture`, `generation-fixture`, and `wire-fixture`.

## Verification

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
nix flake check --no-update-lock-file --no-write-lock-file .
tests/vm/s0.sh
```

The showcase lives at the architecture's `tests/vm/` interface, but **S0 does not launch a VM**. It builds the locked Nix fixture outputs, executes the real CLI, compares canonical bytes and independent SHA-256 identities, checks the generation-to-plan/root bindings, and exercises malformed-record and authority-domain failures. It uses temporary files and does not rewrite locks. Set `MISA_PLAN_BIN` to an already-built executable to avoid an additional Cargo build.

Repeated locked realization may use the Nix cache. It proves stable evaluated identities, **not** an independent byte-for-byte rebuild witness. Only the locally exercised architecture/toolchain is evidenced; the aarch64 flake output is not a hardware qualification claim.

## Code map

| Path | Responsibility |
| --- | --- |
| `crates/misa-plan/` | Strict parser, closed-schema validation, semantic invariants, canonical identities and conformance tests |
| `crates/misa-cli/` | Read-only command-line interface |
| `schemas/` | Published schemas and their deterministic Python generator |
| `fixtures/` | Synthetic records and byte-level acceptance/rejection vectors |
| `nix/`, `flake.nix`, `flake.lock` | Pinned packaging, declaration constructors and cross-language checks |
| `tests/vm/s0.sh` | End-to-end S0 showcase |
| `.github/workflows/s0.yml` | CI |

`python3 schemas/generate.py` regenerates the schemas and synthetic record fixtures. Shared nested definitions have one generator source; generated schemas contain only reachable definitions and need no network resolution. The generator's fixture hashing is intentionally restricted to ASCII property names and safe integers; general JCS encoding belongs to the Rust implementation. `fixtures/wire.json` is the independent golden corpus and is not regenerated by that script.

Named-but-unspecified nested types in the PDF have conservative concrete layouts documented in schema `$comment` fields. Provider IDs identify service nodes. Target membership adds hard ordered prerequisites to the named milestone. This S0 ownership profile has no handoff declaration, so overlapping managed path claims are rejected rather than inferred. No runtime capability is qualified by schema acceptance.

## Next implementation sequence

1. **S1: standalone strata on stock NixOS.** Add `misa-resolve` and `misa-image` around pinned, daemonless `skopeo`/`umoci`: explicit digest/platform/publisher policy, verified OCI admission, sealed roots and permanent `retain-all` storage. Then implement `misa-exec` and a narrowly scoped NixOS module/export registry. Complete the slice with one Debian CLI and one desktop export launched unprivileged, denied host paths, upgrade survival, retained old/new roots, and offline relaunch. No per-launch root broker or automatic collector.
2. **S2: second foreign ecosystem.** Qualify a pinned Arch or Void root with its own ABI and database. Package composition and lease-based GC are separate gates, not prerequisites for the full host.
3. **S3: owned Linux host.** Dinit first, then s6-rc; real UEFI VM boot, generation journal and old-entry recovery, qualified service transitions and offline rollback. Do not alter the development machine's PID 1 to experiment.
4. **Later gated work:** owned-host desktop/hardware, extended recovery/boot trust where justified, additional architectures, then separately qualified firmware targets. Firmware and fleet control are not part of this initial Linux milestone.

Not implemented: image import or signature verification, actual foreign execution, symlink-safe privileged path opening, host enrollment/approval, activation, boot, init adapters, rollback, GC, firmware flashing or fleet deployment. No host reproducibility, security-isolation, recovery or hardware-support claim follows from S0.

## Architecture provenance

Implemented from Chapters 8 and 11, with nested boot/service/trust contracts from Chapters 4, 12, 13, 15 and 16 of `MisaOS-Architecture.pdf`, design baseline 1.4. The PDF remains in the owner's Downloads rather than being republished in this repository.

Source PDF SHA-256: `e1ccb5484999c0e6c515c4869e625a8e8e61a06b53e6b12a3e407607a90b54c8`.
