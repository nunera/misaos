# MisaOS

Declarative Linux hosts and isolated foreign application roots, following **MisaOS Architecture and Implementation Contract, baseline 1.4**.

**Implemented: S0 wire contracts, plus the S1 OCI admission/import/retention slice.** `misa-plan` validates plans; `misa` resolves, locally approves, imports and checks real foreign roots. This is not yet a bootable operating system, application launcher or NixOS activation module. It does not change the machine's bootloader, init, accounts, packages or services. Extraction uses temporary unprivileged namespaces; persistent writes are limited to explicitly selected key/output/store paths.

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

**Every root, store path, boot image and signing key in `fixtures/` is synthetic.** These files exercise schemas; they do not supply artifacts that can be run, imported or booted. `misa-plan validate` deliberately reports `validationScope: "schema-and-semantics-only"` and `artifactVerification: "not-performed"`.

## Import a real Debian root

The Nix package is `.#misa` (also the default); it installs both binaries and pins `skopeo`, `umoci` and `bubblewrap` to the existing Nixpkgs revision. Run imports as an ordinary user, never with `sudo`. Linux `openat2`, unprivileged user/mount/PID/network namespaces and xattr-capable storage are required; there is no weaker extraction fallback.

`examples/debian-bookworm.lock.json` and `examples/debian-trixie.lock.json` are **real linux/amd64 candidate locks**, unlike `fixtures/`. Each pins the original multi-architecture index and the exact selected OCI manifest. Review the source and descriptors before approving a lock.

```sh
tool=./result/bin/misa
mkdir -p "$HOME/.config/misa"
"$tool" trust keygen --directory "$HOME/.config/misa/admission"
"$tool" strata approve \
  --lock examples/debian-bookworm.lock.json \
  --secret-key "$HOME/.config/misa/admission/secret.json" \
  --output "$HOME/.config/misa/bookworm.approval.json"
"$tool" strata import \
  --lock examples/debian-bookworm.lock.json \
  --approval "$HOME/.config/misa/bookworm.approval.json" \
  --trusted-key "$HOME/.config/misa/admission/public.json" \
  --name debian --store "$HOME/.local/share/misa/roots"
"$tool" strata doctor --store "$HOME/.local/share/misa/roots"
"$tool" strata list --store "$HOME/.local/share/misa/roots"
```

Key generation creates a new `0700` directory with `0600` key files. Keys and `--output` records are never overwritten. Keep the secret key outside Git and back it up privately. To create a new candidate, use `misa strata resolve --image docker.io/library/debian:bookworm-slim --name debian --platform linux/amd64 --libc glibc --output candidate.lock.json`. Tags are permitted **only at resolution**; importing always uses locked digests. Resolution does not approve or import anything.

Repeat the import command with `--offline` to use only the retained store, or `--from-layout /absolute/oci/layout` to import a local OCI layout without network access. A missing/corrupt local artifact is an error, never a reason to fetch. `misa schema lock|approval|public-key` prints the corresponding closed wire schema.

### Admission and identity

This slice uses **Ed25519 local operator approval, not an upstream publisher signature**. The caller supplies the trusted public key explicitly. A domain-separated signature binds the SHA-256 of the entire JCS-canonical lock, including repository, index/manifest descriptors, platform and resource limits. Changed locks, unknown properties, duplicate JSON keys, wrong authorities and invalid signatures fail before admission. Skopeo's scoped transport policy allows downloading that approved repository into private staging; transport acceptance alone never admits an image.

The importer independently verifies the original index, manifest, config and every layer's size/media type/SHA-256, then verifies ordered uncompressed `rootfs.diff_ids`. The manifest digest remains the root identity. The import response contains a `misa.import/v1` receipt, its digest and a `VerifiedRootRef` usable by the existing strata schema. `libcFamily` is an operator declaration; `R1` is source/artifact identity qualification, not application ABI, publisher, reproducible-build or launch qualification.

### Extraction and retention

- Source blobs are copied through confined directory-relative file descriptors into a private snapshot before scanning. Archive entries are never extracted by the Rust tar parser.
- Preflight rejects traversal, writes through symlink parents, forward/non-regular hardlinks, duplicate paths, special/sparse files, capabilities, archive xattrs and ambiguous extension headers. Whiteouts affect lower layers only, even when their markers follow new files.
- One explicit normalization differs from the PDF's blanket dot-component rule: a lone `.`/`./` **directory** header denotes extraction-root metadata, as present in official Debian layers. It is not a child path or a traversal permission. Other dot components remain rejected. Umoci may apply that metadata only to its private extraction root; subsequent sealing applies the uniform cache policy.
- Pinned `umoci --rootless` runs inside a networkless `bubblewrap` namespace with no host home or host `/etc`, and no image entrypoint or package script execution. Actual ownership maps to the caller. Only umoci-generated inert `user.rootlesscontainers` ownership bookkeeping is allowed after extraction and included in the tree digest; an archive cannot supply it.
- All setuid/setgid bits and regular-file/directory write bits are removed. Receipts record stripped-mode counts. The derived tree digest covers framed paths, types, modes, file content, symlink targets and allowed helper metadata, not mtimes.
- `<store>/oci` is a standard OCI layout with original blobs, digest-named retained manifest references and deduplication. Materializations live under `<store>/materialized/<manifest-hex>/rootfs`; signed lock/key/approval evidence lives under `<store>/receipts`.
- Single-writer locking, fsynced content and no-replace publication prevent partial roots becoming usable index entries. Reimporting an existing image verifies rather than overwrites it. Both successful roots and failed private stages are retained; only a successful operation's own temporary staging is removed. There is **no GC, deletion, repair or activation command**.
- `list` reports retained roots, receipts, blob bytes, logical materialized file bytes and incomplete stages. `doctor` rechecks persisted local approvals, OCI bytes and tree digests offline; it never repairs corruption.

**Storage is caller-owned and permission-sealed, not immutable against that caller.** `sealMode: "read-only-permissions"` does not replace a read-only/nosuid/nodev launch view. The owner can replace the entire store and its local evidence; `doctor` is an integrity check, not an external trust anchor. System-owned storage and publisher-policy integration remain separate gates.

The bounded profile accepts OCI v1 manifests, raw/gzip layers and UTF-8 paths. It rejects zstd, package composition, global PAX, PAX size overrides, mixed GNU/PAX naming and unrecorded platform variants/requirements. JSON metadata is limited to 1 MiB, extension payloads to 64 KiB and depth to 64. Defaults/caps: 512 MiB per blob/file, 2 GiB expanded bytes, 200,000 entries/view nodes, 4,096-byte paths and a 256:1 expansion ratio. Network fetch additionally caps layer count at 128, declared compressed bytes at the expanded-byte budget and temporary file size with `RLIMIT_FSIZE`; it copies one layer at a time. Private snapshot copying is bounded by `maxExpandedBytes + 3 × maxBlobBytes`.

`timeoutSeconds` is a **phase budget**, not a hard total-operation deadline: snapshot copying, a complete verifier invocation, a tool invocation and a tree scan each receive a budget (default 300 seconds, maximum 600). Retained-blob checks have individual budgets. Filesystem checks are cooperative; kernel-blocked reads/fsync/publication are not preemptible. Failed stages and retained content consume disk indefinitely, so monitor the reported growth.


## S0 plan contracts

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

Run Rust checks inside `nix develop` so the real extraction tests receive `MISA_TEST_SKOPEO`, `MISA_TEST_UMOCI` and `MISA_TEST_BWRAP`. Without those variables, or under UID 0, the runtime storage cases explicitly skip; a passing sandboxed Nix build alone is not rootless-runtime evidence. GitHub Actions runs these tests outside the Nix build sandbox with the pinned tools.

CI uses Ubuntu 22.04 with the same locked Nix userland. The 24.04 runner denied the pinned bubblewrap's network-namespace setup (`Failed RTM_NEWADDR: Operation not permitted`), matching [Ubuntu's documented restriction](https://bugs.launchpad.net/bugs/2069526). The workflow does not disable AppArmor, drop namespace isolation, run imports as root or skip the runtime cases to obtain a pass. Ubuntu installations enforcing that policy need a separately reviewed host sandbox policy; this project does not change one automatically.

The image suite covers signature/lock substitution, descriptor/platform/diff-ID corruption, malicious archives, whiteout ordering, decompression bounds, inherited-pipe deadlines, real rootless extraction, retention, offline reimport and tamper detection. A separate live x86_64 smoke imported the two checked-in Debian locks, ran each with its own ELF loader/libc using explicit `bubblewrap`, denied root writes/host paths, kept a Bookworm process alive across the Trixie import and reimported both with zero network syscalls under `strace`. Standard `skopeo` could read both retained manifests. This is importer evidence, **not an implemented Misa launcher or the complete S1 gate**.

The showcase lives at the architecture's `tests/vm/` interface, but **S0 does not launch a VM**. It builds the locked Nix fixture outputs, executes the real CLI, compares canonical bytes and independent SHA-256 identities, checks the generation-to-plan/root bindings, and exercises malformed-record and authority-domain failures. It uses temporary files and does not rewrite locks. Set `MISA_PLAN_BIN` to an already-built executable to avoid an additional Cargo build.

Repeated locked realization may use the Nix cache. It proves stable evaluated identities, **not** an independent byte-for-byte rebuild witness. Only the locally exercised architecture/toolchain is evidenced; the aarch64 flake output is not a hardware qualification claim.

## Code map

| Path | Responsibility |
| --- | --- |
| `crates/misa-plan/` | Strict parser, closed-schema validation, semantic invariants, canonical identities and conformance tests |
| `crates/misa-image/` | Strict foreign locks, Ed25519 local admission, OCI resolution/preflight, retained storage and offline integrity checks |
| `crates/misa-cli/` | `misa-plan` inspection and unprivileged `misa` image commands |
| `schemas/` | Published schemas and their deterministic Python generator |
| `fixtures/` | Synthetic records and byte-level acceptance/rejection vectors |
| `examples/` | Real digest-pinned Debian candidate locks; no secret keys or operator approvals |
| `nix/`, `flake.nix`, `flake.lock` | Pinned packaging, declaration constructors and cross-language checks |
| `tests/vm/s0.sh` | End-to-end S0 showcase |
| `.github/workflows/verification.yml` | Plan and image CI with pinned dependencies |

`python3 schemas/generate.py` regenerates the schemas and synthetic record fixtures. Shared nested definitions have one generator source; generated schemas contain only reachable definitions and need no network resolution. The generator's fixture hashing is intentionally restricted to ASCII property names and safe integers; general JCS encoding belongs to the Rust implementation. `fixtures/wire.json` is the independent golden corpus and is not regenerated by that script.

Named-but-unspecified nested types in the PDF have conservative concrete layouts documented in schema `$comment` fields. Provider IDs identify service nodes. Target membership adds hard ordered prerequisites to the named milestone. This S0 ownership profile has no handoff declaration, so overlapping managed path claims are rejected rather than inferred. No runtime capability is qualified by schema acceptance.

## Next implementation sequence

1. **Continue S1: application launch and stock-NixOS integration.** Implement `misa-exec` for declared exports, read-only/nosuid/nodev roots, explicit grants and sanitized environments; then a narrowly scoped NixOS strata module/export registry and one Debian CLI plus one desktop export in the existing graphical session. Integrate the publisher trust policy rather than relabeling local approvals. Qualify host-path denial, upgrade survival and offline relaunch through the actual launcher. No per-launch root broker or automatic collector.
2. **S2: second foreign ecosystem.** Qualify a pinned Arch or Void root with its own ABI and database. Package composition and lease-based GC are separate gates, not prerequisites for the full host.
3. **S3: owned Linux host.** Dinit first, then s6-rc; real UEFI VM boot, generation journal and old-entry recovery, qualified service transitions and offline rollback. Do not alter the development machine's PID 1 to experiment.
4. **Later gated work:** owned-host desktop/hardware, extended recovery/boot trust where justified, additional architectures, then separately qualified firmware targets. Firmware and fleet control are not part of this initial Linux milestone.

Not implemented: publisher signature verification, the Misa application launcher/desktop exports/NixOS strata module, privileged host path opening, system-owned storage activation, host enrollment/approval, boot, init adapters, rollback, GC, firmware flashing or fleet deployment. No whole-host reproducibility, complete security-isolation, recovery or hardware-support claim follows from these checks.

## Architecture provenance

Implemented from Chapters 2, 8, 11, 14 and 16, with nested boot/service/trust contracts from Chapters 4, 12, 13 and 15 of `MisaOS-Architecture.pdf`, design baseline 1.4. The local-admission profile, root-header normalization and ownership/sealing limits above are explicit implementation choices, not silent claims of every architecture gate. The PDF remains in the owner's Downloads rather than being republished in this repository.

Source PDF SHA-256: `e1ccb5484999c0e6c515c4869e625a8e8e61a06b53e6b12a3e407607a90b54c8`.
