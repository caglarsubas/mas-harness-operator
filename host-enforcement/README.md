# host-enforcement

The Rust workspace for the Planeon host-enforcement modules (W03). HE-001 adds only the scaffold: a closed configuration
library, five binaries that parse their argv and exit, the toolchain pin, a reviewed closure table and an in-repo gate.
Module logic arrives in HE-002 to HE-007. HE-002 adds the effect gate's I05 v3 logic as two libraries, tested against
the published contract vectors; no binary links them yet.

## Layout

| Path | Purpose |
| --- | --- |
| `Cargo.toml`, `Cargo.lock` | Workspace (edition 2024, Apache-2.0); the lock lists only workspace crates |
| `crates/host-common/` | Closed configuration parser; thread counts come from configuration, never from the host |
| `crates/{containment,broker,observer,gate,writer}/` | Binaries `planeon-*`; argv only, no file access |
| `crates/i05-protocol/` | Library (HE-002): the I05 v3 wire codec, canonical encoder, SHA-256 (NIST CAVP tested), schema subset, outcome mapping and request rendering |
| `crates/effect-gate/` | Library (HE-002): the I05 v3 gate state machine with an in-memory journal and failure marker; `MODEL_DEFINED.md` lists what the pinned model, not the READMEs, defines |
| `contracts/` | The I05 and I07 contract data and READMEs copied byte for byte from harness-onion `a2eab93`; `PROVENANCE.md` |
| `toolchain.json` | The pinned toolchain, each target's ELF shape and the Command Line Tools dependency |
| `licenses/closure-1.99.0.json` | The reviewed classification of every shipped file under `lib/rustlib/<target>/` |
| `tools/gate.py`, `tools/test_gate.py` | The gate and its self-test (stdlib only) |
| `tools/rust-lld` | Linker wrapper (see below) |
| `../.cargo/config.toml` | Repository root: offline, the linker and static linking for both musl targets |

## Acceptance commands

Every R10 packet from HE-001 on runs these after HE-000's and HE-000B's commands, from the repository root:

1. `cargo build --locked --offline --frozen --release --manifest-path host-enforcement/Cargo.toml --target x86_64-unknown-linux-musl`
2. the same with `--target aarch64-unknown-linux-musl`
3. `cargo test --locked --offline --frozen --manifest-path host-enforcement/Cargo.toml`
4. `python3 -I -B host-enforcement/tools/gate.py`

The gate checks the toolchain pin, the cargo config and linker wrapper, the workspace and lock, the closure table against the installed toolchain, the crt
objects (compiler-rt, not GCC), each binary's ELF shape, the start-up lint, and writes one deterministic CycloneDX 1.5
SBOM per binary and target under `target/sbom/`. Every line it prints starts with `he-gate: `.

## Rules

- **Forward-fix only.** A merged packet is never reverted or rewritten; a defect is fixed by a new packet.
- **Offline builds.** `[net] offline = true`, `--locked --offline --frozen`, no registry or git dependency. The first
  packet that vendors a crate extends the gate and the closure table.
- **No build scripts or proc-macros** in the workspace.
- **Start-up lint.** Workspace sources must not use `available_parallelism`, `current_exe`, `current_dir`, `env::var`,
  `var_os`, `vars`, `/proc` or `/sys` (every `.rs` file outside `target/`). It is a source lint, not proof of behaviour
  (that is T04's trace).
- **Units must not set `RUST_BACKTRACE`** (HE-008).
- **The closure table is anchored by the packet.** `TABLE_SHA256` in `tools/gate.py` pins the reviewed table; a change
  needs a new packet with a regenerated and independently reviewed table.

## Linker wrapper

The official `rustc` component ships `libLLVM.dylib` in `<sysroot>/lib`, but `rust-lld`'s rpath points at
`<sysroot>/lib/rustlib/<host>/lib`, so on macOS it loads only when `DYLD_FALLBACK_LIBRARY_PATH` names `<sysroot>/lib`.
Set through cargo's `[env]`, the variable did not reach the linker in the local simulation, so `tools/rust-lld` sets it
and execs the pinned `rust-lld`. The file keeps the name `rust-lld` so rustc infers the lld flavor. The gate checks the
cargo config and the wrapper's command lines against `toolchain.json`, and each binary's `.comment` must name LLD of
rustc's LLVM version.

## Host dependencies outside the profile's inventories

- **Command Line Tools** (owner decision Q-HE2): `cargo test` links the `aarch64-apple-darwin` test binaries with the
  system linker. The gate fails if the path is missing and prints, without failing, a version that differs from
  `toolchain.json`.
- **cosign** (HE-000 review H3): `go test ./...` runs `/opt/planeon/bin/cosign verify-blob --offline` and checks its
  sha256 against the digest pinned in `internal/verify`; it is not in the profile's inventories, so it changes only
  together with an R10 packet.

## Limits

- `aarch64-unknown-linux-musl` has no static-pie default at 1.99.0, so its binaries are static `ET_EXEC`
  (`toolchain.json`).
- The profile has no C cross-compiler or musl headers, no rustfmt or clippy, no BPF toolchain and no crate cache. A
  toolchain bundle may be needed before HE-003 (TLS) or HE-006 (BPF) if pure-Rust options do not suffice.
- Out of scope here: the host image, runc/containerd SBOMs, NOTICE files, license texts and source offers (HE-008), and
  native traces (T04).
