# host-enforcement

The Rust workspace for the Planeon host-enforcement modules (W03). HE-001 adds only the scaffold: a closed configuration
library, five binaries that parse their argv and exit, the toolchain pin, a reviewed closure table and an in-repo gate.
Module logic arrives in HE-002 to HE-007. HE-002 adds the effect gate's I05 v3 logic as two libraries, tested against
the published contract vectors; HE-003D's `planeon-gate` is the first binary that links them (with gate-sys and
gate-tls).

## Layout

| Path | Purpose |
| --- | --- |
| `Cargo.toml`, `Cargo.lock` | Workspace (edition 2024, Apache-2.0); the lock lists the workspace crates, the 11 LINKED vendored crates as path packages (HE-003D's `[patch.crates-io]`) and the other vendor rows as registry packages with their checksums |
| `crates/host-common/` | Closed configuration parser; thread counts come from configuration, never from the host |
| `crates/{containment,broker,writer}/` | Binaries `planeon-*`; argv only, no file access |
| `crates/observer/` | `planeon-observer` (HE-004A, B1, C, D1): the OBSERVER seal, the I06 RBAC snapshot, OR and ADM-4 logic, and (HE-004C) the apiserver read client: after the seal it reads its signed configuration and credentials under `/etc/planeon`, connects over TLS 1.3 to the one loopback apiserver and runs the observation epoch; (HE-004D1) once per cycle it takes the native-profile v4 kernel captures (the five roles, WORKER first inside the broker's frozen bracket, the lifecycle and the backends) of its enrolled qualification record, checks each with R10's port of the v4 capture checks and keeps the latest set in memory, reading the kernel read-only through `crates/observer-sys` (a std-only crate, its one foreign item `syscall` with six calls); links `gate-sys`, `i05-protocol`, `observer-sys` and the vendored rustls/ring through its own registry lines (gate-tls is a test-only edge) |
| `crates/gate/` | `planeon-gate` (HE-003D): the effect gate binary; seal stage 1, the signed configuration, stage 2, the composition and the loop; path dependencies on `effect-gate` and `gate-tls` only |
| `crates/i05-protocol/` | Library (HE-002): the I05 v3 wire codec, canonical encoder, SHA-256 (NIST CAVP tested), schema subset, outcome mapping and request rendering |
| `crates/effect-gate/` | Library (HE-002): the I05 v3 gate state machine with an in-memory journal and failure marker; `MODEL_DEFINED.md` lists what the pinned model, not the READMEs, defines |
| `contracts/` | The I05 and I07 contract data and READMEs copied byte for byte from harness-onion `a2eab93`, and the I05 v3 supplementary vectors (S01-S06) from `93d32e1`; `PROVENANCE.md` |
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

The gate checks the toolchain pin (the Command Line Tools' clang and ar included, since HE-003B), the cargo config and
linker wrapper, the vendored crates against the vendor table, the workspace and lock, the closure table against the installed toolchain, the crt
objects (compiler-rt, not GCC), each binary's ELF shape, the start-up lint, and writes one deterministic CycloneDX 1.5
SBOM per binary and target under `target/sbom/`. Every line it prints starts with `he-gate: `.

## Rules

- **Forward-fix only.** A merged packet is never reverted or rewritten; a defect is fixed by a new packet.
- **Offline builds.** `[net] offline = true`, `--locked --offline --frozen`, no git dependency. Registry packages come
  only from the vendored directory source `host-enforcement/vendor/` (`.cargo/config.toml` `[source]`), pinned file by
  file by `licenses/vendor-crates.json` (`VENDOR_TABLE_SHA256` in `tools/gate.py`); HE-003B extended the gate and added
  that table beside the sysroot closure table. HE-003D (owner decision Q-HE3B-27 (a), the host-path direction) maps
  the 11 LINKED vendored crates through the workspace manifest's `[patch.crates-io]` table to path packages under
  `vendor/<name>-<version>` (vendored bytes unchanged), so cargo passes rustc workspace-relative source paths and
  `planeon-gate` carries no build-host path; in `Cargo.lock` they have no `source` or `checksum`, the gate admits
  exactly that table and holds their names, versions and edges to the vendor rows, and `check_vendor` stays their
  file-level pin (cargo does not verify a path package's `.cargo-checksum.json`). The directory source stays for the
  build-host crates and the lock-only stubs.
- **No build scripts or proc-macros** in the workspace.
- **Start-up lint.** Workspace sources must not use `available_parallelism`, `current_exe`, `current_dir`, `env::var`,
  `var_os`, `vars`, `/proc` or `/sys` (every `.rs` file outside `target/` and `vendor/`). It is a source lint, not proof of behaviour
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
