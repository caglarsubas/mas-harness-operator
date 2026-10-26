//! The OBSERVER process seal (HE-004A DESIGN section 4): two stages with nothing between them in HE-004A (the observer
//! reads no configuration yet: owner decision Q-HE4A-1, DESIGN-A §10 option (b), which the monitor's "(a), as
//! recommended" decided, confirmed 2026-10-16; HE-003A3, D1-1). Since HE-005A0 (DESIGN-HE005 revision 5 section 4,
//! HE-005A step A0; owner decision Q-HE5-11 (a)) the role-neutral helpers and the engine are `role-seal`'s, moved there
//! with no change of behaviour; this module keeps the observer's role specification and calls role-seal's stages with it.
//!
//! - The specification: the start bounding set and the kept set are both {CAP_NET_ADMIN, CAP_BPF} (`KEPT`):
//!   `planeon_observer_t` has no `setpcap` (matrix v5), so the observer cannot drop a bounding capability, and the start
//!   state is accepted only when the bounding set already equals the two, the permitted set holds both and the ambient
//!   set is empty; the program is the published OBSERVER program for the running architecture with its pinned count.
//! - Stage 1 and stage 2 are role-seal's, as R87 states them: the preconditions (one thread, root), the start state,
//!   the core limit 0/0, the ambient set asserted empty, `capset` to permitted = effective = the two, no_new_privs, then
//!   the final-state assertion and the OBSERVER program installed with `SECCOMP_FILTER_FLAG_TSYNC`, nothing after it.
//!
//! The two public stages below are one-line wrappers; the names the observer's other modules and tests import from here
//! (the helpers, `SealError`, `SealFailure`, `SealStep`, `Stage`, `Stage1` and `Sealed`) are re-exported from role-seal.
//! role-seal's engine over its `SealOps` is crate-private there and its public stages are concrete over the Linux
//! implementation (effect-gate's D6), so no crate can obtain a [`Stage1`] or [`Sealed`] token from a fake; on other
//! targets the public stages are absent. Both programs are compiled in on every target.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub use role_seal::{capability_sets, capability_words, filter_length, status_threads, CapabilitySets, Prctl, BPF_MAXINSNS,
                    CAP_LAST_CAP};
pub use role_seal::{SealError, SealFailure, SealStep, Sealed, Stage, Stage1};

/// CAP_NET_ADMIN and CAP_BPF: the observer's capabilities (W01 section 5.3 OBSERVER row; BPF_PROG_QUERY and the
/// unredacted translated instructions).
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_BPF: u32 = 39;

/// The observer's bounding, permitted and effective set after the seal: {CAP_NET_ADMIN, CAP_BPF}.
pub const KEPT: u64 = 1 << CAP_NET_ADMIN | 1 << CAP_BPF;

/// The published OBSERVER programs: the kernel's `struct sock_filter` arrays, 8 bytes per instruction. The array types
/// pin each file's length at compile time; both are compiled in on every target and [`RUNNING_ARCH`] selects the one
/// installed. HE-004-I01a (DESIGN-I01A section 3) embeds the seccomp-v5 programs (harness-onion compiled filter programs
/// v3, MET-ENFORCE-036; edge record v8's two rows, vendored byte-identically under `host-enforcement/contracts/seccomp-v5/`
/// and pinned by `tools/gate.py`), which add the I01 listener's `bind`, `listen` and `accept4` to the OBSERVER row. The
/// seccomp-v3 programs HE-004A embedded stay vendored and pinned, no longer embedded (Q-P2-3 (a)).
pub static PROGRAM_X86_64: &[u8; 2024] = include_bytes!("../../../contracts/seccomp-v5/OBSERVER.x86_64.bpf");
pub static PROGRAM_AARCH64: &[u8; 1936] = include_bytes!("../../../contracts/seccomp-v5/OBSERVER.aarch64.bpf");

/// The programs' instruction counts (seccomp-v5: 253 and 242).
pub const INSTRUCTIONS_X86_64: u16 = 253;
pub const INSTRUCTIONS_AARCH64: u16 = 242;
const _: () = assert!(INSTRUCTIONS_X86_64 as usize * role_seal::INSTRUCTION_BYTES == 2024);
const _: () = assert!(INSTRUCTIONS_AARCH64 as usize * role_seal::INSTRUCTION_BYTES == 1936);

/// The two architectures the observer is built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// The published OBSERVER program for this architecture.
    pub fn program(self) -> &'static [u8] {
        match self {
            Arch::X86_64 => PROGRAM_X86_64.as_slice(),
            Arch::Aarch64 => PROGRAM_AARCH64.as_slice(),
        }
    }

    /// Its pinned instruction count.
    pub fn instructions(self) -> u16 {
        match self {
            Arch::X86_64 => INSTRUCTIONS_X86_64,
            Arch::Aarch64 => INSTRUCTIONS_AARCH64,
        }
    }
}

/// The architecture this crate is compiled for: its program is the one the seal installs.
#[cfg(target_arch = "x86_64")]
pub const RUNNING_ARCH: Arch = Arch::X86_64;
#[cfg(target_arch = "aarch64")]
pub const RUNNING_ARCH: Arch = Arch::Aarch64;

/// The observer's role specification for role-seal's stages: the start bounding set and the kept set both `KEPT`, and
/// the running architecture's OBSERVER program with its pinned instruction count.
fn observer_spec() -> role_seal::RoleSpec {
    role_seal::RoleSpec {
        bounding: KEPT,
        kept: KEPT,
        program: RUNNING_ARCH.program(),
        instructions: RUNNING_ARCH.instructions(),
    }
}

/// Stage 1 of the seal, first thing in `main`, before any input is read, any socket opened or any thread spawned.
#[cfg(target_os = "linux")]
pub fn seal_stage1() -> Result<Stage1, SealError> {
    role_seal::seal_stage1(observer_spec())
}

/// Stage 2 of the seal, the statement right after stage 1 in HE-004A.
#[cfg(target_os = "linux")]
pub fn seal_stage2(stage1: Stage1) -> Result<Sealed, SealError> {
    role_seal::seal_stage2(stage1)
}
