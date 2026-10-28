//! The BROKER process seal (HE-005A: DESIGN-HE005 revision 5 section 4, HE-005A, with the scope notes; owner decision
//! Q-HE5A-1 (a), Q-HE4A-1 (b)'s precedent: two stages with nothing between them). The role-neutral helpers and the
//! engine are role-seal's (HE-005A0); this module holds the broker's role specification, its pre-check of the start
//! state and the two stage wrappers, in the observer's seal.rs form.
//!
//! - The specification: the start bounding set and the kept set are both {CAP_NET_ADMIN, CAP_BPF, CAP_SETUID,
//!   CAP_SETGID} (`KEPT`; HI-7's BROKER row, DESIGN-HE005 O4): the seal drops no bounding capability, so the start state
//!   is accepted only when the bounding set already equals the four, the permitted set holds them and the ambient set is
//!   empty; the program is the published BROKER program for the running architecture with its pinned count (326
//!   instructions on x86_64, 311 on aarch64; harness-onion compiled filter programs, MET-ENFORCE-025, edge record v11's
//!   rows, vendored byte-identically under `host-enforcement/contracts/seccomp-v3/` and pinned by `tools/gate.py`).
//! - The pre-check (MON-HE005A-LAUNCH; DESIGN-HE005 O2 and O11, SEC-5, A1-GROUPS, O-W03-PEER-EXE): role-seal checks
//!   the real, effective and saved ids, not the filesystem ids or the supplementary groups. So [`seal_stage1`] first
//!   reads the process's own status once (`gate_sys::seal::own_status`) and requires the fourth field of the `Uid:` and
//!   `Gid:` lines (the filesystem uid and gid) to be 0 and the `Groups:` line to list nothing; a refusal makes no write.
//!   Its refusals have their own statuses, 36-39, outside the seal's 40-79.
//! - Stage 1 and stage 2 are role-seal's, as R87 states them: the preconditions (one thread, root), the start state, the
//!   core limit 0/0, the ambient set asserted empty, `capset` to permitted = effective = the four, no_new_privs, then
//!   the final-state assertion and the BROKER program installed with `SECCOMP_FILTER_FLAG_TSYNC`, nothing after it.
//!
//! The two public stages are the only callers of role-seal's stages in this crate (`tools/gate.py`, R1-5), and both
//! return [`SealError`], so `main` maps either through one `status::seal`. Both programs are compiled in on every
//! target; on other targets the public stages are absent.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::io;

pub use role_seal::{SealStep, Sealed, Stage, Stage1};

/// CAP_SETGID, CAP_SETUID, CAP_NET_ADMIN and CAP_BPF: the broker's capabilities (HI-7's BROKER row).
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_BPF: u32 = 39;

/// The broker's bounding, permitted and effective set after the seal: the four.
pub const KEPT: u64 = 1 << CAP_NET_ADMIN | 1 << CAP_BPF | 1 << CAP_SETUID | 1 << CAP_SETGID;

/// The published BROKER programs: the kernel's `struct sock_filter` arrays, 8 bytes per instruction. The array types
/// pin each file's length at compile time; both are compiled in on every target and [`RUNNING_ARCH`] selects the one
/// installed. The WORKER programs are vendored beside them and embedded in HE-005C.
pub static PROGRAM_X86_64: &[u8; 2608] = include_bytes!("../../../contracts/seccomp-v3/BROKER.x86_64.bpf");
pub static PROGRAM_AARCH64: &[u8; 2488] = include_bytes!("../../../contracts/seccomp-v3/BROKER.aarch64.bpf");

/// The programs' instruction counts (326 and 311).
pub const INSTRUCTIONS_X86_64: u16 = 326;
pub const INSTRUCTIONS_AARCH64: u16 = 311;
const _: () = assert!(INSTRUCTIONS_X86_64 as usize * role_seal::INSTRUCTION_BYTES == 2608);
const _: () = assert!(INSTRUCTIONS_AARCH64 as usize * role_seal::INSTRUCTION_BYTES == 2488);

/// The two architectures the broker is built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// The published BROKER program for this architecture.
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

/// The broker's role specification for role-seal's stages on `arch`: the start bounding set and the kept set both
/// `KEPT`, and that architecture's BROKER program with its pinned instruction count.
pub fn spec(arch: Arch) -> role_seal::RoleSpec {
    role_seal::RoleSpec { bounding: KEPT, kept: KEPT, program: arch.program(), instructions: arch.instructions() }
}

/// What the pre-check refused (statuses 36-39, `status::start`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartCheck {
    /// The read of the process's own status failed.
    Status,
    /// The `Uid:` line is not one line of four decimal fields, or its fourth (the filesystem uid) is not 0.
    FsUid,
    /// The `Gid:` line is not one line of four decimal fields, or its fourth (the filesystem gid) is not 0.
    FsGid,
    /// The `Groups:` line is missing, repeated or lists a group.
    Groups,
}

/// Why the broker's seal stopped: its own pre-check, before any write, or a step of role-seal's stages.
#[derive(Debug)]
pub enum SealError {
    /// The pre-check refused the start state (no write was made).
    Start(StartCheck),
    /// A step of role-seal's stage 1 or stage 2.
    Seal(role_seal::SealError),
}

/// The one line of `status` that starts with `prefix`, after the prefix; `None` when no line or more than one does.
fn one_line<'a>(status: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let mut found = None;
    for line in status.split(|byte| *byte == b'\n') {
        if let Some(rest) = line.strip_prefix(prefix) {
            if found.is_some() {
                return None;
            }
            found = Some(rest);
        }
    }
    found
}

/// A field of decimal digits as a `u32`; `None` when it is empty, holds anything else or does not fit.
fn decimal(field: &[u8]) -> Option<u32> {
    if field.is_empty() {
        return None;
    }
    let mut value: u32 = 0;
    for digit in field {
        if !digit.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(digit - b'0'))?;
    }
    Some(value)
}

/// The filesystem id on the one `Uid:` or `Gid:` line (`prefix`): the line must hold exactly four decimal fields (real,
/// effective, saved and filesystem) separated by tabs or spaces, and the fourth is returned.
fn filesystem_id(status: &[u8], prefix: &[u8]) -> Option<u32> {
    let rest = one_line(status, prefix)?;
    let mut fields = rest.split(|byte| matches!(byte, b' ' | b'\t')).filter(|field| !field.is_empty());
    let mut ids = [0u32; 4];
    for id in ids.iter_mut() {
        *id = decimal(fields.next()?)?;
    }
    if fields.next().is_some() {
        return None;
    }
    let [_real, _effective, _saved, filesystem] = ids;
    Some(filesystem)
}

/// Whether the one `Groups:` line lists no group: after the prefix only tabs and spaces (the kernel writes a trailing
/// space). `None` when no line or more than one line starts with `Groups:`.
fn groups_empty(status: &[u8]) -> Option<bool> {
    let rest = one_line(status, b"Groups:")?;
    Some(rest.iter().all(|byte| matches!(byte, b' ' | b'\t')))
}

/// The broker's start-state pre-check over the result of one read of its own status (MON-HE005A-LAUNCH): the read
/// succeeded, the filesystem uid and gid are 0 and no supplementary group is listed, checked in that order. It writes
/// nothing; [`seal_stage1`] runs it before role-seal's stage 1.
pub fn pre_check(status: io::Result<Vec<u8>>) -> Result<(), StartCheck> {
    let Ok(status) = status else {
        return Err(StartCheck::Status);
    };
    if filesystem_id(&status, b"Uid:") != Some(0) {
        return Err(StartCheck::FsUid);
    }
    if filesystem_id(&status, b"Gid:") != Some(0) {
        return Err(StartCheck::FsGid);
    }
    if groups_empty(&status) != Some(true) {
        return Err(StartCheck::Groups);
    }
    Ok(())
}

/// Stage 1 of the seal, first thing in `main`, before any input is read, any socket opened or any thread spawned: the
/// pre-check over one read of the process's own status, then role-seal's stage 1 with the broker's specification.
#[cfg(target_os = "linux")]
pub fn seal_stage1() -> Result<Stage1, SealError> {
    pre_check(gate_sys::seal::own_status()).map_err(SealError::Start)?;
    role_seal::seal_stage1(spec(RUNNING_ARCH)).map_err(SealError::Seal)
}

/// Stage 2 of the seal, the statement right after stage 1 (Q-HE5A-1 (a)).
#[cfg(target_os = "linux")]
pub fn seal_stage2(stage1: Stage1) -> Result<Sealed, SealError> {
    role_seal::seal_stage2(stage1).map_err(SealError::Seal)
}
