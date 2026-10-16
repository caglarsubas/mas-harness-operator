//! The EFFECT_GATE process seal (HE-002S DESIGN §2 as amended by §18, and §5-§7): two stages around the signed
//! configuration's read and check, in safe Rust over `gate_sys::seal`'s raw calls.
//!
//! - Preconditions: the process is single-threaded (the `Threads:` line of its own status file) and root (real,
//!   effective and saved uid and gid 0, read before the filter, which kills `getuid`).
//! - Start sets: `capget` (effective, permitted, inheritable) and `PR_CAPBSET_READ` 0..=40 (the bounding set), with
//!   `PR_CAPBSET_READ(41)` failing with EINVAL. Every target derives from them.
//! - Stage 1, before any input is read, any socket opened or any thread spawned: (1) the core limit 0/0, read back;
//!   (2) the ambient set cleared, read back with `PR_CAP_AMBIENT_IS_SET` 0..=40; (3) the bounding set reduced to
//!   {CAP_SETPCAP} ∩ start bounding by dropping every other present capability, read back; (4) `capset` to permitted =
//!   effective = {CAP_SETPCAP} ∩ start permitted, inheritable empty, read back; (5) no_new_privs 1, read back.
//! - Between the stages HE-003's `main` reads and checks only the signed configuration.
//! - Stage 2: (6) single-threaded again; (7) CAP_SETPCAP dropped from the bounding set if it is still there, read
//!   back; (8) `capset` to all sets empty, read back; the final-state assertion (D4: `capget`, `PR_CAPBSET_READ`
//!   0..=40 and `PR_CAP_AMBIENT_IS_SET` 0..=40 show every set empty, no_new_privs is 1, the core limit is 0/0), the
//!   last reads before (9) the published EFFECT_GATE program for the running architecture, installed with
//!   `SECCOMP_FILTER_FLAG_TSYNC`; any return but 0 is a failure.
//!
//! Owner decision Q-HE2S-9 (a) (§18): the signed I04 port is 1024 or above, so the gate keeps no capability after the
//! seal and the API takes no `kept` value; stage 1 keeps only CAP_SETPCAP, which stage 2's bounding drop needs.
//! Accepted start states (§18): the full root set, or any superset of {CAP_SETPCAP}; or a start already within
//! {CAP_SETPCAP}, with nothing left to drop when CAP_SETPCAP is absent. Any other start fails at the step the kernel
//! refuses or at the final-state assertion.
//!
//! Every step's failure and every read-back mismatch is a typed [`SealError`]; the library never exits (HE-003's
//! `main` exits with a distinct status on any of them). The generic engine over `SealOps` is crate-private and the
//! public stages are concrete over the Linux implementation (design review round 3, D6), so no crate can obtain a
//! [`Stage1`] or [`Sealed`] token from a fake; on other targets the public stages are absent. The marshalling helpers
//! (the capability words, the `sock_fprog` length, the prctl argument vectors, the `Threads:` parser) are portable and
//! host-tested, and both programs are compiled in on every target.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::ffi::c_int;
use std::ffi::c_long;
use std::ffi::c_ulong;
use std::io;

/// CAP_SETPCAP: the one capability stage 1 keeps, for stage 2's bounding drop.
pub const CAP_SETPCAP: u32 = 8;

/// CAP_LAST_CAP: the seal reads capabilities 0..=40 and requires `PR_CAPBSET_READ(41)` to fail with EINVAL (C9).
pub const CAP_LAST_CAP: u32 = 40;

/// EINVAL (22 on Linux, and on the macOS build host).
const EINVAL: i32 = 22;

/// The longest classic-BPF program the kernel accepts (`BPF_MAXINSNS`), and the size of one instruction.
pub const BPF_MAXINSNS: usize = 4096;
const INSTRUCTION_BYTES: usize = 8;

const PR_CAPBSET_READ: c_int = 23;
const PR_CAPBSET_DROP: c_int = 24;
const PR_SET_NO_NEW_PRIVS: c_int = 38;
const PR_GET_NO_NEW_PRIVS: c_int = 39;
const PR_CAP_AMBIENT: c_int = 47;
const PR_CAP_AMBIENT_IS_SET: c_ulong = 1;
const PR_CAP_AMBIENT_CLEAR_ALL: c_ulong = 4;

/// The core limit the seal sets and reads back, `[soft, hard]`.
const NO_CORE: [u64; 2] = [0, 0];

/// The published EFFECT_GATE programs (harness-onion MET-ENFORCE-029, seccomp allowlists v4: v3 plus `readlinkat` with
/// a non-negative dirfd; vendored byte-identically under `host-enforcement/contracts/seccomp-v4/` and pinned by
/// `tools/gate.py`, HE-003A2; MET-ENFORCE-025's v3 programs stay pinned under `contracts/seccomp-v3/` but are no longer
/// embedded): the kernel's `struct sock_filter` arrays, 8 bytes per instruction. Both are compiled in on every target;
/// [`RUNNING_ARCH`] selects the one installed.
pub static PROGRAM_X86_64: &[u8] = include_bytes!("../../../contracts/seccomp-v4/EFFECT_GATE.x86_64.bpf");
pub static PROGRAM_AARCH64: &[u8] = include_bytes!("../../../contracts/seccomp-v4/EFFECT_GATE.aarch64.bpf");

/// The two architectures the gate is built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    /// The published EFFECT_GATE program for this architecture.
    pub fn program(self) -> &'static [u8] {
        match self {
            Arch::X86_64 => PROGRAM_X86_64,
            Arch::Aarch64 => PROGRAM_AARCH64,
        }
    }
}

/// The architecture this crate is compiled for: its program is the one the seal installs.
#[cfg(target_arch = "x86_64")]
pub const RUNNING_ARCH: Arch = Arch::X86_64;
#[cfg(target_arch = "aarch64")]
pub const RUNNING_ARCH: Arch = Arch::Aarch64;

/// The three sets `capget` and `capset` carry, one bit per capability (bit n is capability n).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilitySets {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
}

/// The two `_LINUX_CAPABILITY_VERSION_3` data words for `sets`, each `[effective, permitted, inheritable]`:
/// capabilities 0-31 in the first word and 32-63 (so 32-40) in the second.
pub fn capability_words(sets: CapabilitySets) -> [[u32; 3]; 2] {
    let low = |set: u64| (set & 0xFFFF_FFFF) as u32;
    let high = |set: u64| (set >> 32) as u32;
    [
        [low(sets.effective), low(sets.permitted), low(sets.inheritable)],
        [high(sets.effective), high(sets.permitted), high(sets.inheritable)],
    ]
}

/// The sets two version-3 data words carry (the inverse of [`capability_words`]).
pub fn capability_sets(words: [[u32; 3]; 2]) -> CapabilitySets {
    let set = |field: usize| u64::from(words[0][field]) | u64::from(words[1][field]) << 32;
    CapabilitySets { effective: set(0), permitted: set(1), inheritable: set(2) }
}

/// The `sock_fprog` length of a program: its instruction count, when it is 1 to 4096 whole 8-byte instructions.
pub fn filter_length(program: &[u8]) -> Option<u16> {
    let count = program.len() / INSTRUCTION_BYTES;
    if program.len() % INSTRUCTION_BYTES != 0 || count == 0 || count > BPF_MAXINSNS {
        return None;
    }
    u16::try_from(count).ok()
}

/// The thread count on the one `Threads:` line of the process status file: `Threads:`, optional tabs or spaces,
/// decimal digits, nothing else on the line. `None` when no line or more than one line starts with `Threads:`, or the
/// value is not such a number or does not fit in a `u64`.
pub fn status_threads(status: &[u8]) -> Option<u64> {
    let mut found = None;
    for line in status.split(|byte| *byte == b'\n') {
        let Some(rest) = line.strip_prefix(b"Threads:") else {
            continue;
        };
        if found.is_some() {
            return None;
        }
        let start = rest.iter().position(|byte| !matches!(byte, b' ' | b'\t')).unwrap_or(rest.len());
        let digits = &rest[start..];
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let mut count: u64 = 0;
        for digit in digits {
            count = count.checked_mul(10)?.checked_add(u64::from(digit - b'0'))?;
        }
        found = Some(count);
    }
    found
}

/// The prctl calls the seal makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prctl {
    /// `PR_CAPBSET_READ` (23): is the capability in the bounding set?
    BoundingRead(u32),
    /// `PR_CAPBSET_DROP` (24).
    BoundingDrop(u32),
    /// `PR_CAP_AMBIENT` (47) with `PR_CAP_AMBIENT_IS_SET` (1).
    AmbientIsSet(u32),
    /// `PR_CAP_AMBIENT` (47) with `PR_CAP_AMBIENT_CLEAR_ALL` (4).
    AmbientClearAll,
    /// `PR_SET_NO_NEW_PRIVS` (38) to 1.
    SetNoNewPrivs,
    /// `PR_GET_NO_NEW_PRIVS` (39).
    GetNoNewPrivs,
}

impl Prctl {
    /// The option and exactly four further `c_ulong` arguments, zeros where unused (design review round 3, D5: musl's
    /// variadic `prctl` reads four `unsigned long`s, and the kernel refuses non-zero unused arguments for options 38,
    /// 39 and 47's CLEAR_ALL).
    pub fn arguments(self) -> (c_int, [c_ulong; 4]) {
        match self {
            Prctl::BoundingRead(capability) => (PR_CAPBSET_READ, [c_ulong::from(capability), 0, 0, 0]),
            Prctl::BoundingDrop(capability) => (PR_CAPBSET_DROP, [c_ulong::from(capability), 0, 0, 0]),
            Prctl::AmbientIsSet(capability) => (PR_CAP_AMBIENT, [PR_CAP_AMBIENT_IS_SET, c_ulong::from(capability), 0, 0]),
            Prctl::AmbientClearAll => (PR_CAP_AMBIENT, [PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0]),
            Prctl::SetNoNewPrivs => (PR_SET_NO_NEW_PRIVS, [1, 0, 0, 0]),
            Prctl::GetNoNewPrivs => (PR_GET_NO_NEW_PRIVS, [0, 0, 0, 0]),
        }
    }
}

/// The two stages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    One,
    Two,
}

/// Where the seal stopped (DESIGN §2's preconditions, steps 1-9 and the final-state assertion).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealStep {
    /// The single-thread check: before stage 1, and step 6 at the start of stage 2.
    Threads(Stage),
    /// `getresuid`: the real, effective and saved uid must be 0.
    UserIds,
    /// `getresgid`: the real, effective and saved gid must be 0.
    GroupIds,
    /// `capget` of the start sets.
    StartCapabilities,
    /// `PR_CAPBSET_READ` 0..=41 of the start bounding set.
    StartBounding,
    /// The `sock_fprog` length of the running architecture's program (checked before any change).
    Program,
    /// Step 1: `prlimit(RLIMIT_CORE, {0, 0})`.
    CoreLimit,
    /// Step 1's read-back.
    CoreLimitReadBack,
    /// Step 2: `PR_CAP_AMBIENT_CLEAR_ALL`.
    AmbientClear,
    /// Step 2's read-back.
    AmbientReadBack,
    /// Steps 3 and 7: `PR_CAPBSET_DROP` of this capability.
    BoundingDrop(Stage, u32),
    /// Steps 3 and 7: the bounding set's read-back.
    BoundingReadBack(Stage),
    /// Steps 4 and 8: `capset`.
    Capabilities(Stage),
    /// Steps 4 and 8: `capget`'s read-back.
    CapabilitiesReadBack(Stage),
    /// Step 5: `PR_SET_NO_NEW_PRIVS`.
    NoNewPrivs,
    /// Step 5's read-back.
    NoNewPrivsReadBack,
    /// The final-state assertion: `capget`.
    FinalCapabilities,
    /// The final-state assertion: the bounding set.
    FinalBounding,
    /// The final-state assertion: the ambient set.
    FinalAmbient,
    /// The final-state assertion: no_new_privs.
    FinalNoNewPrivs,
    /// The final-state assertion: the core limit.
    FinalCoreLimit,
    /// Step 9: the filter.
    Filter,
}

/// What went wrong at that step.
#[derive(Debug)]
pub enum SealFailure {
    /// The call failed with this OS error.
    Os(io::Error),
    /// The status file has no single well-formed `Threads:` line.
    StatusFormat,
    /// The process has this many threads, not one.
    Threads(u64),
    /// Not all three ids are 0.
    NotRoot([u32; 3]),
    /// `PR_CAPBSET_READ` or `PR_CAP_AMBIENT_IS_SET` failed with EINVAL for a capability within 0..=40 (C9).
    InvalidCapability(u32),
    /// `PR_CAPBSET_READ(41)` did not fail with EINVAL, so the kernel's last capability is not 40: the value it returned,
    /// or the other errno it failed with.
    LastCapability { returned: Option<c_int>, errno: Option<i32> },
    /// A prctl read returned something other than 0 or 1 (for this capability, if it reads one).
    NotABoolean { capability: Option<u32>, value: c_int },
    /// A set read back differs from its target.
    SetMismatch { expected: u64, found: u64 },
    /// `capget` read back other sets than the target.
    CapabilitiesMismatch { expected: CapabilitySets, found: CapabilitySets },
    /// The core limit read back is not 0/0.
    CoreLimitMismatch([u64; 2]),
    /// `PR_GET_NO_NEW_PRIVS` read back 0.
    NoNewPrivsUnset,
    /// The program is not 1 to 4096 whole instructions (this many bytes).
    ProgramLength(usize),
    /// With TSYNC, `seccomp` returned this positive id of a thread it could not synchronise; no filter was installed.
    TsyncThread(c_long),
    /// `seccomp` returned this other value that is not 0.
    Returned(c_long),
}

/// A seal step's failure or read-back mismatch.
#[derive(Debug)]
pub struct SealError {
    step: SealStep,
    failure: SealFailure,
}

impl SealError {
    /// The step that failed.
    pub fn step(&self) -> SealStep {
        self.step
    }

    /// How it failed.
    pub fn failure(&self) -> &SealFailure {
        &self.failure
    }
}

fn fail(step: SealStep, failure: SealFailure) -> SealError {
    SealError { step, failure }
}

fn os(step: SealStep) -> impl FnOnce(io::Error) -> SealError {
    move |error| fail(step, SealFailure::Os(error))
}

fn is_einval(error: &io::Error) -> bool {
    error.raw_os_error() == Some(EINVAL)
}

fn bit(capability: u32) -> u64 {
    1 << capability
}

/// The capabilities in `set`, ascending.
fn members(set: u64) -> Vec<u32> {
    (0..=CAP_LAST_CAP).filter(|capability| set & bit(*capability) != 0).collect()
}

/// The seal's system calls: `gate_sys::seal` on Linux, a model of the kernel in the tests.
pub(crate) trait SealOps {
    /// The process's own status file.
    fn own_status(&mut self) -> io::Result<Vec<u8>>;
    /// `getresuid`.
    fn user_ids(&mut self) -> io::Result<[u32; 3]>;
    /// `getresgid`.
    fn group_ids(&mut self) -> io::Result<[u32; 3]>;
    /// `capget` of the calling thread, version 3.
    fn read_capabilities(&mut self) -> io::Result<[[u32; 3]; 2]>;
    /// `capset` of the calling thread, version 3.
    fn write_capabilities(&mut self, words: [[u32; 3]; 2]) -> io::Result<()>;
    /// `prctl` with exactly four further arguments.
    fn process_control(&mut self, option: c_int, arguments: [c_ulong; 4]) -> io::Result<c_int>;
    /// `prlimit(0, RLIMIT_CORE, new, &old)`: the limit before the call.
    fn core_limit(&mut self, new: Option<[u64; 2]>) -> io::Result<[u64; 2]>;
    /// `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog)`: the call's value.
    fn install_filter(&mut self, program: &'static [u8], length: u16) -> io::Result<c_long>;
}

/// The Linux implementation, over gate-sys's safe functions.
#[cfg(target_os = "linux")]
struct LinuxOps;

#[cfg(target_os = "linux")]
impl SealOps for LinuxOps {
    fn own_status(&mut self) -> io::Result<Vec<u8>> {
        gate_sys::seal::own_status()
    }

    fn user_ids(&mut self) -> io::Result<[u32; 3]> {
        gate_sys::seal::user_ids()
    }

    fn group_ids(&mut self) -> io::Result<[u32; 3]> {
        gate_sys::seal::group_ids()
    }

    fn read_capabilities(&mut self) -> io::Result<[[u32; 3]; 2]> {
        gate_sys::seal::read_capabilities()
    }

    fn write_capabilities(&mut self, words: [[u32; 3]; 2]) -> io::Result<()> {
        gate_sys::seal::write_capabilities(words)
    }

    fn process_control(&mut self, option: c_int, arguments: [c_ulong; 4]) -> io::Result<c_int> {
        gate_sys::seal::process_control(option, arguments)
    }

    fn core_limit(&mut self, new: Option<[u64; 2]>) -> io::Result<[u64; 2]> {
        gate_sys::seal::core_limit(new)
    }

    fn install_filter(&mut self, program: &'static [u8], length: u16) -> io::Result<c_long> {
        gate_sys::seal::install_filter(program, length)
    }
}

/// The start sets every target derives from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StartSets {
    pub(crate) capabilities: CapabilitySets,
    pub(crate) bounding: u64,
}

/// The seal plan for both stages, built from the start sets and the target architecture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    /// Step 3: the capabilities dropped from the bounding set, ascending (every present one but CAP_SETPCAP).
    pub(crate) stage1_drops: Vec<u32>,
    /// Step 3's target: {CAP_SETPCAP} ∩ start bounding.
    pub(crate) stage1_bounding: u64,
    /// Step 4's target for the permitted and effective sets: {CAP_SETPCAP} ∩ start permitted.
    pub(crate) stage1_capabilities: u64,
    /// Step 7: CAP_SETPCAP when stage 1 left it in the bounding set.
    pub(crate) stage2_drops: Vec<u32>,
    /// Step 9: the architecture whose program is installed, and its length in instructions.
    pub(crate) arch: Arch,
    pub(crate) length: u16,
}

/// The plan for these start sets (§18: stage 1 keeps {CAP_SETPCAP} ∩ start, stage 2 leaves every set empty).
pub(crate) fn plan(start: StartSets, arch: Arch) -> Result<Plan, SealError> {
    let program = arch.program();
    let length = filter_length(program).ok_or_else(|| fail(SealStep::Program, SealFailure::ProgramLength(program.len())))?;
    let kept = bit(CAP_SETPCAP);
    let stage1_bounding = start.bounding & kept;
    Ok(Plan {
        stage1_drops: members(start.bounding & !kept),
        stage1_bounding,
        stage1_capabilities: start.capabilities.permitted & kept,
        stage2_drops: members(stage1_bounding),
        arch,
        length,
    })
}

fn control<O: SealOps>(ops: &mut O, call: Prctl) -> io::Result<c_int> {
    let (option, arguments) = call.arguments();
    ops.process_control(option, arguments)
}

/// A prctl read of a flag: 0 or 1, anything else an error; EINVAL for a capability within 0..=40 is C9's error.
fn read_flag<O: SealOps>(ops: &mut O, call: Prctl, capability: Option<u32>, step: SealStep) -> Result<bool, SealError> {
    match control(ops, call) {
        Ok(0) => Ok(false),
        Ok(1) => Ok(true),
        Ok(value) => Err(fail(step, SealFailure::NotABoolean { capability, value })),
        Err(error) => match capability {
            Some(capability) if is_einval(&error) => Err(fail(step, SealFailure::InvalidCapability(capability))),
            _ => Err(fail(step, SealFailure::Os(error))),
        },
    }
}

/// `PR_CAPBSET_READ` 0..=40, then `PR_CAPBSET_READ(41)`, which must fail with EINVAL.
fn read_bounding<O: SealOps>(ops: &mut O, step: SealStep) -> Result<u64, SealError> {
    let mut set = 0;
    for capability in 0..=CAP_LAST_CAP {
        if read_flag(ops, Prctl::BoundingRead(capability), Some(capability), step)? {
            set |= bit(capability);
        }
    }
    match control(ops, Prctl::BoundingRead(CAP_LAST_CAP + 1)) {
        Err(error) if is_einval(&error) => Ok(set),
        Err(error) => Err(fail(step, SealFailure::LastCapability { returned: None, errno: error.raw_os_error() })),
        Ok(value) => Err(fail(step, SealFailure::LastCapability { returned: Some(value), errno: None })),
    }
}

/// `PR_CAP_AMBIENT_IS_SET` 0..=40.
fn read_ambient<O: SealOps>(ops: &mut O, step: SealStep) -> Result<u64, SealError> {
    let mut set = 0;
    for capability in 0..=CAP_LAST_CAP {
        if read_flag(ops, Prctl::AmbientIsSet(capability), Some(capability), step)? {
            set |= bit(capability);
        }
    }
    Ok(set)
}

fn expect_set(step: SealStep, expected: u64, found: u64) -> Result<(), SealError> {
    if found == expected { Ok(()) } else { Err(fail(step, SealFailure::SetMismatch { expected, found })) }
}

fn expect_capabilities<O: SealOps>(ops: &mut O, step: SealStep, expected: CapabilitySets) -> Result<(), SealError> {
    let found = ops.read_capabilities().map(capability_sets).map_err(os(step))?;
    if found == expected { Ok(()) } else { Err(fail(step, SealFailure::CapabilitiesMismatch { expected, found })) }
}

fn expect_no_new_privs<O: SealOps>(ops: &mut O, step: SealStep) -> Result<(), SealError> {
    if read_flag(ops, Prctl::GetNoNewPrivs, None, step)? { Ok(()) } else { Err(fail(step, SealFailure::NoNewPrivsUnset)) }
}

fn expect_no_core<O: SealOps>(ops: &mut O, step: SealStep) -> Result<(), SealError> {
    let found = ops.core_limit(None).map_err(os(step))?;
    if found == NO_CORE { Ok(()) } else { Err(fail(step, SealFailure::CoreLimitMismatch(found))) }
}

fn single_thread<O: SealOps>(ops: &mut O, stage: Stage) -> Result<(), SealError> {
    let step = SealStep::Threads(stage);
    let status = ops.own_status().map_err(os(step))?;
    match status_threads(&status) {
        Some(1) => Ok(()),
        Some(count) => Err(fail(step, SealFailure::Threads(count))),
        None => Err(fail(step, SealFailure::StatusFormat)),
    }
}

fn root_ids(ids: io::Result<[u32; 3]>, step: SealStep) -> Result<(), SealError> {
    match ids {
        Ok([0, 0, 0]) => Ok(()),
        Ok(found) => Err(fail(step, SealFailure::NotRoot(found))),
        Err(error) => Err(fail(step, SealFailure::Os(error))),
    }
}

/// Steps 3 and 7: drop each capability, then read the bounding set back.
fn drop_bounding<O: SealOps>(ops: &mut O, stage: Stage, drops: &[u32], target: u64) -> Result<(), SealError> {
    for &capability in drops {
        control(ops, Prctl::BoundingDrop(capability)).map_err(os(SealStep::BoundingDrop(stage, capability)))?;
    }
    let step = SealStep::BoundingReadBack(stage);
    let found = read_bounding(ops, step)?;
    expect_set(step, target, found)
}

/// Steps 4 and 8: permitted = effective = `target`, inheritable empty, then `capget`'s read-back.
fn set_capabilities<O: SealOps>(ops: &mut O, stage: Stage, target: u64) -> Result<(), SealError> {
    let sets = CapabilitySets { effective: target, permitted: target, inheritable: 0 };
    ops.write_capabilities(capability_words(sets)).map_err(os(SealStep::Capabilities(stage)))?;
    expect_capabilities(ops, SealStep::CapabilitiesReadBack(stage), sets)
}

/// Stage 1, preconditions and start sets included: the plan stage 2 carries out.
pub(crate) fn run_stage1<O: SealOps>(ops: &mut O, arch: Arch) -> Result<Plan, SealError> {
    single_thread(ops, Stage::One)?;
    root_ids(ops.user_ids(), SealStep::UserIds)?;
    root_ids(ops.group_ids(), SealStep::GroupIds)?;
    let capabilities = ops.read_capabilities().map(capability_sets).map_err(os(SealStep::StartCapabilities))?;
    let bounding = read_bounding(ops, SealStep::StartBounding)?;
    let plan = plan(StartSets { capabilities, bounding }, arch)?;
    // Step 1.
    ops.core_limit(Some(NO_CORE)).map_err(os(SealStep::CoreLimit))?;
    expect_no_core(ops, SealStep::CoreLimitReadBack)?;
    // Step 2.
    control(ops, Prctl::AmbientClearAll).map_err(os(SealStep::AmbientClear))?;
    let ambient = read_ambient(ops, SealStep::AmbientReadBack)?;
    expect_set(SealStep::AmbientReadBack, 0, ambient)?;
    // Steps 3 and 4.
    drop_bounding(ops, Stage::One, &plan.stage1_drops, plan.stage1_bounding)?;
    set_capabilities(ops, Stage::One, plan.stage1_capabilities)?;
    // Step 5.
    control(ops, Prctl::SetNoNewPrivs).map_err(os(SealStep::NoNewPrivs))?;
    expect_no_new_privs(ops, SealStep::NoNewPrivsReadBack)?;
    Ok(plan)
}

/// Stage 2: the thread check, the last drops, the final-state assertion and the filter.
pub(crate) fn run_stage2<O: SealOps>(ops: &mut O, plan: &Plan) -> Result<(), SealError> {
    single_thread(ops, Stage::Two)?;
    // Steps 7 and 8.
    drop_bounding(ops, Stage::Two, &plan.stage2_drops, 0)?;
    set_capabilities(ops, Stage::Two, 0)?;
    // The final-state assertion (D4): the last reads before the filter, which kills every one of them.
    expect_capabilities(ops, SealStep::FinalCapabilities, CapabilitySets::default())?;
    let bounding = read_bounding(ops, SealStep::FinalBounding)?;
    expect_set(SealStep::FinalBounding, 0, bounding)?;
    let ambient = read_ambient(ops, SealStep::FinalAmbient)?;
    expect_set(SealStep::FinalAmbient, 0, ambient)?;
    expect_no_new_privs(ops, SealStep::FinalNoNewPrivs)?;
    expect_no_core(ops, SealStep::FinalCoreLimit)?;
    // Step 9.
    match ops.install_filter(plan.arch.program(), plan.length) {
        Ok(0) => Ok(()),
        Ok(id) if id > 0 => Err(fail(SealStep::Filter, SealFailure::TsyncThread(id))),
        Ok(value) => Err(fail(SealStep::Filter, SealFailure::Returned(value))),
        Err(error) => Err(fail(SealStep::Filter, SealFailure::Os(error))),
    }
}

/// Stage 1 is done: the process is single-threaded, root, with the core limit 0/0, no ambient capability, at most
/// CAP_SETPCAP left and no_new_privs set. Only [`seal_stage1`] makes one (private field; no Clone, Copy or Default).
#[derive(Debug)]
#[must_use]
pub struct Stage1 {
    plan: Plan,
}

/// The seal is installed: every capability set is empty, no_new_privs is set, the core limit is 0/0 and the published
/// EFFECT_GATE program filters every thread. Only [`seal_stage2`] makes one (private field; no Clone, Copy or
/// Default), so HE-003's constructors that open sockets or spawn threads can take `&Sealed`.
#[derive(Debug)]
#[must_use]
pub struct Sealed {
    _sealed: (),
}

/// Stage 1 of the seal, first thing in `main`, before any input is read, any socket opened or any thread spawned.
#[cfg(target_os = "linux")]
pub fn seal_stage1() -> Result<Stage1, SealError> {
    run_stage1(&mut LinuxOps, RUNNING_ARCH).map(|plan| Stage1 { plan })
}

/// Stage 2 of the seal, right after the signed configuration's read and check.
#[cfg(target_os = "linux")]
pub fn seal_stage2(stage1: Stage1) -> Result<Sealed, SealError> {
    run_stage2(&mut LinuxOps, &stage1.plan).map(|()| Sealed { _sealed: () })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    const EPERM: i32 = 1;
    const EIO: i32 = 5;
    const EACCES: i32 = 13;
    const CAP_NET_BIND_SERVICE: u32 = 10;
    const CAP_SYS_ADMIN: u32 = 21;
    const CAP_SYS_RESOURCE: u32 = 24;
    /// Capabilities 0..=40.
    const ALL: u64 = (1 << 41) - 1;
    const SETPCAP: u64 = 1 << CAP_SETPCAP;
    const NET_BIND: u64 = 1 << CAP_NET_BIND_SERVICE;
    const ARCHES: [Arch; 2] = [Arch::X86_64, Arch::Aarch64];

    /// One call the seal made, with its arguments.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Call {
        Status,
        UserIds,
        GroupIds,
        CapGet,
        CapSet([[u32; 3]; 2]),
        Prctl(c_int, [c_ulong; 4]),
        CoreLimit(Option<[u64; 2]>),
        Filter(Arch, u16),
    }

    /// What the fake does instead at one call.
    #[derive(Clone, Debug)]
    enum Fault {
        /// Fails with this errno and changes nothing.
        Errno(i32),
        /// A prctl returns this value.
        Value(c_int),
        /// A prctl flag read returns the other flag.
        Flip,
        /// getresuid or getresgid returns these ids.
        Ids([u32; 3]),
        /// capget returns these words.
        Words([[u32; 3]; 2]),
        /// A core limit read returns this limit.
        Limit([u64; 2]),
        /// The status file holds this text.
        Status(&'static str),
        /// seccomp returns this value and installs nothing.
        Returned(c_long),
        /// A write succeeds without changing anything.
        Ignore,
    }

    /// The process state the fake kernel keeps (C2): capset's subset rule and PR_CAPBSET_DROP's CAP_SETPCAP check are
    /// modelled, as are the zero-argument and range checks of the prctl options the seal uses.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Kernel {
        effective: u64,
        permitted: u64,
        inheritable: u64,
        bounding: u64,
        ambient: u64,
        no_new_privs: bool,
        core: [u64; 2],
        user_ids: [u32; 3],
        group_ids: [u32; 3],
        /// The thread count the first and every later status read report.
        threads: [u64; 2],
        filter: Option<(Arch, u16)>,
        /// What seccomp with TSYNC returns: 0, or the id of a thread it cannot synchronise.
        tsync: c_long,
    }

    impl Kernel {
        /// Full root: every capability, no ambient or inheritable one, unlimited core files, one thread.
        fn root() -> Kernel {
            Kernel {
                effective: ALL,
                permitted: ALL,
                inheritable: 0,
                bounding: ALL,
                ambient: 0,
                no_new_privs: false,
                core: [u64::MAX, u64::MAX],
                user_ids: [0, 0, 0],
                group_ids: [0, 0, 0],
                threads: [1, 1],
                filter: None,
                tsync: 0,
            }
        }

        /// Root with permitted = effective = `sets` and this bounding set.
        fn with(sets: u64, bounding: u64) -> Kernel {
            Kernel { effective: sets, permitted: sets, bounding, ..Kernel::root() }
        }

        fn capable(&self, capability: u32) -> bool {
            self.effective & bit(capability) != 0
        }
    }

    struct Fake {
        kernel: Kernel,
        calls: Vec<Call>,
        faults: BTreeMap<usize, Fault>,
        status_reads: usize,
    }

    fn errno(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    fn subset(set: u64, of: u64) -> bool {
        set & !of == 0
    }

    impl Fake {
        fn new(kernel: Kernel) -> Fake {
            Fake { kernel, calls: Vec::new(), faults: BTreeMap::new(), status_reads: 0 }
        }

        fn with_fault(kernel: Kernel, index: usize, fault: Fault) -> Fake {
            let mut fake = Fake::new(kernel);
            fake.faults.insert(index, fault);
            fake
        }

        /// Records the call and returns the fault planned for it.
        fn record(&mut self, call: Call) -> Option<Fault> {
            self.calls.push(call);
            self.faults.get(&(self.calls.len() - 1)).cloned()
        }

        /// The kernel's prctl for the options the seal uses.
        fn prctl(&mut self, option: c_int, arguments: [c_ulong; 4], ignore: bool) -> io::Result<c_int> {
            let valid = |capability: c_ulong| capability <= c_ulong::from(CAP_LAST_CAP);
            let flag = |set: u64, capability: c_ulong| c_int::from(set & (1 << capability) != 0);
            match (option, arguments) {
                (PR_CAPBSET_READ, [capability, ..]) => {
                    if valid(capability) { Ok(flag(self.kernel.bounding, capability)) } else { Err(errno(EINVAL)) }
                }
                (PR_CAPBSET_DROP, [capability, ..]) => {
                    // cap_prctl_drop: CAP_SETPCAP is checked first, even for a capability already absent.
                    if !self.kernel.capable(CAP_SETPCAP) {
                        return Err(errno(EPERM));
                    }
                    if !valid(capability) {
                        return Err(errno(EINVAL));
                    }
                    if !ignore {
                        self.kernel.bounding &= !(1 << capability);
                    }
                    Ok(0)
                }
                (PR_SET_NO_NEW_PRIVS, [1, 0, 0, 0]) => {
                    if !ignore {
                        self.kernel.no_new_privs = true;
                    }
                    Ok(0)
                }
                (PR_GET_NO_NEW_PRIVS, [0, 0, 0, 0]) => Ok(c_int::from(self.kernel.no_new_privs)),
                (PR_CAP_AMBIENT, [PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0]) => {
                    if !ignore {
                        self.kernel.ambient = 0;
                    }
                    Ok(0)
                }
                (PR_CAP_AMBIENT, [PR_CAP_AMBIENT_IS_SET, capability, 0, 0]) => {
                    if valid(capability) { Ok(flag(self.kernel.ambient, capability)) } else { Err(errno(EINVAL)) }
                }
                _ => Err(errno(EINVAL)),
            }
        }
    }

    impl SealOps for Fake {
        fn own_status(&mut self) -> io::Result<Vec<u8>> {
            let fault = self.record(Call::Status);
            let threads = self.kernel.threads[self.status_reads.min(1)];
            self.status_reads += 1;
            match fault {
                Some(Fault::Errno(code)) => Err(errno(code)),
                Some(Fault::Status(text)) => Ok(text.as_bytes().to_vec()),
                _ => Ok(format!("Name:\tplaneon-gate\nState:\tR (running)\nTgid:\t7\nThreads:\t{threads}\nSigQ:\t0/1\n")
                    .into_bytes()),
            }
        }

        fn user_ids(&mut self) -> io::Result<[u32; 3]> {
            match self.record(Call::UserIds) {
                Some(Fault::Errno(code)) => Err(errno(code)),
                Some(Fault::Ids(ids)) => Ok(ids),
                _ => Ok(self.kernel.user_ids),
            }
        }

        fn group_ids(&mut self) -> io::Result<[u32; 3]> {
            match self.record(Call::GroupIds) {
                Some(Fault::Errno(code)) => Err(errno(code)),
                Some(Fault::Ids(ids)) => Ok(ids),
                _ => Ok(self.kernel.group_ids),
            }
        }

        fn read_capabilities(&mut self) -> io::Result<[[u32; 3]; 2]> {
            match self.record(Call::CapGet) {
                Some(Fault::Errno(code)) => Err(errno(code)),
                Some(Fault::Words(words)) => Ok(words),
                _ => Ok(capability_words(CapabilitySets {
                    effective: self.kernel.effective,
                    permitted: self.kernel.permitted,
                    inheritable: self.kernel.inheritable,
                })),
            }
        }

        fn write_capabilities(&mut self, words: [[u32; 3]; 2]) -> io::Result<()> {
            let fault = self.record(Call::CapSet(words));
            if let Some(Fault::Errno(code)) = fault {
                return Err(errno(code));
            }
            let new = capability_sets(words);
            let old = &self.kernel;
            // cap_capset: the inheritable set grows only within the old inheritable and permitted sets (unless
            // CAP_SETPCAP is effective) and within the old inheritable and bounding sets; the permitted set only
            // shrinks; the effective set stays within the new permitted set.
            if (!subset(new.inheritable, old.inheritable | old.permitted) && !old.capable(CAP_SETPCAP))
                || !subset(new.inheritable, old.inheritable | old.bounding)
                || !subset(new.permitted, old.permitted)
                || !subset(new.effective, new.permitted)
            {
                return Err(errno(EPERM));
            }
            if matches!(fault, Some(Fault::Ignore)) {
                return Ok(());
            }
            self.kernel.effective = new.effective;
            self.kernel.permitted = new.permitted;
            self.kernel.inheritable = new.inheritable;
            self.kernel.ambient &= new.permitted & new.inheritable;
            Ok(())
        }

        fn process_control(&mut self, option: c_int, arguments: [c_ulong; 4]) -> io::Result<c_int> {
            let fault = self.record(Call::Prctl(option, arguments));
            if let Some(Fault::Errno(code)) = fault {
                return Err(errno(code));
            }
            let result = self.prctl(option, arguments, matches!(fault, Some(Fault::Ignore)));
            match (fault, result) {
                (Some(Fault::Value(value)), _) => Ok(value),
                (Some(Fault::Flip), Ok(value)) => Ok(1 - value),
                (_, result) => result,
            }
        }

        fn core_limit(&mut self, new: Option<[u64; 2]>) -> io::Result<[u64; 2]> {
            let fault = self.record(Call::CoreLimit(new));
            if let Some(Fault::Errno(code)) = fault {
                return Err(errno(code));
            }
            let old = self.kernel.core;
            if let Some([soft, hard]) = new {
                if soft > hard {
                    return Err(errno(EINVAL));
                }
                if hard > old[1] && !self.kernel.capable(CAP_SYS_RESOURCE) {
                    return Err(errno(EPERM));
                }
                if !matches!(fault, Some(Fault::Ignore)) {
                    self.kernel.core = [soft, hard];
                }
            }
            match fault {
                Some(Fault::Limit(limit)) => Ok(limit),
                _ => Ok(old),
            }
        }

        fn install_filter(&mut self, program: &'static [u8], length: u16) -> io::Result<c_long> {
            let arch = if program == PROGRAM_X86_64 {
                Arch::X86_64
            } else {
                assert_eq!(program, PROGRAM_AARCH64, "only the published programs are installed");
                Arch::Aarch64
            };
            let fault = self.record(Call::Filter(arch, length));
            match fault {
                Some(Fault::Errno(code)) => return Err(errno(code)),
                Some(Fault::Returned(value)) => return Ok(value),
                _ => {}
            }
            if !self.kernel.no_new_privs && !self.kernel.capable(CAP_SYS_ADMIN) {
                return Err(errno(EACCES));
            }
            if self.kernel.tsync != 0 {
                return Ok(self.kernel.tsync);
            }
            self.kernel.filter = Some((arch, length));
            Ok(0)
        }
    }

    fn seal(fake: &mut Fake, arch: Arch) -> Result<(), SealError> {
        let plan = run_stage1(fake, arch)?;
        run_stage2(fake, &plan)
    }

    fn instructions(arch: Arch) -> u16 {
        match arch {
            Arch::X86_64 => 200,
            Arch::Aarch64 => 189,
        }
    }

    /// The version-3 words, computed here independently of `capability_words`.
    fn words(effective: u64, permitted: u64, inheritable: u64) -> [[u32; 3]; 2] {
        let low = |set: u64| u32::try_from(set & 0xFFFF_FFFF).expect("low word");
        let high = |set: u64| u32::try_from(set >> 32).expect("high word");
        [[low(effective), low(permitted), low(inheritable)], [high(effective), high(permitted), high(inheritable)]]
    }

    fn bounding_reads(step: SealStep) -> Vec<(Call, SealStep)> {
        (0..=41).map(|capability| (Call::Prctl(23, [capability, 0, 0, 0]), step)).collect()
    }

    fn ambient_reads(step: SealStep) -> Vec<(Call, SealStep)> {
        (0..=40).map(|capability| (Call::Prctl(47, [1, capability, 0, 0]), step)).collect()
    }

    /// DESIGN §2 (amended by §18) written out: the seal's calls in order, with literal options and arguments, for a
    /// start with these bounding and permitted sets, each with the step a failure there reports.
    fn expected(bounding: u64, permitted: u64, arch: Arch) -> Vec<(Call, SealStep)> {
        use SealStep::*;
        let mut calls = vec![(Call::Status, Threads(Stage::One)), (Call::UserIds, UserIds), (Call::GroupIds, GroupIds),
                             (Call::CapGet, StartCapabilities)];
        calls.extend(bounding_reads(StartBounding));
        // Step 1.
        calls.push((Call::CoreLimit(Some([0, 0])), CoreLimit));
        calls.push((Call::CoreLimit(None), CoreLimitReadBack));
        // Step 2.
        calls.push((Call::Prctl(47, [4, 0, 0, 0]), AmbientClear));
        calls.extend(ambient_reads(AmbientReadBack));
        // Step 3: every present capability but CAP_SETPCAP, ascending.
        for capability in 0..=40u32 {
            if bounding & (1 << capability) != 0 && capability != 8 {
                calls.push((Call::Prctl(24, [c_ulong::from(capability), 0, 0, 0]), BoundingDrop(Stage::One, capability)));
            }
        }
        calls.extend(bounding_reads(BoundingReadBack(Stage::One)));
        // Step 4.
        let kept = permitted & (1 << 8);
        calls.push((Call::CapSet(words(kept, kept, 0)), Capabilities(Stage::One)));
        calls.push((Call::CapGet, CapabilitiesReadBack(Stage::One)));
        // Step 5.
        calls.push((Call::Prctl(38, [1, 0, 0, 0]), NoNewPrivs));
        calls.push((Call::Prctl(39, [0, 0, 0, 0]), NoNewPrivsReadBack));
        // Stage 2, step 6.
        calls.push((Call::Status, Threads(Stage::Two)));
        // Step 7.
        if bounding & (1 << 8) != 0 {
            calls.push((Call::Prctl(24, [8, 0, 0, 0]), BoundingDrop(Stage::Two, 8)));
        }
        calls.extend(bounding_reads(BoundingReadBack(Stage::Two)));
        // Step 8.
        calls.push((Call::CapSet([[0; 3]; 2]), Capabilities(Stage::Two)));
        calls.push((Call::CapGet, CapabilitiesReadBack(Stage::Two)));
        // The final-state assertion.
        calls.push((Call::CapGet, FinalCapabilities));
        calls.extend(bounding_reads(FinalBounding));
        calls.extend(ambient_reads(FinalAmbient));
        calls.push((Call::Prctl(39, [0, 0, 0, 0]), FinalNoNewPrivs));
        calls.push((Call::CoreLimit(None), FinalCoreLimit));
        // Step 9, and nothing after it.
        calls.push((Call::Filter(arch, instructions(arch)), Filter));
        calls
    }

    fn only_calls(expected: Vec<(Call, SealStep)>) -> Vec<Call> {
        expected.into_iter().map(|(call, _)| call).collect()
    }

    /// The kernel state after a seal: every set empty, no_new_privs, core limit 0/0, the program installed.
    fn assert_sealed(kernel: &Kernel, arch: Arch, name: &str) {
        let sets = [kernel.effective, kernel.permitted, kernel.inheritable, kernel.bounding, kernel.ambient];
        assert_eq!(sets, [0; 5], "{name}: every set empty");
        assert!(kernel.no_new_privs, "{name}: no_new_privs");
        assert_eq!(kernel.core, [0, 0], "{name}: core limit");
        assert_eq!(kernel.filter, Some((arch, instructions(arch))), "{name}: the program");
    }

    fn os_errno(failure: &SealFailure) -> Option<i32> {
        match failure {
            SealFailure::Os(error) => error.raw_os_error(),
            _ => None,
        }
    }

    #[test]
    fn the_plan_derives_from_the_start_sets() {
        let start = |permitted: u64, bounding: u64| StartSets {
            capabilities: CapabilitySets { effective: permitted, permitted, inheritable: 0 },
            bounding,
        };
        let full = plan(start(ALL, ALL), Arch::X86_64).expect("plan");
        assert_eq!(full.stage1_drops, (0..=40).filter(|capability| *capability != 8).collect::<Vec<u32>>());
        assert_eq!((full.stage1_bounding, full.stage1_capabilities), (SETPCAP, SETPCAP));
        assert_eq!(full.stage2_drops, [8]);
        assert_eq!((full.arch, full.length), (Arch::X86_64, 200));
        let only = plan(start(SETPCAP, SETPCAP), Arch::Aarch64).expect("plan");
        assert_eq!((only.stage1_drops.len(), only.stage1_bounding, only.stage1_capabilities), (0, SETPCAP, SETPCAP));
        assert_eq!(only.stage2_drops, [8]);
        assert_eq!((only.arch, only.length), (Arch::Aarch64, 189));
        let empty = plan(start(0, 0), Arch::X86_64).expect("plan");
        assert_eq!((empty.stage1_drops.len(), empty.stage1_bounding, empty.stage1_capabilities), (0, 0, 0));
        assert!(empty.stage2_drops.is_empty());
        // Only present capabilities are dropped; CAP_NET_BIND_SERVICE is dropped like any other (§18).
        let some = plan(start(ALL, NET_BIND | SETPCAP | 1 << 40), Arch::X86_64).expect("plan");
        assert_eq!(some.stage1_drops, [10, 40]);
        assert_eq!(some.stage2_drops, [8]);
    }

    #[test]
    fn the_seal_makes_exactly_the_planned_calls_in_order() {
        for arch in ARCHES {
            let mut fake = Fake::new(Kernel::root());
            seal(&mut fake, arch).expect("full root seals");
            assert_eq!(fake.calls, only_calls(expected(ALL, ALL, arch)), "{arch:?}");
            assert_sealed(&fake.kernel, arch, "full root");
            // 4 + 42 start, 2 + 1 + 41 + 40 drops + 42 + 2 + 2 in stage 1; 1 + 1 + 42 + 2 + 1 + 42 + 41 + 1 + 1 + 1.
            assert_eq!(fake.calls.len(), 46 + 130 + 133, "{arch:?}");
        }
    }

    #[test]
    fn stage_one_alone_leaves_only_cap_setpcap_and_sets_no_new_privs() {
        let mut fake = Fake::new(Kernel { inheritable: NET_BIND, ambient: NET_BIND, ..Kernel::root() });
        let plan = run_stage1(&mut fake, Arch::X86_64).expect("stage 1");
        let kernel = &fake.kernel;
        assert_eq!([kernel.effective, kernel.permitted, kernel.bounding], [SETPCAP; 3]);
        assert_eq!([kernel.inheritable, kernel.ambient], [0, 0]);
        assert!(kernel.no_new_privs && kernel.core == [0, 0] && kernel.filter.is_none());
        assert_eq!(plan.stage2_drops, [8]);
        assert_eq!(fake.calls.last(), Some(&Call::Prctl(39, [0, 0, 0, 0])), "stage 1 ends with the nnp read-back");
    }

    #[test]
    fn accepted_start_states_seal() {
        let cases = [
            ("full root", Kernel::root()),
            ("full root with an inheritable and ambient capability",
             Kernel { inheritable: NET_BIND, ambient: NET_BIND, ..Kernel::root() }),
            ("a superset of {CAP_SETPCAP}", Kernel::with(SETPCAP | NET_BIND | 1 << 40, SETPCAP | NET_BIND | 1 << 40)),
            ("{CAP_SETPCAP} only", Kernel::with(SETPCAP, SETPCAP)),
            ("{CAP_NET_BIND_SERVICE, CAP_SETPCAP}", Kernel::with(SETPCAP | NET_BIND, SETPCAP | NET_BIND)),
            ("empty", Kernel::with(0, 0)),
            ("CAP_SETPCAP permitted and effective but not bounding", Kernel::with(SETPCAP, 0)),
            // D4: a permitted set beyond the bounding set ends empty too.
            ("permitted beyond bounding", Kernel::with(ALL, SETPCAP)),
            // Nothing to drop from the bounding set, and capset lowers permitted without any capability.
            ("another permitted capability, no CAP_SETPCAP, empty bounding set", Kernel::with(NET_BIND, 0)),
        ];
        for (name, kernel) in cases {
            for arch in ARCHES {
                let mut fake = Fake::new(kernel.clone());
                if let Err(error) = seal(&mut fake, arch) {
                    panic!("{name} ({arch:?}): {error:?}");
                }
                assert_eq!(fake.calls, only_calls(expected(kernel.bounding, kernel.permitted, arch)), "{name}");
                assert_sealed(&fake.kernel, arch, name);
            }
        }
    }

    #[test]
    fn other_start_states_fail_where_the_kernel_refuses() {
        let cases = [
            // §18: CAP_SETPCAP absent with another capability left to drop from the bounding set.
            ("CAP_NET_BIND_SERVICE without CAP_SETPCAP", Kernel::with(NET_BIND, NET_BIND),
             SealStep::BoundingDrop(Stage::One, 10)),
            ("a full bounding set without capabilities", Kernel::with(0, ALL), SealStep::BoundingDrop(Stage::One, 0)),
            ("CAP_SETPCAP permitted but not effective", Kernel { effective: 0, ..Kernel::root() },
             SealStep::BoundingDrop(Stage::One, 0)),
            // §18: CAP_SETPCAP absent from the permitted set but still to drop from the bounding set.
            ("CAP_SETPCAP only in the bounding set", Kernel::with(0, SETPCAP), SealStep::BoundingDrop(Stage::Two, 8)),
        ];
        for (name, kernel, step) in cases {
            let mut fake = Fake::new(kernel);
            let error = seal(&mut fake, Arch::X86_64).expect_err(name);
            assert_eq!(error.step(), step, "{name}");
            assert_eq!(os_errno(error.failure()), Some(EPERM), "{name}");
            assert!(fake.kernel.filter.is_none(), "{name}");
        }
        for (kernel, step) in [(Kernel { user_ids: [0, 1000, 0], ..Kernel::root() }, SealStep::UserIds),
                               (Kernel { group_ids: [0, 0, 1000], ..Kernel::root() }, SealStep::GroupIds)] {
            let mut fake = Fake::new(kernel.clone());
            let error = seal(&mut fake, Arch::X86_64).expect_err("not root");
            assert_eq!(error.step(), step);
            assert!(matches!(error.failure(), SealFailure::NotRoot(_)));
            assert_eq!(fake.kernel, kernel, "nothing changed");
        }
    }

    #[test]
    fn a_second_thread_stops_either_stage() {
        let mut fake = Fake::new(Kernel { threads: [2, 1], ..Kernel::root() });
        let error = seal(&mut fake, Arch::X86_64).expect_err("two threads before stage 1");
        assert_eq!(error.step(), SealStep::Threads(Stage::One));
        assert!(matches!(error.failure(), SealFailure::Threads(2)));
        assert_eq!(fake.calls, [Call::Status], "nothing after the check");
        assert_eq!(fake.kernel, Kernel { threads: [2, 1], ..Kernel::root() });

        let mut fake = Fake::new(Kernel { threads: [1, 3], ..Kernel::root() });
        let error = seal(&mut fake, Arch::Aarch64).expect_err("a thread spawned between the stages");
        assert_eq!(error.step(), SealStep::Threads(Stage::Two));
        assert!(matches!(error.failure(), SealFailure::Threads(3)));
        assert_eq!(fake.calls.last(), Some(&Call::Status), "nothing after the check");
        assert_eq!(fake.calls.len(), 46 + 130 + 1);
        assert_eq!([fake.kernel.effective, fake.kernel.bounding], [SETPCAP, SETPCAP], "stage 1's state, untouched");
        assert!(fake.kernel.filter.is_none());

        for text in ["Name:\tgate\n", "Threads:\t1\nThreads:\t1\n", "Threads:\tone\n", "Threads:\n", "threads:\t1\n"] {
            let mut fake = Fake::with_fault(Kernel::root(), 0, Fault::Status(text));
            let error = seal(&mut fake, Arch::X86_64).expect_err(text);
            assert_eq!(error.step(), SealStep::Threads(Stage::One), "{text:?}");
            assert!(matches!(error.failure(), SealFailure::StatusFormat), "{text:?}");
        }
    }

    #[test]
    fn every_call_failure_stops_the_seal_at_its_own_step() {
        for arch in ARCHES {
            let plan = expected(ALL, ALL, arch);
            for (index, (call, step)) in plan.iter().enumerate() {
                let mut fake = Fake::with_fault(Kernel::root(), index, Fault::Errno(EIO));
                let error = seal(&mut fake, arch).expect_err("a failed call stops the seal");
                assert_eq!(error.step(), *step, "call {index}: {call:?}");
                assert_eq!(fake.calls.len(), index + 1, "nothing after call {index}: {call:?}");
                if *call == Call::Prctl(23, [41, 0, 0, 0]) {
                    assert!(matches!(error.failure(), SealFailure::LastCapability { returned: None, errno: Some(EIO) }));
                } else {
                    assert_eq!(os_errno(error.failure()), Some(EIO), "call {index}: {call:?}");
                }
                assert!(fake.kernel.filter.is_none());
            }
        }
    }

    #[test]
    fn einval_for_a_capability_within_0_to_40_is_an_error() {
        let plan = expected(ALL, ALL, Arch::X86_64);
        let mut checked = 0;
        for (index, (call, step)) in plan.iter().enumerate() {
            let capability = match call {
                Call::Prctl(23, [capability, ..]) | Call::Prctl(47, [1, capability, ..]) if *capability <= 40 => *capability,
                _ => continue,
            };
            let mut fake = Fake::with_fault(Kernel::root(), index, Fault::Errno(EINVAL));
            let error = seal(&mut fake, Arch::X86_64).expect_err("EINVAL within 0..=40");
            assert_eq!(error.step(), *step);
            let expected = u32::try_from(capability).expect("a capability");
            assert!(matches!(error.failure(), SealFailure::InvalidCapability(found) if *found == expected), "{index}");
            assert_eq!(fake.calls.len(), index + 1);
            checked += 1;
        }
        assert_eq!(checked, 41 * 4 + 41 * 2, "four bounding reads and two ambient reads of 0..=40");
    }

    #[test]
    fn every_read_back_mismatch_stops_the_seal() {
        let plan = expected(ALL, ALL, Arch::X86_64);
        let mut checked = 0;
        for (index, (call, step)) in plan.iter().enumerate() {
            let fault = match (call, step) {
                // The start reads define the plan; their failures are the other tests'.
                (_, SealStep::StartCapabilities | SealStep::StartBounding) => continue,
                (Call::Status, _) => Fault::Status("Name:\tgate\nThreads:\t2\n"),
                (Call::UserIds | Call::GroupIds, _) => Fault::Ids([0, 0, 1]),
                (Call::CapGet, _) => Fault::Words(words(SETPCAP | 1, SETPCAP | 1, 0)),
                (Call::Prctl(23, [41, ..]), _) => Fault::Value(0),
                (Call::Prctl(23 | 39, _) | Call::Prctl(47, [1, ..]), _) => Fault::Flip,
                (Call::CoreLimit(None), _) => Fault::Limit([0, 1]),
                _ => continue,
            };
            let mut fake = Fake::with_fault(Kernel::root(), index, fault.clone());
            let error = seal(&mut fake, Arch::X86_64).expect_err("a mismatch stops the seal");
            assert_eq!(error.step(), *step, "call {index}: {call:?}");
            // The seal stops at the end of the read it checks.
            let end = plan.iter().rposition(|(_, other)| other == step).expect("the step");
            assert_eq!(fake.calls.len(), end + 1, "call {index}: {call:?}");
            let kind = match error.failure() {
                SealFailure::Threads(2) => "threads",
                SealFailure::NotRoot([0, 0, 1]) => "ids",
                SealFailure::CapabilitiesMismatch { .. } => "capabilities",
                SealFailure::LastCapability { returned: Some(0), errno: None } => "last capability",
                SealFailure::SetMismatch { .. } => "set",
                SealFailure::NoNewPrivsUnset => "nnp",
                SealFailure::CoreLimitMismatch([0, 1]) => "core",
                other => panic!("call {index}: {other:?}"),
            };
            let wanted = match (call, &fault) {
                (Call::Status, _) => "threads",
                (Call::UserIds | Call::GroupIds, _) => "ids",
                (Call::CapGet, _) => "capabilities",
                (Call::Prctl(23, [41, ..]), _) => "last capability",
                (Call::Prctl(39, _), _) => "nnp",
                (Call::CoreLimit(_), _) => "core",
                _ => "set",
            };
            assert_eq!(kind, wanted, "call {index}: {call:?}");
            assert!(fake.kernel.filter.is_none());
            checked += 1;
        }
        // 2 status, 2 ids, 3 capget and 3 x 42 bounding reads (the start's excluded), 2 x 41 ambient, 2 nnp, 2 core.
        assert_eq!(checked, 2 + 2 + 3 + 3 * 42 + 2 * 41 + 2 + 2);
    }

    #[test]
    fn a_prctl_read_outside_0_and_1_is_an_error() {
        let plan = expected(ALL, ALL, Arch::Aarch64);
        for (index, (call, step)) in plan.iter().enumerate() {
            let capability = match call {
                Call::Prctl(23, [capability, ..]) if *capability <= 40 => Some(*capability),
                Call::Prctl(47, [1, capability, ..]) => Some(*capability),
                Call::Prctl(39, _) => None,
                _ => continue,
            };
            let mut fake = Fake::with_fault(Kernel::root(), index, Fault::Value(2));
            let error = seal(&mut fake, Arch::Aarch64).expect_err("2 is not a flag");
            assert_eq!(error.step(), *step);
            let expected = capability.map(|capability| u32::try_from(capability).expect("a capability"));
            assert!(matches!(error.failure(), SealFailure::NotABoolean { capability, value: 2 } if *capability == expected));
            assert_eq!(fake.calls.len(), index + 1);
        }
    }

    #[test]
    fn a_positive_tsync_return_and_any_other_non_zero_return_fail() {
        for arch in ARCHES {
            let mut fake = Fake::new(Kernel { tsync: 4242, ..Kernel::root() });
            let error = seal(&mut fake, arch).expect_err("TSYNC could not synchronise a thread");
            assert_eq!(error.step(), SealStep::Filter);
            assert!(matches!(error.failure(), SealFailure::TsyncThread(4242)));
            assert!(fake.kernel.filter.is_none());
            let last = expected(ALL, ALL, arch).len() - 1;
            for value in [-2, 1] {
                let mut fake = Fake::with_fault(Kernel::root(), last, Fault::Returned(value));
                let error = seal(&mut fake, arch).expect_err("a non-zero return");
                assert_eq!(error.step(), SealStep::Filter);
                match error.failure() {
                    SealFailure::Returned(found) => assert_eq!((*found, value), (-2, -2)),
                    SealFailure::TsyncThread(found) => assert_eq!((*found, value), (1, 1)),
                    other => panic!("{other:?}"),
                }
            }
        }
    }

    #[test]
    fn the_final_state_assertion_is_the_last_read_before_the_filter() {
        use SealStep::*;
        let plan = expected(ALL, ALL, Arch::X86_64);
        let steps: Vec<SealStep> = plan.iter().map(|(_, step)| *step).collect();
        let tail = &steps[steps.len() - 87..];
        assert_eq!(tail[0], FinalCapabilities);
        assert!(tail[1..43].iter().all(|step| *step == FinalBounding));
        assert!(tail[43..84].iter().all(|step| *step == FinalAmbient));
        assert_eq!(tail[84..], [FinalNoNewPrivs, FinalCoreLimit, Filter]);
        assert_eq!(steps[steps.len() - 88], CapabilitiesReadBack(Stage::Two));
        // A write the kernel silently ignores is caught by its own read-back.
        let start = Kernel { inheritable: NET_BIND, ambient: NET_BIND, ..Kernel::root() };
        let mut checked = 0;
        for (index, (call, step)) in plan.iter().enumerate() {
            let read_back = match step {
                CoreLimit => CoreLimitReadBack,
                AmbientClear => AmbientReadBack,
                BoundingDrop(stage, _) => BoundingReadBack(*stage),
                Capabilities(stage) => CapabilitiesReadBack(*stage),
                NoNewPrivs => NoNewPrivsReadBack,
                _ => continue,
            };
            let mut fake = Fake::with_fault(start.clone(), index, Fault::Ignore);
            let error = seal(&mut fake, Arch::X86_64).expect_err("an ignored write");
            assert_eq!(error.step(), read_back, "call {index}: {call:?}");
            assert!(fake.kernel.filter.is_none());
            checked += 1;
        }
        assert_eq!(checked, 1 + 1 + 40 + 1 + 1 + 1 + 1);
        // Read-backs that disagree at the final-state assertion only.
        for (index, (_, step)) in plan.iter().enumerate() {
            let fault = match step {
                FinalCapabilities => Fault::Words(words(1, 1, 0)),
                FinalBounding | FinalAmbient | FinalNoNewPrivs if index == steps.iter().position(|other| other == step)
                    .expect("step") => Fault::Flip,
                FinalCoreLimit => Fault::Limit([0, u64::MAX]),
                _ => continue,
            };
            let mut fake = Fake::with_fault(Kernel::root(), index, fault);
            let error = seal(&mut fake, Arch::X86_64).expect_err("the final state differs");
            assert_eq!(error.step(), *step);
            assert!(fake.kernel.filter.is_none());
        }
    }

    #[test]
    fn the_portable_helpers_used_by_the_engine() {
        for (call, option, arguments) in [(Prctl::BoundingRead(41), 23, [41, 0, 0, 0]),
                                          (Prctl::BoundingDrop(8), 24, [8, 0, 0, 0]),
                                          (Prctl::AmbientIsSet(40), 47, [1, 40, 0, 0]),
                                          (Prctl::AmbientClearAll, 47, [4, 0, 0, 0]),
                                          (Prctl::SetNoNewPrivs, 38, [1, 0, 0, 0]),
                                          (Prctl::GetNoNewPrivs, 39, [0, 0, 0, 0])] {
            assert_eq!(call.arguments(), (option, arguments), "{call:?}");
        }
        assert_eq!(members(SETPCAP | NET_BIND | 1 << 40), [8, 10, 40]);
        assert_eq!(members(ALL).len(), 41);
        assert_eq!(members(1 << 41), Vec::<u32>::new(), "only 0..=40 are capabilities");
        let sets = CapabilitySets { effective: 1 << 40 | 1, permitted: ALL, inheritable: 1 << 32 };
        assert_eq!(capability_words(sets), words(sets.effective, sets.permitted, sets.inheritable));
        assert_eq!(capability_sets(capability_words(sets)), sets);
    }
}
