//! The OBSERVER process seal (HE-004A DESIGN section 4): two stages with nothing between them in HE-004A (the observer
//! reads no configuration yet, owner decision Q-HE4A-1 (b)), in safe Rust over `gate_sys::seal`'s raw calls, which are
//! role-neutral and used unchanged (its `prctl` wrapper cannot reach `PR_SET_DUMPABLE`).
//!
//! - Preconditions: the process is single-threaded (the `Threads:` line of its own status file) and root (real,
//!   effective and saved uid and gid 0, read before the filter, which kills `getresuid`).
//! - Start state: `capget` (effective, permitted, inheritable), `PR_CAPBSET_READ` 0..=40 (the bounding set, with
//!   `PR_CAPBSET_READ(41)` failing with EINVAL) and `PR_CAP_AMBIENT_IS_SET` 0..=40 (the ambient set). It is accepted only
//!   when the bounding set already equals {CAP_NET_ADMIN, CAP_BPF}, the permitted set holds both and the ambient set is
//!   empty: `planeon_observer_t` has no `setpcap` (matrix v5), so the observer cannot drop a bounding capability, and
//!   `PR_CAPBSET_DROP` is never called. A refused start state makes no write.
//! - Stage 1, before any input is read, any socket opened or any thread spawned: (1) the core limit 0/0, read back
//!   (dumpability is kept: nothing calls `PR_SET_DUMPABLE`); (2) the ambient set asserted empty; (3) `capset` to
//!   permitted = effective = {CAP_NET_ADMIN, CAP_BPF}, inheritable empty, read back; (4) no_new_privs 1, read back.
//! - Stage 2: (5) single-threaded again; the final-state assertion (`capget` shows permitted = effective = the two and
//!   inheritable empty, `PR_CAPBSET_READ` 0..=40 the two, `PR_CAP_AMBIENT_IS_SET` 0..=40 nothing, no_new_privs is 1, the
//!   core limit is 0/0), the last reads before (6) the published OBSERVER program for the running architecture,
//!   installed with `SECCOMP_FILTER_FLAG_TSYNC`; any return but 0 is a failure. Nothing follows the install.
//!
//! The private helpers (the capability words, the `sock_fprog` length, the prctl argument vectors, the `Threads:`
//! parser, the C9 bounding read, the TSYNC return) are copied from effect-gate's seal with its test cases (owner decision
//! Q-HE4A-6 (a)); a shared module is extracted before HE-005..HE-007 add their seals. Every step's failure and every
//! read-back mismatch is a typed [`SealError`]; the library never exits (`main` exits with a distinct status on each).
//! The generic engine over `SealOps` is crate-private and the public stages are concrete over the Linux implementation
//! (effect-gate's D6), so no crate can obtain a [`Stage1`] or [`Sealed`] token from a fake; on other targets the public
//! stages are absent. Both programs are compiled in on every target.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::ffi::c_int;
use std::ffi::c_long;
use std::ffi::c_ulong;
use std::io;

/// CAP_NET_ADMIN and CAP_BPF: the observer's capabilities (W01 section 5.3 OBSERVER row; BPF_PROG_QUERY and the
/// unredacted translated instructions).
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_BPF: u32 = 39;

/// The observer's bounding, permitted and effective set after the seal: {CAP_NET_ADMIN, CAP_BPF}.
pub const KEPT: u64 = 1 << CAP_NET_ADMIN | 1 << CAP_BPF;

/// CAP_LAST_CAP: the seal reads capabilities 0..=40 and requires `PR_CAPBSET_READ(41)` to fail with EINVAL (C9).
pub const CAP_LAST_CAP: u32 = 40;

/// EINVAL (22 on Linux, and on the macOS build host).
const EINVAL: i32 = 22;

/// The longest classic-BPF program the kernel accepts (`BPF_MAXINSNS`), and the size of one instruction.
pub const BPF_MAXINSNS: usize = 4096;
const INSTRUCTION_BYTES: usize = 8;

const PR_CAPBSET_READ: c_int = 23;
const PR_SET_NO_NEW_PRIVS: c_int = 38;
const PR_GET_NO_NEW_PRIVS: c_int = 39;
const PR_CAP_AMBIENT: c_int = 47;
const PR_CAP_AMBIENT_IS_SET: c_ulong = 1;

/// The core limit the seal sets and reads back, `[soft, hard]`.
const NO_CORE: [u64; 2] = [0, 0];

/// The published OBSERVER programs (harness-onion MET-ENFORCE-025, seccomp allowlists v3, unchanged in v4; vendored
/// byte-identically under `host-enforcement/contracts/seccomp-v3/` and pinned by `tools/gate.py`, HE-004A): the kernel's
/// `struct sock_filter` arrays, 8 bytes per instruction. The array types pin each file's length at compile time; both
/// are compiled in on every target and [`RUNNING_ARCH`] selects the one installed.
pub static PROGRAM_X86_64: &[u8; 1904] = include_bytes!("../../../contracts/seccomp-v3/OBSERVER.x86_64.bpf");
pub static PROGRAM_AARCH64: &[u8; 1816] = include_bytes!("../../../contracts/seccomp-v3/OBSERVER.aarch64.bpf");

/// The programs' instruction counts (seccomp allowlists v4 `programLengths`: 238 and 227).
pub const INSTRUCTIONS_X86_64: u16 = 238;
pub const INSTRUCTIONS_AARCH64: u16 = 227;
const _: () = assert!(INSTRUCTIONS_X86_64 as usize * INSTRUCTION_BYTES == 1904);
const _: () = assert!(INSTRUCTIONS_AARCH64 as usize * INSTRUCTION_BYTES == 1816);

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

/// The prctl calls the observer's seal makes: reads, and no_new_privs. There is no bounding drop (no `setpcap`) and no
/// ambient clear (a non-empty start ambient set is refused).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prctl {
    /// `PR_CAPBSET_READ` (23): is the capability in the bounding set?
    BoundingRead(u32),
    /// `PR_CAP_AMBIENT` (47) with `PR_CAP_AMBIENT_IS_SET` (1).
    AmbientIsSet(u32),
    /// `PR_SET_NO_NEW_PRIVS` (38) to 1.
    SetNoNewPrivs,
    /// `PR_GET_NO_NEW_PRIVS` (39).
    GetNoNewPrivs,
}

impl Prctl {
    /// The option and exactly four further `c_ulong` arguments, zeros where unused (effect-gate's design review round 3,
    /// D5: musl's variadic `prctl` reads four `unsigned long`s, and the kernel refuses non-zero unused arguments for
    /// options 38 and 39).
    pub fn arguments(self) -> (c_int, [c_ulong; 4]) {
        match self {
            Prctl::BoundingRead(capability) => (PR_CAPBSET_READ, [c_ulong::from(capability), 0, 0, 0]),
            Prctl::AmbientIsSet(capability) => (PR_CAP_AMBIENT, [PR_CAP_AMBIENT_IS_SET, c_ulong::from(capability), 0, 0]),
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

/// Where the seal stopped (DESIGN section 4's preconditions, start state, steps 1-6 and the final-state assertion).
/// Every value is distinct, and `status::seal_step` gives each its own exit status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealStep {
    /// The single-thread check: before stage 1, and step 5 at the start of stage 2.
    Threads(Stage),
    /// `getresuid`: the real, effective and saved uid must be 0.
    UserIds,
    /// `getresgid`: the real, effective and saved gid must be 0.
    GroupIds,
    /// `capget` of the start sets.
    StartCapabilities,
    /// `PR_CAPBSET_READ` 0..=41 of the start bounding set.
    StartBounding,
    /// `PR_CAP_AMBIENT_IS_SET` 0..=40 of the start ambient set.
    StartAmbient,
    /// The start state's acceptance: bounding set the two, permitted set holding both, ambient set empty.
    StartState,
    /// The `sock_fprog` length of the running architecture's program (checked before any change).
    Program,
    /// Step 1: `prlimit(RLIMIT_CORE, {0, 0})`.
    CoreLimit,
    /// Step 1's read-back.
    CoreLimitReadBack,
    /// Step 2: the ambient set asserted empty (`PR_CAP_AMBIENT_IS_SET` 0..=40).
    Ambient,
    /// Step 3: `capset`.
    Capabilities,
    /// Step 3: `capget`'s read-back.
    CapabilitiesReadBack,
    /// Step 4: `PR_SET_NO_NEW_PRIVS`.
    NoNewPrivs,
    /// Step 4's read-back.
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
    /// Step 6: the filter.
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
    /// The start bounding set (this one) is not exactly {CAP_NET_ADMIN, CAP_BPF}: wider or narrower.
    StartBounding(u64),
    /// The start permitted set (this one) lacks CAP_NET_ADMIN or CAP_BPF.
    StartPermitted(u64),
    /// The start ambient set (this one) is not empty.
    StartAmbient(u64),
    /// A set read back differs from its target.
    SetMismatch { expected: u64, found: u64 },
    /// `capget` read back other sets than the target.
    CapabilitiesMismatch { expected: CapabilitySets, found: CapabilitySets },
    /// The core limit read back is not 0/0.
    CoreLimitMismatch([u64; 2]),
    /// `PR_GET_NO_NEW_PRIVS` read back 0.
    NoNewPrivsUnset,
    /// The program is not its pinned number of whole instructions (this many bytes).
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

/// The start sets the acceptance reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StartSets {
    pub(crate) capabilities: CapabilitySets,
    pub(crate) bounding: u64,
    pub(crate) ambient: u64,
}

/// What stage 2 carries out: the architecture whose program is installed, and its length in instructions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) arch: Arch,
    pub(crate) length: u16,
}

/// The start state's acceptance (DESIGN section 4): the bounding set exactly the two, the permitted set holding both,
/// the ambient set empty; checked in that order, before any write.
pub(crate) fn accept_start(start: StartSets) -> Result<(), SealError> {
    if start.bounding != KEPT {
        return Err(fail(SealStep::StartState, SealFailure::StartBounding(start.bounding)));
    }
    if start.capabilities.permitted & KEPT != KEPT {
        return Err(fail(SealStep::StartState, SealFailure::StartPermitted(start.capabilities.permitted)));
    }
    if start.ambient != 0 {
        return Err(fail(SealStep::StartState, SealFailure::StartAmbient(start.ambient)));
    }
    Ok(())
}

/// The plan for this architecture: its program's `sock_fprog` length, which must be the pinned count.
pub(crate) fn plan(arch: Arch) -> Result<Plan, SealError> {
    let program = arch.program();
    match filter_length(program) {
        Some(length) if length == arch.instructions() => Ok(Plan { arch, length }),
        _ => Err(fail(SealStep::Program, SealFailure::ProgramLength(program.len()))),
    }
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

/// The observer's sets after step 3 and at the final-state assertion: permitted = effective = the two, inheritable
/// empty.
fn kept_sets() -> CapabilitySets {
    CapabilitySets { effective: KEPT, permitted: KEPT, inheritable: 0 }
}

/// Stage 1, preconditions and the start state included: the plan stage 2 carries out.
pub(crate) fn run_stage1<O: SealOps>(ops: &mut O, arch: Arch) -> Result<Plan, SealError> {
    single_thread(ops, Stage::One)?;
    root_ids(ops.user_ids(), SealStep::UserIds)?;
    root_ids(ops.group_ids(), SealStep::GroupIds)?;
    let capabilities = ops.read_capabilities().map(capability_sets).map_err(os(SealStep::StartCapabilities))?;
    let bounding = read_bounding(ops, SealStep::StartBounding)?;
    let ambient = read_ambient(ops, SealStep::StartAmbient)?;
    accept_start(StartSets { capabilities, bounding, ambient })?;
    let plan = plan(arch)?;
    // Step 1.
    ops.core_limit(Some(NO_CORE)).map_err(os(SealStep::CoreLimit))?;
    expect_no_core(ops, SealStep::CoreLimitReadBack)?;
    // Step 2.
    let ambient = read_ambient(ops, SealStep::Ambient)?;
    expect_set(SealStep::Ambient, 0, ambient)?;
    // Step 3.
    ops.write_capabilities(capability_words(kept_sets())).map_err(os(SealStep::Capabilities))?;
    expect_capabilities(ops, SealStep::CapabilitiesReadBack, kept_sets())?;
    // Step 4.
    control(ops, Prctl::SetNoNewPrivs).map_err(os(SealStep::NoNewPrivs))?;
    expect_no_new_privs(ops, SealStep::NoNewPrivsReadBack)?;
    Ok(plan)
}

/// Stage 2: the thread check, the final-state assertion and the filter, then nothing.
pub(crate) fn run_stage2<O: SealOps>(ops: &mut O, plan: &Plan) -> Result<(), SealError> {
    single_thread(ops, Stage::Two)?;
    // The final-state assertion: the last reads before the filter, which kills every one of them.
    expect_capabilities(ops, SealStep::FinalCapabilities, kept_sets())?;
    let bounding = read_bounding(ops, SealStep::FinalBounding)?;
    expect_set(SealStep::FinalBounding, KEPT, bounding)?;
    let ambient = read_ambient(ops, SealStep::FinalAmbient)?;
    expect_set(SealStep::FinalAmbient, 0, ambient)?;
    expect_no_new_privs(ops, SealStep::FinalNoNewPrivs)?;
    expect_no_core(ops, SealStep::FinalCoreLimit)?;
    // Step 6, the last call.
    match ops.install_filter(plan.arch.program(), plan.length) {
        Ok(0) => Ok(()),
        Ok(id) if id > 0 => Err(fail(SealStep::Filter, SealFailure::TsyncThread(id))),
        Ok(value) => Err(fail(SealStep::Filter, SealFailure::Returned(value))),
        Err(error) => Err(fail(SealStep::Filter, SealFailure::Os(error))),
    }
}

/// Stage 1 is done: the process is single-threaded, root, with the core limit 0/0, no ambient capability, permitted =
/// effective = {CAP_NET_ADMIN, CAP_BPF} within that bounding set, and no_new_privs set. Only [`seal_stage1`] makes one
/// (private field; no Clone, Copy or Default).
#[derive(Debug)]
#[must_use]
pub struct Stage1 {
    plan: Plan,
}

/// The seal is installed: permitted = effective = bounding = {CAP_NET_ADMIN, CAP_BPF}, inheritable and ambient empty,
/// no_new_privs set, the core limit 0/0, and the published OBSERVER program filters every thread. Only [`seal_stage2`]
/// makes one (private field; no Clone, Copy or Default), so later packets' constructors that open sockets or spawn
/// threads can take `&Sealed`.
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

/// Stage 2 of the seal, the statement right after stage 1 in HE-004A.
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
    /// The prctl options the observer never uses: PR_CAPBSET_DROP (24) and PR_CAP_AMBIENT's CLEAR_ALL (47, 4).
    const PR_CAPBSET_DROP: c_int = 24;
    const PR_CAP_AMBIENT_CLEAR_ALL: c_ulong = 4;
    /// Capabilities 0..=40.
    const ALL: u64 = (1 << 41) - 1;
    const NET_ADMIN: u64 = 1 << CAP_NET_ADMIN;
    const BPF: u64 = 1 << CAP_BPF;
    const NET_BIND: u64 = 1 << CAP_NET_BIND_SERVICE;
    const ARCHES: [Arch; 2] = [Arch::X86_64, Arch::Aarch64];
    /// The calls of the start state's reads: status, uid, gid, capget, 42 bounding reads, 41 ambient reads.
    const START_READS: usize = 4 + 42 + 41;
    /// Stage 1's calls after the start reads: core limit and read-back, 41 ambient reads, capset and read-back, nnp
    /// and read-back.
    const STAGE1_WRITES: usize = 2 + 41 + 2 + 2;
    /// Stage 2's calls: status, capget, 42 bounding reads, 41 ambient reads, nnp, core limit, filter.
    const STAGE2: usize = 1 + 1 + 42 + 41 + 1 + 1 + 1;

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

    impl Call {
        /// A call that changes the process (a write), as opposed to a read.
        fn writes(&self) -> bool {
            match self {
                Call::CapSet(_) | Call::CoreLimit(Some(_)) | Call::Filter(..) => true,
                Call::Prctl(option, arguments) => {
                    !matches!((*option, arguments[0]), (PR_CAPBSET_READ, _) | (PR_GET_NO_NEW_PRIVS, _)
                              | (PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET))
                }
                _ => false,
            }
        }
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

    /// The process state the fake kernel keeps: capset's subset rule, PR_CAPBSET_DROP's CAP_SETPCAP check and the
    /// zero-argument and range checks of the prctl options are modelled.
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
        /// The observer's start as HE-008's unit gives it: root, bounding = permitted = effective = the two, no
        /// ambient or inheritable capability, unlimited core files, one thread.
        fn observer() -> Kernel {
            Kernel {
                effective: KEPT,
                permitted: KEPT,
                inheritable: 0,
                bounding: KEPT,
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
            Kernel { effective: sets, permitted: sets, bounding, ..Kernel::observer() }
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

        /// The kernel's prctl for the options the gate's and the observer's seals use.
        fn prctl(&mut self, option: c_int, arguments: [c_ulong; 4], ignore: bool) -> io::Result<c_int> {
            let valid = |capability: c_ulong| capability <= c_ulong::from(CAP_LAST_CAP);
            let flag = |set: u64, capability: c_ulong| c_int::from(set & (1 << capability) != 0);
            match (option, arguments) {
                (PR_CAPBSET_READ, [capability, ..]) => {
                    if valid(capability) { Ok(flag(self.kernel.bounding, capability)) } else { Err(errno(EINVAL)) }
                }
                (PR_CAPBSET_DROP, [capability, ..]) => {
                    // cap_prctl_drop: CAP_SETPCAP (8) is checked first, even for a capability already absent.
                    if !self.kernel.capable(8) {
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
                _ => Ok(format!("Name:\tplaneon-observ\nState:\tR (running)\nTgid:\t9\nThreads:\t{threads}\nSigQ:\t0/1\n")
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
            if (!subset(new.inheritable, old.inheritable | old.permitted) && !old.capable(8))
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
            let arch = if program == PROGRAM_X86_64.as_slice() {
                Arch::X86_64
            } else {
                assert_eq!(program, PROGRAM_AARCH64.as_slice(), "only the published programs are installed");
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

    /// DESIGN section 5's three residual assertions (D2-5), checked after every run: PR_CAPBSET_DROP (and the ambient
    /// clear) never appears, a refused start state made no write, and nothing follows the filter install.
    fn assert_invariants(fake: &Fake, result: &Result<(), SealError>, name: &str) {
        for call in &fake.calls {
            assert!(!matches!(call, Call::Prctl(PR_CAPBSET_DROP, _)), "{name}: PR_CAPBSET_DROP was called");
            assert!(!matches!(call, Call::Prctl(PR_CAP_AMBIENT, [PR_CAP_AMBIENT_CLEAR_ALL, ..])), "{name}: ambient clear");
        }
        if let Some(position) = fake.calls.iter().position(|call| matches!(call, Call::Filter(..))) {
            assert_eq!(position, fake.calls.len() - 1, "{name}: a call follows the filter install");
        }
        if let Err(error) = result {
            if matches!(error.step(), SealStep::Threads(Stage::One) | SealStep::UserIds | SealStep::GroupIds
                                      | SealStep::StartCapabilities | SealStep::StartBounding | SealStep::StartAmbient
                                      | SealStep::StartState | SealStep::Program) {
                assert!(fake.calls.iter().all(|call| !call.writes()), "{name}: a refused start state made a write");
            }
        }
    }

    fn seal(fake: &mut Fake, arch: Arch) -> Result<(), SealError> {
        let result = run_stage1(fake, arch).and_then(|plan| run_stage2(fake, &plan));
        assert_invariants(fake, &result, "seal");
        result
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

    /// DESIGN section 4 written out: the seal's calls in order, with literal options and arguments, each with the step a
    /// failure there reports. The calls do not depend on the start state (nothing is dropped).
    fn expected(arch: Arch) -> Vec<(Call, SealStep)> {
        use SealStep::*;
        let mut calls = vec![(Call::Status, Threads(Stage::One)), (Call::UserIds, UserIds), (Call::GroupIds, GroupIds),
                             (Call::CapGet, StartCapabilities)];
        calls.extend(bounding_reads(StartBounding));
        calls.extend(ambient_reads(StartAmbient));
        // Step 1.
        calls.push((Call::CoreLimit(Some([0, 0])), CoreLimit));
        calls.push((Call::CoreLimit(None), CoreLimitReadBack));
        // Step 2.
        calls.extend(ambient_reads(Ambient));
        // Step 3: CAP_NET_ADMIN (12) and CAP_BPF (39, bit 7 of the second word).
        calls.push((Call::CapSet([[1 << 12, 1 << 12, 0], [1 << 7, 1 << 7, 0]]), Capabilities));
        calls.push((Call::CapGet, CapabilitiesReadBack));
        // Step 4.
        calls.push((Call::Prctl(38, [1, 0, 0, 0]), NoNewPrivs));
        calls.push((Call::Prctl(39, [0, 0, 0, 0]), NoNewPrivsReadBack));
        // Stage 2, step 5.
        calls.push((Call::Status, Threads(Stage::Two)));
        // The final-state assertion.
        calls.push((Call::CapGet, FinalCapabilities));
        calls.extend(bounding_reads(FinalBounding));
        calls.extend(ambient_reads(FinalAmbient));
        calls.push((Call::Prctl(39, [0, 0, 0, 0]), FinalNoNewPrivs));
        calls.push((Call::CoreLimit(None), FinalCoreLimit));
        // Step 6, and nothing after it.
        calls.push((Call::Filter(arch, arch.instructions()), Filter));
        calls
    }

    fn only_calls(expected: Vec<(Call, SealStep)>) -> Vec<Call> {
        expected.into_iter().map(|(call, _)| call).collect()
    }

    /// The kernel state after a seal: permitted = effective = bounding = the two, inheritable and ambient empty,
    /// no_new_privs, core limit 0/0, the program installed.
    fn assert_sealed(kernel: &Kernel, arch: Arch, name: &str) {
        assert_eq!([kernel.effective, kernel.permitted, kernel.bounding], [KEPT; 3], "{name}: the two capabilities");
        assert_eq!([kernel.inheritable, kernel.ambient], [0, 0], "{name}: inheritable and ambient empty");
        assert!(kernel.no_new_privs, "{name}: no_new_privs");
        assert_eq!(kernel.core, [0, 0], "{name}: core limit");
        assert_eq!(kernel.filter, Some((arch, arch.instructions())), "{name}: the program");
    }

    fn os_errno(failure: &SealFailure) -> Option<i32> {
        match failure {
            SealFailure::Os(error) => error.raw_os_error(),
            _ => None,
        }
    }

    #[test]
    fn the_seal_makes_exactly_the_planned_calls_in_order() {
        for arch in ARCHES {
            let mut fake = Fake::new(Kernel::observer());
            seal(&mut fake, arch).expect("the observer's start seals");
            assert_eq!(fake.calls, only_calls(expected(arch)), "{arch:?}");
            assert_sealed(&fake.kernel, arch, "the observer's start");
            assert_eq!(fake.calls.len(), START_READS + STAGE1_WRITES + STAGE2, "{arch:?}");
            assert_eq!(fake.calls.len(), 87 + 47 + 88, "{arch:?}");
        }
        assert_eq!(KEPT, 1 << 12 | 1 << 39);
        assert_eq!(plan(Arch::X86_64).expect("plan"), Plan { arch: Arch::X86_64, length: 238 });
        assert_eq!(plan(Arch::Aarch64).expect("plan"), Plan { arch: Arch::Aarch64, length: 227 });
    }

    #[test]
    fn stage_one_alone_leaves_the_two_capabilities_and_sets_no_new_privs() {
        let mut fake = Fake::new(Kernel { effective: ALL, permitted: ALL, inheritable: NET_BIND, ..Kernel::observer() });
        let plan = run_stage1(&mut fake, Arch::X86_64).expect("stage 1");
        let kernel = &fake.kernel;
        assert_eq!([kernel.effective, kernel.permitted, kernel.bounding], [KEPT; 3]);
        assert_eq!([kernel.inheritable, kernel.ambient], [0, 0]);
        assert!(kernel.no_new_privs && kernel.core == [0, 0] && kernel.filter.is_none());
        assert_eq!(plan, Plan { arch: Arch::X86_64, length: 238 });
        assert_eq!(fake.calls.len(), START_READS + STAGE1_WRITES);
        assert_eq!(fake.calls.last(), Some(&Call::Prctl(39, [0, 0, 0, 0])), "stage 1 ends with the nnp read-back");
    }

    #[test]
    fn accepted_start_states_seal() {
        let cases = [
            ("exactly the two", Kernel::observer()),
            ("a full permitted and effective set within the two's bounding set", Kernel::with(ALL, KEPT)),
            ("the two permitted but not effective", Kernel { effective: 0, ..Kernel::observer() }),
            ("one of the two effective", Kernel { effective: BPF, ..Kernel::observer() }),
            ("an inheritable capability", Kernel { inheritable: NET_BIND | KEPT, ..Kernel::observer() }),
            ("more permitted, fewer effective", Kernel { effective: NET_ADMIN, permitted: KEPT | NET_BIND,
                                                         ..Kernel::observer() }),
        ];
        for (name, kernel) in cases {
            for arch in ARCHES {
                let mut fake = Fake::new(kernel.clone());
                if let Err(error) = seal(&mut fake, arch) {
                    panic!("{name} ({arch:?}): {error:?}");
                }
                assert_eq!(fake.calls, only_calls(expected(arch)), "{name}");
                assert_sealed(&fake.kernel, arch, name);
            }
        }
    }

    #[test]
    fn refused_start_states_make_no_write() {
        let cases = [
            ("bounding wider by one", Kernel::with(KEPT | NET_BIND, KEPT | NET_BIND), "bounding"),
            ("bounding full", Kernel::with(ALL, ALL), "bounding"),
            ("bounding narrower: CAP_NET_ADMIN only", Kernel { bounding: NET_ADMIN, ..Kernel::observer() }, "bounding"),
            ("bounding narrower: CAP_BPF only", Kernel { bounding: BPF, ..Kernel::observer() }, "bounding"),
            ("bounding empty", Kernel { bounding: 0, ..Kernel::observer() }, "bounding"),
            ("permitted missing CAP_BPF", Kernel::with(NET_ADMIN, KEPT), "permitted"),
            ("permitted missing CAP_NET_ADMIN", Kernel::with(BPF, KEPT), "permitted"),
            ("permitted empty", Kernel::with(0, KEPT), "permitted"),
            ("ambient CAP_NET_ADMIN", Kernel { inheritable: KEPT, ambient: NET_ADMIN, ..Kernel::observer() }, "ambient"),
            ("ambient both", Kernel { inheritable: KEPT, ambient: KEPT, ..Kernel::observer() }, "ambient"),
            // The bounding set is checked first.
            ("bounding and ambient", Kernel { bounding: ALL, inheritable: KEPT, ambient: BPF, ..Kernel::observer() },
             "bounding"),
        ];
        for (name, kernel, kind) in cases {
            for arch in ARCHES {
                let mut fake = Fake::new(kernel.clone());
                let error = seal(&mut fake, arch).expect_err(name);
                assert_eq!(error.step(), SealStep::StartState, "{name}");
                let found = match error.failure() {
                    SealFailure::StartBounding(set) if *set == kernel.bounding => "bounding",
                    SealFailure::StartPermitted(set) if *set == kernel.permitted => "permitted",
                    SealFailure::StartAmbient(set) if *set == kernel.ambient => "ambient",
                    other => panic!("{name}: {other:?}"),
                };
                assert_eq!(found, kind, "{name}");
                assert_eq!(fake.calls, only_calls(expected(arch)[..START_READS].to_vec()), "{name}: only the start reads");
                assert!(fake.calls.iter().all(|call| !call.writes()), "{name}: no write");
                assert_eq!(fake.kernel, kernel, "{name}: nothing changed");
            }
        }
    }

    #[test]
    fn not_root_refuses_before_any_change() {
        for (kernel, step) in [(Kernel { user_ids: [0, 1000, 0], ..Kernel::observer() }, SealStep::UserIds),
                               (Kernel { user_ids: [1000, 1000, 1000], ..Kernel::observer() }, SealStep::UserIds),
                               (Kernel { group_ids: [0, 0, 1000], ..Kernel::observer() }, SealStep::GroupIds),
                               (Kernel { group_ids: [1000, 0, 0], ..Kernel::observer() }, SealStep::GroupIds)] {
            let mut fake = Fake::new(kernel.clone());
            let error = seal(&mut fake, Arch::X86_64).expect_err("not root");
            assert_eq!(error.step(), step);
            assert!(matches!(error.failure(), SealFailure::NotRoot(_)));
            assert_eq!(fake.kernel, kernel, "nothing changed");
            assert!(fake.calls.len() <= 3);
        }
    }

    #[test]
    fn a_second_thread_stops_either_stage() {
        let mut fake = Fake::new(Kernel { threads: [2, 1], ..Kernel::observer() });
        let error = seal(&mut fake, Arch::X86_64).expect_err("two threads before stage 1");
        assert_eq!(error.step(), SealStep::Threads(Stage::One));
        assert!(matches!(error.failure(), SealFailure::Threads(2)));
        assert_eq!(fake.calls, [Call::Status], "nothing after the check");
        assert_eq!(fake.kernel, Kernel { threads: [2, 1], ..Kernel::observer() });

        let mut fake = Fake::new(Kernel { threads: [1, 3], effective: ALL, permitted: ALL, ..Kernel::observer() });
        let error = seal(&mut fake, Arch::Aarch64).expect_err("a thread spawned between the stages");
        assert_eq!(error.step(), SealStep::Threads(Stage::Two));
        assert!(matches!(error.failure(), SealFailure::Threads(3)));
        assert_eq!(fake.calls.last(), Some(&Call::Status), "nothing after the check");
        assert_eq!(fake.calls.len(), START_READS + STAGE1_WRITES + 1);
        assert_eq!([fake.kernel.effective, fake.kernel.permitted, fake.kernel.bounding], [KEPT; 3], "stage 1's state");
        assert!(fake.kernel.filter.is_none());

        for text in ["Name:\tobserver\n", "Threads:\t1\nThreads:\t1\n", "Threads:\tone\n", "Threads:\n", "threads:\t1\n"] {
            let mut fake = Fake::with_fault(Kernel::observer(), 0, Fault::Status(text));
            let error = seal(&mut fake, Arch::X86_64).expect_err(text);
            assert_eq!(error.step(), SealStep::Threads(Stage::One), "{text:?}");
            assert!(matches!(error.failure(), SealFailure::StatusFormat), "{text:?}");
        }
    }

    #[test]
    fn every_call_failure_stops_the_seal_at_its_own_step() {
        for arch in ARCHES {
            let plan = expected(arch);
            for (index, (call, step)) in plan.iter().enumerate() {
                let mut fake = Fake::with_fault(Kernel::observer(), index, Fault::Errno(EIO));
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
    fn capset_eperm_stops_stage_one_at_step_3() {
        let plan = expected(Arch::X86_64);
        let index = plan.iter().position(|(_, step)| *step == SealStep::Capabilities).expect("capset");
        let mut fake = Fake::with_fault(Kernel::with(ALL, KEPT), index, Fault::Errno(EPERM));
        let error = seal(&mut fake, Arch::X86_64).expect_err("capset refused");
        assert_eq!(error.step(), SealStep::Capabilities);
        assert_eq!(os_errno(error.failure()), Some(EPERM));
        assert_eq!(fake.calls.len(), index + 1, "no no_new_privs, no stage 2");
        assert!(!fake.kernel.no_new_privs && fake.kernel.filter.is_none());
    }

    #[test]
    fn einval_for_a_capability_within_0_to_40_is_an_error() {
        let plan = expected(Arch::X86_64);
        let mut checked = 0;
        for (index, (call, step)) in plan.iter().enumerate() {
            let capability = match call {
                Call::Prctl(23, [capability, ..]) | Call::Prctl(47, [1, capability, ..]) if *capability <= 40 => *capability,
                _ => continue,
            };
            let mut fake = Fake::with_fault(Kernel::observer(), index, Fault::Errno(EINVAL));
            let error = seal(&mut fake, Arch::X86_64).expect_err("EINVAL within 0..=40");
            assert_eq!(error.step(), *step);
            let expected = u32::try_from(capability).expect("a capability");
            assert!(matches!(error.failure(), SealFailure::InvalidCapability(found) if *found == expected), "{index}");
            assert_eq!(fake.calls.len(), index + 1);
            checked += 1;
        }
        assert_eq!(checked, 41 * 2 + 41 * 3, "two bounding reads and three ambient reads of 0..=40");
        // C9: PR_CAPBSET_READ(41) answered, at the start read too, means the last capability is not 40.
        for (index, step) in [(4 + 41, SealStep::StartBounding)] {
            assert_eq!(plan[index], (Call::Prctl(23, [41, 0, 0, 0]), step));
            for value in [0, 1] {
                let mut fake = Fake::with_fault(Kernel::observer(), index, Fault::Value(value));
                let error = seal(&mut fake, Arch::X86_64).expect_err("41 answered");
                assert_eq!(error.step(), step);
                assert!(matches!(error.failure(), SealFailure::LastCapability { returned: Some(found), errno: None }
                                 if *found == value));
                assert_eq!(fake.kernel, Kernel::observer(), "no write");
            }
        }
    }

    #[test]
    fn every_read_back_mismatch_stops_the_seal() {
        let plan = expected(Arch::X86_64);
        let mut checked = 0;
        for (index, (call, step)) in plan.iter().enumerate() {
            let fault = match (call, step) {
                // The start reads feed the acceptance; their refusals are the other tests'.
                (_, SealStep::StartCapabilities | SealStep::StartBounding | SealStep::StartAmbient) => continue,
                (Call::Status, _) => Fault::Status("Name:\tobserver\nThreads:\t2\n"),
                (Call::UserIds | Call::GroupIds, _) => Fault::Ids([0, 0, 1]),
                (Call::CapGet, _) => Fault::Words(words(KEPT | 1, KEPT | 1, 0)),
                (Call::Prctl(23, [41, ..]), _) => Fault::Value(0),
                (Call::Prctl(23 | 39, _) | Call::Prctl(47, [1, ..]), _) => Fault::Flip,
                (Call::CoreLimit(None), _) => Fault::Limit([0, 1]),
                _ => continue,
            };
            let mut fake = Fake::with_fault(Kernel::observer(), index, fault.clone());
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
            let wanted = match call {
                Call::Status => "threads",
                Call::UserIds | Call::GroupIds => "ids",
                Call::CapGet => "capabilities",
                Call::Prctl(23, [41, ..]) => "last capability",
                Call::Prctl(39, _) => "nnp",
                Call::CoreLimit(_) => "core",
                _ => "set",
            };
            assert_eq!(kind, wanted, "call {index}: {call:?}");
            assert!(fake.kernel.filter.is_none());
            checked += 1;
        }
        // 2 status, 2 ids, 2 capget, 42 final bounding reads, 2 x 41 ambient (stage 1 and final), 2 nnp, 2 core.
        assert_eq!(checked, 2 + 2 + 2 + 42 + 2 * 41 + 2 + 2);
    }

    #[test]
    fn a_prctl_read_outside_0_and_1_is_an_error() {
        let plan = expected(Arch::Aarch64);
        let mut checked = 0;
        for (index, (call, step)) in plan.iter().enumerate() {
            let capability = match call {
                Call::Prctl(23, [capability, ..]) if *capability <= 40 => Some(*capability),
                Call::Prctl(47, [1, capability, ..]) => Some(*capability),
                Call::Prctl(39, _) => None,
                _ => continue,
            };
            let mut fake = Fake::with_fault(Kernel::observer(), index, Fault::Value(2));
            let error = seal(&mut fake, Arch::Aarch64).expect_err("2 is not a flag");
            assert_eq!(error.step(), *step);
            let expected = capability.map(|capability| u32::try_from(capability).expect("a capability"));
            assert!(matches!(error.failure(), SealFailure::NotABoolean { capability, value: 2 } if *capability == expected));
            assert_eq!(fake.calls.len(), index + 1);
            checked += 1;
        }
        assert_eq!(checked, 41 * 5 + 2);
    }

    #[test]
    fn a_positive_tsync_return_and_any_other_non_zero_return_fail() {
        for arch in ARCHES {
            let mut fake = Fake::new(Kernel { tsync: 4242, ..Kernel::observer() });
            let error = seal(&mut fake, arch).expect_err("TSYNC could not synchronise a thread");
            assert_eq!(error.step(), SealStep::Filter);
            assert!(matches!(error.failure(), SealFailure::TsyncThread(4242)));
            assert!(fake.kernel.filter.is_none());
            let last = expected(arch).len() - 1;
            for value in [-2, 1] {
                let mut fake = Fake::with_fault(Kernel::observer(), last, Fault::Returned(value));
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
        let plan = expected(Arch::X86_64);
        let steps: Vec<SealStep> = plan.iter().map(|(_, step)| *step).collect();
        let tail = &steps[steps.len() - 87..];
        assert_eq!(tail[0], FinalCapabilities);
        assert!(tail[1..43].iter().all(|step| *step == FinalBounding));
        assert!(tail[43..84].iter().all(|step| *step == FinalAmbient));
        assert_eq!(tail[84..], [FinalNoNewPrivs, FinalCoreLimit, Filter]);
        assert_eq!(steps[steps.len() - 88], Threads(Stage::Two), "stage 2 makes no write before the assertion");
        // A write the kernel silently ignores is caught by its own read-back.
        let start = Kernel { effective: ALL, permitted: ALL, inheritable: NET_BIND, ..Kernel::observer() };
        let mut checked = 0;
        for (index, (call, step)) in plan.iter().enumerate() {
            let read_back = match step {
                CoreLimit => CoreLimitReadBack,
                Capabilities => CapabilitiesReadBack,
                NoNewPrivs => NoNewPrivsReadBack,
                _ => continue,
            };
            let mut fake = Fake::with_fault(start.clone(), index, Fault::Ignore);
            let error = seal(&mut fake, Arch::X86_64).expect_err("an ignored write");
            assert_eq!(error.step(), read_back, "call {index}: {call:?}");
            assert!(fake.kernel.filter.is_none());
            checked += 1;
        }
        assert_eq!(checked, 3, "the core limit, capset and no_new_privs");
        // Read-backs that disagree at the final-state assertion only.
        for (index, (_, step)) in plan.iter().enumerate() {
            let fault = match step {
                FinalCapabilities => Fault::Words(words(KEPT, KEPT, 1)),
                FinalBounding | FinalAmbient | FinalNoNewPrivs if index == steps.iter().position(|other| other == step)
                    .expect("step") => Fault::Flip,
                FinalCoreLimit => Fault::Limit([0, u64::MAX]),
                _ => continue,
            };
            let mut fake = Fake::with_fault(Kernel::observer(), index, fault);
            let error = seal(&mut fake, Arch::X86_64).expect_err("the final state differs");
            assert_eq!(error.step(), *step);
            assert!(fake.kernel.filter.is_none());
        }
    }

    #[test]
    fn no_bounding_drop_and_nothing_after_the_filter_in_any_run() {
        // D2-5's assertions over every run of the other tests' shapes, beside the check `seal` makes after each run.
        let mut runs = 0;
        let starts = [Kernel::observer(), Kernel::with(ALL, KEPT), Kernel::with(ALL, ALL), Kernel::with(0, 0),
                      Kernel { bounding: NET_ADMIN, ..Kernel::observer() },
                      Kernel { inheritable: KEPT, ambient: BPF, ..Kernel::observer() }, Kernel::with(NET_ADMIN, KEPT)];
        for kernel in starts {
            for arch in ARCHES {
                let mut fake = Fake::new(kernel.clone());
                let result = seal(&mut fake, arch);
                assert!(!fake.calls.iter().any(|call| matches!(call, Call::Prctl(24, _))));
                if result.is_ok() {
                    assert!(matches!(fake.calls.last(), Some(Call::Filter(..))), "the filter is the last call");
                } else {
                    assert!(fake.calls.iter().all(|call| !call.writes()), "a refused start makes no write");
                }
                runs += 1;
            }
        }
        for arch in ARCHES {
            for index in 0..expected(arch).len() {
                for fault in [Fault::Errno(EIO), Fault::Ignore, Fault::Flip] {
                    let mut fake = Fake::with_fault(Kernel::with(ALL, KEPT), index, fault);
                    let _ = seal(&mut fake, arch);
                    assert!(!fake.calls.iter().any(|call| matches!(call, Call::Prctl(24, _))));
                    runs += 1;
                }
            }
        }
        assert_eq!(runs, 7 * 2 + 2 * 222 * 3);
    }

    #[test]
    fn the_portable_helpers_used_by_the_engine() {
        for (call, option, arguments) in [(Prctl::BoundingRead(41), 23, [41, 0, 0, 0]),
                                          (Prctl::AmbientIsSet(40), 47, [1, 40, 0, 0]),
                                          (Prctl::SetNoNewPrivs, 38, [1, 0, 0, 0]),
                                          (Prctl::GetNoNewPrivs, 39, [0, 0, 0, 0])] {
            assert_eq!(call.arguments(), (option, arguments), "{call:?}");
        }
        let sets = CapabilitySets { effective: 1 << 40 | 1, permitted: ALL, inheritable: 1 << 32 };
        assert_eq!(capability_words(sets), words(sets.effective, sets.permitted, sets.inheritable));
        assert_eq!(capability_sets(capability_words(sets)), sets);
        assert_eq!(capability_words(kept_sets()), [[1 << 12, 1 << 12, 0], [1 << 7, 1 << 7, 0]]);
        let start = |permitted: u64, bounding: u64, ambient: u64| StartSets {
            capabilities: CapabilitySets { effective: 0, permitted, inheritable: 0 },
            bounding,
            ambient,
        };
        assert!(accept_start(start(KEPT, KEPT, 0)).is_ok());
        assert!(accept_start(start(ALL, KEPT, 0)).is_ok());
        assert!(matches!(accept_start(start(KEPT, ALL, 0)).map_err(|e| e.failure), Err(SealFailure::StartBounding(ALL))));
        assert!(matches!(accept_start(start(BPF, KEPT, 0)).map_err(|e| e.failure), Err(SealFailure::StartPermitted(BPF))));
        assert!(matches!(accept_start(start(KEPT, KEPT, BPF)).map_err(|e| e.failure), Err(SealFailure::StartAmbient(BPF))));
    }
}
