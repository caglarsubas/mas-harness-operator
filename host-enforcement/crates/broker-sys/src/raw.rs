//! The capacity broker's raw calls (HE-005C; DESIGN-HE005 revision 5 sections 3.2, 3.5 and 4.0; the frozen seam note
//! DESIGN-HE005.SEAM-C revision 4, `ad6d3a75`, sections 1, 2 and 5). Written by hand by the Build-R10 session, in its
//! main session, with no subagent (owner rulings of 2026-10-30).
//!
//! **One foreign item.** `syscall` (gate-sys's and observer-sys's precedent), private, issuing every call by number
//! with six further `long` arguments (musl's `syscall` reads six, so unused ones are zero), through one place:
//! `Kernel`'s implementation of the raw-call trait. The numbers are the v6.12 kernel's for both targets, as the vendored libc
//! 0.2.190's musl modules give them (`linux/musl/b64/x86_64/mod.rs` and `linux/musl/b64/aarch64/mod.rs`); any other
//! target architecture does not compile. Each call and its BROKER duty is the seam note's section 5.
//!
//! **The rule (seam note section 2).** No function here chooses an outcome or retries a failed call. The admitted forms
//! are: refusing an argument before any call (`InvalidInput`); refusing the shape of a kernel reply after a call
//! (`InvalidData`); `fd_table`'s one bounded listing; and `sleep_monotonic`'s one call. Every other failure is the
//! call's errno.
//!
//! **What crosses the line.** No pointer and no bare errno. Descriptors cross only as the opaque `LeafDir`, `Script`,
//! `ChannelEnd` and `Pidfd`, whose `OwnedFd` is private to this file; no accessor, conversion or Debug gives its
//! number.
//! The only descriptor numbers that cross are `W3Expect`'s two source numbers and the child's numbers in `FdEntry`.
//!
//! **The span (section 3.5; G-HE5C-1..3).** `clone_span` (the parent's all-ones block, clone3, the restore) and
//! `child_path` (the nine steps, `-> !`) are generic over `RawCalls`, whose production implementation is the pinned
//! `syscall` wrapper and whose recording fake drives the same text in the host tests (H5F-5). The span's every value is
//! computed in the parent before clone3; it holds no index, slice, arithmetic or other panicking operation, and the
//! child allocates nothing, takes no lock, does not unwind and calls nothing but `syscall`.
//!
//! **Targets (seam note section 1).** The types, the argument checks, the span, the reply parsers and the recording
//! fake compile on every target, so the host tests run them. The `syscall` wrapper and every function that calls it are
//! Linux only.
#![allow(unsafe_code)]
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use std::ffi::CString;
use std::ffi::c_int;
use std::ffi::c_long;
use std::fs::File;
use std::io;
use std::mem::offset_of;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use crate::FdEntry;
use crate::FdIdentity;
use crate::LeafWrite;
use crate::Reaped;
use crate::W3Expect;

#[cfg(target_arch = "x86_64")]
mod numbers {
    use std::ffi::c_long;

    pub const SYS_WRITE: c_long = 1;
    pub const SYS_RT_SIGACTION: c_long = 13;
    pub const SYS_RT_SIGPROCMASK: c_long = 14;
    pub const SYS_IOCTL: c_long = 16;
    pub const SYS_SOCKETPAIR: c_long = 53;
    pub const SYS_FCNTL: c_long = 72;
    pub const SYS_SETRESUID: c_long = 117;
    pub const SYS_SETRESGID: c_long = 119;
    pub const SYS_CAPSET: c_long = 126;
    pub const SYS_PRCTL: c_long = 157;
    pub const SYS_GETDENTS64: c_long = 217;
    pub const SYS_CLOCK_NANOSLEEP: c_long = 230;
    pub const SYS_EXIT_GROUP: c_long = 231;
    pub const SYS_WAITID: c_long = 247;
    pub const SYS_OPENAT: c_long = 257;
    pub const SYS_NEWFSTATAT: c_long = 262;
    pub const SYS_DUP3: c_long = 292;
    pub const SYS_SECCOMP: c_long = 317;
    pub const SYS_EXECVEAT: c_long = 322;
    pub const SYS_CLONE3: c_long = 435;
    pub const SYS_CLOSE_RANGE: c_long = 436;
    pub const O_DIRECTORY: c_long = 0o200000;
    pub const O_NOFOLLOW: c_long = 0o400000;
}

#[cfg(target_arch = "aarch64")]
mod numbers {
    use std::ffi::c_long;

    pub const SYS_DUP3: c_long = 24;
    pub const SYS_FCNTL: c_long = 25;
    pub const SYS_IOCTL: c_long = 29;
    pub const SYS_OPENAT: c_long = 56;
    pub const SYS_GETDENTS64: c_long = 61;
    pub const SYS_WRITE: c_long = 64;
    pub const SYS_NEWFSTATAT: c_long = 79;
    pub const SYS_CAPSET: c_long = 91;
    pub const SYS_EXIT_GROUP: c_long = 94;
    pub const SYS_WAITID: c_long = 95;
    pub const SYS_CLOCK_NANOSLEEP: c_long = 115;
    pub const SYS_RT_SIGACTION: c_long = 134;
    pub const SYS_RT_SIGPROCMASK: c_long = 135;
    pub const SYS_SETRESUID: c_long = 147;
    pub const SYS_SETRESGID: c_long = 149;
    pub const SYS_PRCTL: c_long = 167;
    pub const SYS_SOCKETPAIR: c_long = 199;
    pub const SYS_SECCOMP: c_long = 277;
    pub const SYS_EXECVEAT: c_long = 281;
    pub const SYS_CLONE3: c_long = 435;
    pub const SYS_CLOSE_RANGE: c_long = 436;
    pub const O_DIRECTORY: c_long = 0o40000;
    pub const O_NOFOLLOW: c_long = 0o100000;
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("broker-sys pins the system call numbers for x86_64 and aarch64 only");

use numbers::*;

// Open flags (gate-sys `openat.rs`'s values) and the three sets this file uses. The leaf directory and the child's
// descriptor directory are read-only opens (duty 17, and duty 5's mask too); the control opener is O_WRONLY, which only
// duty 17's mask (O_CREAT, O_TRUNC, __O_TMPFILE) admits.
const O_RDONLY: c_long = 0;
const O_WRONLY: c_long = 1;
const O_CLOEXEC: c_long = 0o2000000;
const LEAF_DIR_FLAGS: c_long = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW;
const FD_DIR_FLAGS: c_long = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
const CONTROL_FLAGS: c_long = O_WRONLY | O_CLOEXEC | O_NOFOLLOW;
const WRITE_AND_CREATE_MASK: c_long = 0x400643;
const CREATE_MASK: c_long = 0x400240;
const _: () = assert!(LEAF_DIR_FLAGS & CREATE_MASK == 0 && LEAF_DIR_FLAGS & WRITE_AND_CREATE_MASK == 0);
const _: () = assert!(FD_DIR_FLAGS & CREATE_MASK == 0 && FD_DIR_FLAGS & WRITE_AND_CREATE_MASK == 0);
const _: () = assert!(CONTROL_FLAGS & CREATE_MASK == 0 && CONTROL_FLAGS & WRITE_AND_CREATE_MASK != 0);

const AT_FDCWD: c_long = -100;
const AT_EMPTY_PATH: c_long = 0x1000;
const F_DUPFD_CLOEXEC: c_long = 1030;
const AF_UNIX: c_long = 1;
const SOCK_SEQPACKET: c_long = 5;
const SOCK_CLOEXEC: c_long = 0o2000000;
/// `_IOWR('f', 134, 4)`, equal to gate.py's IOCTL_REQUESTS and observer-sys's constant.
const MEASURE_VERITY: c_long = 0xC0046686;
const VERITY_DIGEST_BYTES: u16 = 32;
const P_PIDFD: c_long = 3;
const WEXITED: c_long = 4;
const WNOHANG: c_long = 1;
const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
const CLD_DUMPED: i32 = 3;
const CLOCK_MONOTONIC: c_long = 1;

// The span's constants.
const SIG_SETMASK: c_long = 2;
/// The kernel's sigset size: 64 signals, 8 bytes.
const SIGSET_BYTES: c_long = 8;
const CLONE_PIDFD: u64 = 0x1000;
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
const SIGCHLD: u64 = 17;
/// `struct clone_args` through its `cgroup` member (CLONE_ARGS_SIZE_VER2).
const CLONE_ARGS_BYTES: c_long = 88;
/// The worker's descriptors (section 3.2): the I03 channel at 3, the verity-checked script at 4, all others closed.
const WORKER_CHANNEL_FD: c_long = 3;
const WORKER_SCRIPT_FD: c_long = 4;
const FIRST_FREE_FD: c_long = 5;
/// close_range's last descriptor, `~0U`.
const CLOSE_RANGE_LAST: c_long = 0xFFFF_FFFF;
const PR_SET_NO_NEW_PRIVS: c_long = 38;
const SECCOMP_SET_MODE_FILTER: c_long = 1;
const EXIT_STATUS: c_long = 127;

/// Every signal 1..64 but SIGKILL (9) and SIGSTOP (19), whose actions the kernel refuses to change (section 3.5,
/// step 1).
const RESET_SIGNALS: [c_long; 62] = [
    1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
    34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62,
    63, 64,
];

const fn reset_signals_hold() -> bool {
    let mut position = 0;
    let mut previous = 0;
    while position < RESET_SIGNALS.len() {
        let signal = RESET_SIGNALS[position];
        if signal <= previous || signal > 64 || signal == 9 || signal == 19 {
            return false;
        }
        previous = signal;
        position += 1;
    }
    true
}
const _: () = assert!(reset_signals_hold());

// The worker (section 3.1 and the seam note's ChildPlan): uid and gid in 10000..=2147483647, and a classic BPF program
// of 1 to 4096 eight-byte instructions.
const WORKER_UID_MIN: u32 = 10_000;
const WORKER_UID_MAX: u32 = 2_147_483_647;
const BPF_INSTRUCTION_BYTES: usize = 8;
const BPF_MAX_INSTRUCTIONS: usize = 4_096;
/// The capability header's version (`_LINUX_CAPABILITY_VERSION_3`), whose data is two 32-bit sets.
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// fd_table's bound (seam note section 2): directory entries returned in total, "." and ".." included.
const FD_TABLE_ENTRIES: usize = 1_024;
const DIRENT_BUFFER: usize = 32_768;
/// `struct linux_dirent64`: `d_reclen` at 16, `d_name` at 19.
const DIRENT_RECLEN_OFFSET: usize = 16;
const DIRENT_NAME_OFFSET: usize = 19;

/// The kernel's struct stat as the vendored libc 0.2.190's musl b64 modules lay it out: st_dev and st_ino first on both
/// targets; st_mode after a 64-bit st_nlink on x86_64 and before a 32-bit one on aarch64 (the seam note's SM-R2-10).
#[allow(dead_code)] // both layouts are pinned and host-tested on every target
const X86_64_STAT: (usize, usize, usize) = (0, 8, 24);
#[allow(dead_code)] // both layouts are pinned and host-tested on every target
const AARCH64_STAT: (usize, usize, usize) = (0, 8, 16);
#[cfg(target_arch = "x86_64")]
const STAT: (usize, usize, usize) = X86_64_STAT;
#[cfg(target_arch = "aarch64")]
const STAT: (usize, usize, usize) = AARCH64_STAT;
/// Larger than both targets' struct stat (144 and 128 bytes).
const STAT_BYTES: usize = 256;

/// `siginfo_t` for SIGCHLD on 64-bit Linux: si_code at 8, si_pid at 16, si_status at 24; 128 bytes in all.
const SIGINFO_BYTES: usize = 128;
const SIGINFO_CODE_OFFSET: usize = 8;
const SIGINFO_PID_OFFSET: usize = 16;
const SIGINFO_STATUS_OFFSET: usize = 24;

// The child path's static values: every mask's address, the default action, the empty path and argv[0].
static ALL_SIGNALS: u64 = u64::MAX;
static NO_SIGNALS: u64 = 0;
/// SIG_DFL, no flags, no restorer, an empty mask: all zero, and as long as either target's kernel sigaction.
static DEFAULT_ACTION: [u64; 4] = [0; 4];
static EMPTY_PATH: [u8; 1] = [0];
/// argv is exactly ["planeon-worker"] and envp is exactly [] (seam note Q-SEAM-4 (a); readiness :103-104).
static WORKER_ARGV0: [u8; 15] = *b"planeon-worker\0";

/// The two leaf control files, the only names the opener admits (H5E-2).
const CGROUP_FREEZE: &[u8] = b"cgroup.freeze\0";
const CGROUP_KILL: &[u8] = b"cgroup.kill\0";

/// `struct clone_args`, through `cgroup`.
#[allow(dead_code)] // fields the kernel reads
#[derive(Default)]
#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// `struct __user_cap_header_struct`.
#[allow(dead_code)] // fields the kernel reads
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: c_int,
}

/// `struct __user_cap_data_struct`.
#[allow(dead_code)] // fields the kernel reads
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// `struct sock_fprog`: the instruction count and the instructions' address.
#[allow(dead_code)] // fields the kernel reads
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const u8,
}

/// `struct fsverity_digest` with room for a SHA-256 digest.
#[repr(C)]
struct VerityDigest {
    algorithm: u16,
    size: u16,
    digest: [u8; 32],
}

/// getdents64's buffer, 8-aligned.
#[repr(C, align(8))]
struct DirBuffer([u8; DIRENT_BUFFER]);

/// A struct stat, 8-aligned.
#[repr(C, align(8))]
struct StatBuffer([u8; STAT_BYTES]);

/// A siginfo_t, 8-aligned.
#[repr(C, align(8))]
struct SigInfo([u8; SIGINFO_BYTES]);

const _: () = assert!(size_of::<CloneArgs>() == CLONE_ARGS_BYTES as usize && align_of::<CloneArgs>() == 8);
const _: () = assert!(offset_of!(CloneArgs, pidfd) == 8 && offset_of!(CloneArgs, exit_signal) == 32);
const _: () = assert!(offset_of!(CloneArgs, cgroup) == 80);
const _: () = assert!(size_of::<CapHeader>() == 8 && size_of::<CapData>() == 12);
const _: () = assert!(size_of::<SockFprog>() == 16 && offset_of!(SockFprog, filter) == 8);
const _: () = assert!(size_of::<VerityDigest>() == 36 && align_of::<VerityDigest>() == 2);
const _: () = assert!(offset_of!(VerityDigest, size) == 2 && offset_of!(VerityDigest, digest) == 4);
const _: () = assert!(size_of::<DirBuffer>() == DIRENT_BUFFER && align_of::<DirBuffer>() == 8);
const _: () = assert!(size_of::<StatBuffer>() == STAT_BYTES && align_of::<StatBuffer>() == 8);
const _: () = assert!(size_of::<SigInfo>() == SIGINFO_BYTES && align_of::<SigInfo>() == 8);

/// The leaf's directory: the control opener's dirfd and clone3's CLONE_INTO_CGROUP target.
pub struct LeafDir {
    fd: OwnedFd,
}

/// The worker script, O_RDONLY, at a number of 5 or more: the one open file description from the measure to the exec.
pub struct Script {
    fd: OwnedFd,
}

/// One end of the I03 socketpair, at a number of 5 or more.
pub struct ChannelEnd {
    fd: OwnedFd,
}

/// The clone pidfd.
pub struct Pidfd {
    fd: OwnedFd,
}

/// The values the child path reads, built before clone3, held at a fixed heap address while clone3 runs.
#[repr(C)]
struct ChildData {
    clone_args: CloneArgs,
    pidfd: c_int,
    saved_mask: u64,
    cap_header: CapHeader,
    cap_data: [CapData; 2],
    program: SockFprog,
    argv: [*const u8; 2],
    envp: [*const u8; 1],
}

/// Everything the child path needs, computed in the parent before clone3 (section 3.5; the seam note's section 2).
pub struct ChildPlan {
    worker_uid: u32,
    data: Box<ChildData>,
    channel: ChannelEnd,
    script: Script,
}

/// A spawned worker. Once clone3 has returned a child, `spawn` returns this, never Err (SM-R1-5); a failed restore of
/// the parent's mask is `mask_restored: false`.
pub struct Child {
    pub pid: i32,
    pub pidfd: Pidfd,
    pub mask_restored: bool,
}

/// H5F-5's raw-call trait: the span is generic over it. `Kernel` is the production implementation (the pinned `syscall`
/// wrapper); the host tests' recording fake is the other.
trait RawCalls {
    fn call(&mut self, number: c_long, args: [c_long; 6]) -> c_long;
}

/// The span's values: numbers, sizes and addresses, every one computed in the parent before clone3.
struct ChildValues {
    all_signals: c_long,
    no_signals: c_long,
    saved_mask: c_long,
    default_action: c_long,
    clone_args: c_long,
    channel: c_long,
    script: c_long,
    worker_id: c_long,
    cap_header: c_long,
    cap_data: c_long,
    worker_program: c_long,
    empty_path: c_long,
    argv: c_long,
    envp: c_long,
}

impl ChildValues {
    fn of(plan: &mut ChildPlan) -> ChildValues {
        let channel = plan.channel.fd.as_raw_fd() as c_long;
        let script = plan.script.fd.as_raw_fd() as c_long;
        let worker_id = c_long::from(plan.worker_uid);
        let data = &mut *plan.data;
        ChildValues {
            all_signals: (&raw const ALL_SIGNALS) as c_long,
            no_signals: (&raw const NO_SIGNALS) as c_long,
            saved_mask: (&raw mut data.saved_mask) as c_long,
            default_action: (&raw const DEFAULT_ACTION) as c_long,
            clone_args: (&raw mut data.clone_args) as c_long,
            channel,
            script,
            worker_id,
            cap_header: (&raw mut data.cap_header) as c_long,
            cap_data: (&raw const data.cap_data) as c_long,
            worker_program: (&raw const data.program) as c_long,
            empty_path: (&raw const EMPTY_PATH) as c_long,
            argv: (&raw const data.argv) as c_long,
            envp: (&raw const data.envp) as c_long,
        }
    }
}

/// What the parent's side of the span ends with.
#[derive(Debug, PartialEq, Eq)]
enum Cloned {
    /// The all-ones block failed; clone3 was never called.
    NotBlocked,
    /// clone3 failed; the restore was attempted.
    Failed,
    /// clone3 returned a child.
    Parent { pid: c_long, restored: bool },
}

/// G-HE5C-1's pinned span, the parent's side (H5F-2, H5G-3): the all-ones block directly before clone3, clone3 into the
/// leaf with no namespace flag, the child path on its return-0 branch, and the restore directly after. A G-HE5C-9
/// marker.
#[inline(never)]
fn clone_span<R: RawCalls>(raw: &mut R, values: &ChildValues) -> Cloned {
    if raw.call(SYS_RT_SIGPROCMASK, [SIG_SETMASK, values.all_signals, values.saved_mask, SIGSET_BYTES, 0, 0]) < 0 {
        return Cloned::NotBlocked;
    }
    let pid = raw.call(SYS_CLONE3, [values.clone_args, CLONE_ARGS_BYTES, 0, 0, 0, 0]);
    if pid == 0 {
        child_path(raw, values);
    }
    let restored = raw.call(SYS_RT_SIGPROCMASK, [SIG_SETMASK, values.saved_mask, 0, SIGSET_BYTES, 0, 0]) >= 0;
    if pid < 0 {
        return Cloned::Failed;
    }
    Cloned::Parent { pid, restored }
}

/// The child's path from clone3 to execveat (section 3.5, steps 1-9): block every signal; reset every disposition but
/// SIGKILL's and SIGSTOP's; dup3 the channel to 3 and the script to 4; close_range from 5; unblock, directly before
/// setresgid; setresgid and setresuid to the signed uid; capset to empty; no_new_privs; the WORKER filter, no TSYNC;
/// execveat of fd 4; and exit_group(127) on any failure. A G-HE5C-9 marker.
#[inline(never)]
fn child_path<R: RawCalls>(raw: &mut R, values: &ChildValues) -> ! {
    'steps: {
        if raw.call(SYS_RT_SIGPROCMASK, [SIG_SETMASK, values.all_signals, 0, SIGSET_BYTES, 0, 0]) < 0 {
            break 'steps;
        }
        for signal in RESET_SIGNALS {
            if raw.call(SYS_RT_SIGACTION, [signal, values.default_action, 0, SIGSET_BYTES, 0, 0]) < 0 {
                break 'steps;
            }
        }
        if raw.call(SYS_DUP3, [values.channel, WORKER_CHANNEL_FD, 0, 0, 0, 0]) < 0 {
            break 'steps;
        }
        if raw.call(SYS_DUP3, [values.script, WORKER_SCRIPT_FD, 0, 0, 0, 0]) < 0 {
            break 'steps;
        }
        if raw.call(SYS_CLOSE_RANGE, [FIRST_FREE_FD, CLOSE_RANGE_LAST, 0, 0, 0, 0]) < 0 {
            break 'steps;
        }
        if raw.call(SYS_RT_SIGPROCMASK, [SIG_SETMASK, values.no_signals, 0, SIGSET_BYTES, 0, 0]) < 0 {
            break 'steps;
        }
        if raw.call(SYS_SETRESGID, [values.worker_id, values.worker_id, values.worker_id, 0, 0, 0]) < 0 {
            break 'steps;
        }
        if raw.call(SYS_SETRESUID, [values.worker_id, values.worker_id, values.worker_id, 0, 0, 0]) < 0 {
            break 'steps;
        }
        if raw.call(SYS_CAPSET, [values.cap_header, values.cap_data, 0, 0, 0, 0]) < 0 {
            break 'steps;
        }
        if raw.call(SYS_PRCTL, [PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0]) < 0 {
            break 'steps;
        }
        if raw.call(SYS_SECCOMP, [SECCOMP_SET_MODE_FILTER, 0, values.worker_program, 0, 0, 0]) < 0 {
            break 'steps;
        }
        raw.call(SYS_EXECVEAT, [WORKER_SCRIPT_FD, values.empty_path, values.argv, values.envp, AT_EMPTY_PATH, 0]);
    }
    loop {
        raw.call(SYS_EXIT_GROUP, [EXIT_STATUS, 0, 0, 0, 0, 0]);
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// ChildPlan::new's argument checks, before any call (seam note section 2).
fn plan_arguments(worker_uid: u32, worker_program: &[u8]) -> io::Result<()> {
    if !(WORKER_UID_MIN..=WORKER_UID_MAX).contains(&worker_uid) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "a worker uid outside 10000..=2147483647"));
    }
    let length = worker_program.len();
    if length == 0 || length % BPF_INSTRUCTION_BYTES != 0 || length > BPF_MAX_INSTRUCTIONS * BPF_INSTRUCTION_BYTES {
        let message = "a worker program of other than 1 to 4096 instructions";
        return Err(io::Error::new(io::ErrorKind::InvalidInput, message));
    }
    Ok(())
}

/// LeafDir::open's and fd_table's path argument, before any call: a NUL byte refuses.
fn path_argument(text: &str) -> io::Result<CString> {
    CString::new(text).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a path argument holding a NUL byte"))
}

/// A descriptor-table entry's name as its number: 1 to 10 ASCII digits that fit a u32.
fn decimal_name(name: &[u8]) -> Option<u32> {
    if name.is_empty() || name.len() > 10 {
        return None;
    }
    let mut value: u32 = 0;
    for &byte in name {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    Some(value)
}

/// The next `struct linux_dirent64` in `bytes` from `offset`: its name, without the NUL, and the next record's offset.
/// A record that runs past the buffer, is too short to hold a name, or holds no NUL is a reply of another shape.
fn next_dirent(bytes: &[u8], offset: usize) -> io::Result<Option<(&[u8], usize)>> {
    if offset == bytes.len() {
        return Ok(None);
    }
    let shape = || invalid("a getdents64 record of another shape");
    let length_at = offset.checked_add(DIRENT_RECLEN_OFFSET).ok_or_else(shape)?;
    let length_bytes = bytes.get(length_at..length_at + 2).ok_or_else(shape)?;
    let record = usize::from(u16::from_ne_bytes([length_bytes[0], length_bytes[1]]));
    let end = offset.checked_add(record).ok_or_else(shape)?;
    if record <= DIRENT_NAME_OFFSET || end > bytes.len() {
        return Err(shape());
    }
    let field = bytes.get(offset + DIRENT_NAME_OFFSET..end).ok_or_else(shape)?;
    let name_length = field.iter().position(|&byte| byte == 0).ok_or_else(shape)?;
    Ok(Some((&field[..name_length], end)))
}

fn read_u64(bytes: &[u8], at: usize) -> io::Result<u64> {
    let field = bytes.get(at..at + 8).ok_or_else(|| invalid("a kernel reply shorter than its layout"))?;
    let mut word = [0u8; 8];
    word.copy_from_slice(field);
    Ok(u64::from_ne_bytes(word))
}

fn read_u32(bytes: &[u8], at: usize) -> io::Result<u32> {
    let field = bytes.get(at..at + 4).ok_or_else(|| invalid("a kernel reply shorter than its layout"))?;
    let mut word = [0u8; 4];
    word.copy_from_slice(field);
    Ok(u32::from_ne_bytes(word))
}

/// (st_dev, st_ino, st_mode) at this target's pinned offsets.
fn stat_fields(bytes: &[u8]) -> io::Result<(u64, u64, u32)> {
    let (dev, ino, mode) = STAT;
    Ok((read_u64(bytes, dev)?, read_u64(bytes, ino)?, read_u32(bytes, mode)?))
}

/// A reaped worker's end from siginfo's si_code and si_status; any other code is a reply of another shape.
fn reaped(code: i32, status: i32) -> io::Result<Reaped> {
    match code {
        CLD_EXITED => Ok(Reaped::Exited(status)),
        CLD_KILLED => Ok(Reaped::Killed(status)),
        CLD_DUMPED => Ok(Reaped::Dumped(status)),
        _ => Err(invalid("waitid reported a code other than exited, killed or dumped")),
    }
}

/// The measure's reply: a digest of 32 bytes, else a reply of another shape.
fn verity_result(algorithm: u16, size: u16, digest: [u8; 32]) -> io::Result<(u16, [u8; 32])> {
    if size != VERITY_DIGEST_BYTES {
        return Err(invalid("the verity measure reported a digest size other than 32"));
    }
    Ok((algorithm, digest))
}

/// clock_nanosleep's request: whole seconds and the remaining nanoseconds.
fn timespec_of(ms: u32) -> [i64; 2] {
    [i64::from(ms / 1_000), i64::from(ms % 1_000) * 1_000_000]
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
}

/// The production raw-call implementation: the pinned `syscall` wrapper.
#[cfg(target_os = "linux")]
struct Kernel;

#[cfg(target_os = "linux")]
impl RawCalls for Kernel {
    #[inline(always)]
    fn call(&mut self, number: c_long, args: [c_long; 6]) -> c_long {
        let [first, second, third, fourth, fifth, sixth] = args;
        // SAFETY: `number` is one of this file's pinned numbers, and each argument is what that call's one site states:
        // a descriptor this process owns, a size, flags, or the address of memory laid out as the kernel reads (or
        // writes) it, which lives until the call returns (the statics, ChildData in its Box, or a local of the caller).
        // musl's `syscall` reads six `long` arguments, so the unused ones are zero.
        unsafe { syscall(number, first, second, third, fourth, fifth, sixth) }
    }
}

/// One call through `Kernel`, its -1 read as the errno it set.
#[cfg(target_os = "linux")]
fn sys(number: c_long, args: [c_long; 6]) -> io::Result<c_long> {
    let result = Kernel.call(number, args);
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result)
}

/// A descriptor the kernel has just returned.
#[cfg(target_os = "linux")]
fn owned(descriptor: c_long) -> OwnedFd {
    // SAFETY: `descriptor` was just returned by the kernel as a new descriptor of this process (openat, socketpair,
    // fcntl's duplicate, or clone3's pidfd, which the kernel writes whenever clone3 returns a child), so it is valid
    // and nothing else owns or will close it.
    unsafe { OwnedFd::from_raw_fd(descriptor as c_int) }
}

/// fcntl(F_DUPFD_CLOEXEC, 5), the original closed: the same open file description at a number of 5 or more.
#[cfg(target_os = "linux")]
fn move_to_five(fd: OwnedFd) -> io::Result<OwnedFd> {
    let moved = sys(SYS_FCNTL, [fd.as_raw_fd() as c_long, F_DUPFD_CLOEXEC, FIRST_FREE_FD, 0, 0, 0])?;
    Ok(owned(moved))
}

/// A source descriptor's number and (dev, ino): newfstatat(fd, "", AT_EMPTY_PATH).
#[cfg(target_os = "linux")]
fn identity(fd: &OwnedFd) -> io::Result<FdIdentity> {
    let mut stat = StatBuffer([0; STAT_BYTES]);
    let empty = EMPTY_PATH.as_ptr() as c_long;
    sys(SYS_NEWFSTATAT, [fd.as_raw_fd() as c_long, empty, (&raw mut stat) as c_long, AT_EMPTY_PATH, 0, 0])?;
    let (dev, ino, _) = stat_fields(&stat.0)?;
    Ok(FdIdentity { number: fd.as_raw_fd() as u32, dev, ino })
}

#[cfg(target_os = "linux")]
impl LeafDir {
    /// openat(AT_FDCWD, path, O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW). A NUL in `path` is InvalidInput.
    pub fn open(path: &str) -> io::Result<LeafDir> {
        let path = path_argument(path)?;
        let descriptor = sys(SYS_OPENAT, [AT_FDCWD, path.as_ptr() as c_long, LEAF_DIR_FLAGS, 0, 0, 0])?;
        Ok(LeafDir { fd: owned(descriptor) })
    }

    /// openat(leaf, name, O_WRONLY|O_CLOEXEC|O_NOFOLLOW) for exactly the two control files, then one write of exactly
    /// one byte, then close. A short write is InvalidData.
    pub fn write(&self, what: LeafWrite) -> io::Result<()> {
        let (name, byte): (&[u8], &[u8; 1]) = match what {
            LeafWrite::Freeze => (CGROUP_FREEZE, b"1"),
            LeafWrite::Thaw => (CGROUP_FREEZE, b"0"),
            LeafWrite::Kill => (CGROUP_KILL, b"1"),
        };
        let leaf = self.fd.as_raw_fd() as c_long;
        let control = owned(sys(SYS_OPENAT, [leaf, name.as_ptr() as c_long, CONTROL_FLAGS, 0, 0, 0])?);
        let written = sys(SYS_WRITE, [control.as_raw_fd() as c_long, byte.as_ptr() as c_long, 1, 0, 0, 0])?;
        if written != 1 {
            return Err(invalid("a short write to a leaf control file"));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Script {
    /// Moves an opened script (gate-sys Dir::file_ro's File) to a number of 5 or more, the original closed: the same
    /// open file description, never reopened (section 3.2).
    pub fn from_file(file: File) -> io::Result<Script> {
        Ok(Script { fd: move_to_five(OwnedFd::from(file))? })
    }
}

/// FS_IOC_MEASURE_VERITY on the script with a 32-byte digest buffer: (hash algorithm, digest). A reported size other
/// than 32 is InvalidData. G-HE5C-9's past-step-2 W5 marker, called once, from the lifecycle's W5 arm.
#[cfg(target_os = "linux")]
#[inline(never)]
pub fn measure_verity(script: &Script) -> io::Result<(u16, [u8; 32])> {
    let mut digest = VerityDigest { algorithm: 0, size: VERITY_DIGEST_BYTES, digest: [0; 32] };
    sys(SYS_IOCTL, [script.fd.as_raw_fd() as c_long, MEASURE_VERITY, (&raw mut digest) as c_long, 0, 0, 0])?;
    verity_result(digest.algorithm, digest.size, digest.digest)
}

/// socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0), each end moved to a number of 5 or more, the originals closed:
/// (parent end, child end).
#[cfg(target_os = "linux")]
pub fn seqpacket_pair() -> io::Result<(ChannelEnd, ChannelEnd)> {
    let mut ends: [c_int; 2] = [-1, -1];
    sys(SYS_SOCKETPAIR, [AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, (&raw mut ends) as c_long, 0, 0])?;
    let [first, second] = ends;
    let first = owned(c_long::from(first));
    let second = owned(c_long::from(second));
    let parent = ChannelEnd { fd: move_to_five(first)? };
    let child = ChannelEnd { fd: move_to_five(second)? };
    Ok((parent, child))
}

#[cfg(target_os = "linux")]
impl ChildPlan {
    /// Refuses (InvalidInput, before any call) a uid outside 10000..=2147483647 or a program of other than 1 to 4096
    /// eight-byte instructions; captures W3Expect (the two source numbers and their (dev, ino)); and builds the
    /// sock_fprog, the capability header and data, and the static argv and envp.
    pub fn new(worker_uid: u32, worker_program: &'static [u8], channel: ChannelEnd, script: Script)
        -> io::Result<(ChildPlan, W3Expect)> {
        plan_arguments(worker_uid, worker_program)?;
        let expect = W3Expect { channel: identity(&channel.fd)?, script: identity(&script.fd)? };
        let data = Box::new(ChildData {
            clone_args: CloneArgs::default(),
            pidfd: -1,
            saved_mask: 0,
            cap_header: CapHeader { version: CAPABILITY_VERSION_3, pid: 0 },
            cap_data: [CapData::default(); 2],
            program: SockFprog {
                len: (worker_program.len() / BPF_INSTRUCTION_BYTES) as u16,
                filter: worker_program.as_ptr(),
            },
            argv: [WORKER_ARGV0.as_ptr(), std::ptr::null()],
            envp: [std::ptr::null()],
        });
        Ok((ChildPlan { worker_uid, data, channel, script }, expect))
    }
}

/// W2 (section 3.5): fills clone_args (CLONE_PIDFD|CLONE_INTO_CGROUP into the leaf, SIGCHLD, no namespace flag), then
/// runs the span. Err only when no child exists: a failed block-all, or a failed clone3 after which the restore was
/// attempted. The parent's copies of the child's channel end and the script close when `spawn` returns.
#[cfg(target_os = "linux")]
pub fn spawn(leaf: &LeafDir, mut plan: ChildPlan) -> io::Result<Child> {
    let leaf_descriptor = leaf.fd.as_raw_fd();
    let data = &mut *plan.data;
    data.pidfd = -1;
    data.clone_args = CloneArgs {
        flags: CLONE_PIDFD | CLONE_INTO_CGROUP,
        pidfd: (&raw mut data.pidfd) as u64,
        exit_signal: SIGCHLD,
        cgroup: leaf_descriptor as u64,
        ..CloneArgs::default()
    };
    let values = ChildValues::of(&mut plan);
    match clone_span(&mut Kernel, &values) {
        Cloned::NotBlocked | Cloned::Failed => Err(io::Error::last_os_error()),
        Cloned::Parent { pid, restored } => Ok(Child {
            pid: pid as i32,
            pidfd: Pidfd { fd: owned(c_long::from(plan.data.pidfd)) },
            mask_restored: restored,
        }),
    }
}

/// W3's descriptor table (section 4.0 :422): the frozen child's descriptor directory, read to its end by getdents64,
/// with one link-following newfstatat per decimal entry. At most 1,024 entries in total, "." and ".." included; any
/// other non-decimal name is InvalidData. The order is the kernel's; the lifecycle sorts.
#[cfg(target_os = "linux")]
pub fn fd_table(pid: i32) -> io::Result<Vec<FdEntry>> {
    let path = path_argument(&format!("/proc/{}/fd", pid))?;
    let directory = owned(sys(SYS_OPENAT, [AT_FDCWD, path.as_ptr() as c_long, FD_DIR_FLAGS, 0, 0, 0])?);
    let mut buffer = DirBuffer([0; DIRENT_BUFFER]);
    let mut entries = Vec::new();
    let mut seen = 0;
    let dirfd = directory.as_raw_fd() as c_long;
    loop {
        let filled = sys(SYS_GETDENTS64, [dirfd, (&raw mut buffer) as c_long, DIRENT_BUFFER as c_long, 0, 0, 0])?;
        if filled == 0 {
            return Ok(entries);
        }
        let bytes = buffer.0.get(..filled as usize).ok_or_else(|| invalid("getdents64 reported more than its buffer"))?;
        let mut offset = 0;
        while let Some((name, next)) = next_dirent(bytes, offset)? {
            offset = next;
            seen += 1;
            if seen > FD_TABLE_ENTRIES {
                return Err(invalid("the child's descriptor table lists over 1024 entries"));
            }
            if name == b"." || name == b".." {
                continue;
            }
            let number =
                decimal_name(name).ok_or_else(|| invalid("a non-decimal entry in the child's descriptor table"))?;
            let name = CString::new(name).map_err(|_| invalid("a descriptor-table entry holding a NUL byte"))?;
            let mut stat = StatBuffer([0; STAT_BYTES]);
            sys(SYS_NEWFSTATAT, [dirfd, name.as_ptr() as c_long, (&raw mut stat) as c_long, 0, 0, 0])?;
            let (dev, ino, mode) = stat_fields(&stat.0)?;
            entries.push(FdEntry { number, dev, ino, mode });
        }
    }
}

/// W6: waitid(P_PIDFD, pidfd, &info, WEXITED|WNOHANG). Ok(None) means the worker has not yet exited.
#[cfg(target_os = "linux")]
pub fn reap(pidfd: &Pidfd) -> io::Result<Option<Reaped>> {
    let mut info = SigInfo([0; SIGINFO_BYTES]);
    sys(SYS_WAITID, [P_PIDFD, pidfd.fd.as_raw_fd() as c_long, (&raw mut info) as c_long, WEXITED | WNOHANG, 0, 0])?;
    if read_u32(&info.0, SIGINFO_PID_OFFSET)? == 0 {
        return Ok(None);
    }
    let code = read_u32(&info.0, SIGINFO_CODE_OFFSET)? as i32;
    let status = read_u32(&info.0, SIGINFO_STATUS_OFFSET)? as i32;
    reaped(code, status).map(Some)
}

/// One clock_nanosleep(CLOCK_MONOTONIC, 0, &{ms}, NULL). An early wake is an error, never a retry.
#[cfg(target_os = "linux")]
pub fn sleep_monotonic(ms: u32) -> io::Result<()> {
    let time = timespec_of(ms);
    sys(SYS_CLOCK_NANOSLEEP, [CLOCK_MONOTONIC, 0, (&raw const time) as c_long, 0, 0, 0])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::panic;

    use super::*;

    /// The recording fake (H5F-5): it records every call, answers clone3 as told, fails execveat, and ends the child
    /// path's exit_group by unwinding, so the test can read what was recorded.
    struct Recording {
        calls: Vec<(c_long, [c_long; 6])>,
        clone_answer: c_long,
    }

    impl RawCalls for Recording {
        fn call(&mut self, number: c_long, args: [c_long; 6]) -> c_long {
            self.calls.push((number, args));
            if number == SYS_EXIT_GROUP {
                panic!("exit_group");
            }
            if number == SYS_CLONE3 {
                return self.clone_answer;
            }
            if number == SYS_EXECVEAT {
                return -1;
            }
            0
        }
    }

    fn values() -> ChildValues {
        ChildValues {
            all_signals: 0x1000,
            no_signals: 0x1008,
            saved_mask: 0x2000,
            default_action: 0x3000,
            clone_args: 0x4000,
            channel: 7,
            script: 8,
            worker_id: 10_001,
            cap_header: 0x5000,
            cap_data: 0x5008,
            worker_program: 0x6000,
            empty_path: 0x7000,
            argv: 0x8000,
            envp: 0x9000,
        }
    }

    fn recording(clone_answer: c_long) -> Recording {
        Recording { calls: Vec::new(), clone_answer }
    }

    #[test]
    fn child_path_signal_order() {
        // The parent's side: the all-ones block before clone3, the restore after it.
        let mut parent = recording(4242);
        assert_eq!(clone_span(&mut parent, &values()), Cloned::Parent { pid: 4242, restored: true });
        let block = (SYS_RT_SIGPROCMASK, [SIG_SETMASK, 0x1000, 0x2000, SIGSET_BYTES, 0, 0]);
        let clone = (SYS_CLONE3, [0x4000, CLONE_ARGS_BYTES, 0, 0, 0, 0]);
        let restore = (SYS_RT_SIGPROCMASK, [SIG_SETMASK, 0x2000, 0, SIGSET_BYTES, 0, 0]);
        assert_eq!(parent.calls, vec![block, clone, restore]);

        // The child's side: block, reset (62 signals, never 9 or 19), dup3, dup3, close_range, unblock, setresgid, then
        // the rest, and exit_group(127) after the failed execveat.
        let mut child = recording(0);
        let ended = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            clone_span(&mut child, &values());
        }));
        assert!(ended.is_err());
        let mut expected = vec![block, clone, (SYS_RT_SIGPROCMASK, [SIG_SETMASK, 0x1000, 0, SIGSET_BYTES, 0, 0])];
        for signal in RESET_SIGNALS {
            expected.push((SYS_RT_SIGACTION, [signal, 0x3000, 0, SIGSET_BYTES, 0, 0]));
        }
        expected.extend([
            (SYS_DUP3, [7, 3, 0, 0, 0, 0]),
            (SYS_DUP3, [8, 4, 0, 0, 0, 0]),
            (SYS_CLOSE_RANGE, [5, 0xFFFF_FFFF, 0, 0, 0, 0]),
            (SYS_RT_SIGPROCMASK, [SIG_SETMASK, 0x1008, 0, SIGSET_BYTES, 0, 0]),
            (SYS_SETRESGID, [10_001, 10_001, 10_001, 0, 0, 0]),
            (SYS_SETRESUID, [10_001, 10_001, 10_001, 0, 0, 0]),
            (SYS_CAPSET, [0x5000, 0x5008, 0, 0, 0, 0]),
            (SYS_PRCTL, [38, 1, 0, 0, 0, 0]),
            (SYS_SECCOMP, [1, 0, 0x6000, 0, 0, 0]),
            (SYS_EXECVEAT, [4, 0x7000, 0x8000, 0x9000, 0x1000, 0]),
            (SYS_EXIT_GROUP, [127, 0, 0, 0, 0, 0]),
        ]);
        assert_eq!(child.calls, expected);
        let reset: Vec<c_long> =
            child.calls.iter().filter(|call| call.0 == SYS_RT_SIGACTION).map(|call| call.1[0]).collect();
        assert_eq!(reset.len(), 62);
        assert!(!reset.contains(&9) && !reset.contains(&19));
    }

    #[test]
    fn a_failed_clone_still_restores() {
        let mut parent = recording(-1);
        assert_eq!(clone_span(&mut parent, &values()), Cloned::Failed);
        let numbers: Vec<c_long> = parent.calls.iter().map(|call| call.0).collect();
        assert_eq!(numbers, vec![SYS_RT_SIGPROCMASK, SYS_CLONE3, SYS_RT_SIGPROCMASK]);
    }

    #[test]
    fn the_reset_signals_are_every_signal_but_kill_and_stop() {
        let expected: Vec<c_long> = (1..=64).filter(|signal| *signal != 9 && *signal != 19).collect();
        assert_eq!(RESET_SIGNALS.to_vec(), expected);
    }

    #[test]
    fn plan_arguments_refuse_before_any_call() {
        let program = [0u8; 8];
        assert_eq!(plan_arguments(9_999, &program).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(plan_arguments(10_000, &program).is_ok());
        assert!(plan_arguments(2_147_483_647, &program).is_ok());
        assert_eq!(plan_arguments(2_147_483_648, &program).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(plan_arguments(10_000, &[]).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(plan_arguments(10_000, &[0u8; 7]).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(plan_arguments(10_000, &[0u8; 4_096 * 8]).is_ok());
        assert_eq!(plan_arguments(10_000, &[0u8; 4_097 * 8]).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn a_path_argument_holding_a_nul_refuses() {
        assert_eq!(path_argument("a\0b").unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(path_argument("planeon").is_ok());
    }

    #[test]
    fn the_stat_offsets_are_pinned() {
        assert_eq!(X86_64_STAT, (0, 8, 24));
        assert_eq!(AARCH64_STAT, (0, 8, 16));
        #[cfg(target_arch = "x86_64")]
        assert_eq!(STAT, X86_64_STAT);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(STAT, AARCH64_STAT);
    }

    fn dirent(name: &[u8], record: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; usize::from(record)];
        bytes[16..18].copy_from_slice(&record.to_ne_bytes());
        bytes[19..19 + name.len()].copy_from_slice(name);
        bytes
    }

    #[test]
    fn dirent_records_parse_and_bad_shapes_refuse() {
        let mut buffer = dirent(b".", 24);
        buffer.extend(dirent(b"..", 24));
        buffer.extend(dirent(b"12", 24));
        assert_eq!(next_dirent(&buffer, 0).unwrap(), Some((&b"."[..], 24)));
        assert_eq!(next_dirent(&buffer, 24).unwrap(), Some((&b".."[..], 48)));
        assert_eq!(next_dirent(&buffer, 48).unwrap(), Some((&b"12"[..], 72)));
        assert_eq!(next_dirent(&buffer, 72).unwrap(), None);
        let truncated = dirent(b"3", 24);
        assert_eq!(next_dirent(&truncated[..20], 0).unwrap_err().kind(), io::ErrorKind::InvalidData);
        let mut unterminated = dirent(b"", 24);
        unterminated[19..24].copy_from_slice(b"12345");
        assert_eq!(next_dirent(&unterminated, 0).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn decimal_names() {
        assert_eq!(decimal_name(b"0"), Some(0));
        assert_eq!(decimal_name(b"12"), Some(12));
        assert_eq!(decimal_name(b"4294967295"), Some(u32::MAX));
        assert_eq!(decimal_name(b""), None);
        assert_eq!(decimal_name(b"1a"), None);
        assert_eq!(decimal_name(b"4294967296"), None);
        assert_eq!(decimal_name(b"12345678901"), None);
    }

    #[test]
    fn reaped_codes() {
        assert_eq!(reaped(1, 0).unwrap(), Reaped::Exited(0));
        assert_eq!(reaped(2, 9).unwrap(), Reaped::Killed(9));
        assert_eq!(reaped(3, 11).unwrap(), Reaped::Dumped(11));
        assert_eq!(reaped(4, 0).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn the_verity_reply_must_be_32_bytes() {
        assert_eq!(verity_result(1, 32, [7; 32]).unwrap(), (1, [7; 32]));
        assert_eq!(verity_result(2, 64, [0; 32]).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn timespecs() {
        assert_eq!(timespec_of(1_500), [1, 500_000_000]);
        assert_eq!(timespec_of(100), [0, 100_000_000]);
        assert_eq!(timespec_of(0), [0, 0]);
    }
}
