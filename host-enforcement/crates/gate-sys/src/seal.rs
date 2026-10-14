//! The process seal's raw calls (HE-002S DESIGN §2 and §6), Linux only: `prlimit`, `prctl`, `capget`, `capset`,
//! `getresuid`, `getresgid` and `syscall` (for `seccomp`, which musl does not wrap), each behind a safe function that
//! takes and returns plain values, and the read of the process's own status file through [`Dir::file_ro`]. The seal's
//! plan, its order and its checks are effect-gate's (`effect_gate::seal`); this module only marshals.
//!
//! The seven symbols are the ones the pinned musl 1.2.5 `libc.a` defines (it has no `prlimit64` or `seccomp` symbol;
//! `crates/effect-gate/MODEL_DEFINED.md`, HE-002S), and `tools/gate.py` checks that this file declares exactly them.
//! musl's `prctl` and `syscall` are variadic and read every further argument as a 64-bit value, so `prctl` always gets
//! exactly four `c_ulong` arguments and `syscall` six `c_long` or pointer arguments (design review round 3, D5). Every
//! `repr(C)` struct has compile-time size, alignment and offset asserts, which both musl release builds check.
#![allow(unsafe_code)]

use std::ffi::c_int;
use std::ffi::c_long;
use std::ffi::c_uint;
use std::ffi::c_ulong;
use std::ffi::c_ushort;
use std::io;
use std::io::Read;
use std::mem::offset_of;

use crate::openat::Dir;

/// `_LINUX_CAPABILITY_VERSION_3`: two data words, capabilities 0-31 in the first and 32-63 in the second.
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// `RLIMIT_CORE`, the generic value both x86_64 and aarch64 use.
const RLIMIT_CORE: c_int = 4;

// The prctl options `process_control` accepts (`linux/prctl.h`). None of them reads or writes memory through an
// argument: the arguments are capability numbers, flags and zeros.
const PR_CAPBSET_READ: c_int = 23;
const PR_CAPBSET_DROP: c_int = 24;
const PR_SET_NO_NEW_PRIVS: c_int = 38;
const PR_GET_NO_NEW_PRIVS: c_int = 39;
const PR_CAP_AMBIENT: c_int = 47;
const PR_CAP_AMBIENT_IS_SET: c_ulong = 1;
const PR_CAP_AMBIENT_CLEAR_ALL: c_ulong = 4;

/// The number musl's `SYS_seccomp` names for `seccomp(2)`.
#[cfg(target_arch = "x86_64")]
const SYS_SECCOMP: c_long = 317;
#[cfg(target_arch = "aarch64")]
const SYS_SECCOMP: c_long = 277;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("gate-sys pins the seccomp system call number for x86_64 and aarch64 only");

const SECCOMP_SET_MODE_FILTER: c_long = 1;
const SECCOMP_FILTER_FLAG_TSYNC: c_long = 1;

/// The longest classic-BPF program the kernel accepts (`BPF_MAXINSNS`), and the size of one instruction.
const BPF_MAXINSNS: usize = 4096;
const INSTRUCTION_BYTES: usize = 8;

/// The most bytes read from the status file (it is about 1.5 KiB).
const STATUS_LIMIT: usize = 64 * 1024;

/// `struct __user_cap_header_struct`.
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: c_int,
}

/// `struct __user_cap_data_struct`: one of the two version-3 data words.
#[repr(C)]
#[derive(Copy, Clone)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// `struct rlimit`; musl's `rlim_t` is 64 bits on both targets.
#[repr(C)]
struct Rlimit {
    cur: u64,
    max: u64,
}

/// `struct sock_fprog`: the instruction count and the instructions, passed as a byte pointer (the kernel copies
/// them; the `include_bytes!` data has alignment 1 and is never cast to a typed instruction slice).
#[repr(C)]
struct SockFprog {
    len: c_ushort,
    filter: *const u8,
}

const _: () = assert!(size_of::<CapHeader>() == 8 && align_of::<CapHeader>() == 4);
const _: () = assert!(offset_of!(CapHeader, version) == 0 && offset_of!(CapHeader, pid) == 4);
const _: () = assert!(size_of::<CapData>() == 12 && align_of::<CapData>() == 4);
const _: () = assert!(
    offset_of!(CapData, effective) == 0 && offset_of!(CapData, permitted) == 4 && offset_of!(CapData, inheritable) == 8
);
const _: () = assert!(size_of::<[CapData; 2]>() == 24);
const _: () = assert!(size_of::<Rlimit>() == 16 && align_of::<Rlimit>() == 8);
const _: () = assert!(offset_of!(Rlimit, cur) == 0 && offset_of!(Rlimit, max) == 8);
const _: () = assert!(size_of::<SockFprog>() == 16 && align_of::<SockFprog>() == 8);
const _: () = assert!(offset_of!(SockFprog, len) == 0 && offset_of!(SockFprog, filter) == 8);
const _: () = assert!(size_of::<c_ulong>() == 8 && size_of::<c_long>() == 8 && size_of::<c_uint>() == 4);

unsafe extern "C" {
    fn prlimit(pid: c_int, resource: c_int, new_limit: *const Rlimit, old_limit: *mut Rlimit) -> c_int;
    fn prctl(option: c_int, ...) -> c_int;
    fn capget(header: *mut CapHeader, data: *mut CapData) -> c_int;
    fn capset(header: *mut CapHeader, data: *const CapData) -> c_int;
    fn getresuid(ruid: *mut c_uint, euid: *mut c_uint, suid: *mut c_uint) -> c_int;
    fn getresgid(rgid: *mut c_uint, egid: *mut c_uint, sgid: *mut c_uint) -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
}

fn refusal(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// musl's convention for these wrappers: -1 and `errno` on failure.
fn checked(value: c_int) -> io::Result<c_int> {
    if value < 0 { Err(io::Error::last_os_error()) } else { Ok(value) }
}

/// The calling process's status file, read whole (at most 64 KiB) through [`Dir::at`] and [`Dir::file_ro`]: the
/// single-thread check's input (owner decision Q-HE2S-5 (a)). The directory open follows the `self` link; `O_NOFOLLOW`
/// applies to `status`.
pub fn own_status() -> io::Result<Vec<u8>> {
    let file = Dir::at("/proc/self")?.file_ro("status")?;
    let mut bytes = Vec::new();
    file.take(STATUS_LIMIT as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > STATUS_LIMIT {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "the status file is longer than 64 KiB"));
    }
    Ok(bytes)
}

/// `getresuid`: the real, effective and saved user ids.
pub fn user_ids() -> io::Result<[u32; 3]> {
    let mut ids: [c_uint; 3] = [c_uint::MAX; 3];
    let [real, effective, saved] = &mut ids;
    // SAFETY: the three pointers are distinct, live and writable `c_uint`s (musl's `uid_t`); getresuid writes one id
    // through each and reads nothing.
    checked(unsafe { getresuid(real, effective, saved) })?;
    Ok(ids)
}

/// `getresgid`: the real, effective and saved group ids.
pub fn group_ids() -> io::Result<[u32; 3]> {
    let mut ids: [c_uint; 3] = [c_uint::MAX; 3];
    let [real, effective, saved] = &mut ids;
    // SAFETY: the three pointers are distinct, live and writable `c_uint`s (musl's `gid_t`); getresgid writes one id
    // through each and reads nothing.
    checked(unsafe { getresgid(real, effective, saved) })?;
    Ok(ids)
}

/// `capget` of the calling thread (pid 0), version 3: per data word `[effective, permitted, inheritable]`.
pub fn read_capabilities() -> io::Result<[[u32; 3]; 2]> {
    let mut header = CapHeader { version: CAPABILITY_VERSION_3, pid: 0 };
    let mut data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];
    // SAFETY: `header` is a live, writable header of the kernel's layout (the kernel may write a version back into
    // it), and `data` points at two live, writable data words, the most version 3 writes; nothing else is read or
    // written through the pointers.
    checked(unsafe { capget(&mut header, data.as_mut_ptr()) })?;
    if header.version != CAPABILITY_VERSION_3 || header.pid != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "capget changed the version 3 header"));
    }
    Ok(data.map(|word| [word.effective, word.permitted, word.inheritable]))
}

/// `capset` of the calling thread (pid 0), version 3, from per data word `[effective, permitted, inheritable]`.
pub fn write_capabilities(words: [[u32; 3]; 2]) -> io::Result<()> {
    let mut header = CapHeader { version: CAPABILITY_VERSION_3, pid: 0 };
    let data = words.map(|[effective, permitted, inheritable]| CapData { effective, permitted, inheritable });
    // SAFETY: `header` is a live, writable header of the kernel's layout, and `data` points at two live data words,
    // which version 3 reads and does not write; nothing else is read or written through the pointers.
    checked(unsafe { capset(&mut header, data.as_ptr()) })?;
    Ok(())
}

/// `prctl(option, a, b, c, d)` for the five options the seal uses, always with exactly four further `c_ulong`
/// arguments: `PR_CAPBSET_READ`, `PR_CAPBSET_DROP`, `PR_SET_NO_NEW_PRIVS`, `PR_GET_NO_NEW_PRIVS`, and `PR_CAP_AMBIENT`
/// with `PR_CAP_AMBIENT_IS_SET` or `PR_CAP_AMBIENT_CLEAR_ALL`. Any other option or sub-option is refused before the
/// call (`InvalidInput`), so no argument is ever taken as a pointer. The kernel checks the rest (zeros, ranges).
pub fn process_control(option: c_int, arguments: [c_ulong; 4]) -> io::Result<c_int> {
    let accepted = match option {
        PR_CAPBSET_READ | PR_CAPBSET_DROP | PR_SET_NO_NEW_PRIVS | PR_GET_NO_NEW_PRIVS => true,
        PR_CAP_AMBIENT => matches!(arguments[0], PR_CAP_AMBIENT_IS_SET | PR_CAP_AMBIENT_CLEAR_ALL),
        _ => false,
    };
    if !accepted {
        return Err(refusal("a prctl option the seal does not use"));
    }
    let [a, b, c, d] = arguments;
    // SAFETY: the option is one of the five above, none of which reads or writes memory through its arguments, and
    // musl's prctl reads exactly four further `unsigned long` arguments, which are passed as `c_ulong`.
    checked(unsafe { prctl(option, a, b, c, d) })
}

/// `prlimit(0, RLIMIT_CORE, new, &old)`: sets the calling process's core limit to `new` (`[soft, hard]`) when given,
/// and returns the limit as it was before (with `None`, the current limit). musl's wrapper issues `prlimit64`.
pub fn core_limit(new: Option<[u64; 2]>) -> io::Result<[u64; 2]> {
    let new = new.map(|[cur, max]| Rlimit { cur, max });
    let new_pointer = new.as_ref().map_or(std::ptr::null(), |limit| limit as *const Rlimit);
    let mut old = Rlimit { cur: 0, max: 0 };
    // SAFETY: pid 0 is the calling process; `new_pointer` is null or points at a live `Rlimit` that is only read, and
    // `old` is a live, writable `Rlimit`; nothing else is read or written through the pointers.
    checked(unsafe { prlimit(0, RLIMIT_CORE, new_pointer, &mut old) })?;
    Ok([old.cur, old.max])
}

/// `syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog)`, with `program` as the
/// instructions and `length` their count, which must be 1 to 4096 and exactly `program`'s size in instructions
/// (`InvalidInput` otherwise, before the call). Returns the call's value: 0 when the filter is installed; with TSYNC
/// a positive value is the id of a thread that could not be synchronised (and nothing was installed). A -1 return is
/// the error.
pub fn install_filter(program: &[u8], length: c_ushort) -> io::Result<c_long> {
    let count = usize::from(length);
    if count == 0 || count > BPF_MAXINSNS || count.checked_mul(INSTRUCTION_BYTES) != Some(program.len()) {
        return Err(refusal("a filter program must be 1 to 4096 whole instructions of its stated count"));
    }
    let prog = SockFprog { len: length, filter: program.as_ptr() };
    let zero: c_long = 0;
    // SAFETY: `prog` is a live `sock_fprog` whose pointer addresses `program`, which holds exactly `length` eight-byte
    // instructions and outlives the call; the kernel copies the instructions and reads nothing else through the
    // pointers. musl's syscall reads six further `long` arguments, which are passed (the pointer is 64 bits wide).
    let value = unsafe {
        syscall(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog as *const SockFprog, zero, zero,
                zero)
    };
    if value == -1 { Err(io::Error::last_os_error()) } else { Ok(value) }
}
