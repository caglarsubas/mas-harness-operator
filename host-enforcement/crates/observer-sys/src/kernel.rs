//! The policy observer's raw kernel reads (HE-004D1 DESIGN-D1 section 4; owner decisions Q-HE4D1-4, -5 and -D1), Linux
//! only: the one file of observer-sys allowed to hold `unsafe` code, each call in its own block with its own
//! `// SAFETY:` argument (section 4.4's eight items) behind the safe API of section 4.5.
//!
//! **One foreign item.** `syscall` (gate-sys's precedent for `accept4` and `pidfd_open`), private, issuing exactly six
//! calls by number with the number and six further `long` arguments each (musl's `syscall` reads six, so unused ones are
//! the named zero): `openat`, `getdents64`, `readlinkat`, `fstatfs`, `ioctl` (only `FS_IOC_MEASURE_VERITY`) and `bpf`
//! (only commands 7, 15 and 16). The numbers are the v6.12 kernel's for both targets, as the vendored libc 0.2.190's
//! musl modules give them (`linux/musl/b64/x86_64/mod.rs` lines 425, 385, 435, 306, 184, 489 and
//! `linux/musl/b64/aarch64/mod.rs` lines 357, 362, 379, 345, 330, 565); any other target does not compile. Which call a
//! std or musl wrapper issues is not claimed here: the proof is a T04 trace (OBS-INV-1). std's `read`, `close` (a
//! descriptor's own release) and metadata on the descriptors this module owns are gate-sys's patterns.
//!
//! **Open flags.** gate-sys's per-target values (`openat.rs`): `O_RDONLY` 0, `O_DIRECTORY` 0o200000 / 0o40000,
//! `O_NOFOLLOW` 0o400000 / 0o100000, `O_CLOEXEC` 0o2000000, `O_NONBLOCK` 0o4000, `O_PATH` 0o10000000, `AT_FDCWD` -100.
//! Exactly four named sets, each asserted at compile time against the OBSERVER row's write-and-create mask 0x400643
//! (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, `O_APPEND`, `__O_TMPFILE`): `ROOT_PATH_FLAGS` (the cgroup2 root),
//! `DIR_FLAGS` (the proc root, a process, task or cgroup directory, every fresh listing), `READ_FLAGS` (proc, cgroup and
//! enrolled files, the seal marker) and `TARGET_FLAGS` (the `exe` magic link, followed, for its device and inode). No
//! call can open anything for writing (NP-3, G-D1-4).
//!
//! **Layouts.** `struct linux_dirent64` is `dirent`'s; `struct statfs` is musl's fifteen 8-byte words with `f_type` first
//! (`linux/musl/mod.rs` lines 352-365); the filesystem magic values `PROC_SUPER_MAGIC` 0x9fa0, `CGROUP2_SUPER_MAGIC`
//! 0x63677270 and `TMPFS_MAGIC` 0x01021994 are the vendored libc's (`linux_like/mod.rs` lines 1563, 1532, 1573). No
//! bpffs magic is held: the pin mount is not checked (D1-3), and `BPF_OBJ_GET` itself refuses a path that is not a bpffs
//! object. `FS_IOC_MEASURE_VERITY` is 0xC0046686, its reply a u16 algorithm, a u16 digest size and the digest, read with
//! a capacity of 32 (`NATIVE_QUALIFICATION_READINESS.md` lines 151-153; the OBSERVER row's argument).
//!
//! **BPF values cited by name (owner decision Q-HE4D1-D1 (c), 2026-10-18; no fetch, no vendoring; each a T04 check
//! item).** From the v6.12 kernel's UAPI header `linux/bpf.h` (whose sha256 native-profile v4 pins): the commands
//! `BPF_OBJ_GET` 7, `BPF_OBJ_GET_INFO_BY_FD` 15 and `BPF_PROG_QUERY` 16 (the schema's `inspection.bpfCommands`
//! constant); `BPF_F_RDONLY` (1 << 3, the object-get file flag), `BPF_F_ALLOW_OVERRIDE` (1 << 0) and `BPF_F_ALLOW_MULTI`
//! (1 << 1, attach flags), and `BPF_F_QUERY_EFFECTIVE` (1 << 0, a query flag; the readiness document's lines 187-189);
//! the three `union bpf_attr` layouts used (`BPF_OBJ_*`: `pathname`, `bpf_fd`, `file_flags`, `path_fd`; the info
//! command: `bpf_fd`, `info_len`, `info`; `BPF_PROG_QUERY`: `target_fd`, `attach_type`, `query_flags`, `attach_flags`,
//! `prog_ids`, `prog_cnt`, `prog_attach_flags`, `link_ids`, `link_attach_flags`, `revision`); `struct bpf_prog_info` (232
//! bytes, with `type` at 0, `id` at 4, `xlated_prog_len` at 20, `xlated_prog_insns` at 32, `nr_map_ids` at 52,
//! `map_ids` at 56 and `ifindex` at 80); and the numbers of `enum bpf_attach_type` for the seven containment hooks (2,
//! 8, 9, 10, 11, 14, 15) and the 22 census types of the model's `CENSUS_ATTACH_TYPES`. Compile-time asserts check what
//! can be checked without the header: the 29 attach-type numbers are distinct, each flag is a single bit and the two
//! attach flags differ (the query flag shares its value with `BPF_F_ALLOW_OVERRIDE` in another word, by the kernel's
//! definition). Any query error, EINVAL included, is an error and never an empty list. The residual, recorded in
//! MODEL_DEFINED R124: a value that is wrong but distinct and that the kernel accepts can make one census slot read
//! another attach type until T04 confirms each value.
//!
//! **Bounds refuse and never truncate (D1-4).** A listing opens a fresh descriptor (`openat` of `.` or `task` on a held
//! directory, so its offset starts at 0 and no seek is used), reads `getdents64` to the end into a 32 KiB buffer and
//! refuses the whole listing over its bound, on any error or on a malformed record buffer. A read past its limit, a
//! translated program over 64 KiB, more than 16 map ids or 64 query ids refuse too.
//!
//! No macro is defined; no type derives `Debug`, and each manual impl prints the type name only, never a descriptor.
#![allow(unsafe_code)]

use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::c_int;
use std::ffi::c_long;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::Read;
use std::mem::offset_of;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::fs::MetadataExt;

use crate::dirent;

#[cfg(target_arch = "x86_64")]
mod numbers {
    use std::ffi::c_long;

    pub const SYS_OPENAT: c_long = 257;
    pub const SYS_GETDENTS64: c_long = 217;
    pub const SYS_READLINKAT: c_long = 267;
    pub const SYS_FSTATFS: c_long = 138;
    pub const SYS_IOCTL: c_long = 16;
    pub const SYS_BPF: c_long = 321;
    pub const O_DIRECTORY: c_long = 0o200000;
    pub const O_NOFOLLOW: c_long = 0o400000;
}

#[cfg(target_arch = "aarch64")]
mod numbers {
    use std::ffi::c_long;

    pub const SYS_OPENAT: c_long = 56;
    pub const SYS_GETDENTS64: c_long = 61;
    pub const SYS_READLINKAT: c_long = 78;
    pub const SYS_FSTATFS: c_long = 44;
    pub const SYS_IOCTL: c_long = 29;
    pub const SYS_BPF: c_long = 280;
    pub const O_DIRECTORY: c_long = 0o40000;
    pub const O_NOFOLLOW: c_long = 0o100000;
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("observer-sys pins the system call numbers for linux x86_64 and aarch64 only");

use numbers::*;

const O_RDONLY: c_long = 0;
const O_CLOEXEC: c_long = 0o2000000;
const O_NONBLOCK: c_long = 0o4000;
const O_PATH: c_long = 0o10000000;
const AT_FDCWD: c_long = -100;
/// The unused `long` arguments of a call.
const ZERO: c_long = 0;

/// The cgroup2 root: a path handle only.
const ROOT_PATH_FLAGS: c_long = O_PATH | O_DIRECTORY | O_CLOEXEC;
/// The proc root, a process, task or cgroup directory, and every fresh listing.
const DIR_FLAGS: c_long = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW;
/// Proc, cgroup and enrolled files and the seal marker: read-only, never following a final link, never waiting.
const READ_FLAGS: c_long = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
/// The `exe` magic link, followed, for its device and inode only.
const TARGET_FLAGS: c_long = O_PATH | O_CLOEXEC;

const _: () = assert!(ROOT_PATH_FLAGS & 0x400643 == 0);
const _: () = assert!(DIR_FLAGS & 0x400643 == 0);
const _: () = assert!(READ_FLAGS & 0x400643 == 0);
const _: () = assert!(TARGET_FLAGS & 0x400643 == 0);

/// The proc root and the cgroup2 root (G-D1-5: the crate's two path literals).
const PROC_ROOT: &str = "/proc";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The filesystem magic values (vendored libc 0.2.190).
const PROC_SUPER_MAGIC: u64 = 0x9fa0;
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const TMPFS_MAGIC: u64 = 0x0102_1994;

/// The verity measurement request and its digest capacity.
const FS_IOC_MEASURE_VERITY: c_long = 0xC004_6686;
const VERITY_CAPACITY: u16 = 32;
const VERITY_SHA256: u16 = 1;

/// The three BPF commands (cited by name, v6.12 `linux/bpf.h`).
const BPF_OBJ_GET: c_long = 7;
const BPF_OBJ_GET_INFO_BY_FD: c_long = 15;
const BPF_PROG_QUERY: c_long = 16;
/// `BPF_OBJ_GET`'s read-only file flag.
const BPF_F_RDONLY: u32 = 1 << 3;
/// The attach flags a local query reports.
pub const BPF_F_ALLOW_OVERRIDE: u32 = 1 << 0;
pub const BPF_F_ALLOW_MULTI: u32 = 1 << 1;
/// The query flag of an effective query.
const BPF_F_QUERY_EFFECTIVE: u32 = 1 << 0;

const _: () = assert!(BPF_F_RDONLY.count_ones() == 1 && BPF_F_QUERY_EFFECTIVE.count_ones() == 1);
const _: () = assert!(BPF_F_ALLOW_OVERRIDE.count_ones() == 1 && BPF_F_ALLOW_MULTI.count_ones() == 1);
const _: () = assert!(BPF_F_ALLOW_OVERRIDE != BPF_F_ALLOW_MULTI);

/// The seven containment hooks' and the 22 census types' `enum bpf_attach_type` numbers (cited by name, v6.12
/// `linux/bpf.h`), in the model's orders (`HOOK_ATTACH_TYPES`, then `CENSUS_ATTACH_TYPES`).
pub const ATTACH_TYPES: [(&str, u32); 29] = [
    ("BPF_CGROUP_INET_SOCK_CREATE", 2),
    ("BPF_CGROUP_INET4_BIND", 8),
    ("BPF_CGROUP_INET6_BIND", 9),
    ("BPF_CGROUP_INET4_CONNECT", 10),
    ("BPF_CGROUP_INET6_CONNECT", 11),
    ("BPF_CGROUP_UDP4_SENDMSG", 14),
    ("BPF_CGROUP_UDP6_SENDMSG", 15),
    ("BPF_CGROUP_INET_INGRESS", 0),
    ("BPF_CGROUP_INET_EGRESS", 1),
    ("BPF_CGROUP_SOCK_OPS", 3),
    ("BPF_CGROUP_DEVICE", 6),
    ("BPF_CGROUP_UNIX_CONNECT", 49),
    ("BPF_CGROUP_INET4_POST_BIND", 12),
    ("BPF_CGROUP_INET6_POST_BIND", 13),
    ("BPF_CGROUP_UNIX_SENDMSG", 50),
    ("BPF_CGROUP_SYSCTL", 18),
    ("BPF_CGROUP_UDP4_RECVMSG", 19),
    ("BPF_CGROUP_UDP6_RECVMSG", 20),
    ("BPF_CGROUP_UNIX_RECVMSG", 51),
    ("BPF_CGROUP_GETSOCKOPT", 21),
    ("BPF_CGROUP_SETSOCKOPT", 22),
    ("BPF_CGROUP_INET4_GETPEERNAME", 29),
    ("BPF_CGROUP_INET6_GETPEERNAME", 30),
    ("BPF_CGROUP_UNIX_GETPEERNAME", 52),
    ("BPF_CGROUP_INET4_GETSOCKNAME", 31),
    ("BPF_CGROUP_INET6_GETSOCKNAME", 32),
    ("BPF_CGROUP_UNIX_GETSOCKNAME", 53),
    ("BPF_CGROUP_INET_SOCK_RELEASE", 34),
    ("BPF_LSM_CGROUP", 43),
];

/// Whether the 29 attach-type numbers are pairwise distinct.
const fn distinct_attach_types() -> bool {
    let mut left = 0;
    while left < ATTACH_TYPES.len() {
        let mut right = left + 1;
        while right < ATTACH_TYPES.len() {
            if ATTACH_TYPES[left].1 == ATTACH_TYPES[right].1 {
                return false;
            }
            right += 1;
        }
        left += 1;
    }
    true
}

const _: () = assert!(distinct_attach_types());

/// The attach-type number of a name of [`ATTACH_TYPES`].
pub fn attach_type(name: &str) -> Option<u32> {
    ATTACH_TYPES.iter().find(|(known, _)| *known == name).map(|(_, number)| *number)
}

/// The name of a local query's attach flags: exactly one of the two named flags, or `None`.
pub fn attach_flags_name(flags: u32) -> Option<&'static str> {
    match flags {
        BPF_F_ALLOW_OVERRIDE => Some("BPF_F_ALLOW_OVERRIDE"),
        BPF_F_ALLOW_MULTI => Some("BPF_F_ALLOW_MULTI"),
        _ => None,
    }
}

/// The run filesystem's type name for a magic value (R10's table: tmpfs only).
pub fn run_fs_type(magic: u64) -> Option<&'static str> {
    (magic == TMPFS_MAGIC).then_some("tmpfs")
}

/// The bounds of section 4.5 and 16.
pub const MAX_PROCESSES: usize = 65_536;
pub const MAX_CHILDREN: usize = 64;
const DIRENT_BUFFER: usize = 32_768;
const LINK_BUFFER: usize = 4_096;
const XLATED_BYTES: usize = 65_536;
const MAP_IDS: usize = 16;
const QUERY_IDS: usize = 64;
/// A relative cgroup path: 1 to 16 components, at most 4,096 bytes.
const MAX_COMPONENTS: usize = 16;
const MAX_REL_BYTES: usize = 4_096;

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
}

/// `getdents64`'s buffer: 32 KiB, 8-aligned (section 4.4 item 2).
#[repr(C, align(8))]
struct DirBuffer([u8; DIRENT_BUFFER]);

/// musl's 64-bit `struct statfs`: fifteen 8-byte words, `f_type` first.
#[allow(dead_code)] // fields the kernel reads or writes
#[repr(C)]
struct StatFs {
    words: [u64; 15],
}

/// The verity measurement reply: `struct fsverity_digest` with a 32-byte digest.
#[allow(dead_code)] // fields the kernel reads or writes
#[repr(C)]
struct VerityDigest {
    algorithm: u16,
    size: u16,
    digest: [u8; 32],
}

/// `union bpf_attr` for `BPF_OBJ_GET`.
#[allow(dead_code)] // fields the kernel reads or writes
#[repr(C, align(8))]
struct ObjGetAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
    path_fd: i32,
    pad: u32,
}

/// `union bpf_attr` for `BPF_OBJ_GET_INFO_BY_FD`.
#[allow(dead_code)] // fields the kernel reads or writes
#[repr(C, align(8))]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

/// `union bpf_attr` for `BPF_PROG_QUERY` (v6.12: with `link_ids`, `link_attach_flags` and `revision`).
#[allow(dead_code)] // fields the kernel reads or writes
#[repr(C, align(8))]
struct QueryAttr {
    target_fd: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    prog_ids: u64,
    prog_cnt: u32,
    pad: u32,
    prog_attach_flags: u64,
    link_ids: u64,
    link_attach_flags: u64,
    revision: u64,
}

/// v6.12's `struct bpf_prog_info` (232 bytes).
#[allow(dead_code)] // fields the kernel reads or writes
#[repr(C, align(8))]
struct ProgInfoRaw {
    kind: u32,
    id: u32,
    tag: [u8; 8],
    jited_prog_len: u32,
    xlated_prog_len: u32,
    jited_prog_insns: u64,
    xlated_prog_insns: u64,
    load_time: u64,
    created_by_uid: u32,
    nr_map_ids: u32,
    map_ids: u64,
    name: [u8; 16],
    ifindex: u32,
    gpl_compatible: u32,
    netns_dev: u64,
    netns_ino: u64,
    nr_jited_ksyms: u32,
    nr_jited_func_lens: u32,
    jited_ksyms: u64,
    jited_func_lens: u64,
    btf_id: u32,
    func_info_rec_size: u32,
    func_info: u64,
    nr_func_info: u32,
    nr_line_info: u32,
    line_info: u64,
    jited_line_info: u64,
    nr_jited_line_info: u32,
    line_info_rec_size: u32,
    jited_line_info_rec_size: u32,
    nr_prog_tags: u32,
    prog_tags: u64,
    run_time_ns: u64,
    run_cnt: u64,
    recursion_misses: u64,
    verified_insns: u32,
    attach_btf_obj_id: u32,
    attach_btf_id: u32,
    tail: u32,
}

const _: () = assert!(size_of::<DirBuffer>() == DIRENT_BUFFER && align_of::<DirBuffer>() == 8);
const _: () = assert!(size_of::<StatFs>() == 120 && align_of::<StatFs>() == 8);
const _: () = assert!(size_of::<VerityDigest>() == 36 && align_of::<VerityDigest>() == 2);
const _: () = assert!(offset_of!(VerityDigest, size) == 2 && offset_of!(VerityDigest, digest) == 4);
const _: () = assert!(size_of::<ObjGetAttr>() == 24 && align_of::<ObjGetAttr>() == 8);
const _: () = assert!(offset_of!(ObjGetAttr, bpf_fd) == 8 && offset_of!(ObjGetAttr, file_flags) == 12);
const _: () = assert!(offset_of!(ObjGetAttr, path_fd) == 16);
const _: () = assert!(size_of::<InfoAttr>() == 16 && offset_of!(InfoAttr, info_len) == 4 && offset_of!(InfoAttr, info) == 8);
const _: () = assert!(size_of::<QueryAttr>() == 64 && align_of::<QueryAttr>() == 8);
const _: () = assert!(offset_of!(QueryAttr, attach_type) == 4 && offset_of!(QueryAttr, query_flags) == 8);
const _: () = assert!(offset_of!(QueryAttr, attach_flags) == 12 && offset_of!(QueryAttr, prog_ids) == 16);
const _: () = assert!(offset_of!(QueryAttr, prog_cnt) == 24 && offset_of!(QueryAttr, prog_attach_flags) == 32);
const _: () = assert!(offset_of!(QueryAttr, link_ids) == 40 && offset_of!(QueryAttr, revision) == 56);
const _: () = assert!(size_of::<ProgInfoRaw>() == 232 && align_of::<ProgInfoRaw>() == 8);
const _: () = assert!(offset_of!(ProgInfoRaw, id) == 4 && offset_of!(ProgInfoRaw, xlated_prog_len) == 20);
const _: () = assert!(offset_of!(ProgInfoRaw, xlated_prog_insns) == 32 && offset_of!(ProgInfoRaw, nr_map_ids) == 52);
const _: () = assert!(offset_of!(ProgInfoRaw, map_ids) == 56 && offset_of!(ProgInfoRaw, ifindex) == 80);
const _: () = assert!(offset_of!(ProgInfoRaw, netns_dev) == 88 && offset_of!(ProgInfoRaw, btf_id) == 128);
const _: () = assert!(offset_of!(ProgInfoRaw, prog_tags) == 184 && offset_of!(ProgInfoRaw, attach_btf_id) == 224);
const _: () = assert!(size_of::<c_long>() == 8 && size_of::<c_int>() == 4 && size_of::<usize>() == 8);

fn refusal(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// A call's result as a count: a negative value is the OS's error (musl's `syscall` sets errno).
fn counted(value: c_long) -> io::Result<usize> {
    if value < 0 {
        return Err(io::Error::last_os_error());
    }
    usize::try_from(value).map_err(|_| refusal("a call returned a count past usize"))
}

/// A descriptor an `openat` or `bpf` call just returned, owned from here on (closed on every later path).
fn adopt(value: c_long) -> io::Result<File> {
    if value < 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor = c_int::try_from(value).map_err(|_| refusal("a call returned a descriptor past int"))?;
    // SAFETY: `descriptor` was returned by the successful call just made, is open, and nothing else owns it.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

/// A held descriptor as a call's `long` argument.
fn raw(handle: &File) -> c_long {
    c_long::from(handle.as_raw_fd())
}

/// One of the four named flag sets.
#[derive(Clone, Copy)]
enum Set {
    RootPath,
    Dir,
    Read,
    Target,
}

/// One `openat` with a named flag set: relative to a held directory, or to `AT_FDCWD` with an absolute path.
fn open_at(dirfd: c_long, path: &CStr, set: Set) -> io::Result<File> {
    let value = match set {
        // SAFETY (section 4.4 item 1): `path` is NUL-terminated and outlives the call; `dirfd` is a held descriptor or
        // AT_FDCWD with an absolute path; the flags are a named set without O_CREAT, so the mode slot is the zero; the
        // kernel reads only the path through a pointer.
        Set::RootPath => unsafe { syscall(SYS_OPENAT, dirfd, path.as_ptr(), ROOT_PATH_FLAGS, ZERO, ZERO, ZERO) },
        // SAFETY: as above (item 1), with DIR_FLAGS.
        Set::Dir => unsafe { syscall(SYS_OPENAT, dirfd, path.as_ptr(), DIR_FLAGS, ZERO, ZERO, ZERO) },
        // SAFETY: as above (item 1), with READ_FLAGS.
        Set::Read => unsafe { syscall(SYS_OPENAT, dirfd, path.as_ptr(), READ_FLAGS, ZERO, ZERO, ZERO) },
        // SAFETY: as above (item 1), with TARGET_FLAGS.
        Set::Target => unsafe { syscall(SYS_OPENAT, dirfd, path.as_ptr(), TARGET_FLAGS, ZERO, ZERO, ZERO) },
    };
    adopt(value)
}

/// One `fstatfs` on a held descriptor: the filesystem's magic.
fn magic(handle: &File) -> io::Result<u64> {
    let mut reply = StatFs { words: [0; 15] };
    // SAFETY (item 4): `reply` is a live, writable, zeroed `struct statfs` of the asserted 120 bytes, which is what
    // the kernel writes on both targets; the descriptor is held.
    let value = unsafe { syscall(SYS_FSTATFS, raw(handle), &raw mut reply, ZERO, ZERO, ZERO, ZERO) };
    counted(value)?;
    Ok(reply.words[0])
}

/// A fresh listing of `name` under the held directory `dir` (`.` or `task`): every record, read to the end, refused
/// past `bound` kept entries, on any error or on a malformed buffer. `keep` says which entries count.
fn listing(dir: &File, name: &CStr, bound: usize, keep: fn(u8, &str) -> bool) -> io::Result<Vec<String>> {
    let fresh = open_at(raw(dir), name, Set::Dir)?;
    let mut buffer = DirBuffer([0; DIRENT_BUFFER]);
    let mut kept = Vec::new();
    loop {
        let length = c_long::try_from(DIRENT_BUFFER).map_err(|_| refusal("the listing buffer's length"))?;
        // SAFETY (item 2): the descriptor is a fresh DIR_FLAGS directory held for the call; `buffer` is a live,
        // writable, 8-aligned 32 KiB array whose exact length is passed, so the kernel writes at most that many bytes.
        let value = unsafe { syscall(SYS_GETDENTS64, raw(&fresh), buffer.0.as_mut_ptr(), length, ZERO, ZERO, ZERO) };
        let count = counted(value)?;
        if count == 0 {
            break;
        }
        let records = buffer.0.get(..count).ok_or_else(|| refusal("getdents64 returned more than its buffer"))?;
        for (kind, entry) in dirent::entries(records).map_err(|_| refusal("a malformed directory record"))? {
            if keep(kind, &entry) {
                if kept.len() >= bound {
                    return Err(refusal("a listing over its bound"));
                }
                kept.push(entry);
            }
        }
    }
    Ok(kept)
}

/// A process or thread number: decimal digits without a leading zero, 1 to `i32::MAX`.
fn number(name: &str) -> Option<i32> {
    if name.is_empty() || name.starts_with('0') || !name.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    name.parse::<i32>().ok().filter(|value| *value >= 1)
}

fn numeric(_kind: u8, name: &str) -> bool {
    number(name).is_some()
}

fn directory(kind: u8, _name: &str) -> bool {
    kind == dirent::DT_DIR
}

fn numbers_of(names: Vec<String>) -> io::Result<Vec<i32>> {
    names.iter().map(|name| number(name).ok_or_else(|| refusal("a numeric entry changed"))).collect()
}

/// Reads `handle` to its end into a buffer one byte longer than `limit`: the bytes, refused when longer.
fn read_limited(mut handle: File, limit: usize) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; limit.saturating_add(1)];
    let mut filled = 0usize;
    loop {
        let Some(rest) = buffer.get_mut(filled..).filter(|rest| !rest.is_empty()) else {
            return Err(refusal("a read over its limit"));
        };
        match handle.read(rest) {
            Ok(0) => break,
            Ok(count) => filled = filled.saturating_add(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

/// One `readlinkat` of a held directory's link `name` into `buffer`: the count, refused when 0 or when it fills the
/// buffer (a possible truncation), as gate-sys refuses.
fn link_at(dir: &File, name: &CStr, buffer: &mut [u8]) -> io::Result<usize> {
    if buffer.is_empty() {
        return Err(refusal("a link buffer must hold at least one byte"));
    }
    let size = c_long::try_from(buffer.len()).map_err(|_| refusal("a link buffer's length"))?;
    // SAFETY (item 3): the directory is held; `name` is one of the six link constants, NUL-terminated and alive for
    // the call; `buffer` is live and writable and its length is passed, so the kernel writes at most that many bytes.
    let value = unsafe { syscall(SYS_READLINKAT, raw(dir), name.as_ptr(), buffer.as_mut_ptr(), size, ZERO, ZERO) };
    match counted(value)? {
        0 => Err(refusal("a link read back empty")),
        count if count < buffer.len() => Ok(count),
        _ => Err(refusal("a link filled its buffer and may be longer")),
    }
}

fn name(text: &'static str) -> io::Result<CString> {
    CString::new(text).map_err(|_| refusal("a name holds NUL"))
}

// ------------------------------------------------------------------------------------------------ the roots

/// The two roots, opened once after the seal: the proc root (`DIR_FLAGS`, procfs) and the cgroup2 root
/// (`ROOT_PATH_FLAGS`, cgroup2).
pub struct Roots {
    proc_root: File,
    cgroup_root: File,
}

impl fmt::Debug for Roots {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad("Roots")
    }
}

impl Roots {
    /// Opens both roots and checks their filesystem magic (not inlined, so its symbol survives LTO: G-D1-14).
    #[inline(never)]
    pub fn open() -> io::Result<Roots> {
        let proc_root = open_at(AT_FDCWD, &CString::new(PROC_ROOT).map_err(|_| refusal("root"))?, Set::Dir)?;
        if magic(&proc_root)? != PROC_SUPER_MAGIC {
            return Err(refusal("the proc root is not procfs"));
        }
        let cgroup_root = open_at(AT_FDCWD, &CString::new(CGROUP_ROOT).map_err(|_| refusal("root"))?, Set::RootPath)?;
        if magic(&cgroup_root)? != CGROUP2_SUPER_MAGIC {
            return Err(refusal("the cgroup root is not cgroup2"));
        }
        Ok(Roots { proc_root, cgroup_root })
    }

    /// The numeric names of a fresh listing of the proc root; more than 65,536 refuses.
    pub fn processes(&self) -> io::Result<Vec<i32>> {
        numbers_of(listing(&self.proc_root, &name(".")?, MAX_PROCESSES, numeric)?)
    }

    /// The process directory `<pid>` under the proc root, held while a capture reads it.
    pub fn process(&self, pid: i32) -> io::Result<ProcDir> {
        if pid < 1 {
            return Err(refusal("a process number must be at least 1"));
        }
        let path = CString::new(pid.to_string()).map_err(|_| refusal("a process number"))?;
        Ok(ProcDir { handle: open_at(raw(&self.proc_root), &path, Set::Dir)? })
    }

    /// The observer's own pid: one `readlinkat` of the proc root's `self` link, as a decimal number (R2-6).
    pub fn own_pid(&self) -> io::Result<i32> {
        let mut buffer = [0u8; 32];
        let count = link_at(&self.proc_root, &name("self")?, &mut buffer)?;
        let text = std::str::from_utf8(buffer.get(..count).unwrap_or_default()).map_err(|_| refusal("the self link"))?;
        number(text).ok_or_else(|| refusal("the self link is not a process number"))
    }

    /// The cgroup directory `rel` under the cgroup2 root (`DIR_FLAGS`).
    pub fn cgroup(&self, rel: &RelPath) -> io::Result<CgroupDir> {
        Ok(CgroupDir { handle: open_at(raw(&self.cgroup_root), &rel.path, Set::Dir)? })
    }
}

/// A relative cgroup path: 1 to 16 components of `[A-Za-z0-9_.+-]`, none `.` or `..`, at most 4,096 bytes (the
/// characters of native-profile v4's path pattern).
pub struct RelPath {
    path: CString,
}

impl fmt::Debug for RelPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad("RelPath")
    }
}

impl RelPath {
    pub fn new(text: &str) -> Option<RelPath> {
        let parts: Vec<&str> = text.split('/').collect();
        let good = |part: &&str| {
            !part.is_empty()
                && *part != "."
                && *part != ".."
                && part.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'+' | b'-'))
        };
        if text.len() > MAX_REL_BYTES || parts.len() > MAX_COMPONENTS || !parts.iter().all(good) {
            return None;
        }
        CString::new(text).ok().map(|path| RelPath { path })
    }
}

// ------------------------------------------------------------------------------------------------ processes

/// The closed set of process files a capture reads.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProcFile {
    Stat,
    Status,
    Cgroup,
    AttrCurrent,
    Maps,
}

impl ProcFile {
    fn name(self) -> &'static str {
        match self {
            ProcFile::Stat => "stat",
            ProcFile::Status => "status",
            ProcFile::Cgroup => "cgroup",
            ProcFile::AttrCurrent => "attr/current",
            ProcFile::Maps => "maps",
        }
    }
}

/// The closed set of process links a capture reads (G-D1-7).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProcLink {
    Exe,
    NsUser,
    NsMnt,
    NsPid,
    NsNet,
}

impl ProcLink {
    fn name(self) -> &'static str {
        match self {
            ProcLink::Exe => "exe",
            ProcLink::NsUser => "ns/user",
            ProcLink::NsMnt => "ns/mnt",
            ProcLink::NsPid => "ns/pid",
            ProcLink::NsNet => "ns/net",
        }
    }
}

/// A process (or thread) directory, held: after its process exits, reads through it fail and never reach a process
/// that reused the number.
pub struct ProcDir {
    handle: File,
}

impl fmt::Debug for ProcDir {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad("ProcDir")
    }
}

impl ProcDir {
    /// One process file, read whole; more than `limit` bytes refuses.
    pub fn read(&self, which: ProcFile, limit: usize) -> io::Result<Vec<u8>> {
        read_limited(open_at(raw(&self.handle), &name(which.name())?, Set::Read)?, limit)
    }

    /// The numeric names of a fresh listing of the `task` directory; more than `bound` refuses.
    pub fn tasks(&self, bound: usize) -> io::Result<Vec<i32>> {
        numbers_of(listing(&self.handle, &name("task")?, bound, numeric)?)
    }

    /// The thread directory `task/<tid>`, held.
    pub fn task(&self, tid: i32) -> io::Result<ProcDir> {
        if tid < 1 {
            return Err(refusal("a thread number must be at least 1"));
        }
        let path = CString::new(format!("task/{tid}")).map_err(|_| refusal("a thread number"))?;
        Ok(ProcDir { handle: open_at(raw(&self.handle), &path, Set::Dir)? })
    }

    /// One link's text into `buffer` (at most 4 KiB is ever needed): the count.
    pub fn link_text(&self, which: ProcLink, buffer: &mut [u8]) -> io::Result<usize> {
        let limit = buffer.len().min(LINK_BUFFER);
        let buffer = buffer.get_mut(..limit).ok_or_else(|| refusal("a link buffer"))?;
        link_at(&self.handle, &name(which.name())?, buffer)
    }

    /// The running image's device and inode: `exe` opened with `TARGET_FLAGS`, which follows the magic link.
    pub fn target_identity(&self) -> io::Result<(u64, u64)> {
        let target = open_at(raw(&self.handle), &name("exe")?, Set::Target)?;
        let facts = target.metadata()?;
        Ok((facts.dev(), facts.ino()))
    }
}

// ------------------------------------------------------------------------------------------------ cgroups

/// The closed set of cgroup files a capture reads (G-D1-4: seven names, no write target among them).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CgroupFile {
    Procs,
    Events,
    Stat,
    MemoryMax,
    PidsMax,
    PidsCurrent,
    CpuMax,
}

impl CgroupFile {
    fn name(self) -> &'static str {
        match self {
            CgroupFile::Procs => "cgroup.procs",
            CgroupFile::Events => "cgroup.events",
            CgroupFile::Stat => "cgroup.stat",
            CgroupFile::MemoryMax => "memory.max",
            CgroupFile::PidsMax => "pids.max",
            CgroupFile::PidsCurrent => "pids.current",
            CgroupFile::CpuMax => "cpu.max",
        }
    }
}

/// A cgroup directory, held (`DIR_FLAGS`).
pub struct CgroupDir {
    handle: File,
}

impl fmt::Debug for CgroupDir {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad("CgroupDir")
    }
}

impl CgroupDir {
    /// One cgroup file, read whole; more than `limit` bytes refuses.
    pub fn read(&self, which: CgroupFile, limit: usize) -> io::Result<Vec<u8>> {
        read_limited(open_at(raw(&self.handle), &name(which.name())?, Set::Read)?, limit)
    }

    /// The child cgroups (`DT_DIR` names) of a fresh listing; more than 64 refuses.
    pub fn children(&self) -> io::Result<Vec<String>> {
        listing(&self.handle, &name(".")?, MAX_CHILDREN, directory)
    }

    /// The directory's inode.
    pub fn inode(&self) -> io::Result<u64> {
        Ok(self.handle.metadata()?.ino())
    }

    /// One `BPF_PROG_QUERY` of `attach_type` on this cgroup, local or effective: the program ids and the attach flags
    /// word. Any error (EINVAL, ENOSPC, EPERM or another) is returned and is never an empty list.
    pub fn prog_query(&self, attach_type: u32, effective: bool) -> io::Result<(Vec<u32>, u32)> {
        let target_fd = u32::try_from(self.handle.as_raw_fd()).map_err(|_| refusal("a cgroup descriptor"))?;
        let mut ids = [0u32; QUERY_IDS];
        let capacity = u32::try_from(QUERY_IDS).map_err(|_| refusal("the query capacity"))?;
        let mut attr = QueryAttr {
            target_fd,
            attach_type,
            query_flags: if effective { BPF_F_QUERY_EFFECTIVE } else { 0 },
            attach_flags: 0,
            prog_ids: ids.as_mut_ptr() as u64,
            prog_cnt: capacity,
            pad: 0,
            prog_attach_flags: 0,
            link_ids: 0,
            link_attach_flags: 0,
            revision: 0,
        };
        let size = c_long::try_from(size_of::<QueryAttr>()).map_err(|_| refusal("the query size"))?;
        // SAFETY (item 8): `attr` is a live, 8-aligned v6.12 query layout whose exact size is passed; `target_fd` is
        // this held cgroup directory; `prog_ids` points to the live, writable `[u32; 64]` and `prog_cnt` is 64; the
        // per-program flag and link arrays are null, so the kernel writes only `ids` and the attribute's outputs.
        let value = unsafe { syscall(SYS_BPF, BPF_PROG_QUERY, &raw mut attr, size, ZERO, ZERO, ZERO) };
        counted(value)?;
        let count = usize::try_from(attr.prog_cnt).map_err(|_| refusal("a query count"))?;
        let found = ids.get(..count).ok_or_else(|| refusal("a query count over 64"))?;
        Ok((found.to_vec(), attr.attach_flags))
    }
}

// ------------------------------------------------------------------------------------------------ pinned programs

/// A pinned program opened read-only.
pub struct ProgFd {
    handle: File,
}

impl fmt::Debug for ProgFd {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad("ProgFd")
    }
}

/// What `BPF_OBJ_GET_INFO_BY_FD` reports of a program.
pub struct ProgInfo {
    pub id: u32,
    pub kind: u32,
    /// The translated instructions, exactly `xlated_prog_len` bytes (at most 64 KiB).
    pub xlated: Vec<u8>,
    pub map_ids: Vec<u32>,
    pub ifindex: u32,
}

impl fmt::Debug for ProgInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad("ProgInfo")
    }
}

/// Opens the program pinned at the absolute `path` read-only (`BPF_OBJ_GET`, `BPF_F_RDONLY`).
pub fn open_pinned(path: &CStr) -> io::Result<ProgFd> {
    if path.to_bytes().first() != Some(&b'/') {
        return Err(refusal("a pin is named by an absolute path"));
    }
    let mut attr = ObjGetAttr { pathname: path.as_ptr() as u64, bpf_fd: 0, file_flags: BPF_F_RDONLY, path_fd: 0, pad: 0 };
    let size = c_long::try_from(size_of::<ObjGetAttr>()).map_err(|_| refusal("the attribute size"))?;
    // SAFETY (item 6): `attr` is live, zeroed apart from its inputs and 8-aligned; `pathname` is the address of `path`,
    // NUL-terminated and alive for the call; `file_flags` is BPF_F_RDONLY; the exact size of the command's layout is
    // passed. A non-negative result is a new descriptor, adopted at once.
    let value = unsafe { syscall(SYS_BPF, BPF_OBJ_GET, &raw mut attr, size, ZERO, ZERO, ZERO) };
    Ok(ProgFd { handle: adopt(value)? })
}

impl ProgFd {
    /// The program's id, type, translated instructions, map ids and ifindex; a program over 64 KiB, more than 16 map
    /// ids or an over-long reply refuses.
    pub fn info(&self) -> io::Result<ProgInfo> {
        let mut insns = vec![0u64; XLATED_BYTES / 8];
        let mut map_ids = [0u32; MAP_IDS];
        let mut info = ProgInfoRaw {
            kind: 0, id: 0, tag: [0; 8], jited_prog_len: 0, xlated_prog_len: 0, jited_prog_insns: 0, xlated_prog_insns: 0,
            load_time: 0, created_by_uid: 0, nr_map_ids: 0, map_ids: 0, name: [0; 16], ifindex: 0, gpl_compatible: 0,
            netns_dev: 0, netns_ino: 0, nr_jited_ksyms: 0, nr_jited_func_lens: 0, jited_ksyms: 0, jited_func_lens: 0,
            btf_id: 0, func_info_rec_size: 0, func_info: 0, nr_func_info: 0, nr_line_info: 0, line_info: 0,
            jited_line_info: 0, nr_jited_line_info: 0, line_info_rec_size: 0, jited_line_info_rec_size: 0, nr_prog_tags: 0,
            prog_tags: 0, run_time_ns: 0, run_cnt: 0, recursion_misses: 0, verified_insns: 0, attach_btf_obj_id: 0,
            attach_btf_id: 0, tail: 0,
        };
        info.xlated_prog_len = u32::try_from(XLATED_BYTES).map_err(|_| refusal("the program buffer"))?;
        info.xlated_prog_insns = insns.as_mut_ptr() as u64;
        info.nr_map_ids = u32::try_from(MAP_IDS).map_err(|_| refusal("the map buffer"))?;
        info.map_ids = map_ids.as_mut_ptr() as u64;
        let given = u32::try_from(size_of::<ProgInfoRaw>()).map_err(|_| refusal("the info size"))?;
        let bpf_fd = u32::try_from(self.handle.as_raw_fd()).map_err(|_| refusal("a program descriptor"))?;
        let mut attr = InfoAttr { bpf_fd, info_len: given, info: (&raw mut info) as u64 };
        let size = c_long::try_from(size_of::<InfoAttr>()).map_err(|_| refusal("the attribute size"))?;
        // SAFETY (item 7): `attr` is live and names this held program descriptor and `info`, a live, zeroed v6.12
        // `bpf_prog_info` of the size passed in `info_len`; its `xlated_prog_insns` points to the live, writable,
        // 8-aligned 64 KiB `insns` with `xlated_prog_len` 65,536 and its `map_ids` to the live `[u32; 16]` with
        // `nr_map_ids` 16; every other pointer is null with length 0, so the kernel copies nothing else.
        let value = unsafe { syscall(SYS_BPF, BPF_OBJ_GET_INFO_BY_FD, &raw mut attr, size, ZERO, ZERO, ZERO) };
        counted(value)?;
        if attr.info_len > given {
            return Err(refusal("an info reply longer than its buffer"));
        }
        let length = usize::try_from(info.xlated_prog_len).map_err(|_| refusal("a program length"))?;
        if length > XLATED_BYTES {
            return Err(refusal("a translated program over 64 KiB"));
        }
        let count = usize::try_from(info.nr_map_ids).map_err(|_| refusal("a map count"))?;
        let maps = map_ids.get(..count).ok_or_else(|| refusal("more than 16 map ids"))?.to_vec();
        let mut xlated: Vec<u8> = insns.iter().flat_map(|word| word.to_ne_bytes()).collect();
        xlated.truncate(length);
        Ok(ProgInfo { id: info.id, kind: info.kind, xlated, map_ids: maps, ifindex: info.ifindex })
    }
}

// ------------------------------------------------------------------------------------------------ enrolled files

/// The facts `fstat` gives of an opened enrolled file; `mode` is `st_mode & 0o7777` (D1-5).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Facts {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub mode: u32,
    pub size: u64,
    pub ctime: i64,
    pub ctime_nsec: i64,
}

impl fmt::Debug for Facts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad("Facts")
    }
}

/// An enrolled file (or the seal marker) opened read-only by absolute path, never following a final link, checked to
/// be a regular file (the type, apart from the mode: D1-5).
pub struct Opened {
    handle: File,
}

impl fmt::Debug for Opened {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad("Opened")
    }
}

impl Opened {
    pub fn open(path: &CStr) -> io::Result<Opened> {
        if path.to_bytes().first() != Some(&b'/') {
            return Err(refusal("an enrolled file is named by an absolute path"));
        }
        let handle = open_at(AT_FDCWD, path, Set::Read)?;
        if !handle.metadata()?.file_type().is_file() {
            return Err(refusal("an enrolled name is not a regular file"));
        }
        Ok(Opened { handle })
    }

    pub fn facts(&self) -> io::Result<Facts> {
        let facts = self.handle.metadata()?;
        Ok(Facts {
            device: facts.dev(),
            inode: facts.ino(),
            uid: facts.uid(),
            gid: facts.gid(),
            nlink: facts.nlink(),
            mode: facts.mode() & 0o7777,
            size: facts.size(),
            ctime: facts.ctime(),
            ctime_nsec: facts.ctime_nsec(),
        })
    }

    /// The verity measurement: algorithm 1 (SHA-256) and a 32-byte digest, or refused.
    pub fn verity(&self) -> io::Result<[u8; 32]> {
        let mut reply = VerityDigest { algorithm: 0, size: VERITY_CAPACITY, digest: [0; 32] };
        // SAFETY (item 5): the argument points to the live, writable 36-byte reply whose size field is its capacity,
        // 32; the kernel writes at most 4 + 32 bytes and fails with EOVERFLOW if the capacity is short; the request is
        // passed as the positive `long` 0xC0046686, the OBSERVER row's one allowed value.
        let value = unsafe { syscall(SYS_IOCTL, raw(&self.handle), FS_IOC_MEASURE_VERITY, &raw mut reply, ZERO, ZERO, ZERO) };
        counted(value)?;
        if reply.algorithm != VERITY_SHA256 || reply.size != VERITY_CAPACITY {
            return Err(refusal("a verity measurement other than SHA-256"));
        }
        Ok(reply.digest)
    }

    /// The filesystem magic of the opened file (the seal marker's run filesystem).
    pub fn fs_magic(&self) -> io::Result<u64> {
        magic(&self.handle)
    }

    /// One plain `read` into `buffer` (the portable hashing loop's one primitive).
    pub fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.handle.read(buffer)
    }
}
