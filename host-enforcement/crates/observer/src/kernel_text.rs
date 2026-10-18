//! Portable parsers of the kernel text the captures read (HE-004D1 DESIGN-D1 section 8; MODEL_DEFINED R125). A logic
//! module: pure, no panic, host-tested in `tests/observer_kernel_text.rs`. Every parser refuses (`None`) rather than
//! guesses: numbers are decimal without a sign and within their bounds, duplicate keys refuse, and nothing is truncated.
//!
//! - `stat` (a process or thread): the pid before ` (`, and after the last `)` field 4 (`ppid`) and field 22 (the start
//!   time in clock ticks), so a `comm` holding spaces or parentheses cannot shift a field.
//! - `status`: `Uid` and `Gid` (all four values equal), `NoNewPrivs`, `Seccomp`, `Seccomp_filters`, `Threads` and the five
//!   capability masks (16 hex digits; a bit above 40, `CAP_LAST_CAP`, refuses), decoded into the schema's names.
//! - `cgroup`: exactly one line `0::/<path>`; `attr/current`: the label without its trailing NUL and newline.
//! - `maps`: per line the range, permissions, offset, `MM:mm` device (encoded as musl's `makedev`, so it compares with
//!   `fstat`'s `st_dev`), inode and path; executable lines are kept, `[vdso]` and `[vsyscall]` skipped, and any other
//!   executable line without an absolute path refuses.
//! - The namespace links (`<kind>:[<inode>]`), the `exe` link (a ` (deleted)` suffix refuses), `cgroup.events`
//!   (`populated`, `frozen`), `cgroup.stat` (`nr_descendants`), the limits (`memory.max`, `pids.max`, `pids.current`,
//!   `cpu.max` as quota and period; `max` refuses), the verity reply (algorithm 1, size 32), the mode (always `%04o` of
//!   `st_mode & 0o7777`, so setuid, setgid and sticky bits show, D1-5), canonical UTC seconds and milliseconds, and the
//!   call count of a translated program (D1-10): instructions with opcode 0x85 (`BPF_JMP|BPF_CALL`) whose source
//!   register is 0 (a helper) or 2 (a kfunc) are counted, 1 (a bpf-to-bpf call) is not, and any other refuses.
//!
//! The capability names are v6.12's `linux/capability.h` bits 0 to 40, cited by name (owner decision Q-HE4D1-D1 (c);
//! each a T04 check item). The table is indexed by bit, so each bit has exactly one name by the array's type, and a
//! compile-time check below proves the 41 names distinct; `CAP_NET_ADMIN` (12) and `CAP_BPF` (39) agree with the seal's
//! constants, which the host tests pin.

use std::collections::BTreeMap;

/// The highest capability bit (`CAP_LAST_CAP`).
pub const CAP_LAST_CAP: u32 = 40;

/// The capability names by bit, 0 to 40 (v6.12 `linux/capability.h`).
pub const CAPABILITY_NAMES: [&str; 41] = [
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID",
    "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN",
    "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ",
    "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE",
];

/// Whether two names are the same bytes (a compile-time comparison).
const fn same(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Whether the 41 capability names are pairwise distinct.
const fn distinct_names() -> bool {
    let mut left = 0;
    while left < CAPABILITY_NAMES.len() {
        let mut right = left + 1;
        while right < CAPABILITY_NAMES.len() {
            if same(CAPABILITY_NAMES[left], CAPABILITY_NAMES[right]) {
                return false;
            }
            right += 1;
        }
        left += 1;
    }
    true
}

/// A compile-time proof that the names are distinct: the array's length is 1 only when they are.
const _: [(); 1] = [(); distinct_names() as usize];

/// A decimal number without a sign or a leading zero (except `0` itself).
pub fn decimal(text: &str) -> Option<u64> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if text.len() > 1 && text.starts_with('0') {
        return None;
    }
    text.parse::<u64>().ok()
}

/// A process or thread number, 1 to `i32::MAX`.
pub fn pid(text: &str) -> Option<i32> {
    decimal(text).and_then(|value| i32::try_from(value).ok()).filter(|value| *value >= 1)
}

/// What `stat` gives: the pid, the parent's pid and the start time in clock ticks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub pid: i32,
    pub ppid: i32,
    pub start_ticks: u64,
}

/// Parses `/<pid>/stat` or a thread's: `pid (comm) state ppid ... starttime ...`.
pub fn stat(text: &[u8]) -> Option<Stat> {
    let text = std::str::from_utf8(text).ok()?;
    let (head, _) = text.split_once(" (")?;
    let close = text.rfind(')')?;
    let rest = text.get(close.checked_add(1)?..)?;
    let fields: Vec<&str> = rest.split_ascii_whitespace().collect();
    // After the comm: field 3 (state) is fields[0], field 4 (ppid) fields[1], field 22 (starttime) fields[19].
    let ppid = decimal(fields.get(1)?).and_then(|value| i32::try_from(value).ok())?;
    let start_ticks = decimal(fields.get(19)?)?;
    Some(Stat { pid: pid(head)?, ppid, start_ticks })
}

/// The `status` fields a capture reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub uid: u64,
    pub gid: u64,
    pub no_new_privs: u64,
    pub seccomp_mode: u64,
    pub seccomp_filters: u64,
    pub threads: u64,
    pub inheritable: u64,
    pub permitted: u64,
    pub effective: u64,
    pub bounding: u64,
    pub ambient: u64,
}

/// A capability mask: 16 lowercase or uppercase hex digits, no bit above 40.
pub fn capability_mask(text: &str) -> Option<u64> {
    if text.len() != 16 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mask = u64::from_str_radix(text, 16).ok()?;
    (mask >> (CAP_LAST_CAP + 1) == 0).then_some(mask)
}

/// The names of a mask's bits, in byte order of the names (the captures' order).
pub fn capability_names(mask: u64) -> Vec<String> {
    let mut names: Vec<String> = CAPABILITY_NAMES
        .iter()
        .enumerate()
        .filter(|(bit, _)| u32::try_from(*bit).is_ok_and(|bit| bit < 64 && mask >> bit & 1 == 1))
        .map(|(_, name)| (*name).to_string())
        .collect();
    names.sort();
    names
}

/// Parses `status`: duplicate keys refuse; the four `Uid` (and `Gid`) values must be equal.
pub fn status(text: &[u8]) -> Option<Status> {
    let text = std::str::from_utf8(text).ok()?;
    let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once(':')?;
        if fields.insert(key, value.trim()).is_some() {
            return None;
        }
    }
    let same_four = |key: &str| -> Option<u64> {
        let values: Vec<u64> = fields.get(key)?.split_ascii_whitespace().map(decimal).collect::<Option<Vec<u64>>>()?;
        (values.len() == 4 && values.iter().all(|value| Some(value) == values.first())).then_some(*values.first()?)
    };
    let number = |key: &str| fields.get(key).and_then(|value| decimal(value));
    let mask = |key: &str| fields.get(key).and_then(|value| capability_mask(value));
    Some(Status {
        uid: same_four("Uid")?,
        gid: same_four("Gid")?,
        no_new_privs: number("NoNewPrivs")?,
        seccomp_mode: number("Seccomp")?,
        seccomp_filters: number("Seccomp_filters")?,
        threads: number("Threads")?,
        inheritable: mask("CapInh")?,
        permitted: mask("CapPrm")?,
        effective: mask("CapEff")?,
        bounding: mask("CapBnd")?,
        ambient: mask("CapAmb")?,
    })
}

/// Parses `cgroup`: exactly one line `0::<path>` with an absolute path; the path.
pub fn cgroup_line(text: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(text).ok()?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.contains('\n') {
        return None;
    }
    let path = line.strip_prefix("0::")?;
    path.starts_with('/').then(|| path.to_string())
}

/// `attr/current` without its trailing NUL and newline; printable ASCII only.
pub fn label(text: &[u8]) -> Option<String> {
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    let text = text.strip_suffix(b"\0").unwrap_or(text);
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    let label = std::str::from_utf8(text).ok()?;
    (!label.is_empty() && label.bytes().all(|byte| (0x20..=0x7e).contains(&byte))).then(|| label.to_string())
}

/// An SELinux context's third field, its type, read from `user:role:type:level` (at least four fields, the first three
/// non-empty).
pub fn label_type(label: &str) -> Option<&str> {
    let parts: Vec<&str> = label.split(':').collect();
    let first = parts.get(..3)?;
    (parts.len() >= 4 && first.iter().all(|part| !part.is_empty())).then(|| parts.get(2).copied()).flatten()
}

/// musl's `makedev`: the device number of a `major:minor` pair, as `fstat` reports `st_dev`.
pub fn makedev(major: u64, minor: u64) -> u64 {
    (major & 0x0000_0fff) << 8 | (major & 0xffff_f000) << 32 | (minor & 0x0000_00ff) | (minor & 0xffff_ff00) << 12
}

/// The inverse of [`makedev`] (the tests' fake writes `maps` devices with it).
pub fn device_parts(device: u64) -> (u64, u64) {
    let major = (device >> 8 & 0x0000_0fff) | (device >> 32 & 0xffff_f000);
    let minor = (device & 0x0000_00ff) | (device >> 12 & 0xffff_ff00);
    (major, minor)
}

/// One executable mapping of `maps`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub path: String,
    pub offset: u64,
    pub length: u64,
    pub permissions: String,
    pub device: u64,
    pub inode: u64,
}

fn hex(text: &str) -> Option<u64> {
    (!text.is_empty() && text.len() <= 16 && text.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| u64::from_str_radix(text, 16).ok())
        .flatten()
}

/// Parses `maps`: the executable mappings in order (see the module documentation).
pub fn maps(text: &[u8]) -> Option<Vec<Mapping>> {
    let text = std::str::from_utf8(text).ok()?;
    let mut found = Vec::new();
    for line in text.lines() {
        let mut parts = line.splitn(6, ' ');
        let (range, permissions, offset, device, inode) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?, parts.next()?);
        let path = parts.next().unwrap_or("").trim_start_matches(' ');
        let (start, end) = range.split_once('-')?;
        let (start, end) = (hex(start)?, hex(end)?);
        let bytes = permissions.as_bytes();
        if bytes.len() != 4 || end <= start {
            return None;
        }
        let (major, minor) = device.split_once(':')?;
        let (offset, major, minor, inode) = (hex(offset)?, hex(major)?, hex(minor)?, decimal(inode)?);
        if bytes.get(2) != Some(&b'x') {
            continue;
        }
        if path == "[vdso]" || path == "[vsyscall]" {
            continue;
        }
        if !path.starts_with('/') {
            return None;
        }
        found.push(Mapping { path: path.to_string(), offset, length: end - start, permissions: permissions.to_string(),
                             device: makedev(major, minor), inode });
    }
    Some(found)
}

/// A namespace link's inode: `<kind>:[<inode>]` with the expected kind.
pub fn namespace_inode(text: &str, kind: &str) -> Option<u64> {
    let inner = text.strip_prefix(kind)?.strip_prefix(":[")?.strip_suffix(']')?;
    decimal(inner).filter(|inode| *inode >= 1)
}

/// The `exe` link's path: absolute, without a ` (deleted)` suffix.
pub fn exe_path(text: &str) -> Option<String> {
    (text.starts_with('/') && !text.ends_with(" (deleted)")).then(|| text.to_string())
}

/// `key value` lines (`cgroup.events`, `cgroup.stat`); duplicate keys refuse.
fn key_values(text: &[u8]) -> Option<BTreeMap<String, u64>> {
    let text = std::str::from_utf8(text).ok()?;
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once(' ')?;
        if fields.insert(key.to_string(), decimal(value)?).is_some() {
            return None;
        }
    }
    Some(fields)
}

/// `cgroup.events`: (`populated`, `frozen`), each 0 or 1.
pub fn events(text: &[u8]) -> Option<(u64, u64)> {
    let fields = key_values(text)?;
    let (populated, frozen) = (*fields.get("populated")?, *fields.get("frozen")?);
    (populated <= 1 && frozen <= 1).then_some((populated, frozen))
}

/// `cgroup.stat`'s `nr_descendants`.
pub fn descendants(text: &[u8]) -> Option<u64> {
    key_values(text)?.get("nr_descendants").copied()
}

/// One integer limit file (`memory.max`, `pids.max`, `pids.current`): `max` refuses.
pub fn limit(text: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(text).ok()?;
    decimal(text.strip_suffix('\n').unwrap_or(text))
}

/// `cpu.max`: (quota, period); a `max` quota refuses.
pub fn cpu_max(text: &[u8]) -> Option<(u64, u64)> {
    let text = std::str::from_utf8(text).ok()?;
    let (quota, period) = text.strip_suffix('\n').unwrap_or(text).split_once(' ')?;
    Some((decimal(quota)?, decimal(period)?))
}

/// `cgroup.procs`: one pid per line.
pub fn procs(text: &[u8]) -> Option<Vec<i32>> {
    let text = std::str::from_utf8(text).ok()?;
    text.lines().map(pid).collect()
}

/// The verity reply's digest text: algorithm 1 (SHA-256) and size 32 only.
pub fn verity_text(algorithm: u16, size: u16, digest: &[u8]) -> Option<String> {
    (algorithm == 1 && size == 32 && digest.len() == 32).then(|| format!("sha256:{}", lower_hex(digest)))
}

/// Lowercase hexadecimal.
pub fn lower_hex(bytes: &[u8]) -> String {
    i05_protocol::sha256::hex(bytes)
}

/// A mode as the captures write it: `%04o` of `mode & 0o7777` (D1-5).
pub fn mode_text(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

/// The call count of a translated program (D1-10): opcode 0x85 with source register 0 or 2 counted, 1 not counted, any
/// other refused; a length that is not a multiple of 8 refuses.
pub fn call_count(xlated: &[u8]) -> Option<u64> {
    if xlated.len() % 8 != 0 {
        return None;
    }
    let mut count = 0u64;
    for instruction in xlated.chunks_exact(8) {
        if instruction.first() != Some(&0x85) {
            continue;
        }
        match instruction.get(1).map(|registers| registers >> 4) {
            Some(0 | 2) => count = count.checked_add(1)?,
            Some(1) => {}
            _ => return None,
        }
    }
    Some(count)
}

/// Days since 1970-01-01 of a civil date (H. Hinnant's algorithm), for years 1970-9999.
fn days_from_civil(year: u64, month: u64, day: u64) -> Option<u64> {
    let year = if month <= 2 { year.checked_sub(1)? } else { year };
    let era = year / 400;
    let year_of_era = year - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day.checked_sub(1)?;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era).checked_sub(719_468)
}

/// The civil date of a day count since 1970-01-01.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// The last second a canonical UTC time can name: 9999-12-31T23:59:59Z.
pub const MAX_UTC_SECONDS: u64 = 253_402_300_799;

/// The canonical UTC text `YYYY-MM-DDTHH:MM:SSZ` of `seconds` since the epoch; `None` past 9999.
pub fn utc_text(seconds: u64) -> Option<String> {
    if seconds > MAX_UTC_SECONDS {
        return None;
    }
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    let (year, month, day) = civil_from_days(days);
    Some(format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rest / 3_600, rest % 3_600 / 60, rest % 60))
}

/// The seconds of a canonical UTC text: it must render back to itself (the model's `canonical UTC time`).
pub fn utc_seconds(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() != 20 || bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':') || bytes.get(16) != Some(&b':') || bytes.get(19) != Some(&b'Z')
    {
        return None;
    }
    let field = |from: usize, to: usize| text.get(from..to).filter(|part| part.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|part| part.parse::<u64>().ok());
    let (year, month, day) = (field(0, 4)?, field(5, 7)?, field(8, 10)?);
    let (hour, minute, second) = (field(11, 13)?, field(14, 16)?, field(17, 19)?);
    if year < 1970 || !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let seconds = days_from_civil(year, month, day)?.checked_mul(86_400)?.checked_add(hour * 3_600 + minute * 60 + second)?;
    (utc_text(seconds).as_deref() == Some(text)).then_some(seconds)
}

/// The Unix milliseconds of a canonical UTC text.
pub fn utc_millis(text: &str) -> Option<u64> {
    utc_seconds(text)?.checked_mul(1_000)
}
