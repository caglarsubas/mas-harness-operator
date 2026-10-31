//! The readers of the leaf's control files and of the frozen child's process-directory files (pure; host-tested). A
//! reader answers `None` or `false` for any shape it does not know, and the step that called it refuses. The `stat`
//! and label readers are gate-sys's forms, written again here (B's gate_peer.rs holds the same forms; this module names
//! none of B's modules, G-HE5B-1).

use broker_sys::{FdEntry, FdIdentity, W3Expect};

/// The broker's process label, written without the NUL the kernel delivers: native-profile v4's BROKER
/// `processLabel` constant (`contracts/native-profile-v4/qualification.schema.json`, `$defs/roles`, :1501). W3 reads
/// the frozen child before any of its own steps runs, so the child is still in the broker's domain (section 4.0,
/// H5E-6; the frozen seam note, section 4, W3).
pub const BROKER_LABEL: &str = "system_u:system_r:planeon_broker_t:s0";
/// A mode's file-type bits, and a socket's type (W3's descriptor check, SM-R1-3, SM-R2-4).
pub const S_IFMT: u32 = 0o170000;
pub const S_IFSOCK: u32 = 0o140000;

/// `cgroup.events`' two keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Events {
    pub populated: bool,
    pub frozen: bool,
}

/// `cgroup.events`' text: lines of `<key> <value>`, the last ending with at most one newline; `populated` and `frozen`
/// each exactly once, with 0 or 1; any other key is read past. `None` for any other shape.
pub fn events(text: &[u8]) -> Option<Events> {
    let body = text.strip_suffix(b"\n").unwrap_or(text);
    let (mut populated, mut frozen) = (None, None);
    for line in body.split(|byte| *byte == b'\n') {
        let space = line.iter().position(|byte| *byte == b' ')?;
        let key = line.get(..space)?;
        let value = line.get(space.checked_add(1)?..)?;
        let slot = match key {
            b"populated" => &mut populated,
            b"frozen" => &mut frozen,
            _ => continue,
        };
        let flag = match value {
            b"0" => false,
            b"1" => true,
            _ => return None,
        };
        if slot.replace(flag).is_some() {
            return None;
        }
    }
    Some(Events { populated: populated?, frozen: frozen? })
}

/// `cgroup.type`'s text is exactly `domain`, with at most one final newline (O8: the leaf stays a domain cgroup).
pub fn is_domain(text: &[u8]) -> bool {
    text.strip_suffix(b"\n").unwrap_or(text) == b"domain"
}

/// `cgroup.procs` lists no process: its text is empty.
pub fn procs_empty(text: &[u8]) -> bool {
    text.is_empty()
}

/// The rest of the one `status` line that starts with `key`; `None` when no line or more than one does.
fn status_line<'a>(status: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut lines = status.split(|byte| *byte == b'\n').filter(|line| line.starts_with(key));
    let line = lines.next()?;
    if lines.next().is_some() {
        return None;
    }
    line.get(key.len()..)
}

/// `status`' line `key` (`Uid:` or `Gid:`) holds exactly four fields (real, effective, saved and filesystem), each
/// `0`: the frozen child's credentials are still the broker's, uid and gid 0 (HI-7).
pub fn ids_are_root(status: &[u8], key: &[u8]) -> bool {
    status_line(status, key).is_some_and(|rest| {
        let fields: Vec<&[u8]> = rest.split(|byte| *byte == b'\t' || *byte == b' ').filter(|field| !field.is_empty()).collect();
        fields.len() == 4 && fields.iter().all(|field| *field == b"0")
    })
}

/// `status`' `Groups:` line is there once and lists no group: only tabs or spaces after the key (O2, O3).
pub fn groups_empty(status: &[u8]) -> bool {
    status_line(status, b"Groups:").is_some_and(|rest| rest.iter().all(|byte| *byte == b'\t' || *byte == b' '))
}

/// An unsigned decimal of ASCII digits only.
fn decimal(text: &[u8]) -> Option<u64> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(text).ok()?.parse().ok()
}

/// A `stat` line's pid (field 1, the decimal before ` (`) and start time (field 22, clock ticks since boot: the
/// twentieth field after the last `)`, fields separated by single spaces, the line ending with at most one newline),
/// in gate-sys's `stat_start_time` form. `None` for any other shape.
pub fn stat_identity(stat: &[u8]) -> Option<(i32, u64)> {
    let open = stat.iter().position(|byte| *byte == b'(')?;
    let close = stat.iter().rposition(|byte| *byte == b')')?;
    if close < open {
        return None;
    }
    let head = stat.get(..open)?.strip_suffix(b" ")?;
    let pid = i32::try_from(decimal(head)?).ok()?;
    let rest = stat.get(close.checked_add(1)?..)?;
    let rest = rest.strip_suffix(b"\n").unwrap_or(rest);
    let rest = rest.strip_prefix(b" ")?;
    // Field 3 (the state) is the first after the parenthesis, so field 22 is the twentieth.
    let start = decimal(rest.split(|byte| *byte == b' ').nth(19)?)?;
    Some((pid, start))
}

/// The child's `cgroup` text is exactly one cgroup v2 line, `0::` and the leaf as a member's line names it
/// (`leaf::membership`), with at most one final newline: the child is in the probe-worker leaf and nowhere else.
pub fn in_leaf(cgroup: &[u8], membership: &str) -> bool {
    let body = cgroup.strip_suffix(b"\n").unwrap_or(cgroup);
    !membership.is_empty() && body.strip_prefix(b"0::").is_some_and(|rest| rest == membership.as_bytes())
}

/// A delivered label against an expected one written without a NUL: exactly one trailing NUL stripped, then equal
/// (gate-sys's `label_matches` form); an empty expected label never matches.
pub fn label_matches(delivered: &[u8], expected: &[u8]) -> bool {
    let stripped = match delivered.split_last() {
        Some((0, rest)) => rest,
        _ => delivered,
    };
    !expected.is_empty() && stripped == expected
}

/// W3's descriptor check (the frozen seam note, section 3, SM-R1-2, SM-R2-4): the table, sorted here by number (the
/// sort is the lifecycle's, SM-R1-4), names no number twice; fds 0, 1 and 2 are each present and not a socket; and the
/// entries at W3Expect's two numbers have those sources' (dev, ino).
pub fn descriptors_hold(mut table: Vec<FdEntry>, expect: &W3Expect) -> bool {
    table.sort_unstable_by_key(|entry| entry.number);
    if table.windows(2).any(|pair| matches!(pair, [first, second] if first.number == second.number)) {
        return false;
    }
    let entry = |number: u32| table.binary_search_by_key(&number, |entry| entry.number).ok().and_then(|at| table.get(at));
    let stdio = [0u32, 1, 2].iter().all(|number| entry(*number).is_some_and(|found| (found.mode & S_IFMT) != S_IFSOCK));
    let source =
        |identity: &FdIdentity| entry(identity.number).is_some_and(|found| found.dev == identity.dev && found.ino == identity.ino);
    stdio && source(&expect.channel) && source(&expect.script)
}
