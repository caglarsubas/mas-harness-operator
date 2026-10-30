//! The gate's qualification, from the broker's side (HE-005B: DESIGN-HE005 revision 5 sections 1 (O10, O11) and 3.3
//! step 2; the HE-005B plan's item 5; MON-HE005B-PLAN, Q-HE5B-5 (a) and its condition). A logic module: pure (no I/O,
//! no system call, safe Rust only), no panic, std's ordered collections only. Nothing in `main`, `serve`, `seal.rs`,
//! `status.rs` or `linux_listen.rs` names it, so planeon-broker's behaviour stays HE-005A's (G-HE5B-1).
//!
//! HS53 section 4.3: "BROKER qualifies EFFECT_GATE as a peer (artifact, label, cgroup, pidfd/start, SO_PEERCRED) before
//! BIND_EXECUTION", its artifact check reading the gate's `exe` link (hs43 H1: the gate holds no capability, stays
//! dumpable and runs with uids and gids 0, the broker's filesystem uid and gid, O-W03-PEER-EXE). The inputs are
//! the observed values ([`GateObservation`]: SO_PEERCRED, the held pidfd's origin, the `exe` link, `attr/current`, the
//! `cgroup` file, the `stat` line, and whether the pidfd fired after those reads) and the signed `gateExecutablePath`
//! (section 3.1). Reading them is HE-005D's.
//!
//! - [`qualify_gate`] is the one minting function of [`GateQualified`], the token D's BIND_EXECUTION will require
//!   (`QualificationAccepted`'s form: private fields, no `Clone`, `Copy` or `Default`). The token has no impl, so
//!   it has no other constructor, no trait that could make one, and no method (Q-HE5B-5's condition, G-HE5B-5).
//! - [`compare_start_time`], a free function over `&GateQualified`, is the per-frame comparison: "A peer's start time
//!   is compared on every frame with a reference taken without a race at its first frame" (HS53 section 4.3).
//! - The pidfd is the socket's only (O11): [`SocketPidfd`] has a variant for SO_PEERPIDFD and one for SCM_PIDFD and
//!   none for a `pidfd_open` of SO_PEERCRED's pid, which "may already name a later process" (HS53, HS43), so
//!   such a pidfd cannot be given here.
//!
//! The expected label, ids and cgroup are R10 constants in effect-gate's `peers.rs` form, each cited; T04 confirms
//! them on the real gate. The label, cgroup-line and `stat` readers are the pure forms of gate-sys's `label_matches`,
//! `same_lines` and `stat_start_time` (this module names no gate-sys item, G-HE5B-2).

use std::collections::BTreeSet;

/// The gate's process label, written without the NUL the kernel delivers: native-profile v4's EFFECT_GATE
/// `processLabel` constant (`contracts/native-profile-v4/qualification.schema.json`, `$defs/roles`; the SELinux type
/// `planeon_gate_t`, HS53 :330).
pub const GATE_LABEL: &str = "system_u:system_r:planeon_gate_t:s0";
/// The gate's uid and gid: native-profile v4's EFFECT_GATE `uid` and `gid` constants (0), hs43 H1's "uids and gids 0".
pub const GATE_UID: u32 = 0;
pub const GATE_GID: u32 = 0;
/// The gate's cgroup v2 line: `0::` followed by native-profile v4's EFFECT_GATE `cgroup.path` constant without the
/// cgroup filesystem's mount point (effect-gate's `BROKER_CGROUP` form, read from the root cgroup namespace).
pub const GATE_CGROUP: &str = "0::/planeon.slice/planeon-effect-gate.service";

/// Where the held pidfd came from: the connected socket only (O11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketPidfd {
    /// SO_PEERPIDFD, read after `connect`.
    PeerPidfd,
    /// SCM_PIDFD, delivered on a frame.
    ScmPidfd,
}

/// SO_PEERCRED as the kernel gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i64,
    pub uid: u32,
    pub gid: u32,
}

/// What the broker observed of the gate at its first frame: SO_PEERCRED, the socket pidfd's origin, then, through the
/// process directory that pidfd names, the `exe` link's target, `attr/current` (with the kernel's NUL), the whole
/// `cgroup` file and the `stat` line, and last whether the pidfd's poll showed the process gone after those reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateObservation {
    pub credentials: PeerCredentials,
    pub pidfd: SocketPidfd,
    pub exe_link: Vec<u8>,
    pub attr_current: Vec<u8>,
    pub cgroup: Vec<u8>,
    pub stat: Vec<u8>,
    pub exited: bool,
}

/// The gate qualified as the broker's I05 peer: its pid and the start time taken at its first frame, the reference for
/// every later frame. Minted only by [`qualify_gate`].
#[derive(Debug)]
#[must_use]
pub struct GateQualified {
    pid: i64,
    start_ticks: u64,
}

/// Why the gate is not qualified, or a later frame's process is not the qualified one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateRefusal {
    /// SO_PEERCRED's pid is not positive.
    Pid,
    /// SO_PEERCRED's uid is not the gate's.
    Uid,
    /// SO_PEERCRED's gid is not the gate's.
    Gid,
    /// `attr/current` is not the gate's label.
    Label,
    /// The `cgroup` file is not exactly the gate's line.
    Cgroup,
    /// The `exe` link is not the signed `gateExecutablePath` (or that path is empty).
    Executable,
    /// The `stat` line has no readable pid or start time.
    Stat,
    /// The `stat` line's pid is not SO_PEERCRED's (or the qualified one).
    StatPid,
    /// A later frame's start time is not the qualified one.
    StartTime,
    /// The pidfd fired: the process had exited, so the reads may not have been its.
    Exited,
}

/// Qualifies the gate (HS53 section 4.3, O10, O11), in effect-gate's own qualification order: SO_PEERCRED's pid, uid
/// and gid; the label; the cgroup; the executable; the `stat` line's pid and start time; last, the pidfd unfired after
/// the reads. On success only it mints the token.
pub fn qualify_gate(observed: &GateObservation, gate_executable_path: &str) -> Result<GateQualified, GateRefusal> {
    let credentials = observed.credentials;
    match observed.pidfd {
        SocketPidfd::PeerPidfd | SocketPidfd::ScmPidfd => {}
    }
    if credentials.pid <= 0 {
        return Err(GateRefusal::Pid);
    }
    if credentials.uid != GATE_UID {
        return Err(GateRefusal::Uid);
    }
    if credentials.gid != GATE_GID {
        return Err(GateRefusal::Gid);
    }
    if !label_matches(&observed.attr_current, GATE_LABEL.as_bytes()) {
        return Err(GateRefusal::Label);
    }
    if !same_lines(&observed.cgroup, GATE_CGROUP.as_bytes()) {
        return Err(GateRefusal::Cgroup);
    }
    if gate_executable_path.is_empty() || observed.exe_link != gate_executable_path.as_bytes() {
        return Err(GateRefusal::Executable);
    }
    let (pid, start_ticks) = stat_identity(&observed.stat).ok_or(GateRefusal::Stat)?;
    if pid != credentials.pid {
        return Err(GateRefusal::StatPid);
    }
    if observed.exited {
        return Err(GateRefusal::Exited);
    }
    Ok(GateQualified { pid, start_ticks })
}

/// The per-frame comparison: the gate's `stat` line read again through the held directory names the qualified pid and
/// start time, and the held socket pidfd has not fired after the read.
pub fn compare_start_time(qualified: &GateQualified, stat: &[u8], exited: bool) -> Result<(), GateRefusal> {
    let (pid, start_ticks) = stat_identity(stat).ok_or(GateRefusal::Stat)?;
    if pid != qualified.pid {
        return Err(GateRefusal::StatPid);
    }
    if start_ticks != qualified.start_ticks {
        return Err(GateRefusal::StartTime);
    }
    if exited {
        return Err(GateRefusal::Exited);
    }
    Ok(())
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

/// A `cgroup` text's set of lines, a final newline ending the last; `None` for an empty text or an empty line
/// (gate-sys's `line_set` form).
pub fn line_set(text: &[u8]) -> Option<BTreeSet<Vec<u8>>> {
    let body = text.strip_suffix(b"\n").unwrap_or(text);
    if body.is_empty() {
        return None;
    }
    let mut lines = BTreeSet::new();
    for line in body.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            return None;
        }
        lines.insert(line.to_vec());
    }
    Some(lines)
}

/// Two cgroup texts name exactly the same lines (gate-sys's `same_lines` form).
pub fn same_lines(observed: &[u8], expected: &[u8]) -> bool {
    match (line_set(observed), line_set(expected)) {
        (Some(observed), Some(expected)) => observed == expected,
        _ => false,
    }
}

/// Field 22 of a `stat` line (the process's start time in clock ticks since boot): the fields after the last `)` are
/// fields 3 onwards, separated by single spaces, the line ending with at most one newline. `None` for any other shape
/// (gate-sys's `stat_start_time` form; `tests/gate_peer_parity.rs` compares the two).
pub fn stat_start_time(stat: &[u8]) -> Option<u64> {
    let open = stat.iter().position(|byte| *byte == b'(')?;
    let close = stat.iter().rposition(|byte| *byte == b')')?;
    if close < open {
        return None;
    }
    let rest = stat.get(close.checked_add(1)?..)?;
    let rest = rest.strip_suffix(b"\n").unwrap_or(rest);
    let rest = rest.strip_prefix(b" ")?;
    // Field 3 (the state) is the first after the parenthesis, so field 22 is the twentieth.
    let field = rest.split(|byte| *byte == b' ').nth(19)?;
    if field.is_empty() || !field.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(field).ok()?.parse().ok()
}

/// A `stat` line's pid (field 1, the decimal before ` (`) and its start time ([`stat_start_time`]). `None` when either
/// is unreadable.
fn stat_identity(stat: &[u8]) -> Option<(i64, u64)> {
    let open = stat.iter().position(|byte| *byte == b'(')?;
    let head = stat.get(..open)?.strip_suffix(b" ")?;
    let pid = i64::try_from(decimal(head)?).ok()?;
    Some((pid, stat_start_time(stat)?))
}

/// An unsigned decimal of ASCII digits only.
fn decimal(text: &[u8]) -> Option<u64> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(text).ok()?.parse().ok()
}
