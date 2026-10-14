//! The byte parsers of the channel substrate (HE-003A DESIGN §3 and §4.3), portable and host-tested with fixed byte
//! vectors: the control-message buffer `recvmsg` fills, the identity reads of a peer process, and the label rule.
//! Nothing here makes a system call; `channel.rs` (Linux) and effect-gate's substrate call these functions.
//!
//! - Control messages. The buffer is exactly `CMSG_SPACE(12) + CMSG_SPACE(L)` bytes, where L is the accept-time
//!   SO_PEERSEC length: room for one credentials message and one security message of the accepted label's length and
//!   nothing else, so a descriptor-passing message after them is never installed (the kernel sets MSG_CTRUNC and
//!   releases the files). Each message header is the kernel's: a 64-bit little-endian `cmsg_len` (musl declares a
//!   32-bit field and padding; both targets are little-endian), then the 32-bit level and type; messages start on
//!   8-byte boundaries. A delivery is accepted only with exactly one `SOL_SOCKET`/`SCM_CREDENTIALS` of length
//!   `CMSG_LEN(12)` and exactly one `SOL_SOCKET`/`SCM_SECURITY`; MSG_CTRUNC, a missing or repeated message, any other
//!   level or type, or a malformed length is a violation.
//! - Labels. SO_PEERSEC, SCM_SECURITY and the process's `attr/current` deliver the context with its trailing NUL. The
//!   socket labels are compared byte for byte as delivered; a comparison with an expected label (written without a
//!   NUL) strips exactly one trailing NUL from the delivered bytes first.
//! - The process's `stat` line: field 22 (the start time in clock ticks) is counted from the last `)`, so a command name
//!   with spaces or parentheses cannot shift it.
//! - The process's `cgroup` file is compared as its exact set of lines.
//!
//! The kernel files these reads come from are named in this module only by their file names; the proc filesystem's
//! paths are `channel.rs`'s, behind the start-up lint's two exceptions.

use std::collections::BTreeSet;

/// The receive buffer of one datagram: one byte more than the largest frame (16,384 bytes), so a longer datagram is
/// seen as longer than a frame (MSG_TRUNC) and the frame decoder refuses its size.
pub const FRAME_BUFFER_BYTES: usize = 16385;

/// `struct ucred` (pid, uid, gid): the payload of SO_PEERCRED and of an SCM_CREDENTIALS message.
pub const CREDENTIALS_BYTES: usize = 12;

/// The longest label the substrate reads (SO_PEERSEC's buffer, and each identity file read whole).
pub const LABEL_LIMIT: usize = 4096;

/// The kernel's `struct cmsghdr` on both 64-bit targets: `cmsg_len` (8 bytes), `cmsg_level` (4), `cmsg_type` (4).
const HEADER_BYTES: usize = 16;

/// `CMSG_ALIGN`: control messages are aligned to `sizeof(size_t)`.
const ALIGNMENT: usize = 8;

/// `SOL_SOCKET` (1 on x86_64 and aarch64: the kernel's generic `socket.h`, which both use).
pub const SOL_SOCKET: i32 = 1;
/// `SCM_RIGHTS` (`linux/socket.h`): descriptors; never accepted.
pub const SCM_RIGHTS: i32 = 1;
/// `SCM_CREDENTIALS` (`linux/socket.h`).
pub const SCM_CREDENTIALS: i32 = 2;
/// `SCM_SECURITY` (`linux/socket.h`).
pub const SCM_SECURITY: i32 = 3;

/// `CMSG_ALIGN(length)`; `None` on overflow.
pub fn cmsg_align(length: usize) -> Option<usize> {
    length.checked_add(ALIGNMENT - 1).map(|padded| padded & !(ALIGNMENT - 1))
}

/// `CMSG_LEN(length)`: a header and `length` payload bytes, without trailing padding.
pub fn cmsg_len(length: usize) -> Option<usize> {
    HEADER_BYTES.checked_add(length)
}

/// `CMSG_SPACE(length)`: a header and `length` payload bytes with the padding to the next message.
pub fn cmsg_space(length: usize) -> Option<usize> {
    HEADER_BYTES.checked_add(cmsg_align(length)?)
}

/// The control buffer for a connection whose accept-time SO_PEERSEC length (NUL included) is `label_length`:
/// `CMSG_SPACE(12) + CMSG_SPACE(label_length)`. `None` for an empty or over-long label.
pub fn control_capacity(label_length: usize) -> Option<usize> {
    if label_length == 0 || label_length > LABEL_LIMIT {
        return None;
    }
    cmsg_space(CREDENTIALS_BYTES)?.checked_add(cmsg_space(label_length)?)
}

/// The credentials an SCM_CREDENTIALS message (or SO_PEERCRED) carries.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

impl Credentials {
    /// `struct ucred` from its 12 bytes, little-endian.
    pub fn from_bytes(bytes: &[u8]) -> Option<Credentials> {
        let [p0, p1, p2, p3, u0, u1, u2, u3, g0, g1, g2, g3] = <[u8; CREDENTIALS_BYTES]>::try_from(bytes).ok()?;
        Some(Credentials {
            pid: i32::from_le_bytes([p0, p1, p2, p3]),
            uid: u32::from_le_bytes([u0, u1, u2, u3]),
            gid: u32::from_le_bytes([g0, g1, g2, g3]),
        })
    }
}

/// What one datagram's control messages carried, when they obeyed the rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Control {
    pub credentials: Credentials,
    /// The SCM_SECURITY payload exactly as delivered (with its NUL).
    pub security: Vec<u8>,
}

/// Why a datagram's control messages were refused (each one a custody deviation).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ControlViolation {
    /// The kernel set MSG_CTRUNC: something did not fit (a descriptor-passing message, or a longer label).
    Truncated,
    /// A header that does not fit, a `cmsg_len` shorter than the header or past the buffer.
    Malformed,
    /// A message of another level or type (SCM_RIGHTS among them).
    Foreign { level: i32, kind: i32 },
    /// An SCM_CREDENTIALS message whose length is not `CMSG_LEN(12)`.
    CredentialsLength,
    MissingCredentials,
    RepeatedCredentials,
    MissingSecurity,
    RepeatedSecurity,
}

fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    Some(u64::from_le_bytes(<[u8; 8]>::try_from(bytes.get(at..end)?).ok()?))
}

fn read_i32(bytes: &[u8], at: usize) -> Option<i32> {
    let end = at.checked_add(4)?;
    Some(i32::from_le_bytes(<[u8; 4]>::try_from(bytes.get(at..end)?).ok()?))
}

/// Parses the control bytes `recvmsg` returned (`control` is the buffer up to the returned `msg_controllen`), with
/// `truncated` the MSG_CTRUNC flag of the same call.
pub fn parse_control(control: &[u8], truncated: bool) -> Result<Control, ControlViolation> {
    if truncated {
        return Err(ControlViolation::Truncated);
    }
    let mut credentials = None;
    let mut security: Option<Vec<u8>> = None;
    let mut at = 0usize;
    while at < control.len() {
        let length = read_u64(control, at).ok_or(ControlViolation::Malformed)?;
        let level = read_i32(control, at.saturating_add(8)).ok_or(ControlViolation::Malformed)?;
        let kind = read_i32(control, at.saturating_add(12)).ok_or(ControlViolation::Malformed)?;
        let length = usize::try_from(length).map_err(|_| ControlViolation::Malformed)?;
        let end = at.checked_add(length).ok_or(ControlViolation::Malformed)?;
        if length < HEADER_BYTES || end > control.len() {
            return Err(ControlViolation::Malformed);
        }
        let payload = control.get(at.saturating_add(HEADER_BYTES)..end).ok_or(ControlViolation::Malformed)?;
        match (level, kind) {
            (SOL_SOCKET, SCM_CREDENTIALS) => {
                if credentials.is_some() {
                    return Err(ControlViolation::RepeatedCredentials);
                }
                if Some(length) != cmsg_len(CREDENTIALS_BYTES) {
                    return Err(ControlViolation::CredentialsLength);
                }
                credentials = Some(Credentials::from_bytes(payload).ok_or(ControlViolation::CredentialsLength)?);
            }
            (SOL_SOCKET, SCM_SECURITY) => {
                if security.is_some() {
                    return Err(ControlViolation::RepeatedSecurity);
                }
                security = Some(payload.to_vec());
            }
            (level, kind) => return Err(ControlViolation::Foreign { level, kind }),
        }
        // The last message's padding may be absent when the buffer ends with it.
        at = cmsg_align(length).and_then(|aligned| at.checked_add(aligned)).ok_or(ControlViolation::Malformed)?;
    }
    let credentials = credentials.ok_or(ControlViolation::MissingCredentials)?;
    let security = security.ok_or(ControlViolation::MissingSecurity)?;
    Ok(Control { credentials, security })
}

/// A delivered label (SO_PEERSEC, SCM_SECURITY or `attr/current`, as the kernel gives it) against an expected label
/// written without a NUL: exactly one trailing NUL is stripped from the delivered bytes, then they must be equal. A
/// delivery without a trailing NUL is compared as it is; one with two NULs keeps the second and differs.
pub fn label_matches(delivered: &[u8], expected: &[u8]) -> bool {
    let stripped = match delivered.split_last() {
        Some((0, rest)) => rest,
        _ => delivered,
    };
    !expected.is_empty() && stripped == expected
}

/// Field 22 of a `stat` line (the process's start time in clock ticks since boot): the fields after the last `)` are
/// fields 3 onwards, separated by single spaces, the line ending with at most one newline. `None` for any other shape.
pub fn stat_start_time(stat: &[u8]) -> Option<u64> {
    let open = stat.iter().position(|byte| *byte == b'(')?;
    let close = stat.iter().rposition(|byte| *byte == b')')?;
    if close < open {
        return None;
    }
    let rest = stat.get(close + 1..)?;
    let rest = rest.strip_suffix(b"\n").unwrap_or(rest);
    let rest = rest.strip_prefix(b" ")?;
    // Field 3 (the state) is the first after the parenthesis, so field 22 is the twentieth.
    let field = rest.split(|byte| *byte == b' ').nth(19)?;
    if field.is_empty() || !field.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(field).ok()?.parse().ok()
}

/// The set of lines of a `cgroup` file (or of an expected value written the same way): split at newlines, a final
/// newline ending the last line. `None` for an empty text or an empty line.
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

/// Two cgroup texts name exactly the same lines (both must be readable as line sets).
pub fn same_lines(observed: &[u8], expected: &[u8]) -> bool {
    match (line_set(observed), line_set(expected)) {
        (Some(observed), Some(expected)) => observed == expected,
        _ => false,
    }
}

/// What the substrate reads of a peer process through its retained directory: the start time (`stat` field 22), the
/// whole `cgroup` file and the whole `attr/current` (the process's SELinux context, with its NUL).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcIdentity {
    pub start_time: u64,
    pub cgroup: Vec<u8>,
    pub label: Vec<u8>,
}

impl ProcIdentity {
    /// The identity from the three files' bytes; `None` when the `stat` line has no readable field 22 or the cgroup
    /// file is not a line set.
    pub fn from_files(stat: &[u8], cgroup: Vec<u8>, label: Vec<u8>) -> Option<ProcIdentity> {
        let start_time = stat_start_time(stat)?;
        line_set(&cgroup)?;
        Some(ProcIdentity { start_time, cgroup, label })
    }
}
