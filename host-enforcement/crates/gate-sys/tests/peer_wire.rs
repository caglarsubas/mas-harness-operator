//! gate-sys's portable parsers of the channel substrate on the build host (HE-003A DESIGN §3, §9), with fixed byte
//! vectors: the control-message rules (exactly one credentials and one security message, MSG_CTRUNC, a missing,
//! repeated or foreign message, a malformed `cmsg_len`, a descriptor-passing message after the two), the label rule
//! (one trailing NUL stripped against an expected label), `stat` field 22 (names with spaces and parentheses) and the
//! cgroup line sets. The raw calls of `channel.rs` are Linux only and wait for T04.

use gate_sys::peer_wire::{cmsg_align, cmsg_len, cmsg_space, control_capacity, label_matches, line_set, parse_control,
                          same_lines, stat_start_time, Control, ControlViolation, Credentials, ProcIdentity,
                          CREDENTIALS_BYTES, FRAME_BUFFER_BYTES, LABEL_LIMIT, SCM_CREDENTIALS, SCM_RIGHTS, SCM_SECURITY,
                          SOL_SOCKET};

const BROKER: &[u8] = b"system_u:system_r:planeon_broker_t:s0";

/// One control message as the kernel lays it out on a 64-bit little-endian target: `cmsg_len` (8 bytes), level,
/// type, the payload, then padding to 8 bytes.
fn message(level: i32, kind: i32, payload: &[u8]) -> Vec<u8> {
    let length = 16 + payload.len();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(length as u64).to_le_bytes());
    bytes.extend_from_slice(&level.to_le_bytes());
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(payload);
    while bytes.len() % 8 != 0 {
        bytes.push(0);
    }
    bytes
}

fn credentials(pid: i32, uid: u32, gid: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&pid.to_le_bytes());
    payload.extend_from_slice(&uid.to_le_bytes());
    payload.extend_from_slice(&gid.to_le_bytes());
    message(SOL_SOCKET, SCM_CREDENTIALS, &payload)
}

fn with_nul(label: &[u8]) -> Vec<u8> {
    let mut bytes = label.to_vec();
    bytes.push(0);
    bytes
}

fn security(label: &[u8]) -> Vec<u8> {
    message(SOL_SOCKET, SCM_SECURITY, label)
}

fn both() -> Vec<u8> {
    [credentials(4100, 0, 0), security(&with_nul(BROKER))].concat()
}

#[test]
fn the_sizes_are_the_kernels() {
    assert_eq!((cmsg_len(12), cmsg_space(12)), (Some(28), Some(32)));
    assert_eq!((cmsg_align(0), cmsg_align(1), cmsg_align(8), cmsg_align(9)), (Some(0), Some(8), Some(8), Some(16)));
    assert_eq!(cmsg_align(usize::MAX), None);
    assert_eq!(CREDENTIALS_BYTES, 12);
    assert_eq!(FRAME_BUFFER_BYTES, 16385);
    // The broker's label with its NUL is 38 bytes: CMSG_SPACE(12) + CMSG_SPACE(38) = 32 + 56.
    assert_eq!(control_capacity(with_nul(BROKER).len()), Some(88));
    assert_eq!(control_capacity(both().len() - 32 - 16), Some(both().len()));
    assert_eq!(control_capacity(0), None);
    assert_eq!(control_capacity(LABEL_LIMIT), Some(32 + 16 + LABEL_LIMIT));
    assert_eq!(control_capacity(LABEL_LIMIT + 1), None);
    assert_eq!((SOL_SOCKET, SCM_RIGHTS, SCM_CREDENTIALS, SCM_SECURITY), (1, 1, 2, 3));
}

#[test]
fn exactly_one_credentials_and_one_security_message_pass() {
    let expected = Control { credentials: Credentials { pid: 4100, uid: 0, gid: 0 }, security: with_nul(BROKER) };
    assert_eq!(parse_control(&both(), false), Ok(expected.clone()));
    // Either order; the buffer may end without the last message's padding.
    let reversed = [security(&with_nul(BROKER)), credentials(4100, 0, 0)].concat();
    assert_eq!(parse_control(&reversed, false), Ok(expected.clone()));
    let mut unpadded = both();
    unpadded.truncate(32 + 16 + with_nul(BROKER).len());
    assert_eq!(parse_control(&unpadded, false), Ok(expected));
    assert_eq!(Credentials::from_bytes(&[1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]), Some(Credentials { pid: 1, uid: 2, gid: 3 }));
    assert_eq!(Credentials::from_bytes(&[0; 11]), None);
}

#[test]
fn a_truncated_control_buffer_is_refused() {
    // MSG_CTRUNC: an SCM_RIGHTS message that followed the two found no room, and the kernel released its files.
    assert_eq!(parse_control(&both(), true), Err(ControlViolation::Truncated));
    assert_eq!(parse_control(&[], true), Err(ControlViolation::Truncated));
}

#[test]
fn a_missing_repeated_or_foreign_message_is_refused() {
    let creds = credentials(4100, 0, 0);
    let label = security(&with_nul(BROKER));
    assert_eq!(parse_control(&[], false), Err(ControlViolation::MissingCredentials));
    assert_eq!(parse_control(&label, false), Err(ControlViolation::MissingCredentials));
    assert_eq!(parse_control(&creds, false), Err(ControlViolation::MissingSecurity));
    assert_eq!(parse_control(&[creds.clone(), creds.clone(), label.clone()].concat(), false),
               Err(ControlViolation::RepeatedCredentials));
    assert_eq!(parse_control(&[creds.clone(), label.clone(), label.clone()].concat(), false),
               Err(ControlViolation::RepeatedSecurity));
    // A descriptor-passing message after the two, had the buffer had room for it.
    let rights = message(SOL_SOCKET, SCM_RIGHTS, &7i32.to_le_bytes());
    assert_eq!(parse_control(&[both(), rights].concat(), false),
               Err(ControlViolation::Foreign { level: SOL_SOCKET, kind: SCM_RIGHTS }));
    // Another level with a known type, and an unknown type.
    let other_level = message(0, SCM_CREDENTIALS, &[0; 12]);
    assert_eq!(parse_control(&[both(), other_level].concat(), false),
               Err(ControlViolation::Foreign { level: 0, kind: SCM_CREDENTIALS }));
    let other_kind = message(SOL_SOCKET, 29, &[0; 8]);
    assert_eq!(parse_control(&[creds, other_kind, label].concat(), false),
               Err(ControlViolation::Foreign { level: SOL_SOCKET, kind: 29 }));
}

#[test]
fn a_malformed_length_is_refused() {
    let mut short = both();
    short[0..8].copy_from_slice(&15u64.to_le_bytes());
    assert_eq!(parse_control(&short, false), Err(ControlViolation::Malformed));
    let mut past = both();
    past[0..8].copy_from_slice(&(both().len() as u64 + 1).to_le_bytes());
    assert_eq!(parse_control(&past, false), Err(ControlViolation::Malformed));
    let mut huge = both();
    huge[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(parse_control(&huge, false), Err(ControlViolation::Malformed));
    // musl declares a 32-bit `cmsg_len`; a value in the high half of the kernel's 64-bit field is read, not ignored.
    let mut high = both();
    high[4..8].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(parse_control(&high, false), Err(ControlViolation::Malformed));
    // A header that does not fit.
    assert_eq!(parse_control(&both()[..32 + 10], false), Err(ControlViolation::Malformed));
    assert_eq!(parse_control(&[0; 7], false), Err(ControlViolation::Malformed));
    // A credentials message of another length.
    let long_creds = message(SOL_SOCKET, SCM_CREDENTIALS, &[0; 16]);
    assert_eq!(parse_control(&[long_creds, security(&with_nul(BROKER))].concat(), false),
               Err(ControlViolation::CredentialsLength));
    let short_creds = message(SOL_SOCKET, SCM_CREDENTIALS, &[0; 8]);
    assert_eq!(parse_control(&[short_creds, security(&with_nul(BROKER))].concat(), false),
               Err(ControlViolation::CredentialsLength));
}

#[test]
fn labels_strip_exactly_one_nul_against_the_expected_label() {
    assert!(label_matches(&with_nul(BROKER), BROKER));
    assert!(label_matches(BROKER, BROKER), "a delivery without the NUL is compared as it is");
    assert!(!label_matches(&with_nul(&with_nul(BROKER)), BROKER), "only one NUL is stripped");
    assert!(!label_matches(b"system_u:system_r:planeon_worker_t:s0\0", BROKER));
    assert!(!label_matches(b"system_u:system_r:planeon_broker_t:s0 \0", BROKER));
    assert!(!label_matches(b"\0", b""), "an empty expected label never matches");
    assert!(!label_matches(b"", BROKER));
}

/// A `stat` line with `name` as the command and `start` as field 22.
fn stat_line(name: &str, start: &str) -> Vec<u8> {
    format!("4100 ({name}) S 1 4100 4100 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 {start} 1000 10 18446744073709551615\n")
        .into_bytes()
}

#[test]
fn the_start_time_is_field_22_after_the_last_parenthesis() {
    assert_eq!(stat_start_time(&stat_line("harness-capacit", "900001")), Some(900001));
    assert_eq!(stat_start_time(&stat_line("a) S 1 2 3 (b", "900002")), Some(900002), "parentheses in the name");
    assert_eq!(stat_start_time(&stat_line("x y z", "17")), Some(17), "spaces in the name");
    assert_eq!(stat_start_time(&stat_line(")", "5")), Some(5));
    let mut no_newline = stat_line("n", "6");
    no_newline.pop();
    assert_eq!(stat_start_time(&no_newline), Some(6));
    assert_eq!(stat_start_time(&stat_line("n", "-1")), None);
    assert_eq!(stat_start_time(&stat_line("n", "1x")), None);
    assert_eq!(stat_start_time(&stat_line("n", "")), None, "an empty field");
    assert_eq!(stat_start_time(b"4100 (n) S 1 2 3\n"), None, "too few fields");
    assert_eq!(stat_start_time(b"4100 n S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21\n"), None, "no name");
    assert_eq!(stat_start_time(b"4100 )n( S 1\n"), None);
    assert_eq!(stat_start_time(b""), None);
}

#[test]
fn cgroup_files_are_compared_as_line_sets() {
    let leaf = b"0::/planeon.slice/planeon-capacity-broker.service/broker\n";
    assert!(same_lines(leaf, b"0::/planeon.slice/planeon-capacity-broker.service/broker"));
    assert!(!same_lines(b"0::/planeon.slice/planeon-capacity-broker.service/probe-worker\n", leaf));
    assert!(!same_lines(b"0::/planeon.slice/planeon-capacity-broker.service/broker\n1:name=x:/\n", leaf), "an extra line");
    assert!(same_lines(b"1:a:/x\n0::/y\n", b"0::/y\n1:a:/x\n"), "order does not matter");
    assert!(!same_lines(b"", b""), "an empty file is not a line set");
    assert_eq!(line_set(b"a\n\nb\n"), None, "an empty line");
    assert_eq!(line_set(b"a\nb").map(|lines| lines.len()), Some(2));
}

#[test]
fn a_process_identity_needs_field_22_and_a_line_set() {
    let identity = ProcIdentity::from_files(&stat_line("n", "42"), b"0::/z\n".to_vec(), with_nul(BROKER));
    assert_eq!(identity, Some(ProcIdentity { start_time: 42, cgroup: b"0::/z\n".to_vec(), label: with_nul(BROKER) }));
    assert_eq!(ProcIdentity::from_files(b"bad", b"0::/z\n".to_vec(), Vec::new()), None);
    assert_eq!(ProcIdentity::from_files(&stat_line("n", "42"), Vec::new(), Vec::new()), None);
}
