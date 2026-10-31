//! HE-005C (the frozen seam note, sections 3, 4 and 6; delta C3 revision 2, C3-2): the lifecycle's pure readers, the
//! leaf's membership line, the broker's label, the timing constants, and the stand-ins' answers.

use broker_sys::{FdEntry, FdIdentity, W3Expect};
use planeon_broker::lifecycle::leaf::membership;
use planeon_broker::lifecycle::np9::{NP9_HOLD_MS, NP9_RESERVE_MS};
use planeon_broker::lifecycle::seams::{BindAnswer, BindTicket, Binder, BinderStandIn, GateAnswer, GateQualifier, GateTicket,
                                       QualifierStandIn};
use planeon_broker::lifecycle::text::{descriptors_hold, events, groups_empty, ids_are_root, in_leaf, is_domain,
                                      label_matches, procs_empty, stat_identity, Events, BROKER_LABEL, S_IFMT, S_IFSOCK};
use planeon_broker::lifecycle::wait::{FREEZE_WAIT_MS, POLL_MS};

const CHAR_DEVICE: u32 = 0o020000;
const SOCKET: u32 = 0o140000;
const REGULAR: u32 = 0o100000;
const DIRECTORY: u32 = 0o040000;

#[test]
fn the_leaf_and_the_label_are_native_profile_v4s() {
    assert_eq!(membership(), "/planeon.slice/planeon-capacity-broker.service/probe-worker");
    assert_eq!(BROKER_LABEL, "system_u:system_r:planeon_broker_t:s0");
    assert_eq!((S_IFMT, S_IFSOCK), (0o170000, SOCKET));
}

#[test]
fn the_timing_constants() {
    assert_eq!((POLL_MS, FREEZE_WAIT_MS, NP9_HOLD_MS), (100, 2_000, 70_000));
    // The reserve is W6's bound (w6.rs, 10 s) and one freeze wait.
    assert_eq!(NP9_RESERVE_MS, 10_000 + FREEZE_WAIT_MS);
}

#[test]
fn events_reads_populated_and_frozen_exactly_once_each() {
    assert_eq!(events(b"populated 0\nfrozen 1\n"), Some(Events { populated: false, frozen: true }));
    assert_eq!(events(b"frozen 0\npopulated 1"), Some(Events { populated: true, frozen: false }));
    assert_eq!(events(b"populated 0\nnew 7\nfrozen 0\n"), Some(Events { populated: false, frozen: false }));
    let bad: [&[u8]; 9] = [b"", b"\n", b"populated 0\n", b"frozen 0\n", b"populated 2\nfrozen 0\n",
                           b"populated 0\npopulated 0\nfrozen 0\n", b"populated 0\nfrozen 0\n\n", b"populated  0\nfrozen 0\n",
                           b"populated0\nfrozen 0\n"];
    for text in bad {
        assert_eq!(events(text), None, "{:?}", String::from_utf8_lossy(text));
    }
}

#[test]
fn the_type_and_procs_readers() {
    assert!(is_domain(b"domain\n") && is_domain(b"domain"));
    assert!(!is_domain(b"threaded\n") && !is_domain(b"domain threaded\n") && !is_domain(b"domain\n\n") && !is_domain(b""));
    assert!(procs_empty(b""));
    assert!(!procs_empty(b"4242\n") && !procs_empty(b"\n"));
}

#[test]
fn the_status_readers() {
    let status = b"Name:\tplaneon-broker\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\nNSpid:\t4242\n";
    assert!(ids_are_root(status, b"Uid:") && ids_are_root(status, b"Gid:") && groups_empty(status));
    assert!(!ids_are_root(b"Uid:\t0\t10001\t0\t0\n", b"Uid:"));
    assert!(!ids_are_root(b"Uid:\t0\t0\t0\n", b"Uid:"));
    assert!(!ids_are_root(b"Uid:\t0\t0\t0\t0\t0\n", b"Uid:"));
    assert!(!ids_are_root(b"Uid:\t0\t0\t0\t0\nUid:\t0\t0\t0\t0\n", b"Uid:"));
    assert!(!ids_are_root(b"Gid:\t0\t0\t0\t0\n", b"Uid:"));
    assert!(groups_empty(b"Groups: \t\n"));
    assert!(!groups_empty(b"Groups:\t10\n") && !groups_empty(b"Uid:\t0\t0\t0\t0\n") && !groups_empty(b"Groups:\nGroups:\n"));
}

/// A `stat` line with `pid` and `start` (field 22).
fn stat_line(pid: &str, start: &str) -> Vec<u8> {
    let mut fields = vec!["S".to_string()];
    fields.extend((4..=21).map(|field: u32| field.to_string()));
    fields.push(start.to_string());
    fields.extend((23..=52).map(|field: u32| field.to_string()));
    format!("{pid} (planeon) broker) {}\n", fields.join(" ")).into_bytes()
}

#[test]
fn the_stat_reader() {
    assert_eq!(stat_identity(&stat_line("4242", "123456")), Some((4242, 123_456)));
    assert_eq!(stat_identity(stat_line("4242", "123456").strip_suffix(b"\n").unwrap_or_default()), Some((4242, 123_456)));
    for (pid, start) in [("x", "1"), ("", "1"), ("4242", "12a"), ("4242", ""), ("99999999999", "1")] {
        assert_eq!(stat_identity(&stat_line(pid, start)), None, "{pid} {start}");
    }
    assert_eq!(stat_identity(b"4242 planeon S 1 2 3\n"), None);
    assert_eq!(stat_identity(b"4242 (planeon) S 1 2 3\n"), None);
}

#[test]
fn the_cgroup_and_label_readers() {
    let line = format!("0::{}\n", membership());
    assert!(in_leaf(line.as_bytes(), membership()));
    assert!(in_leaf(line.trim_end().as_bytes(), membership()));
    assert!(!in_leaf(format!("{line}0::/other\n").as_bytes(), membership()));
    assert!(!in_leaf(format!("1:name=systemd:/x\n{line}").as_bytes(), membership()));
    assert!(!in_leaf(b"0::/planeon.slice/planeon-capacity-broker.service\n", membership()));
    assert!(!in_leaf(b"0::\n", ""));
    let label = [BROKER_LABEL.as_bytes(), b"\0".as_slice()].concat();
    assert!(label_matches(&label, BROKER_LABEL.as_bytes()) && label_matches(BROKER_LABEL.as_bytes(), BROKER_LABEL.as_bytes()));
    assert!(!label_matches(&[label.as_slice(), b"\0".as_slice()].concat(), BROKER_LABEL.as_bytes()));
    assert!(!label_matches(&[BROKER_LABEL.as_bytes(), b"\n".as_slice()].concat(), BROKER_LABEL.as_bytes()));
    assert!(!label_matches(b"system_u:system_r:planeon_worker_t:s0\0", BROKER_LABEL.as_bytes()));
    assert!(!label_matches(b"\0", b""));
}

fn expect() -> W3Expect {
    W3Expect { channel: FdIdentity { number: 5, dev: 1, ino: 100 }, script: FdIdentity { number: 6, dev: 2, ino: 200 } }
}

/// The frozen child's table before its own steps, in the kernel's order: fds 0-2, the two sources, a broker directory.
fn table() -> Vec<FdEntry> {
    let entry = |number, dev, ino, mode| FdEntry { number, dev, ino, mode };
    vec![entry(6, 2, 200, REGULAR), entry(0, 9, 1, CHAR_DEVICE), entry(5, 1, 100, SOCKET), entry(2, 9, 1, CHAR_DEVICE),
         entry(1, 9, 1, CHAR_DEVICE), entry(8, 3, 300, DIRECTORY)]
}

#[test]
fn the_descriptor_check_sorts_then_checks_stdio_and_the_two_sources() {
    assert!(descriptors_hold(table(), &expect()));
    let mut socket = table();
    socket[4].mode = SOCKET;
    let mut absent = table();
    absent.remove(3);
    let mut twice = table();
    twice.push(FdEntry { number: 5, dev: 1, ino: 100, mode: SOCKET });
    let mut channel = table();
    channel[2].ino = 101;
    let mut script = table();
    script[0].dev = 3;
    let mut no_script = table();
    no_script.remove(0);
    for (case, mutated) in [("fd 1 a socket", socket), ("fd 2 absent", absent), ("a number twice", twice),
                            ("the channel's inode", channel), ("the script's device", script), ("no fd 6", no_script)] {
        assert!(!descriptors_hold(mutated, &expect()), "{case}");
    }
}

#[test]
fn the_stand_ins_answer_unavailable_and_the_success_answers_carry_data() {
    assert_eq!(QualifierStandIn.qualify(), GateAnswer::Unavailable);
    assert_eq!(BinderStandIn.bind(&GateTicket { generation: 7 }, 4242, 9), BindAnswer::Unavailable);
    assert!(std::mem::size_of::<GateTicket>() > 0 && std::mem::size_of::<BindTicket>() > 0);
    assert!(std::mem::size_of::<GateAnswer>() > 0 && std::mem::size_of::<BindAnswer>() > 0);
    assert_ne!(GateAnswer::Qualified(GateTicket { generation: 7 }), GateAnswer::Unavailable);
    assert_ne!(BindAnswer::Bound(BindTicket { pid: 4242, start_ticks: 9 }), BindAnswer::Unavailable);
}
