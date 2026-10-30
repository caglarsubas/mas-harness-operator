//! HE-005B's gate-qualification tests (the HE-005B plan's items 5 and 6; O10, O11; Q-HE5B-5 (a)): a good observation
//! qualifies, for either socket pidfd, and its token holds every later frame with the same pid and start time; one
//! failing case for each gate-qualification mismatch and each per-frame one; and the expected label, ids and cgroup
//! line against native-profile v4's EFFECT_GATE role, read from the vendored schema. The token itself cannot be built
//! here: its fields are private and it has no constructor but `qualify_gate` (G-HE5B-5 holds that in the source).

use i05_protocol::json::{self, Value};
use planeon_broker::gate_peer::{
    compare_start_time, qualify_gate, GateObservation, GateRefusal, PeerCredentials, SocketPidfd, GATE_CGROUP,
    GATE_GID, GATE_LABEL, GATE_UID,
};

const NATIVE_PROFILE_V4: &str = include_str!("../../../contracts/native-profile-v4/qualification.schema.json");

/// A signed `gateExecutablePath` for the tests.
const GATE_PATH: &str = "/opt/planeon/bin/planeon-gate";
const PID: i64 = 4242;
const START: u64 = 987_654;

/// A `stat` line whose field 1 is `pid` and field 22 `start`.
fn stat_line(pid: i64, start: u64) -> Vec<u8> {
    format!("{pid} (planeon-gate) S 1 {pid} {pid} 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 {start} 12345678 300\n")
        .into_bytes()
}

fn good() -> GateObservation {
    GateObservation {
        credentials: PeerCredentials { pid: PID, uid: 0, gid: 0 },
        pidfd: SocketPidfd::PeerPidfd,
        exe_link: GATE_PATH.as_bytes().to_vec(),
        attr_current: b"system_u:system_r:planeon_gate_t:s0\0".to_vec(),
        cgroup: b"0::/planeon.slice/planeon-effect-gate.service\n".to_vec(),
        stat: stat_line(PID, START),
        exited: false,
    }
}

fn member<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or_else(|| panic!("member {key}"))
}

#[test]
fn a_good_observation_qualifies_and_holds_every_frame() {
    for pidfd in [SocketPidfd::PeerPidfd, SocketPidfd::ScmPidfd] {
        let observed = GateObservation { pidfd, ..good() };
        let qualified = qualify_gate(&observed, GATE_PATH).expect("the gate qualifies");
        for _ in 0..3 {
            assert_eq!(compare_start_time(&qualified, &stat_line(PID, START), false), Ok(()));
        }
    }
    // The label without its NUL, and the cgroup file without its final newline, read the same.
    let observed = GateObservation { attr_current: GATE_LABEL.as_bytes().to_vec(), ..good() };
    assert!(qualify_gate(&observed, GATE_PATH).is_ok());
    let observed = GateObservation { cgroup: GATE_CGROUP.as_bytes().to_vec(), ..good() };
    assert!(qualify_gate(&observed, GATE_PATH).is_ok());
    // A command name holding a parenthesis and a space: the fields count from the last `)`.
    let observed = GateObservation {
        stat: format!("{PID} (gate) x) S 1 {PID} {PID} 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 {START} 1 2\n")
            .into_bytes(),
        ..good()
    };
    assert!(qualify_gate(&observed, GATE_PATH).is_ok());
}

#[test]
fn each_qualification_mismatch_is_refused() {
    let credentials =
        |pid: i64, uid: u32, gid: u32| GateObservation { credentials: PeerCredentials { pid, uid, gid }, ..good() };
    let label = |text: &[u8]| GateObservation { attr_current: text.to_vec(), ..good() };
    let cgroup = |text: &[u8]| GateObservation { cgroup: text.to_vec(), ..good() };
    let exe = |text: &[u8]| GateObservation { exe_link: text.to_vec(), ..good() };
    let stat = |text: Vec<u8>| GateObservation { stat: text, ..good() };
    let cases: Vec<(&str, GateObservation, &str, GateRefusal)> = vec![
        ("pid 0", credentials(0, 0, 0), GATE_PATH, GateRefusal::Pid),
        ("a negative pid", credentials(-1, 0, 0), GATE_PATH, GateRefusal::Pid),
        ("another uid", credentials(PID, 1000, 0), GATE_PATH, GateRefusal::Uid),
        ("another gid", credentials(PID, 0, 10), GATE_PATH, GateRefusal::Gid),
        ("the broker's label", label(b"system_u:system_r:planeon_broker_t:s0\0"), GATE_PATH, GateRefusal::Label),
        ("two NULs", label(b"system_u:system_r:planeon_gate_t:s0\0\0"), GATE_PATH, GateRefusal::Label),
        ("a newline", label(b"system_u:system_r:planeon_gate_t:s0\n"), GATE_PATH, GateRefusal::Label),
        ("another level", label(b"system_u:system_r:planeon_gate_t:s0:c1\0"), GATE_PATH, GateRefusal::Label),
        ("an empty label", label(b""), GATE_PATH, GateRefusal::Label),
        ("another unit", cgroup(b"0::/planeon.slice/planeon-capacity-broker.service\n"), GATE_PATH,
         GateRefusal::Cgroup),
        ("a child cgroup", cgroup(b"0::/planeon.slice/planeon-effect-gate.service/x\n"), GATE_PATH,
         GateRefusal::Cgroup),
        ("a second line", cgroup(b"0::/planeon.slice/planeon-effect-gate.service\n1:name=x:/\n"), GATE_PATH,
         GateRefusal::Cgroup),
        ("an empty cgroup file", cgroup(b""), GATE_PATH, GateRefusal::Cgroup),
        ("another executable", exe(b"/opt/planeon/bin/other"), GATE_PATH, GateRefusal::Executable),
        ("a replaced executable", exe(b"/opt/planeon/bin/planeon-gate (deleted)"), GATE_PATH, GateRefusal::Executable),
        ("an empty signed path", exe(b""), "", GateRefusal::Executable),
        ("no parenthesis", stat(b"4242 planeon-gate S 1".to_vec()), GATE_PATH, GateRefusal::Stat),
        ("too few fields", stat(format!("{PID} (planeon-gate) S 1 2 3\n").into_bytes()), GATE_PATH, GateRefusal::Stat),
        ("a start time that is not a number", stat(stat_line(PID, START).iter().map(|byte| if *byte == b'9' { b'x' }
            else { *byte }).collect()), GATE_PATH, GateRefusal::Stat),
        ("another pid in stat", stat(stat_line(PID + 1, START)), GATE_PATH, GateRefusal::StatPid),
        ("exited after the reads", GateObservation { exited: true, ..good() }, GATE_PATH, GateRefusal::Exited),
    ];
    for (name, observed, path, refusal) in cases {
        assert_eq!(qualify_gate(&observed, path).err(), Some(refusal), "{name}");
    }
}

#[test]
fn each_frame_compares_the_start_time() {
    let qualified = qualify_gate(&good(), GATE_PATH).expect("the gate qualifies");
    assert_eq!(compare_start_time(&qualified, &stat_line(PID, START + 1), false), Err(GateRefusal::StartTime));
    assert_eq!(compare_start_time(&qualified, &stat_line(PID + 1, START), false), Err(GateRefusal::StatPid));
    assert_eq!(compare_start_time(&qualified, &stat_line(PID, START), true), Err(GateRefusal::Exited));
    assert_eq!(compare_start_time(&qualified, b"4242 (planeon-gate)", false), Err(GateRefusal::Stat));
    // The comparison holds no state: the reference stays the first frame's.
    assert_eq!(compare_start_time(&qualified, &stat_line(PID, START), false), Ok(()));
}

#[test]
fn the_constants_are_native_profile_v4s_effect_gate_role() {
    let schema = json::parse(NATIVE_PROFILE_V4).expect("the schema parses");
    let role = member(member(member(member(&schema, "$defs"), "roles"), "properties"), "EFFECT_GATE");
    let properties = member(role, "properties");
    let constant = |name: &str| member(member(properties, name), "const").clone();
    assert_eq!(constant("processLabel").as_str(), Some(GATE_LABEL));
    assert_eq!(constant("uid").as_int().and_then(|n| n.to_u64()), Some(u64::from(GATE_UID)));
    assert_eq!(constant("gid").as_int().and_then(|n| n.to_u64()), Some(u64::from(GATE_GID)));
    let path = member(member(member(member(properties, "cgroup"), "properties"), "path"), "const").as_str()
        .expect("the cgroup path");
    let below_mount = path.find("/planeon.slice/").map(|at| &path[at..]).expect("below the mount point");
    assert_eq!(format!("0::{below_mount}"), GATE_CGROUP);
    assert_eq!(GATE_LABEL.split(':').nth(2), Some("planeon_gate_t"));
}
