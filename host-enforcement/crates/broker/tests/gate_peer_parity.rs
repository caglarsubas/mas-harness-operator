//! HE-005B U5 (MON-R10-HE005B-U4-OK, choice 3's condition): gate_peer.rs's four readers against gate-sys's originals in
//! `gate_sys::peer_wire` (`label_matches`, `line_set`, `same_lines`, `stat_start_time`), on shared inputs, the same
//! answer for every one. gate_peer.rs names no gate-sys item (G-HE5B-2), so the copies are compared here, in a test,
//! where planeon-broker's gate-sys dependency is in reach.

use gate_sys::peer_wire;
use planeon_broker::gate_peer;

const LABELS: [&[u8]; 9] = [b"system_u:system_r:planeon_gate_t:s0\0", b"system_u:system_r:planeon_gate_t:s0",
    b"system_u:system_r:planeon_gate_t:s0\0\0", b"system_u:system_r:planeon_gate_t:s0\n", b"", b"\0",
    b"system_u:system_r:planeon_broker_t:s0\0", b"\0system_u:system_r:planeon_gate_t:s0", b"s0\0"];
const EXPECTED_LABELS: [&[u8]; 4] = [b"system_u:system_r:planeon_gate_t:s0", b"", b"\0", b"s0"];

const CGROUPS: [&[u8]; 12] = [b"", b"\n", b"\n\n", b"0::/planeon.slice/planeon-effect-gate.service\n",
    b"0::/planeon.slice/planeon-effect-gate.service", b"0::/planeon.slice/planeon-effect-gate.service\n\n",
    b"0::/a\n1:name=x:/b\n", b"1:name=x:/b\n0::/a\n", b"0::/a\n0::/a\n", b"\n0::/a\n", b"0::/a\r\n", b"0::/a\n \n"];

const STATS: [&[u8]; 16] = [
    b"4242 (planeon-gate) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 12345678 300\n",
    b"4242 (planeon-gate) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 12345678 300",
    b"4242 (gate) x) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1 2\n",
    b"4242 (planeon-gate) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654\n",
    b"4242 (planeon-gate) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0\n",
    b"4242 (planeon-gate) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98x654 1\n",
    b"4242 (planeon-gate) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0  987654 1\n",
    b"4242 (planeon-gate)S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1\n",
    b"4242 (planeon-gate) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1\n\n",
    b"4242 (planeon-gate) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 99999999999999999999999 1\n",
    b"4242 (planeon-gate) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 +987654 1\n",
    b"4242 )planeon-gate( S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1\n",
    b"4242 planeon-gate S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1\n",
    b"",
    b"()",
    b"x (y) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 0\n",
];

#[test]
fn label_matches_agrees() {
    for delivered in LABELS {
        for expected in EXPECTED_LABELS {
            assert_eq!(gate_peer::label_matches(delivered, expected), peer_wire::label_matches(delivered, expected),
                       "{delivered:?} against {expected:?}");
        }
    }
}

#[test]
fn line_set_and_same_lines_agree() {
    for text in CGROUPS {
        assert_eq!(gate_peer::line_set(text), peer_wire::line_set(text), "{text:?}");
        for other in CGROUPS {
            assert_eq!(gate_peer::same_lines(text, other), peer_wire::same_lines(text, other), "{text:?} and {other:?}");
        }
    }
}

#[test]
fn stat_start_time_agrees() {
    let mut readable = 0;
    for stat in STATS {
        let ours = gate_peer::stat_start_time(stat);
        assert_eq!(ours, peer_wire::stat_start_time(stat), "{stat:?}");
        readable += usize::from(ours.is_some());
    }
    assert!(readable >= 4, "the shared inputs hold readable lines");
}
