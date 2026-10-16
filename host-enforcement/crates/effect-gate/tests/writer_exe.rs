//! HE-003A2 DESIGN §3 and §9 (D1-2): the writer executable check's portable parts, which `LinuxOs` calls: the buffer
//! size (the enrolled path's length + 1) and the exact comparison, host-tested with the exact, longer, truncated,
//! `" (deleted)"`, empty, prefix and one-byte-off cases, and composed with gate-sys's `Dir::read_link` on real symbolic
//! links under cargo's `CARGO_TARGET_TMPDIR` (the read through a peer's process directory is T04's).

use effect_gate::peers::{writer_exe_buffer_len, writer_exe_matches};
use gate_sys::Dir;

const ENROLLED: &[u8] = b"/opt/planeon/bin/harness-policy-write";

#[test]
fn the_buffer_is_one_byte_longer_than_the_enrolled_path() {
    assert_eq!(writer_exe_buffer_len(ENROLLED), ENROLLED.len() + 1);
    assert_eq!(writer_exe_buffer_len(b"/x"), 3);
    assert_eq!(writer_exe_buffer_len(b""), 1);
}

#[test]
fn only_the_exact_bytes_match() {
    assert!(writer_exe_matches(ENROLLED, ENROLLED));
    let deleted = [ENROLLED, b" (deleted)".as_slice()].concat();
    let longer = [ENROLLED, b"2".as_slice()].concat();
    let truncated = &ENROLLED[..ENROLLED.len() - 1];
    let prefix = b"/opt/planeon/bin";
    let mut off_by_one = ENROLLED.to_vec();
    *off_by_one.last_mut().expect("a byte") ^= 0x01;
    let mut first_off = ENROLLED.to_vec();
    first_off[0] = b'.';
    for (case, link) in [("a \" (deleted)\" suffix", deleted.as_slice()), ("one byte longer", longer.as_slice()),
                         ("truncated by one", truncated), ("a prefix", prefix.as_slice()), ("empty", b"".as_slice()),
                         ("the last byte off", off_by_one.as_slice()), ("the first byte off", first_off.as_slice()),
                         ("upper case", b"/OPT/PLANEON/BIN/HARNESS-POLICY-WRITE".as_slice())] {
        assert!(!writer_exe_matches(link, ENROLLED), "{case}");
    }
    // An empty enrolled value never matches, not even an empty link.
    assert!(!writer_exe_matches(b"", b""));
}

/// A fresh directory for one test.
fn scratch(test: &str) -> String {
    let path = format!("{}/effect-gate-he003a2/{test}", env!("CARGO_TARGET_TMPDIR"));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("scratch directory");
    path
}

/// The check as `LinuxOs` composes it: a buffer of the enrolled length + 1, `read_link`, then the comparison over the
/// count read (a refused read is a mismatch).
fn check(directory: &Dir, name: &str, expected: &[u8]) -> bool {
    let mut buffer = vec![0u8; writer_exe_buffer_len(expected)];
    match directory.read_link(name, &mut buffer) {
        Ok(count) => buffer.get(..count).is_some_and(|link| writer_exe_matches(link, expected)),
        Err(_) => false,
    }
}

#[test]
fn the_composed_check_on_real_links() {
    let base = scratch("composed");
    let enrolled = std::str::from_utf8(ENROLLED).expect("ASCII");
    let same_length = "/opt/planeon/bin/harness-policy-wrote".to_string();
    for (name, target) in [("exact", enrolled.to_string()), ("deleted", format!("{enrolled} (deleted)")),
                           ("longer", format!("{enrolled}-2")), ("shorter", enrolled[..enrolled.len() - 1].to_string()),
                           ("prefix", "/opt/planeon/bin".to_string()), ("same length", same_length)] {
        std::os::unix::fs::symlink(target, format!("{base}/{name}")).expect("link");
    }
    std::fs::write(format!("{base}/plain"), ENROLLED).expect("a file holding the path is not a link");
    let directory = Dir::at(&base).expect("opens");
    assert!(check(&directory, "exact", ENROLLED));
    for name in ["deleted", "longer", "shorter", "prefix", "same length", "plain", "missing"] {
        assert!(!check(&directory, name, ENROLLED), "{name}");
    }
    let _ = std::fs::remove_dir_all(base);
}
