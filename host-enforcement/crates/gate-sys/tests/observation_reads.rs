//! gate-sys's observation reads on the build host (HE-003A3 DESIGN sections 5 and 9): every refusal of `FixedPath`
//! (1 to 4 components of `[A-Za-z0-9._-]+`, none empty, `.` or `..`; `<pid>/stat` only for a number of at least 1), and
//! the bounded plain-`read` helper on files under cargo's `CARGO_TARGET_TMPDIR` (an empty file, the bound exactly,
//! one byte past it, a read error). `KernelRoot` (an `O_PATH` handle) and `PidFd::open` are Linux only and wait for
//! T04 on a real kernel.

use std::fs::File;
use std::io::Write;

use gate_sys::openat::{read_bounded, FixedPath, MAX_FIXED_COMPONENTS};

const LEAF: &str = "planeon.slice/planeon-capacity-broker.service/probe-worker/cgroup.procs";

fn scratch(test: &str) -> String {
    let path = format!("{}/gate-sys-observation/{test}", env!("CARGO_TARGET_TMPDIR"));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("scratch directory");
    path
}

fn written(directory: &str, name: &str, bytes: &[u8]) -> File {
    let path = format!("{directory}/{name}");
    File::create(&path).expect("create").write_all(bytes).expect("write");
    File::open(&path).expect("open")
}

#[test]
fn fixed_paths_from_constants() {
    assert_eq!(MAX_FIXED_COMPONENTS, 4);
    assert_eq!(FixedPath::from_constant(LEAF).expect("the leaf").as_bytes(), LEAF.as_bytes());
    for good in ["a", "a/b", "a.b/c_d/e-f/G9", "...", "a..b", ".a", "a."] {
        assert!(FixedPath::from_constant(good).is_ok(), "{good}");
    }
    for bad in ["", "/", "/a", "a/", "a//b", ".", "..", "./a", "a/.", "a/../b", "a/b/c/d/e", "a b", "a:b", "a\\b", "a\u{0}b",
                "\u{e4}", "a\nb", "a*b", "~", "a/b/c/../d"] {
        let refused = FixedPath::from_constant(bad).expect_err(bad);
        assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput, "{bad:?}");
        assert_eq!(refused.raw_os_error(), None, "{bad:?}: no errno, so the driver sees NoErrno");
    }
}

#[test]
fn fixed_stat_paths() {
    assert_eq!(FixedPath::pid_stat(1).expect("1").as_bytes(), b"1/stat");
    assert_eq!(FixedPath::pid_stat(4100).expect("4100").as_bytes(), b"4100/stat");
    assert_eq!(FixedPath::pid_stat(i32::MAX).expect("max").as_bytes(), b"2147483647/stat");
    for pid in [0, -1, -4100, i32::MIN] {
        assert_eq!(FixedPath::pid_stat(pid).expect_err("refused").kind(), std::io::ErrorKind::InvalidInput, "{pid}");
    }
}

#[test]
fn the_bounded_read() {
    let directory = scratch("bounded");
    assert_eq!(read_bounded(&written(&directory, "empty", b""), 16).expect("read"), Some(Vec::new()));
    assert_eq!(read_bounded(&written(&directory, "empty0", b""), 0).expect("read"), Some(Vec::new()));
    assert_eq!(read_bounded(&written(&directory, "one0", b"x"), 0).expect("read"), None);
    let exact = vec![b'7'; 65_536];
    assert_eq!(read_bounded(&written(&directory, "exact", &exact), 65_536).expect("read"), Some(exact.clone()));
    let mut over = exact.clone();
    over.push(b'\n');
    assert_eq!(read_bounded(&written(&directory, "over", &over), 65_536).expect("read"), None);
    assert_eq!(read_bounded(&written(&directory, "stat", &exact[..4096]), 4096).expect("read"), Some(exact[..4096].to_vec()));
    assert_eq!(read_bounded(&written(&directory, "stat-over", &exact[..4097]), 4096).expect("read"), None);
    // A read error (a directory opened read-only answers EISDIR) is the OS's error, with its errno.
    let error = read_bounded(&File::open(&directory).expect("the directory opens"), 16).expect_err("EISDIR");
    assert!(error.raw_os_error().is_some(), "{error:?}");
    let _ = std::fs::remove_dir_all(directory);
}
