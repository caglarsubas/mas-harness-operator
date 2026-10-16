//! gate-sys's HE-003A2 addition to the openat module on the build host (DESIGN §3, §9): `Dir::read_link` on real
//! symbolic links in a scratch directory. The count when the link fits with a byte to spare; a link that fills the
//! buffer (possibly truncated), an empty buffer, a missing name, a name that is not a link and every name the store-name
//! check refuses (an absolute one included, which would make the kernel ignore the directory) are refused. The read
//! through a process directory, the kernel's truncation without an error and its errno set are T04's. Everything is
//! written under cargo's `CARGO_TARGET_TMPDIR`.

use std::io;

use gate_sys::Dir;

/// A fresh directory for one test.
fn scratch(test: &str) -> String {
    let path = format!("{}/gate-sys-he003a2/{test}", env!("CARGO_TARGET_TMPDIR"));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("scratch directory");
    path
}

fn done(path: String) {
    let _ = std::fs::remove_dir_all(path);
}

fn kind<T: std::fmt::Debug>(result: io::Result<T>) -> io::ErrorKind {
    match result {
        Ok(value) => panic!("refused, got {value:?}"),
        Err(error) => error.kind(),
    }
}

/// The enrolled writer path's shape, as a link target (the link need not resolve).
const TARGET: &str = "/opt/planeon/bin/harness-policy-write";

#[test]
fn a_link_that_fits_with_a_byte_to_spare_is_read_exactly() {
    let base = scratch("exact");
    std::os::unix::fs::symlink(TARGET, format!("{base}/exe")).expect("link");
    let directory = Dir::at(&base).expect("opens");
    let mut buffer = vec![0u8; TARGET.len() + 1];
    assert_eq!(directory.read_link("exe", &mut buffer).expect("reads"), TARGET.len());
    assert_eq!(&buffer[..TARGET.len()], TARGET.as_bytes());
    assert_eq!(buffer[TARGET.len()], 0, "the byte to spare is untouched (no NUL is written)");
    // A larger buffer reads the same count.
    let mut large = vec![0u8; 4096];
    assert_eq!(directory.read_link("exe", &mut large).expect("reads"), TARGET.len());
    // A relative target is read as written.
    std::os::unix::fs::symlink("bin/x", format!("{base}/relative")).expect("link");
    let mut small = [0u8; 6];
    assert_eq!(directory.read_link("relative", &mut small).expect("reads"), 5);
    assert_eq!(&small[..5], b"bin/x");
    done(base);
}

#[test]
fn a_link_that_fills_the_buffer_is_refused() {
    let base = scratch("full");
    std::os::unix::fs::symlink(TARGET, format!("{base}/exe")).expect("link");
    let deleted = format!("{TARGET} (deleted)");
    std::os::unix::fs::symlink(&deleted, format!("{base}/replaced")).expect("link");
    let directory = Dir::at(&base).expect("opens");
    // Exactly the link's length: the count equals the buffer, so the link may be longer.
    let mut equal = vec![0u8; TARGET.len()];
    assert_eq!(kind(directory.read_link("exe", &mut equal)), io::ErrorKind::InvalidInput);
    let mut shorter = vec![0u8; 3];
    assert_eq!(kind(directory.read_link("exe", &mut shorter)), io::ErrorKind::InvalidInput);
    // The enrolled path's buffer (its length + 1) against a longer link, as the " (deleted)" rendering would be.
    let mut enrolled = vec![0u8; TARGET.len() + 1];
    assert_eq!(kind(directory.read_link("replaced", &mut enrolled)), io::ErrorKind::InvalidInput);
    let mut wide = vec![0u8; deleted.len() + 1];
    assert_eq!(directory.read_link("replaced", &mut wide).expect("reads"), deleted.len());
    done(base);
}

#[test]
fn an_empty_buffer_a_missing_name_and_a_name_that_is_no_link_are_refused() {
    let base = scratch("refused");
    std::os::unix::fs::symlink(TARGET, format!("{base}/exe")).expect("link");
    std::fs::write(format!("{base}/plain"), b"x").expect("plain");
    std::fs::create_dir(format!("{base}/sub")).expect("sub");
    let directory = Dir::at(&base).expect("opens");
    let mut empty: [u8; 0] = [];
    assert_eq!(kind(directory.read_link("exe", &mut empty)), io::ErrorKind::InvalidInput);
    let mut buffer = vec![0u8; 256];
    assert_eq!(kind(directory.read_link("missing", &mut buffer)), io::ErrorKind::NotFound);
    // readlinkat on something that is not a link: EINVAL from the OS.
    assert_eq!(kind(directory.read_link("plain", &mut buffer)), io::ErrorKind::InvalidInput);
    assert_eq!(kind(directory.read_link("sub", &mut buffer)), io::ErrorKind::InvalidInput);
    done(base);
}

#[test]
fn only_one_relative_component_is_read() {
    let base = scratch("names");
    std::fs::create_dir(format!("{base}/inner")).expect("inner");
    std::os::unix::fs::symlink(TARGET, format!("{base}/inner/exe")).expect("link");
    std::os::unix::fs::symlink(TARGET, format!("{base}/exe")).expect("link");
    let directory = Dir::at(&base).expect("opens");
    let mut buffer = vec![0u8; 256];
    // An absolute name would make the kernel ignore the directory's descriptor: refused before any call, as are a path
    // of two components, the empty name, `.`, `..`, a NUL and a name longer than 255 bytes.
    let absolute = format!("{base}/exe");
    let long = "e".repeat(256);
    for name in [absolute.as_str(), "inner/exe", "", ".", "..", "e\0xe", long.as_str()] {
        assert_eq!(kind(directory.read_link(name, &mut buffer)), io::ErrorKind::InvalidInput, "{name:?}");
    }
    // The same link through the inner directory's own descriptor reads.
    let inner = directory.sub("inner").expect("inner");
    assert_eq!(inner.read_link("exe", &mut buffer).expect("reads"), TARGET.len());
    done(base);
}
