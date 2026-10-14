//! gate-sys's HE-003A additions to the openat module on the build host (DESIGN §7, §9): `Dir::file`'s new flags
//! (values and bits only: a terminal node cannot be planted without root, so the behaviour is T04's), `Dir::sub` (one
//! directory component, never a link) and the manual `Debug` of `Dir` (the type name, no descriptor). Everything is
//! written under cargo's `CARGO_TARGET_TMPDIR`.

use std::io;
use std::io::Read;

use gate_sys::Dir;
use gate_sys::FileMode;

/// A fresh directory for one test.
fn scratch(test: &str) -> String {
    let path = format!("{}/gate-sys-he003a/{test}", env!("CARGO_TARGET_TMPDIR"));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("scratch directory");
    path
}

fn done(path: String) {
    let _ = std::fs::remove_dir_all(path);
}

fn kind<T>(result: io::Result<T>) -> io::ErrorKind {
    match result {
        Ok(_) => panic!("refused"),
        Err(error) => error.kind(),
    }
}

#[cfg(target_os = "macos")]
#[test]
fn the_flags_are_the_sdks() {
    // macOS 13.3 SDK `sys/fcntl.h`: O_RDWR 0x2, O_NONBLOCK 0x4, O_NOFOLLOW 0x100, O_NOCTTY 0x20000, O_DIRECTORY
    // 0x100000, O_CLOEXEC 0x1000000.
    assert_eq!(Dir::NOCTTY, 0x20000);
    assert_eq!(Dir::NONBLOCK, 0x4);
    assert_eq!(Dir::FILE_FLAGS, 0x2 | 0x1000000 | 0x100 | 0x4 | 0x20000);
    assert_eq!(Dir::SUB_FLAGS, 0x100000 | 0x1000000 | 0x100);
}

#[cfg(target_os = "linux")]
#[test]
fn the_flags_are_musls() {
    assert_eq!(Dir::NOCTTY, 0o400);
    assert_eq!(Dir::NONBLOCK, 0o4000);
    assert_eq!(Dir::FILE_FLAGS & 0o400, 0o400);
    assert_eq!(Dir::FILE_FLAGS & 0o4000, 0o4000);
    assert_eq!(Dir::FILE_FLAGS & 0o3, 2);
}

#[test]
fn file_carries_nonblock_and_noctty_and_still_opens_store_files() {
    assert_eq!(Dir::FILE_FLAGS & Dir::NOCTTY, Dir::NOCTTY);
    assert_eq!(Dir::FILE_FLAGS & Dir::NONBLOCK, Dir::NONBLOCK);
    assert_eq!(Dir::SUB_FLAGS & (Dir::NOCTTY | Dir::NONBLOCK), 0);
    let base = scratch("file");
    let directory = Dir::at(&base).expect("opens");
    let (file, created) = directory.file("journal", FileMode::CreateOrExisting).expect("creates").expect("a file");
    assert!(created);
    drop(file);
    assert!(matches!(directory.file("journal", FileMode::Existing), Ok(Some((_, false)))));
    done(base);
}

#[test]
fn sub_opens_one_directory_component_and_never_a_link() {
    let base = scratch("sub");
    std::fs::create_dir(format!("{base}/attr")).expect("attr");
    std::fs::write(format!("{base}/attr/current"), b"system_u:system_r:planeon_broker_t:s0\0").expect("current");
    std::fs::write(format!("{base}/plain"), b"x").expect("plain");
    std::os::unix::fs::symlink(format!("{base}/attr"), format!("{base}/link")).expect("link");
    let directory = Dir::at(&base).expect("opens");
    let mut text = Vec::new();
    directory.sub("attr").expect("sub").file_ro("current").expect("current").read_to_end(&mut text).expect("reads");
    assert_eq!(text, b"system_u:system_r:planeon_broker_t:s0\0");
    assert!(directory.sub("link").is_err(), "a symbolic link to a directory is refused");
    assert_eq!(kind(directory.sub("plain")), io::ErrorKind::NotADirectory);
    assert_eq!(kind(directory.sub("missing")), io::ErrorKind::NotFound);
    for name in ["", ".", "..", "attr/current", "a\0b"] {
        assert_eq!(kind(directory.sub(name)), io::ErrorKind::InvalidInput, "{name:?}");
    }
    done(base);
}

#[test]
fn dir_debug_prints_the_type_name_only() {
    let base = scratch("debug");
    let directory = Dir::at(&base).expect("opens");
    assert_eq!(format!("{directory:?}"), "Dir");
    assert_eq!(format!("{:?}", Dir::at(&base)), "Ok(Dir)");
    std::fs::create_dir(format!("{base}/inner")).expect("inner");
    assert_eq!(format!("{:?}", directory.sub("inner")), "Ok(Dir)");
    done(base);
}
