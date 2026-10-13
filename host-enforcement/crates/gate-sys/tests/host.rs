//! gate-sys on the build host (HE-002C DESIGN §11): directory and name refusals, `O_NOFOLLOW`, the exclusive create
//! and its fallback, the regular-file check, close-on-exec observed from a child process, and `flock` between two
//! descriptors of one file. Everything is written under cargo's `CARGO_TARGET_TMPDIR`.
//!
//! The close-on-exec test is meaningful because the pinned Darwin std's `Command::spawn` does not ask `posix_spawn` to
//! close inherited descriptors by default (no `POSIX_SPAWN_CLOEXEC_DEFAULT` among its spawn attribute flags, design
//! review round 3, D4): a descriptor opened without `O_CLOEXEC` would still be open in the child.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::process::Command;

use gate_sys::Dir;
use gate_sys::FileMode;

/// A fresh directory for one test.
fn scratch(test: &str) -> String {
    let path = format!("{}/gate-sys/{test}", env!("CARGO_TARGET_TMPDIR"));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("scratch directory");
    path
}

/// Removes a test's directory at the end of the test; a failed test stops before it, so its directory stays.
fn done(path: String) {
    let _ = std::fs::remove_dir_all(path);
}

fn dir(path: &str) -> Dir {
    Dir::at(path).expect("the scratch directory opens")
}

fn kind<T: std::fmt::Debug>(result: io::Result<T>) -> io::ErrorKind {
    result.expect_err("refused").kind()
}

/// `ELOOP`, which `io::ErrorKind` names only on nightly.
#[cfg(target_os = "macos")]
const ELOOP: i32 = 62;
#[cfg(target_os = "linux")]
const ELOOP: i32 = 40;

fn os_error<T: std::fmt::Debug>(result: io::Result<T>) -> Option<i32> {
    result.expect_err("refused").raw_os_error()
}

#[test]
fn a_directory_path_must_be_an_absolute_directory() {
    let base = scratch("dir_at");
    std::fs::write(format!("{base}/plain"), b"x").expect("plain file");
    assert_eq!(kind(Dir::at(&format!("{base}/plain"))), io::ErrorKind::NotADirectory);
    assert_eq!(kind(Dir::at(&format!("{base}/missing"))), io::ErrorKind::NotFound);
    assert_eq!(kind(Dir::at("relative/path")), io::ErrorKind::InvalidInput);
    assert_eq!(kind(Dir::at(&format!("{base}/a\0b"))), io::ErrorKind::InvalidInput);
    // A symbolic link to a directory is a directory path; only the store file names refuse links.
    std::os::unix::fs::symlink(&base, format!("{base}-link")).ok();
    assert!(Dir::at(&format!("{base}-link")).is_ok());
    let _ = std::fs::remove_file(format!("{base}-link"));
    done(base);
}

#[test]
fn store_names_are_checked_before_any_call() {
    let base = scratch("names");
    let directory = dir(&base);
    let long = "n".repeat(256);
    for name in ["", ".", "..", "a/b", "/abs", "a\0b", long.as_str()] {
        assert_eq!(kind(directory.file(name, FileMode::CreateOrExisting)), io::ErrorKind::InvalidInput, "{name:?}");
    }
    let longest = "n".repeat(255);
    assert!(matches!(directory.file(&longest, FileMode::CreateOrExisting), Ok(Some((_, true)))));
    done(base);
}

#[test]
fn a_final_symbolic_link_is_never_followed() {
    let base = scratch("nofollow");
    std::fs::write(format!("{base}/target"), b"x").expect("target");
    std::os::unix::fs::symlink(format!("{base}/target"), format!("{base}/link")).expect("link");
    std::os::unix::fs::symlink(format!("{base}/absent"), format!("{base}/dangling")).expect("dangling link");
    let directory = dir(&base);
    for name in ["link", "dangling"] {
        assert_eq!(os_error(directory.file(name, FileMode::Existing)), Some(ELOOP), "{name}");
        assert_eq!(os_error(directory.file(name, FileMode::CreateOrExisting)), Some(ELOOP), "{name}");
    }
    assert!(!std::fs::exists(format!("{base}/absent")).unwrap_or(true), "nothing was created through the link");
    done(base);
}

#[test]
fn the_exclusive_create_falls_back_to_a_plain_open() {
    let base = scratch("create");
    let directory = dir(&base);
    assert!(matches!(directory.file("store", FileMode::Existing), Ok(None)));
    let (file, created) = directory.file("store", FileMode::CreateOrExisting).expect("create").expect("a file");
    assert!(created);
    assert_eq!(std::fs::metadata(format!("{base}/store")).expect("metadata").mode() & 0o777, 0o600);
    file.write_all_at(b"kept", 0).expect("write");
    drop(file);
    let (file, created) = directory.file("store", FileMode::CreateOrExisting).expect("open").expect("a file");
    assert!(!created, "an existing name is opened, not created");
    let mut read = [0u8; 4];
    file.read_exact_at(&mut read, 0).expect("read");
    assert_eq!(&read, b"kept");
    let (file, created) = directory.file("store", FileMode::Existing).expect("open").expect("a file");
    assert!(!created);
    assert_eq!(file.metadata().expect("fstat").len(), 4);
    drop(file);
    done(base);
}

#[test]
fn only_regular_files_are_store_files() {
    let base = scratch("regular");
    let status = Command::new("/usr/bin/mkfifo").arg(format!("{base}/fifo")).status().expect("mkfifo runs");
    assert!(status.success(), "the FIFO was made");
    std::fs::create_dir(format!("{base}/sub")).expect("subdirectory");
    let directory = dir(&base);
    for mode in [FileMode::Existing, FileMode::CreateOrExisting] {
        assert_eq!(kind(directory.file("fifo", mode)), io::ErrorKind::InvalidInput, "a FIFO ({mode:?})");
        assert!(directory.file("sub", mode).is_err(), "a directory ({mode:?})");
    }
    done(base);
}

#[test]
fn store_descriptors_are_closed_on_exec() {
    let base = scratch("cloexec");
    let directory = dir(&base);
    let (first, _) = directory.file("one", FileMode::CreateOrExisting).expect("one").expect("a file");
    let (second, _) = directory.file("one", FileMode::Existing).expect("one again").expect("a file");
    for file in [&first, &second] {
        let descriptor = file.as_raw_fd();
        assert!(descriptor > 2);
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("test -e /dev/fd/{descriptor}"))
            .status()
            .expect("the shell runs");
        assert!(!status.success(), "descriptor {descriptor} reached the child");
    }
    drop((first, second));
    done(base);
}

#[test]
fn a_second_descriptor_cannot_take_the_lock() {
    let base = scratch("lock");
    let directory = dir(&base);
    let (first, _) = directory.file("journal", FileMode::CreateOrExisting).expect("first").expect("a file");
    let (second, _) = directory.file("journal", FileMode::Existing).expect("second").expect("a file");
    assert!(first.try_lock().is_ok());
    assert!(second.try_lock().is_err(), "flock conflicts between two open file descriptions");
    drop(first);
    assert!(second.try_lock().is_ok(), "closing the holder releases the lock");
    drop(second);
    done(base);
}

#[test]
fn the_directory_syncs_and_reports_its_device() {
    let base = scratch("device");
    let directory = dir(&base);
    directory.sync().expect("the directory syncs");
    let device = directory.device().expect("fstat");
    assert_eq!(device, std::fs::metadata(&base).expect("metadata").dev());
    drop(directory);
    done(base);
}
