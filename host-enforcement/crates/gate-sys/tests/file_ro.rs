//! gate-sys's read-only opener on the build host (HE-002S DESIGN §6): `Dir::file_ro` reads a regular file and cannot
//! write through it, checks the name before any call, never follows a final symbolic link, refuses a FIFO (without
//! waiting for a writer) and a directory, reports a missing name as `NotFound`, closes on exec, and reads through a directory opened by a path
//! whose last component is a symbolic link (the shape of the seal's own status read). Everything is written under
//! cargo's `CARGO_TARGET_TMPDIR`. The seal's raw calls (`seal.rs`) are Linux only and wait for T04.

use std::io;
use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use gate_sys::Dir;

/// A fresh directory for one test.
fn scratch(test: &str) -> String {
    let path = format!("{}/gate-sys-ro/{test}", env!("CARGO_TARGET_TMPDIR"));
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

#[test]
fn a_regular_file_is_read_and_never_written() {
    let base = scratch("read");
    std::fs::write(format!("{base}/status"), b"Name:\tx\nThreads:\t1\n").expect("file");
    let mut file = dir(&base).file_ro("status").expect("opens");
    let mut text = String::new();
    file.read_to_string(&mut text).expect("reads");
    assert_eq!(text, "Name:\tx\nThreads:\t1\n");
    assert!(file.write_all(b"x").is_err(), "a read-only descriptor");
    drop(file);
    assert_eq!(std::fs::read(format!("{base}/status")).expect("read"), b"Name:\tx\nThreads:\t1\n");
    done(base);
}

#[test]
fn names_are_checked_before_any_call() {
    let base = scratch("names");
    let directory = dir(&base);
    let long = "n".repeat(256);
    for name in ["", ".", "..", "a/b", "/abs", "a\0b", long.as_str()] {
        assert_eq!(kind(directory.file_ro(name)), io::ErrorKind::InvalidInput, "{name:?}");
    }
    assert_eq!(kind(directory.file_ro("missing")), io::ErrorKind::NotFound);
    assert!(!std::fs::exists(format!("{base}/missing")).unwrap_or(true), "nothing is created");
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
        assert_eq!(directory.file_ro(name).expect_err("refused").raw_os_error(), Some(ELOOP), "{name}");
    }
    done(base);
}

#[test]
fn only_regular_files_are_opened() {
    // The FIFO case is a_fifo_is_refused_without_waiting_for_a_writer.
    let base = scratch("regular");
    std::fs::create_dir(format!("{base}/sub")).expect("subdirectory");
    let directory = dir(&base);
    assert_eq!(kind(directory.file_ro("sub")), io::ErrorKind::InvalidInput, "a directory");
    done(base);
}

#[test]
fn a_fifo_is_refused_without_waiting_for_a_writer() {
    // No writer holds the FIFO: without O_NONBLOCK the read-only open would wait for one (Q-HE2S-11 (a)). The open runs
    // on its own thread, so a regression fails the test after a bound instead of hanging it.
    let base = scratch("fifo");
    let status = Command::new("/usr/bin/mkfifo").arg(format!("{base}/fifo")).status().expect("mkfifo runs");
    assert!(status.success(), "the FIFO was made");
    let directory = dir(&base);
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(kind(directory.file_ro("fifo")));
    });
    let refused = receiver.recv_timeout(Duration::from_secs(10)).expect("the open of a FIFO returns without a writer");
    assert_eq!(refused, io::ErrorKind::InvalidInput, "a FIFO");
    done(base);
}

#[test]
fn the_descriptor_is_closed_on_exec() {
    let base = scratch("cloexec");
    std::fs::write(format!("{base}/one"), b"x").expect("file");
    let file = dir(&base).file_ro("one").expect("opens");
    let descriptor = file.as_raw_fd();
    assert!(descriptor > 2);
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("test -e /dev/fd/{descriptor}"))
        .status()
        .expect("the shell runs");
    assert!(!status.success(), "descriptor {descriptor} reached the child");
    drop(file);
    done(base);
}

#[test]
fn a_directory_named_through_a_symbolic_link_is_followed() {
    // The seal's shape: Dir::at follows a link that names the directory, and file_ro opens a name inside it.
    let base = scratch("linked-dir");
    std::fs::create_dir(format!("{base}/real")).expect("directory");
    std::fs::write(format!("{base}/real/status"), b"Threads:\t1\n").expect("file");
    std::os::unix::fs::symlink(format!("{base}/real"), format!("{base}/self")).expect("link");
    let mut text = String::new();
    dir(&format!("{base}/self")).file_ro("status").expect("opens").read_to_string(&mut text).expect("reads");
    assert_eq!(text, "Threads:\t1\n");
    done(base);
}
