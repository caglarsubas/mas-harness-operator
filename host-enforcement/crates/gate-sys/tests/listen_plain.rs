//! gate-sys's context-free listener on Linux (HE-004-I01a, DESIGN-I01A sections 4 and 15): `listen_seqpacket_plain`
//! binds and listens in a fresh directory without any socket context, `accept` finds nothing queued, and a second
//! listener on the same path fails at `bind` (the caller never unlinks, so the path stays after the close). The channel
//! module is compiled for Linux only, and so is this test; the build host's run skips it.
#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::fs::FileTypeExt;

use gate_sys::channel::{self, ListenStep};

/// EADDRINUSE on both Linux targets (the kernel's generic `errno.h`).
const EADDRINUSE: i32 = 98;

/// A fresh directory for one test.
fn scratch(test: &str) -> String {
    let path = format!("{}/gate-sys-listen/{test}", env!("CARGO_TARGET_TMPDIR"));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("scratch directory");
    path
}

#[test]
fn the_plain_listener_binds_listens_and_finds_nothing_queued() {
    let base = scratch("plain");
    let path = format!("{base}/i01.sock");
    let listener = channel::listen_seqpacket_plain(&path).expect("the plain listener binds and listens");
    let kind = std::fs::symlink_metadata(&path).expect("the socket's path exists").file_type();
    assert!(kind.is_socket(), "the bound path is a socket");
    assert!(matches!(channel::accept(&listener), Ok(None)), "nothing is queued, so accept answers None");
    let second = channel::listen_seqpacket_plain(&path).expect_err("an existing path is never replaced");
    assert_eq!(second.step, ListenStep::Bind);
    assert_eq!(second.error.raw_os_error(), Some(EADDRINUSE));
    drop(listener);
    assert!(std::fs::symlink_metadata(&path).is_ok(), "closing the listener leaves its path");
    let _ = std::fs::remove_dir_all(base);
}

#[test]
fn a_relative_long_or_nul_path_fails_before_any_socket() {
    for path in ["relative.sock".to_string(), format!("/{}", "n".repeat(107)), "/a\0b".to_string()] {
        let error = channel::listen_seqpacket_plain(&path).expect_err("refused");
        assert_eq!(error.step, ListenStep::Address, "{path:?}");
        assert_eq!(error.error.kind(), io::ErrorKind::InvalidInput, "{path:?}");
    }
}
