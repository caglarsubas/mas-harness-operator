//! The capacity broker binary, `planeon-broker` (HE-005A: DESIGN-HE005 revision 5 section 4, HE-005A, with the scope
//! notes; owner decisions Q-HE5A-1..3 (a); SEC-4 and HI-7 for BROKER): the BROKER seal's call site and the I02 listener's
//! wiring, in the observer's main.rs form. Sequencing only: each step is a library call, and each failure point exits
//! with its own non-zero status (the library's `status` table). No argv, no environment, nothing printed.
//!
//! On Linux, `main` runs seal stage 1 as its first statement (the broker's pre-check, 36-39, then role-seal's stage 1,
//! 40-59), seal stage 2 as the next statement, with nothing between them (Q-HE5A-1 (a); 60-79), and then exits with
//! `serve`'s status. `serve` builds the I02 listener from `&Sealed` and runs `serve_unanswered`, which binds it, closes
//! every connection unanswered and returns only on a listener error (24, Q-HE5A-3 (a)). `tools/gate.py` holds this file to
//! the seal-order grammar with the broker's parameters (BROKER_SEAL_SITE: stage 1 first, nothing between, the exact
//! stage-2 statement, the exact tail `ExitCode::from(serve(&<the stage-2 binding>))`) and its pinned imports. On other
//! targets a stub exits with status 2.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use planeon_broker::status;
#[cfg(target_os = "linux")]
use planeon_broker::{seal_stage1, seal_stage2, Sealed};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    let stage1 = match seal_stage1() {
        Ok(stage1) => stage1,
        Err(error) => return ExitCode::from(status::seal(&error)),
    };
    let sealed = match seal_stage2(stage1) {
        Ok(sealed) => sealed,
        Err(error) => return ExitCode::from(status::seal(&error)),
    };
    ExitCode::from(serve(&sealed))
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    ExitCode::from(status::NOT_LINUX)
}

/// Everything after the seal: the I02 listener, whose only constructor takes `&Sealed`, served unanswered; the exit
/// status, which is the listener's (24), since nothing else ends it.
#[cfg(target_os = "linux")]
fn serve(sealed: &Sealed) -> u8 {
    use planeon_broker::linux_listen::LinuxI02;
    use planeon_broker::serve_unanswered;

    status::listener(&serve_unanswered(&mut LinuxI02::new(sealed)))
}
