//! The policy observer binary, `planeon-observer` (HE-004A DESIGN section 5; SEC-4 and HI-7 for OBSERVER): the
//! OBSERVER seal's call site. Sequencing only: each step is a library call, and each failure point exits with its own
//! non-zero status (the library's `status` table, R86). No argv, no environment, nothing printed.
//!
//! On Linux, `main` runs seal stage 1 as its first statement (a seal error exits with its step's status, 40-59), seal
//! stage 2 as the next statement, with nothing between them (60-79), and then exits with `status::NOT_YET_SERVING`
//! (owner decision Q-HE4A-2 (a)): HE-004A serves nothing, so nothing else runs under the filter. `tools/gate.py` holds
//! this file to the seal-order grammar with the observer's parameters (stage 1 first, nothing between, the exact
//! stage-2 statement, this exact tail), its pinned imports and the observer's linked-crate rules. On other targets a
//! stub exits with status 2 (command 8's darwin build).
#![forbid(unsafe_code)]

use std::process::ExitCode;

use planeon_observer::status;
#[cfg(target_os = "linux")]
use planeon_observer::{seal_stage1, seal_stage2};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    let stage1 = match seal_stage1() {
        Ok(stage1) => stage1,
        Err(error) => return ExitCode::from(status::seal(&error)),
    };
    let _sealed = match seal_stage2(stage1) {
        Ok(sealed) => sealed,
        Err(error) => return ExitCode::from(status::seal(&error)),
    };
    ExitCode::from(status::NOT_YET_SERVING)
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    ExitCode::from(status::NOT_LINUX)
}
