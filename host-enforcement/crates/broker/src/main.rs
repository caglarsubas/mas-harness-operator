//! The capacity broker binary, `planeon-broker` (HE-005A: DESIGN-HE005 revision 5 section 4, HE-005A, with the scope
//! notes; owner decisions Q-HE5A-1..3 (a); SEC-4 and HI-7 for BROKER. HE-005C: section 3.1, moved to HE-005C by the
//! scope notes; Q-HE5C-1 (a); delta C3 revision 2): the BROKER seal's call site, the signed configuration between the
//! seal's stages, and the I02 listener's wiring. Sequencing only: each step is a library call, and each failure point
//! exits with its own non-zero status (the library's `status` table). No argv, no environment, nothing printed.
//!
//! On Linux, `main` runs in this order (delta C3's site form, the third beside the gate's and HE-005A's):
//! 1. seal stage 1, its first statement (the broker's pre-check, 36-39, then role-seal's stage 1, 40-59);
//! 2. the signed configuration only: `signed_config::load` (11, 12) and `BrokerConfig::parse` (13). While the
//!    compiled-in key is empty (until HE-008) every document is refused here (12), so `main` exits before stage 2: no
//!    BROKER filter is installed and no I02 listener is bound;
//! 3. seal stage 2 (60-79);
//! 4. `drop(document);`, then exactly `ExitCode::from(serve(&sealed, config))`, which closes main.
//!
//! `serve` builds the I02 listener from `&Sealed` and runs `serve_unanswered`, which binds it, closes every connection
//! unanswered and returns only on a listener error (24, Q-HE5A-3 (a)). It takes the checked configuration, which
//! HE-005C's lifecycle unit hands to the startup run. On other targets a stub exits with status 2.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use planeon_broker::status;
#[cfg(target_os = "linux")]
use planeon_broker::config::BrokerConfig;
#[cfg(target_os = "linux")]
use planeon_broker::signed_config::{self, LoadError};
#[cfg(target_os = "linux")]
use planeon_broker::{seal_stage1, seal_stage2, Sealed};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    let stage1 = match seal_stage1() {
        Ok(stage1) => stage1,
        Err(error) => return ExitCode::from(status::seal(&error)),
    };
    let document = match signed_config::load() {
        Ok(document) => document,
        Err(LoadError::Read) => return ExitCode::from(status::CONFIG_READ),
        Err(LoadError::Signature(_)) => return ExitCode::from(status::CONFIG_SIGNATURE),
    };
    let config = match BrokerConfig::parse(&document) {
        Ok(config) => config,
        Err(_) => return ExitCode::from(status::CONFIG_CHECK),
    };
    let sealed = match seal_stage2(stage1) {
        Ok(sealed) => sealed,
        Err(error) => return ExitCode::from(status::seal(&error)),
    };
    drop(document);
    ExitCode::from(serve(&sealed, config))
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    ExitCode::from(status::NOT_LINUX)
}

/// Everything after the seal: the I02 listener, whose only constructor takes `&Sealed`, served unanswered; the exit
/// status, which is the listener's (24), since nothing else ends it. The checked configuration is the startup run's,
/// which HE-005C's lifecycle unit wires in with serve's new exact body; until then serve's body is HE-005A's.
#[cfg(target_os = "linux")]
fn serve(sealed: &Sealed, _config: BrokerConfig) -> u8 {
    use planeon_broker::linux_listen::LinuxI02;
    use planeon_broker::serve_unanswered;

    status::listener(&serve_unanswered(&mut LinuxI02::new(sealed)))
}
