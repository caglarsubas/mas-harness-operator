//! The policy observer binary, `planeon-observer` (HE-004A DESIGN section 5; SEC-4 and HI-7 for OBSERVER; HE-004C
//! DESIGN-C section 14): the OBSERVER seal's call site and the observation's wiring. Sequencing only: each step is a
//! library call, and each failure point exits with its own non-zero status (the library's `status` table, R86 and
//! R106). No argv, no environment, nothing printed.
//!
//! On Linux, `main` runs seal stage 1 as its first statement (a seal error exits with its step's status, 40-59), seal
//! stage 2 as the next statement, with nothing between them (60-79), and then exits with `serve`'s status (owner
//! decision Q-HE4C-5 (a)). `serve` runs after the seal, in this order: the signed configuration's read and signature
//! check (11, 12), its parse (13), its lifetime on the wall clock (14; 97 for an unusable clock), the credentials (20),
//! the TLS client configuration (21), the Linux wire, whose constructor takes `&Sealed` (24), the embedded closure
//! once (22), then the observation epoch, which has no normal end (80-99). `tools/gate.py` holds this file to the
//! seal-order grammar with the observer's parameters (stage 1 first, nothing between, the exact stage-2 statement, the
//! exact tail `ExitCode::from(serve(&<the stage-2 binding>))`), its pinned imports, `serve`'s eight calls in this order
//! and the observer's linked-crate rules. On other targets a stub exits with status 2 (command 8's darwin build).
#![forbid(unsafe_code)]

use std::process::ExitCode;

use planeon_observer::status;
#[cfg(target_os = "linux")]
use planeon_observer::{seal_stage1, seal_stage2, Sealed};

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

/// Everything after the seal (DESIGN-C section 14); the exit status. The only constructor that creates a socket or the
/// poller, `LinuxWire::new`, takes `&Sealed`.
#[cfg(target_os = "linux")]
fn serve(sealed: &Sealed) -> u8 {
    use planeon_observer::config::{self, ObserverConfig};
    use planeon_observer::credentials;
    use planeon_observer::linux_net::LinuxWire;
    use planeon_observer::observe;
    use planeon_observer::signed_config;
    use planeon_observer::snapshot::Closure;
    use planeon_observer::tls::{client_config, time_provider};
    use planeon_observer::utc;

    let document = match signed_config::load() {
        Ok(document) => document,
        Err(error) => return status::config_load(&error),
    };
    let Ok(config) = ObserverConfig::parse(&document) else { return status::CONFIG_CHECK };
    drop(document);
    if let Err(error) = config::check_lifetime(&config, utc::wall_seconds()) {
        return status::lifetime(&error);
    }
    let Ok((serving_ca, identity)) = credentials::observer_inputs(&config.credentials) else {
        return status::CREDENTIALS;
    };
    let Ok(tls) = client_config(identity, serving_ca, time_provider()) else { return status::TLS_SETUP };
    let Ok(wire) = LinuxWire::new(sealed) else { return status::SOCKETS };
    let Ok(closure) = Closure::embedded() else { return status::CLOSURE };
    status::observation(&observe::run(wire, config, tls, closure))
}
