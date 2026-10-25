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
//! exact tail `ExitCode::from(serve(&<the stage-2 binding>))`), its pinned imports, `serve`'s calls in their order and
//! the observer's linked-crate rules. On other targets a stub exits with status 2 (command 8's darwin build).
//!
//! HE-004D1 (DESIGN-D1 section 17.3, G-D1-8) gives `serve` twelve calls in this order: the signed configuration's load
//! (11, 12), its v2 parse with the qualification record's reference (13), the lifetime (14; 97), the credentials (20),
//! the TLS configuration (21), the embedded capture schema (25), the record's read (26, 27), the enrolled record (27,
//! 28, 29), the Linux wire (24), the capture roots, whose constructor `LinuxCapture::new` takes `&Sealed` (30), the
//! embedded closure (22) and the epoch with the capture engine (80-99).
//!
//! HE-004-I01a (DESIGN-I01A sections 4, 6 and 12) gives `serve` a thirteenth call: the enrolled record's server
//! identity (`enrolled.server_identity()`, 27 for a missing SERVER row), right after `Enrolled::new` and before the
//! record moves into the capture engine; the epoch builds the I01 service from it. The Linux wire's constructor also
//! opens and registers the I01 listener, so its refusal maps through `status::wire_setup` (24 for the poller, 31-34
//! for the listener).
//!
//! HE-004-I01B2 (DESIGN-I01B2 rev 3 section 5; G-I01B-4) gives `serve` fourteen calls: the parse is configuration v3's
//! (`ObserverConfig::parse_v3`, 13), and right after the lifetime the one statement building the binding from the
//! configuration's checked member (`I01Binding::from_config(config.binding())`, 13 when it has no digest or nonce); the
//! epoch takes it as `observe::run`'s seventh argument. The load and parse statements are pinned whole, and `document`
//! and `config` each occur only at their pinned places.
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

/// Everything after the seal (DESIGN-C section 14, DESIGN-D1 section 17.3); the exit status. The only constructors
/// that create a socket or the poller (`LinuxWire::new`) or open the capture roots (`LinuxCapture::new`) take `&Sealed`.
#[cfg(target_os = "linux")]
fn serve(sealed: &Sealed) -> u8 {
    use planeon_observer::capture::CaptureEngine;
    use planeon_observer::capture_schema::CaptureSchema;
    use planeon_observer::config::{self, ObserverConfig};
    use planeon_observer::credentials;
    use planeon_observer::enrolled::{self, Enrolled};
    use planeon_observer::i01_request::I01Binding;
    use planeon_observer::linux_capture::LinuxCapture;
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
    let Ok((config, record_ref)) = ObserverConfig::parse_v3(&document) else { return status::CONFIG_CHECK };
    drop(document);
    if let Err(error) = config::check_lifetime(&config, utc::wall_seconds()) {
        return status::lifetime(&error);
    }
    let Some(binding) = I01Binding::from_config(config.binding()) else { return status::CONFIG_CHECK };
    let Ok((serving_ca, identity)) = credentials::observer_inputs(&config.credentials) else {
        return status::CREDENTIALS;
    };
    let Ok(tls) = client_config(identity, serving_ca, time_provider()) else { return status::TLS_SETUP };
    let Ok((schema, record_schema)) = CaptureSchema::embedded() else { return status::CAPTURE_SCHEMA };
    let record = match enrolled::load_record(&record_ref) {
        Ok(record) => record,
        Err(error) => return status::capture_setup(&error),
    };
    let enrolled = match Enrolled::new(record, &record_schema, utc::wall_seconds()) {
        Ok(enrolled) => enrolled,
        Err(error) => return status::capture_setup(&error),
    };
    drop(record_schema);
    let server = match enrolled.server_identity() {
        Ok(server) => server,
        Err(error) => return status::capture_setup(&error),
    };
    let wire = match LinuxWire::new(sealed) {
        Ok(wire) => wire,
        Err(error) => return status::wire_setup(&error),
    };
    let capture = match LinuxCapture::new(sealed) {
        Ok(capture) => capture,
        Err(error) => return status::capture_setup(&error),
    };
    let Ok(closure) = Closure::embedded() else { return status::CLOSURE };
    let captures = Box::new(CaptureEngine::new(capture, enrolled, schema));
    status::observation(&observe::run(wire, config, tls, closure, captures, server, binding))
}
