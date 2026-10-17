//! The effect gate binary, `planeon-gate` (HE-003D DESIGN section 4; obligations O1, O6 and O7): the EFFECT_GATE
//! seal's call site, the signed configuration, the composition and the event loop. Sequencing only: every step is a
//! library call, and each failure point exits with its own non-zero status (effect-gate's `status` table, R71). No
//! argv, no environment, nothing printed.
//!
//! On Linux, `main` runs in this order:
//! 1. seal stage 1, its first statement (a seal error exits with its step's status, 40-59);
//! 2. the signed configuration only: gate-tls's `signed_config::load` (11, 12) and `GateConfig::parse` (13);
//! 3. seal stage 2 (60-79);
//! 4. after the seal, in `serve` below: the credentials (20) and the TLS configurations (21); the fallible socket
//!    setup, the I04 listener and the Linux `Os` with the enrolled writer executable (24, HE-003A2), before anything
//!    durable is written; the observation's two kernel roots (26, HE-003A3); the file stores with the
//!    generation binding (22) and the one PolicyGate on them, created on a fresh journal or reopened deny-first (23),
//!    with the Linux kernel observer attached (HE-003A3); the socket-free composition; the substrate (25) and its loop
//!    (30-35).
//!
//! `tools/gate.py` holds this file to the seal-order grammar (between the stages only the configuration's two calls,
//! the exits and their patterns), the socket and thread name refusals before stage 2, and the linked crates' rules.
//! On other targets a stub exits with status 2 (command 8's darwin build).
#![forbid(unsafe_code)]

use std::process::ExitCode;

use effect_gate::status;
#[cfg(target_os = "linux")]
use effect_gate::{seal_stage1, seal_stage2, GateConfig, Sealed};
#[cfg(target_os = "linux")]
use gate_tls::signed_config::{self, LoadError};

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
    let config = match GateConfig::parse(&document) {
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

/// Everything after the seal (DESIGN section 4 steps 4-7); the exit status. Every constructor that creates a socket
/// takes `&Sealed`.
#[cfg(target_os = "linux")]
fn serve(sealed: &Sealed, config: GateConfig) -> u8 {
    use effect_gate::file_store::fstat_device;
    use effect_gate::linux_net::{LinuxConnector, LinuxStreams, NetTable};
    use effect_gate::linux_os::{KernelRoots, LinuxKernelReads, LinuxOs};
    use effect_gate::{ExpectedPeers, FileStores, KernelObserver, ListenerPlan, Owner, PolicyGate, Stores, Substrate};
    use gate_tls::{client_config, credentials, server_config, Exchange, I04Server, UpstreamClient};

    // Step 4: the credential and CA files, each checked against its pin (20), then the TLS configurations (21).
    let files = &config.credentials;
    let Ok(server_inputs) = credentials::server_inputs(&files.i04_server, &files.i04_client_ca) else {
        return status::CREDENTIALS;
    };
    let Ok(roots) = credentials::serving_roots(&files.apiserver_serving_ca) else { return status::CREDENTIALS };
    let Ok(effect_identity) = credentials::client_identity(&files.effect_identity) else { return status::CREDENTIALS };
    let Ok(writer_identity) = credentials::client_identity(&files.writer_identity) else { return status::CREDENTIALS };
    let time = credentials::time_provider();
    let Ok(server) = server_config(server_inputs, time.clone()) else { return status::TLS_SETUP };
    let Ok(effect) = client_config(effect_identity, &roots, time.clone()) else { return status::TLS_SETUP };
    let Ok(writer) = client_config(writer_identity, &roots, time) else { return status::TLS_SETUP };

    // Step 5: only the fallible socket setup (24). Nothing durable exists yet, so a failure here (a stale socket path,
    // a busy port) leaves the generation fresh.
    let net = NetTable::new();
    if NetTable::listen_i04(&net, sealed, &config.endpoint).is_err() {
        return status::SOCKETS;
    }
    // HE-003A2 (DESIGN section 4, Q-A2-6 (a)): the Linux `Os` takes the enrolled writer executable, a required argument.
    let (i05, i07) = (ListenerPlan::i05(), ListenerPlan::i07());
    let Ok(os) = LinuxOs::with_net(sealed, &i05, &i07, net.clone(), config.writer_executable) else {
        return status::SOCKETS;
    };
    // HE-003A3 (DESIGN section 5, Q-A3-6 and Q-A3-14 (a)): the observation's two kernel roots, at start and after the
    // seal (26); nothing durable exists yet.
    let Ok(kernel) = KernelRoots::open_after_seal(sealed) else { return status::OBSERVER_ROOTS };

    // Step 6: the stores with the generation binding (22), then the one PolicyGate on file stores in this process
    // (C1): created on a fresh journal, otherwise the restart, deny-first (23), whose output is dropped before the loop.
    let stores = match FileStores::open_bound(&config.journal_directory, &config.marker_directory, &config.generation,
                                              &config.document_digest, &fstat_device, None) {
        Ok(stores) => stores,
        Err(_) => return status::STORES,
    };
    let fresh = stores.journal_created() && stores.indexed_now() && stores.entries().is_empty()
        && !stores.marker_file_exists();
    let gate = if fresh {
        match PolicyGate::create(&config.gate, &config.kinds, stores) {
            Ok(gate) => gate,
            Err(_) => return status::GATE,
        }
    } else {
        match PolicyGate::open(&config.gate, &config.kinds, stores) {
            Ok((gate, restart)) => {
                drop(restart);
                gate
            }
            Err(_) => return status::GATE,
        }
    };
    // HE-003A3: the gate observes the BIND's worker through the Linux kernel reads (every BIND refused without it).
    let gate = gate.with_observer(Box::new(KernelObserver::new(LinuxKernelReads::new(kernel))));

    // The infallible, socket-free composition; R16 stays the single parser of the apiserver address (C14).
    let exchange = Exchange::shared();
    let i04 = I04Server::new(LinuxStreams::new(net.clone(), Owner::I04), server, exchange.clone());
    let connector = LinuxConnector::new(sealed, net);
    let upstream = UpstreamClient::new(connector, gate.apiserver_address(), effect, writer, exchange);

    // Step 7: the substrate (25) and the loop, which has no normal end (30-35).
    let mut substrate = match Substrate::new(gate, os, i04, upstream, ExpectedPeers::r10(), config.lifetimes) {
        Ok(substrate) => substrate,
        Err(_) => return status::SUBSTRATE,
    };
    status::loop_exit(&substrate.run())
}
