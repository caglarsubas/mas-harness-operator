//! HE-003B: the TLS server configuration (DESIGN §5, §9, §20; MODEL_DEFINED R46, R47, R58), all through the
//! production builder `server_config(inputs, fixed time)`, with in-memory handshakes against rustls test clients:
//! the configuration's properties; mutual TLS 1.3 and the certificate digest; every refused client certificate (none,
//! another CA, expired, not yet valid, serverAuth only, a CA certificate); a TLS 1.2-only ClientHello; ALPN; key and
//! PEM refusals at setup; and resumption and early data, from a real ticket of a test-only ticketing configuration.

mod tls_support;

use std::sync::Arc;

use gate_tls::{certificate_digest, server_config, TlsServerInputs, TlsSetupError, ALPN_HTTP11};
use i05_protocol::sha256;
use rustls::client::{ClientSessionMemoryCache, Resumption};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::version::TLS13;
use rustls::{ClientConfig, HandshakeKind, ProtocolVersion, RootCertStore, ServerConfig, ServerConnection};
use zeroize::Zeroizing;

use tls_support::*;

fn connect(server: Arc<ServerConfig>, client: Arc<ClientConfig>) -> (rustls::ClientConnection, ServerConnection,
                                                                      Result<(), Failed>) {
    let mut client = tls_support::client(client);
    let mut server = ServerConnection::new(server).expect("a server connection");
    let result = handshake(&mut client, &mut server);
    (client, server, result)
}

fn refused(leaf: Option<Vec<u8>>) -> Failed {
    let pki = pki();
    let (_, _, result) = connect(production(&pki), client_config(&pki, leaf, &[ALPN_HTTP11]));
    result.expect_err("the handshake is refused")
}

#[test]
fn the_configuration_is_the_closed_profile() {
    let pki = pki();
    let config = production(&pki);
    let names: Vec<String> =
        config.crypto_provider().cipher_suites.iter().map(|suite| format!("{:?}", suite.suite())).collect();
    assert_eq!(names, ["TLS13_AES_256_GCM_SHA384", "TLS13_AES_128_GCM_SHA256", "TLS13_CHACHA20_POLY1305_SHA256"]);
    let groups: Vec<String> = config.crypto_provider().kx_groups.iter().map(|group| format!("{:?}", group.name())).collect();
    assert_eq!(groups, ["X25519", "secp256r1", "secp384r1"]);
    assert!(!config.session_storage.can_cache(), "no session storage");
    assert_eq!(config.send_tls13_tickets, 0);
    assert!(!config.ticketer.enabled());
    assert_eq!(config.max_early_data_size, 0);
    assert!(!config.send_half_rtt_data);
    assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    assert!(!config.key_log.will_log("CLIENT_HANDSHAKE_TRAFFIC_SECRET"), "the default key log logs nothing");
    assert!(!config.enable_secret_extraction);
    assert!(config.cert_compressors.is_empty() && config.cert_decompressors.is_empty());
    assert_eq!(config.max_fragment_size, None);
    assert!(format!("{:?}", config.time_provider).contains("FixedTime"), "the time provider is the argument");
    let debug = format!("{:?}", inputs(&pki));
    assert!(debug.contains("key_bytes: 48") && !debug.contains("[48"), "lengths only: {debug}");
}

#[test]
fn mutual_tls_13_succeeds_and_the_digest_is_the_client_leafs() {
    let pki = pki();
    let (client, server, result) = connect(production(&pki), client_config(&pki, Some(pki.client.clone()), &[ALPN_HTTP11]));
    result.expect("mutual TLS 1.3");
    assert_eq!(server.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert_eq!(certificate_digest(&server), Some(sha256::prefixed(&pki.client)));
    assert_eq!(server.alpn_protocol(), Some(ALPN_HTTP11));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
}

#[test]
fn a_client_without_a_certificate_is_refused() {
    let failed = refused(None);
    assert!(matches!(failed, Failed::Server(rustls::Error::NoCertificatesPresented)), "{failed:?}");
}

#[test]
fn a_client_certificate_from_another_ca_is_refused() {
    let pki = pki();
    let failed = refused(Some(pki.other_client.clone()));
    assert!(matches!(failed, Failed::Server(rustls::Error::InvalidCertificate(_))), "{failed:?}");
}

#[test]
fn expired_and_not_yet_valid_client_certificates_are_refused() {
    let pki = pki();
    let mut expired = Spec::leaf(10, "planeon test ca", "planeon server", CLIENT_AUTH, San::Uri(RUN_URI));
    expired.not_after = (2026, 2, 1);
    let mut early = Spec::leaf(11, "planeon test ca", "planeon server", CLIENT_AUTH, San::Uri(RUN_URI));
    early.not_before = (2026, 12, 1);
    for (spec, expected) in [(expired, rustls::CertificateError::Expired), (early, rustls::CertificateError::NotValidYet)] {
        let failed = refused(Some(client_leaf(&pki, &spec)));
        match failed {
            Failed::Server(rustls::Error::InvalidCertificate(error)) => {
                assert!(format!("{error:?}").starts_with(&format!("{expected:?}")), "{error:?}")
            }
            other => panic!("refused as an invalid certificate, not {other:?}"),
        }
    }
}

#[test]
fn a_server_auth_only_leaf_and_a_ca_leaf_are_refused_as_client_certificates() {
    let pki = pki();
    let server_only = Spec::leaf(12, "planeon test ca", "planeon server", SERVER_AUTH, San::Uri(RUN_URI));
    let failed = refused(Some(client_leaf(&pki, &server_only)));
    // As webpki decides it (recorded): the leaf lacks the clientAuth usage.
    assert!(matches!(failed, Failed::Server(rustls::Error::InvalidCertificate(_))), "{failed:?}");
    println!("serverAuth-only client leaf: {failed:?}");
    let mut ca_leaf = Spec::leaf(13, "planeon test ca", "planeon server", CLIENT_AUTH, San::Uri(RUN_URI));
    ca_leaf.ca = true;
    let failed = refused(Some(client_leaf(&pki, &ca_leaf)));
    assert!(matches!(failed, Failed::Server(rustls::Error::InvalidCertificate(_))), "{failed:?}");
    println!("cA=true client leaf: {failed:?}");
}

/// A TLS 1.2 ClientHello (no supported_versions extension) offering one ECDHE suite, as fixed bytes: the test client
/// cannot build one with `tls12` off.
fn tls12_client_hello() -> Vec<u8> {
    let mut hello = vec![0x03, 0x03];
    hello.extend_from_slice(&[0x42; 32]);
    hello.push(0); // no session ID
    hello.extend_from_slice(&[0x00, 0x02, 0xc0, 0x2f]); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    hello.extend_from_slice(&[0x01, 0x00]); // null compression
    let groups = [0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]; // supported_groups: x25519
    let signatures = [0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x01]; // signature_algorithms: rsa_pkcs1_sha256
    let extensions = [groups.as_slice(), signatures.as_slice()].concat();
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);
    let mut handshake = vec![0x01, 0x00];
    handshake.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&hello);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[test]
fn a_tls_12_only_client_hello_is_refused_with_an_alert() {
    let pki = pki();
    let mut server = ServerConnection::new(production(&pki)).expect("a server connection");
    let hello = tls12_client_hello();
    server.read_tls(&mut hello.as_slice()).expect("the record is read");
    let error = server.process_new_packets().expect_err("TLS 1.2 is not offered by the server");
    println!("TLS 1.2-only ClientHello: {error:?}");
    let alert = drain_server(&mut server);
    assert_eq!(record_types(&alert), vec![0x15], "one alert record");
}

#[test]
fn alpn_h2_only_is_refused_and_no_alpn_proceeds() {
    let pki = pki();
    let (_, _, result) = connect(production(&pki), client_config(&pki, Some(pki.client.clone()), &[b"h2"]));
    assert!(matches!(result, Err(Failed::Server(rustls::Error::NoApplicationProtocol))), "{result:?}");
    let (_, server, result) = connect(production(&pki), client_config(&pki, Some(pki.client.clone()), &[]));
    result.expect("a client offering no ALPN proceeds");
    assert_eq!(server.alpn_protocol(), None);
}

#[test]
fn a_key_that_does_not_match_the_leaf_and_pem_inputs_are_refused_at_setup() {
    let pki = pki();
    let mismatched = TlsServerInputs { chain: vec![pki.server.clone()], key: Zeroizing::new(pki.client_key.pkcs8.clone()),
                                       client_cas: vec![pki.ca.clone()] };
    let refused = server_config(mismatched, fixed_time()).expect_err("the key does not match the leaf");
    assert!(matches!(refused, TlsSetupError::Key(rustls::Error::InconsistentKeys(_))), "{refused:?}");
    let pem = |label: &str, der: &[u8]| {
        let mut text = format!("-----BEGIN {label}-----\n").into_bytes();
        text.extend(der.iter().flat_map(|byte| format!("{byte:02x}").into_bytes()));
        text.extend_from_slice(format!("\n-----END {label}-----\n").as_bytes());
        text
    };
    let pem_key = TlsServerInputs { chain: vec![pki.server.clone()],
                                    key: Zeroizing::new(pem("PRIVATE KEY", &pki.server_key.pkcs8)),
                                    client_cas: vec![pki.ca.clone()] };
    assert!(matches!(server_config(pem_key, fixed_time()), Err(TlsSetupError::Key(_))));
    let pem_ca = TlsServerInputs { chain: vec![pki.server.clone()], key: Zeroizing::new(pki.server_key.pkcs8.clone()),
                                   client_cas: vec![pem("CERTIFICATE", &pki.ca)] };
    assert!(matches!(server_config(pem_ca, fixed_time()), Err(TlsSetupError::ClientCa(_))));
    let no_chain = TlsServerInputs { chain: Vec::new(), key: Zeroizing::new(pki.server_key.pkcs8.clone()),
                                     client_cas: vec![pki.ca.clone()] };
    assert!(matches!(server_config(no_chain, fixed_time()), Err(TlsSetupError::NoChain)));
    let no_ca = TlsServerInputs { chain: vec![pki.server.clone()], key: Zeroizing::new(pki.server_key.pkcs8.clone()),
                                  client_cas: Vec::new() };
    assert!(matches!(server_config(no_ca, fixed_time()), Err(TlsSetupError::NoClientCa)));
}

/// A test-only configuration that issues tickets and accepts early data: same certificate and client CA. Its tickets
/// are stateful (rustls's default in-memory session cache, no stateless ticketer): rustls 0.23.46 offers early data
/// only with stateful tickets (`server/tls13.rs:669-671`).
fn ticketing(pki: &Pki) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(pki.ca.clone())).expect("the test CA");
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build().expect("a verifier");
    let mut config = ServerConfig::builder_with_details(provider, fixed_time())
        .with_protocol_versions(&[&TLS13])
        .expect("TLS 1.3")
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![CertificateDer::from(pki.server.clone())],
                          PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.server_key.pkcs8.clone())))
        .expect("the server credential");
    assert!(config.session_storage.can_cache() && !config.ticketer.enabled());
    config.send_tls13_tickets = 2;
    config.max_early_data_size = 1024;
    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    Arc::new(config)
}

/// The extension types of the first ClientHello in a client's first flight.
fn client_hello_extensions(flight: &[u8]) -> Vec<u16> {
    let body = &flight[5 + 4..];
    let mut at = 2 + 32;
    at += 1 + usize::from(body[at]);
    at += 2 + usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
    at += 1 + usize::from(body[at]);
    let end = at + 2 + usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
    at += 2;
    let mut types = Vec::new();
    while at + 4 <= end {
        types.push(u16::from_be_bytes([body[at], body[at + 1]]));
        at += 4 + usize::from(u16::from_be_bytes([body[at + 2], body[at + 3]]));
    }
    types
}

#[test]
fn a_resumption_offer_gets_a_full_handshake_and_early_data_is_never_accepted() {
    let pki = pki();
    let store = Arc::new(ClientSessionMemoryCache::new(8));
    // One base configuration, cloned per leg: a ticket is kept for the verifier and client credential it was issued
    // under (rustls compares them), so every leg shares them.
    let base = client_config(&pki, Some(pki.client.clone()), &[ALPN_HTTP11]);
    let with_store = |early: bool| {
        let mut config = (*base).clone();
        config.resumption = Resumption::store(store.clone());
        config.enable_early_data = early;
        Arc::new(config)
    };
    // A real ticket from the test-only configuration (two tickets: one per leg).
    let (_, _, result) = connect(ticketing(&pki), with_store(true));
    result.expect("the ticketing handshake");

    // PSK leg: the offer is asserted, then the production server answers with a full handshake.
    let mut client = tls_support::client(with_store(false));
    let mut server = ServerConnection::new(production(&pki)).expect("a server connection");
    let first = drain_client(&mut client);
    assert!(client_hello_extensions(&first).contains(&41), "the client offers a pre-shared key: {:?}", client_hello_extensions(&first));
    server.read_tls(&mut first.as_slice()).expect("read");
    server.process_new_packets().expect("the ClientHello");
    handshake(&mut client, &mut server).expect("a full handshake");
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(certificate_digest(&server), Some(sha256::prefixed(&pki.client)));

    // Early-data leg: a few bytes of early data offered; none is accepted or delivered.
    let mut client = tls_support::client(with_store(true));
    let offered = client.early_data().map(|mut early| std::io::Write::write(&mut early, b"GET / HTTP/1.1\r\n"));
    assert!(matches!(offered, Some(Ok(count)) if count > 0), "early data is offered: {offered:?}");
    let mut server = ServerConnection::new(production(&pki)).expect("a server connection");
    let first = drain_client(&mut client);
    assert!(client_hello_extensions(&first).contains(&42), "the ClientHello carries the early-data extension");
    let mut slice = first.as_slice();
    let mut outcome = Ok(());
    while !slice.is_empty() {
        if server.read_tls(&mut slice).is_err() {
            break;
        }
        if let Err(error) = server.process_new_packets() {
            outcome = Err(error);
            break;
        }
        assert!(server.early_data().is_none(), "no early data is accepted");
        let mut plain = [0u8; 64];
        assert!(std::io::Read::read(&mut server.reader(), &mut plain).is_err(), "nothing reaches the reader");
    }
    match outcome {
        Ok(()) => {
            let rest = handshake(&mut client, &mut server);
            println!("early-data leg: full handshake, early records skipped ({rest:?})");
            assert!(rest.is_ok());
            assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
            assert!(!client.is_early_data_accepted());
        }
        Err(error) => println!("early-data leg: refused handshake ({error:?})"),
    }
    assert!(server.early_data().is_none());
}
