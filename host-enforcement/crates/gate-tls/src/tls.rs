//! The TLS server configuration (HE-003B DESIGN §5, §20; MODEL_DEFINED R46, R47, R58): one builder for production
//! and the tests, which differ only in the time provider passed in.
//!
//! - Inputs by value, DER only: the server chain (leaf first), the PKCS#8 key held in `Zeroizing`, so every drop path
//!   clears it, and at least one client CA (Q-HE3B-6 (a)).
//! - The key is consumed first: `CertifiedKey::from_der` hands it to rustls's ring provider, which parses it inside its
//!   own `Zeroizing` and checks it against the leaf; only then are the client CAs and the verifier built (§20).
//! - The ring provider with exactly the three TLS 1.3 suites and X25519, P-256 and P-384, passed explicitly to the
//!   builders; TLS 1.3 only (Q-HE3B-5 (a)); client authentication mandatory against the CAs, no CRLs.
//! - No session storage, no tickets, no early data, no half-RTT data; ALPN `http/1.1` only (Q-HE3B-20 (a)). The other
//!   defaults stay: no key logging, no secret extraction, no certificate compression, no fragment size override.
//!
//! Ring's parsed key pair inside the configuration lives for the process (residual, R58); nothing here formats a
//! configuration, connection or key object.

use std::fmt;
use std::sync::Arc;

use i05_protocol::sha256;
use rustls::crypto::ring::{cipher_suite, default_provider, kx_group};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::time_provider::TimeProvider;
use rustls::version::TLS13;
use rustls::{RootCertStore, ServerConfig, ServerConnection};
use zeroize::Zeroizing;

/// The one ALPN protocol offered.
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// The server's credential and the client trust anchors, all DER (HE-003D reads them from its configuration).
pub struct TlsServerInputs {
    /// The server certificate chain, leaf first.
    pub chain: Vec<Vec<u8>>,
    /// The server's PKCS#8 private key.
    pub key: Zeroizing<Vec<u8>>,
    /// The client CAs (at least one).
    pub client_cas: Vec<Vec<u8>>,
}

impl fmt::Debug for TlsServerInputs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsServerInputs")
            .field("chain_certificates", &self.chain.len())
            .field("key_bytes", &self.key.len())
            .field("client_cas", &self.client_cas.len())
            .finish()
    }
}

/// Why the configuration could not be built.
#[derive(Debug)]
pub enum TlsSetupError {
    /// No server certificate.
    NoChain,
    /// No client CA.
    NoClientCa,
    /// The key does not parse, or does not match the leaf.
    Key(rustls::Error),
    /// A client CA does not parse.
    ClientCa(rustls::Error),
    /// The client verifier could not be built.
    Verifier(String),
    /// The provider does not support TLS 1.3.
    Versions(rustls::Error),
    /// The configuration would issue tickets (never, with the default ticketer).
    Tickets,
}

/// The ring provider with the three TLS 1.3 suites and the three key-exchange groups, explicitly.
fn provider() -> CryptoProvider {
    let mut provider = default_provider();
    provider.cipher_suites = vec![
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_AES_128_GCM_SHA256,
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    provider.kx_groups = vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1];
    provider
}

/// The server configuration (see the module documentation); built once per process and shared by every connection.
pub fn server_config(inputs: TlsServerInputs, time: Arc<dyn TimeProvider>) -> Result<Arc<ServerConfig>, TlsSetupError> {
    let TlsServerInputs { chain, mut key, client_cas } = inputs;
    // Refusals before the key leaves its `Zeroizing` (whose drop clears it).
    if chain.is_empty() {
        return Err(TlsSetupError::NoChain);
    }
    if client_cas.is_empty() {
        return Err(TlsSetupError::NoClientCa);
    }
    let provider = Arc::new(provider());
    // The key first: moved, not copied, into rustls, which parses it inside its own `Zeroizing` (§20).
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::mem::take(&mut *key)));
    let chain: Vec<CertificateDer<'static>> = chain.into_iter().map(CertificateDer::from).collect();
    let certified = CertifiedKey::from_der(chain, key, &provider).map_err(TlsSetupError::Key)?;
    let mut roots = RootCertStore::empty();
    for ca in client_cas {
        roots.add(CertificateDer::from(ca)).map_err(TlsSetupError::ClientCa)?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|error| TlsSetupError::Verifier(error.to_string()))?;
    let mut config = ServerConfig::builder_with_details(provider, time)
        .with_protocol_versions(&[&TLS13])
        .map_err(TlsSetupError::Versions)?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    if config.ticketer.enabled() {
        return Err(TlsSetupError::Tickets);
    }
    Ok(Arc::new(config))
}

/// R47: `sha256:` and the lowercase hex SHA-256 of the client's leaf certificate DER as presented in the handshake that
/// verified it; `None` before the handshake or without a client certificate.
pub fn certificate_digest(connection: &ServerConnection) -> Option<String> {
    connection.peer_certificates().and_then(|chain| chain.first()).map(|leaf| sha256::prefixed(leaf.as_ref()))
}
