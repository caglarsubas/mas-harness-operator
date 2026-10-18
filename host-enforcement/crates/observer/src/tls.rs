//! The observer's TLS 1.3 client profile (HE-004C DESIGN-C section 4.3, HE-003C's R64; MODEL_DEFINED R108), copied
//! from gate-tls (`tls.rs`'s provider and `tls_client.rs`'s builder and server name; owner decision Q-HE4-5 (a)) so
//! that planeon-gate stays byte-identical and the observer links neither gate-tls nor effect-gate. A parity test
//! compares the first flight of this builder with gate-tls's (D1-15), so the copy cannot drift silently.
//!
//! - One identity, `planeon:policy-observer`: a DER chain (leaf first) and a PKCS#8 DER key held in `Zeroizing`; the
//!   key leaves it only when it is moved into rustls, whose `with_client_auth_cert` checks it against the leaf.
//! - The apiserver is verified by webpki against exactly the one configured apiserver serving CA, with the IP literal
//!   of `apiserverAuthority` as the server name: its certificate needs that IP SAN. No custom verifier.
//! - The ring provider with exactly the three TLS 1.3 suites and X25519, P-256 and P-384, passed explicitly to both
//!   builders; TLS 1.3 only; no resumption (no session store), no early data, no SNI (an IP name is never sent as SNI,
//!   but explicit); ALPN `http/1.1` only. One configuration for the process, one connection per TCP connection.
//!
//! Residual (R58's kind): ring's parsed key pair lives for the process; nothing here formats a configuration,
//! connection or key object.

use std::fmt;
use std::sync::Arc;

use gate_sys::inet::{InetAddress, IpLiteral};
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::crypto::ring::{cipher_suite, default_provider, kx_group};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, IpAddr, Ipv4Addr, Ipv6Addr, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::time_provider::{DefaultTimeProvider, TimeProvider};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore};

use crate::credentials::ObserverIdentity;

/// The one ALPN protocol offered.
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Why the client configuration could not be built (status 21).
pub enum TlsClientSetupError {
    /// No certificate in the identity's chain.
    NoChain,
    /// The serving CA does not parse.
    ServerCa(rustls::Error),
    /// The server verifier could not be built.
    Verifier(String),
    /// The provider does not support TLS 1.3.
    Versions(rustls::Error),
    /// The key does not parse, or does not match the leaf.
    Key(rustls::Error),
}

impl fmt::Debug for TlsClientSetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            TlsClientSetupError::NoChain => "TlsClientSetupError::NoChain",
            TlsClientSetupError::ServerCa(_) => "TlsClientSetupError::ServerCa",
            TlsClientSetupError::Verifier(_) => "TlsClientSetupError::Verifier",
            TlsClientSetupError::Versions(_) => "TlsClientSetupError::Versions",
            TlsClientSetupError::Key(_) => "TlsClientSetupError::Key",
        })
    }
}

/// The ring provider with the three TLS 1.3 suites and the three key-exchange groups, explicitly (gate-tls's
/// `tls::provider`, copied).
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

/// The client configuration of the observer's identity (see the module documentation), built once in `serve` and
/// shared by every exchange. `serving_ca` is the one apiserver serving CA certificate.
pub fn client_config(identity: ObserverIdentity, serving_ca: Vec<u8>, time: Arc<dyn TimeProvider>)
                     -> Result<Arc<ClientConfig>, TlsClientSetupError> {
    let ObserverIdentity { chain, mut key } = identity;
    // Refusals before the key leaves its `Zeroizing` (whose drop clears it).
    if chain.is_empty() {
        return Err(TlsClientSetupError::NoChain);
    }
    let provider = Arc::new(provider());
    let mut store = RootCertStore::empty();
    store.add(CertificateDer::from(serving_ca)).map_err(TlsClientSetupError::ServerCa)?;
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider.clone())
        .build()
        .map_err(|error| TlsClientSetupError::Verifier(error.to_string()))?;
    let builder = ClientConfig::builder_with_details(provider, time)
        .with_protocol_versions(&[&TLS13])
        .map_err(TlsClientSetupError::Versions)?
        .with_webpki_verifier(verifier);
    let chain: Vec<CertificateDer<'static>> = chain.into_iter().map(CertificateDer::from).collect();
    // The key last: moved, not copied, into rustls, which parses it inside its own `Zeroizing`.
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::mem::take(&mut *key)));
    let mut config = builder.with_client_auth_cert(chain, key).map_err(TlsClientSetupError::Key)?;
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.enable_sni = false;
    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    Ok(Arc::new(config))
}

/// The server name of the apiserver: its literal IP address (pki-types' own `Ipv4Addr` from the four octets, or
/// `Ipv6Addr` from the sixteen bytes read as eight big-endian pairs; gate-tls's `server_name`, copied).
pub fn server_name(address: &InetAddress) -> ServerName<'static> {
    match address.ip {
        IpLiteral::V4(octets) => ServerName::IpAddress(IpAddr::V4(Ipv4Addr::from(octets))),
        IpLiteral::V6(octets) => {
            let mut groups = [0u16; 8];
            for (group, pair) in groups.iter_mut().zip(octets.chunks_exact(2)) {
                *group = pair.iter().fold(0u16, |value, byte| (value << 8) | u16::from(*byte));
            }
            ServerName::IpAddress(IpAddr::V6(Ipv6Addr::from(groups)))
        }
    }
}

/// rustls's default time provider (std's `SystemTime`, the realtime clock), for `client_config`.
pub fn time_provider() -> Arc<dyn TimeProvider> {
    Arc::new(DefaultTimeProvider)
}
