//! HE-003C: the upstream TLS client profile (DESIGN §3, Q-HE3C-2 (a), Q-HE3C-3 (a); MODEL_DEFINED R64), all through
//! the production builder `client_config(identity, roots, fixed time)`: the closed configuration; the refusals at
//! setup; the identity's `Debug`; the server name of an IPv4 and an IPv6 apiserver address (pki-types' own types,
//! 16 bytes as big-endian pairs); and an apiserver certificate with an IPv6 SAN.

mod tls_support;
mod upstream_support;

use effect_gate::net::{InetAddress, IpLiteral};
use gate_tls::{client_config, server_name, TlsClientIdentity, TlsClientSetupError, ALPN_HTTP11};
use rustls::pki_types::{IpAddr, Ipv4Addr, Ipv6Addr, ServerName};
use zeroize::Zeroizing;

use tls_support::{fixed_time, handshake, Failed};
use upstream_support::*;

#[test]
fn the_client_configuration_is_the_closed_profile() {
    let pki = upstream_pki();
    for config in [effect_config(&pki, &pki.serving_ca), writer_config(&pki, &pki.serving_ca)] {
        let suites: Vec<String> =
            config.crypto_provider().cipher_suites.iter().map(|suite| format!("{:?}", suite.suite())).collect();
        assert_eq!(suites, ["TLS13_AES_256_GCM_SHA384", "TLS13_AES_128_GCM_SHA256", "TLS13_CHACHA20_POLY1305_SHA256"]);
        let groups: Vec<String> = config.crypto_provider().kx_groups.iter().map(|group| format!("{:?}", group.name())).collect();
        assert_eq!(groups, ["X25519", "secp256r1", "secp384r1"]);
        let resumption = format!("{:?}", config.resumption);
        assert!(resumption.contains("NoClientSessionStorage") && resumption.contains("Disabled"), "{resumption}");
        assert!(!config.enable_early_data && !config.enable_sni && !config.enable_secret_extraction);
        assert_eq!(config.alpn_protocols, vec![ALPN_HTTP11.to_vec()]);
        assert!(config.client_auth_cert_resolver.has_certs(), "a client certificate is always presented");
        assert!(!config.key_log.will_log("CLIENT_HANDSHAKE_TRAFFIC_SECRET"));
        assert!(format!("{:?}", config.time_provider).contains("FixedTime"), "the time provider is the argument");
        assert_eq!(config.max_fragment_size, None);
    }
}

#[test]
fn setup_refuses_an_empty_chain_no_serving_ca_a_mismatched_key_and_pem() {
    let pki = upstream_pki();
    let roots = [pki.serving_ca.clone()];
    let refused = |identity: TlsClientIdentity, roots: &[Vec<u8>]| match client_config(identity, roots, fixed_time()) {
        Ok(_) => panic!("refused"),
        Err(error) => error,
    };
    assert!(matches!(refused(TlsClientIdentity { chain: Vec::new(), key: Zeroizing::new(pki.effect_key.pkcs8.clone()) },
                             &roots), TlsClientSetupError::NoChain));
    assert!(matches!(refused(identity(&pki.effect, &pki.effect_key), &[]), TlsClientSetupError::NoServerCa));
    assert!(matches!(refused(identity(&pki.effect, &pki.writer_key), &roots),
                     TlsClientSetupError::Key(rustls::Error::InconsistentKeys(_))), "the key must match the leaf");
    let pem = |label: &str, der: &[u8]| {
        let mut text = format!("-----BEGIN {label}-----\n").into_bytes();
        text.extend(der.iter().flat_map(|byte| format!("{byte:02x}").into_bytes()));
        text.extend_from_slice(format!("\n-----END {label}-----\n").as_bytes());
        text
    };
    assert!(matches!(refused(identity(&pki.effect, &pki.effect_key), &[pem("CERTIFICATE", &pki.serving_ca)]),
                     TlsClientSetupError::ServerCa(_)));
    let pem_key = TlsClientIdentity { chain: vec![pki.effect.clone()], key: Zeroizing::new(pem("PRIVATE KEY", &pki.effect_key.pkcs8)) };
    assert!(matches!(refused(pem_key, &roots), TlsClientSetupError::Key(_)));
    let debug = format!("{:?}", identity(&pki.effect, &pki.effect_key));
    assert!(debug.contains("key_bytes: 48") && debug.contains("chain_certificates: 1") && !debug.contains("[48"),
            "lengths only: {debug}");
}

#[test]
fn the_server_name_is_the_literal_address() {
    assert_eq!(server_name(&APISERVER), ServerName::IpAddress(IpAddr::V4(Ipv4Addr::from([127, 0, 0, 1]))));
    let loopback = InetAddress { ip: IpLiteral::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), port: 6443 };
    assert_eq!(server_name(&loopback), ServerName::IpAddress(IpAddr::V6(Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 1]))));
    // Big-endian pairs: 2001:db8::102:304.
    let address = InetAddress {
        ip: IpLiteral::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04]),
        port: 6443,
    };
    let expected = Ipv6Addr::try_from("2001:db8::102:304").expect("an IPv6 literal");
    assert_eq!(server_name(&address), ServerName::IpAddress(IpAddr::V6(expected)));
}

#[test]
fn an_ipv6_apiserver_needs_its_ipv6_san() {
    let pki = upstream_pki();
    let loopback6 = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let leaf = leaf_v6(40, "planeon serving ca", &pki.apiserver_key, &pki.serving_ca_key, loopback6);
    let server = apiserver_config_with(&pki, &leaf, 0);
    let config = effect_config(&pki, &pki.serving_ca);
    let v6 = InetAddress { ip: IpLiteral::V6(loopback6), port: 6443 };
    let mut client = rustls::ClientConnection::new(config.clone(), server_name(&v6)).expect("a client");
    let mut apiserver = rustls::ServerConnection::new(server.clone()).expect("a server");
    handshake(&mut client, &mut apiserver).expect("the IPv6 SAN matches ::1");
    assert_eq!(apiserver.peer_certificates().and_then(|chain| chain.first()).map(|leaf| leaf.as_ref().to_vec()),
               Some(pki.effect.clone()));
    // The same certificate for the IPv4 loopback address: refused by the client (webpki: no matching IP SAN).
    let mut client = rustls::ClientConnection::new(config, server_name(&APISERVER)).expect("a client");
    let mut apiserver = rustls::ServerConnection::new(server).expect("a server");
    let failed = handshake(&mut client, &mut apiserver).expect_err("no IPv4 SAN");
    assert!(matches!(failed, Failed::Client(rustls::Error::InvalidCertificate(_))), "{failed:?}");
}
