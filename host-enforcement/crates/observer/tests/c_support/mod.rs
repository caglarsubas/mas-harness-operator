//! Test support for HE-004C (DESIGN-C section 17): a test PKI (Ed25519 keys from fixed seeds, a serving CA and the
//! apiserver's leaf with the `127.0.0.1` and `::1` SANs, a client CA and the `planeon:policy-observer` identity; no key
//! or certificate file is committed), the observer's production TLS configuration with a fixed time, a fake `Wire`
//! with a fake monotonic and wall clock, and a scripted apiserver: a rustls server that verifies the client
//! certificate, with an HTTP responder serving discovery, the lists (B1's I06 v2 positive rebuilt as RBAC objects, with
//! the observer's read grants of section 12.1, as `observer_round_trip.rs` rebuilds it), `/version`, `/readyz`,
//! `/metrics` (synthetic, with the hash of the vendored `planeon-a2.json` manifest), the progress read and watch
//! streams with scripted bookmarks and events. Nothing here reads a file or the network.
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{Read, Write};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use gate_sys::inet::{InetAddress, IpLiteral};
use planeon_observer::client::{AcceptResult, ConnId, Connecting, ExeLink, Interest, PeerCreds, PeerId, PeerOps, PeerRecv,
                               PeerWatch, PollError, ProcIdentity, Ready, Transfer, Wire, Woken};
use planeon_observer::config::{CredentialFiles, FileRef, ObserverConfig};
use planeon_observer::credentials::ObserverIdentity;
use planeon_observer::inputs::Resource;
use planeon_observer::observe::{Epoch, ObserverExit, Settings, Trace};
use planeon_observer::requests::{self, Mode};
use planeon_observer::snapshot::Closure;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::sign::SigningKey;
use rustls::time_provider::TimeProvider;
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection, SignatureScheme};
use zeroize::Zeroizing;

use crate::b1_rbac_support::{account, cluster_binding, cluster_role, group, non_resource, role_binding, rule, service_account,
                             user, Rbac, QUALIFICATION};
use crate::b1_support::{field, parse, rows, text};

// ------------------------------------------------------------------------------------------ time

/// Days since 1970-01-01 of a civil date (H. Hinnant's algorithm).
pub fn days(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The tests' wall clock at the epoch's start: 2026-06-01T00:00:00Z.
pub fn wall_start() -> u64 {
    (days(2026, 6, 1) * 86_400) as u64
}

#[derive(Debug)]
pub struct FixedTime(pub u64);

impl TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(self.0)))
    }
}

pub fn fixed_time() -> Arc<dyn TimeProvider> {
    Arc::new(FixedTime(wall_start()))
}

// ------------------------------------------------------------------------------------------ DER

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes: Vec<u8> = length.to_be_bytes().iter().copied().skip_while(|byte| *byte == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

pub fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}

pub fn integer(value: u64) -> Vec<u8> {
    let mut bytes: Vec<u8> = value.to_be_bytes().iter().copied().skip_while(|byte| *byte == 0).collect();
    if bytes.is_empty() || bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    tlv(0x02, &bytes)
}

pub fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut chunk = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            chunk.insert(0, 0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        body.extend(chunk);
    }
    tlv(0x06, &body)
}

pub fn utc_time(year: i64, month: i64, day: i64) -> Vec<u8> {
    tlv(0x17, format!("{:02}{:02}{:02}000000Z", year % 100, month, day).as_bytes())
}

pub fn bit_string(unused: u8, bytes: &[u8]) -> Vec<u8> {
    let mut body = vec![unused];
    body.extend_from_slice(bytes);
    tlv(0x03, &body)
}

pub fn name(common_name: &str) -> Vec<u8> {
    seq(&[set(&[seq(&[oid(&[2, 5, 4, 3]), tlv(0x0c, common_name.as_bytes())])])])
}

pub fn extension(id: &[u64], critical: bool, value: Vec<u8>) -> Vec<u8> {
    let mut parts = vec![oid(id)];
    if critical {
        parts.push(tlv(0x01, &[0xff]));
    }
    parts.push(tlv(0x04, &value));
    seq(&parts)
}

pub const SERVER_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 1];
pub const CLIENT_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 2];
const ED25519: &[u64] = &[1, 3, 101, 112];
pub const V6_LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

// ------------------------------------------------------------------------------------------ keys and certificates

/// An Ed25519 key from a fixed seed: its seed-only PKCS#8 v1 form, rustls's ring signer and its SubjectPublicKeyInfo.
pub struct Key {
    pub pkcs8: Vec<u8>,
    pub signing: Arc<dyn SigningKey>,
    pub spki: Vec<u8>,
}

pub fn key(seed: u8) -> Key {
    let mut pkcs8 = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    pkcs8.extend_from_slice(&[seed; 32]);
    let signing = any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.clone())))
        .expect("the ring signer takes the seed-only Ed25519 PKCS#8 form");
    let spki = signing.public_key().expect("the signer gives its public key").as_ref().to_vec();
    Key { pkcs8, signing, spki }
}

/// A subject alternative name.
#[derive(Copy, Clone, Debug)]
pub enum San {
    Ip4([u8; 4]),
    Ip6([u8; 16]),
}

/// A DER certificate holding `subject_key`'s public key, signed by `issuer_key`.
pub fn certificate(serial: u64, issuer: &str, subject: &str, ca: bool, eku: Option<&[u64]>, sans: &[San], subject_key: &Key,
                   issuer_key: &Key) -> Vec<u8> {
    let algorithm = seq(&[oid(ED25519)]);
    let mut extensions = Vec::new();
    let constraints = if ca { seq(&[tlv(0x01, &[0xff])]) } else { seq(&[]) };
    extensions.push(extension(&[2, 5, 29, 19], true, constraints));
    let usage = if ca { bit_string(2, &[0x04]) } else { bit_string(7, &[0x80]) };
    extensions.push(extension(&[2, 5, 29, 15], true, usage));
    if let Some(eku) = eku {
        extensions.push(extension(&[2, 5, 29, 37], false, seq(&[oid(eku)])));
    }
    if !sans.is_empty() {
        let names: Vec<Vec<u8>> = sans
            .iter()
            .map(|san| match san {
                San::Ip4(address) => tlv(0x87, address),
                San::Ip6(address) => tlv(0x87, address),
            })
            .collect();
        extensions.push(extension(&[2, 5, 29, 17], false, seq(&names)));
    }
    let tbs = seq(&[
        tlv(0xa0, &integer(2)),
        integer(serial),
        algorithm.clone(),
        name(issuer),
        seq(&[utc_time(2026, 1, 1), utc_time(2027, 1, 1)]),
        name(subject),
        subject_key.spki.clone(),
        tlv(0xa3, &seq(&extensions)),
    ]);
    let signer = issuer_key.signing.choose_scheme(&[SignatureScheme::ED25519]).expect("an Ed25519 signer");
    let signature = signer.sign(&tbs).expect("a signature");
    seq(&[tbs, algorithm, bit_string(0, &signature)])
}

/// The test PKI.
pub struct Pki {
    pub serving_ca_key: Key,
    pub serving_ca: Vec<u8>,
    pub apiserver_key: Key,
    /// The apiserver's leaf, with the `127.0.0.1` and `::1` IP SANs.
    pub apiserver: Vec<u8>,
    /// A leaf of the serving CA without an IP SAN.
    pub no_san: Vec<u8>,
    pub client_ca_key: Key,
    pub client_ca: Vec<u8>,
    pub observer_key: Key,
    /// `CN=planeon:policy-observer`, clientAuth.
    pub observer: Vec<u8>,
    pub other_ca_key: Key,
    pub other_ca: Vec<u8>,
    /// The apiserver's key certified by the other CA.
    pub other_apiserver: Vec<u8>,
}

pub fn pki() -> Pki {
    let (serving_ca_key, apiserver_key, client_ca_key, observer_key, other_ca_key) = (key(41), key(42), key(43), key(44), key(45));
    let serving_ca = certificate(1, "planeon serving ca", "planeon serving ca", true, None, &[], &serving_ca_key, &serving_ca_key);
    let apiserver = certificate(2, "planeon serving ca", "kube-apiserver", false, Some(SERVER_AUTH),
                                &[San::Ip4([127, 0, 0, 1]), San::Ip6(V6_LOOPBACK)], &apiserver_key, &serving_ca_key);
    let no_san = certificate(3, "planeon serving ca", "kube-apiserver", false, Some(SERVER_AUTH), &[], &apiserver_key,
                             &serving_ca_key);
    let client_ca = certificate(4, "planeon client ca", "planeon client ca", true, None, &[], &client_ca_key, &client_ca_key);
    let observer = certificate(5, "planeon client ca", "planeon:policy-observer", false, Some(CLIENT_AUTH), &[], &observer_key,
                               &client_ca_key);
    let other_ca = certificate(6, "another ca", "another ca", true, None, &[], &other_ca_key, &other_ca_key);
    let other_apiserver = certificate(7, "another ca", "kube-apiserver", false, Some(SERVER_AUTH), &[San::Ip4([127, 0, 0, 1])],
                                      &apiserver_key, &other_ca_key);
    Pki { serving_ca_key, serving_ca, apiserver_key, apiserver, no_san, client_ca_key, client_ca, observer_key, observer,
          other_ca_key, other_ca, other_apiserver }
}

/// The observer's identity of the test PKI.
pub fn identity(pki: &Pki) -> ObserverIdentity {
    ObserverIdentity { chain: vec![pki.observer.clone()], key: Zeroizing::new(pki.observer_key.pkcs8.clone()) }
}

/// The observer's production client configuration (`tls::client_config`) with the fixed time, trusting `serving_ca`.
pub fn observer_tls(pki: &Pki, serving_ca: &[u8]) -> Arc<ClientConfig> {
    match planeon_observer::tls::client_config(identity(pki), serving_ca.to_vec(), fixed_time()) {
        Ok(config) => config,
        Err(error) => panic!("the observer's client configuration builds: {error:?}"),
    }
}

/// A scripted apiserver's server configuration: `leaf` with the apiserver's key, client certificates required from the
/// client CA, TLS 1.3, ALPN http/1.1, no tickets.
pub fn apiserver_config(pki: &Pki, leaf: &[u8]) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(pki.client_ca.clone())).expect("the client CA");
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build().expect("a verifier");
    let mut config = ServerConfig::builder_with_details(provider, fixed_time())
        .with_protocol_versions(&[&TLS13])
        .expect("TLS 1.3")
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![CertificateDer::from(leaf.to_vec())],
                          PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.apiserver_key.pkcs8.clone())))
        .expect("the apiserver credential");
    config.send_tls13_tickets = 0;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

// ------------------------------------------------------------------------------------------ the configuration

pub const NAMESPACE: &str = QUALIFICATION;
pub const PLUGIN: &str = "planeon-admission";
pub const NONCE: &str = "0123456789abcdef0123456789abcdef";
pub const APISERVER_ID: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
pub const MARKER: &str = "1.7801920e+09";
/// The pinned hash of the tests: the manifest directory hash of the vendored `planeon-a2.json` alone, the value
/// `observer_admission.rs` derives from the vendored bytes.
pub const PINNED: &str = "sha256:5aa2cdec0b8dc08c008b887e30b9954ffc46e7d779365f64db1adfd80656f189";

pub fn pinned_hash() -> String {
    PINNED.to_string()
}

pub fn pin(path: &str) -> FileRef {
    FileRef { path: path.to_string(), sha256: format!("sha256:{}", "a".repeat(64)) }
}

/// A checked configuration for the scripted apiserver at `127.0.0.1:6443`, valid from an hour before the tests' start
/// until `lifetime` after it.
pub fn config_for(lifetime: Duration) -> ObserverConfig {
    ObserverConfig {
        generation: "g-1".to_string(),
        not_before: wall_start() - 3_600,
        not_after: wall_start() + lifetime.as_secs(),
        authority: "127.0.0.1:6443".to_string(),
        address: InetAddress { ip: IpLiteral::V4([127, 0, 0, 1]), port: 6443 },
        namespace: NAMESPACE.to_string(),
        credentials: CredentialFiles { serving_ca: pin("/etc/planeon/observer/ca.crt"),
                                       chain: vec![pin("/etc/planeon/observer/tls.crt")],
                                       key: pin("/etc/planeon/observer/tls.key") },
        pinned_manifest_hash: pinned_hash(),
        expected_plugin: PLUGIN.to_string(),
        nonce: NONCE.to_string(),
    }
}

// ------------------------------------------------------------------------------------------ the RBAC lists

const VECTORS: &str = include_str!("../../../../contracts/i06-v2/vectors.json");

fn subject_ref(kind: &str, subject: &str) -> String {
    match kind {
        "User" => user(subject),
        "Group" => group(subject),
        _ => {
            let (namespace, account_name) =
                subject.strip_prefix("system:serviceaccount:").expect("prefix").split_once(':').expect("split");
            account(Some(namespace), account_name)
        }
    }
}

fn role_rule(item: &i05_protocol::json::Value) -> String {
    let canonical = |value: &i05_protocol::json::Value| {
        String::from_utf8(i05_protocol::json::canonical(value).expect("canonical")).expect("UTF-8")
    };
    format!(r#"{{"apiGroups": {}, "resources": {}, "verbs": {}, "resourceNames": {}}}"#, canonical(field(item, "apiGroups")),
            canonical(field(item, "resources")), canonical(field(item, "verbs")), canonical(field(item, "resourceNames")))
}

/// RBAC objects whose effective snapshot is the I06 v2 positive (as `observer_round_trip.rs` rebuilds it).
pub fn positive_rbac() -> Rbac {
    let snapshot = field(&parse(VECTORS), "snapshotPositive").clone();
    let mut rbac = Rbac::default();
    for (index, subject) in rows(&snapshot, "subjects").iter().enumerate() {
        let (kind, subject_name) = (text(subject, "kind"), text(subject, "name"));
        if kind == "ServiceAccount" && field(subject, "exists").as_bool() == Some(true) {
            let (namespace, account_name) = subject_name["system:serviceaccount:".len()..].split_once(':').expect("split");
            rbac.accounts.push(service_account(namespace, account_name));
        }
        let mut by_scope: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for item in rows(subject, "effectiveRules") {
            by_scope.entry(text(item, "scope").to_string()).or_default().push(role_rule(item));
        }
        if by_scope.is_empty() {
            by_scope.insert("CLUSTER".to_string(), Vec::new());
        }
        for (scope, rules) in by_scope {
            let role_name = format!("rt-{index}-{scope}");
            rbac.cluster_roles.push(cluster_role(&role_name, &rules));
            let binding = format!("rt-{index}");
            if scope == "CLUSTER" {
                rbac.cluster_bindings.push(cluster_binding(&binding, &role_name, &[subject_ref(kind, subject_name)]));
            } else {
                rbac.role_bindings.push(role_binding(&scope, &binding, "ClusterRole", &role_name,
                                                     &[subject_ref(kind, subject_name)]));
            }
        }
    }
    rbac
}

/// The observer's read grants of DESIGN-C section 12.1: one ClusterRole and its binding to User planeon:policy-observer.
pub fn observer_grants() -> (String, String) {
    let verbs = r#"["list", "watch"]"#;
    let role = cluster_role("planeon:policy-observer", &[
        rule(r#"[""]"#, r#"["limitranges", "namespaces", "resourcequotas", "serviceaccounts", "secrets"]"#, verbs),
        rule(r#"["networking.k8s.io"]"#, r#"["networkpolicies"]"#, verbs),
        rule(r#"["rbac.authorization.k8s.io"]"#, r#"["roles", "rolebindings", "clusterroles", "clusterrolebindings"]"#, verbs),
        rule(r#"["admissionregistration.k8s.io"]"#,
             r#"["validatingwebhookconfigurations", "mutatingwebhookconfigurations", "mutatingadmissionpolicies", "mutatingadmissionpolicybindings", "validatingadmissionpolicies", "validatingadmissionpolicybindings"]"#,
             verbs),
        rule(r#"["apiregistration.k8s.io"]"#, r#"["apiservices"]"#, verbs),
        rule(r#"["apiextensions.k8s.io"]"#, r#"["customresourcedefinitions"]"#, verbs),
        rule(r#"["certificates.k8s.io"]"#, r#"["certificatesigningrequests"]"#, verbs),
        non_resource(r#"["/metrics", "/readyz/poststarthook/rbac/bootstrap-roles", "/version", "/apis/admissionregistration.k8s.io", "/apis/admissionregistration.k8s.io/*"]"#,
                     r#"["get"]"#),
    ]);
    let binding = cluster_binding("planeon:policy-observer", "planeon:policy-observer", &[user("planeon:policy-observer")]);
    (role, binding)
}

/// A settled ResourceQuota in `namespace` bounding the six units.
pub fn quota_item(name_text: &str, namespace: &str, hard: &str, used: &str) -> String {
    format!(r#"{{"metadata": {{"name": "{name_text}", "namespace": "{namespace}"}}, "spec": {{"hard": {hard}}}, "status": {{"hard": {hard}, "used": {used}}}}}"#)
}

pub const HARD: &str = r#"{"pods": "10", "configmaps": "10", "services": "5", "requests.cpu": "2", "requests.memory": "4Gi", "requests.ephemeral-storage": "10Gi", "limits.cpu": "1500m"}"#;
pub const USED: &str = r#"{"pods": "2", "configmaps": "1", "services": "0", "requests.cpu": "500m", "requests.memory": "1Gi", "requests.ephemeral-storage": "0", "limits.cpu": "1200m"}"#;

/// The default list items of the scripted apiserver: the positive's RBAC with the observer's grants, a settled quota,
/// three namespaces, and every other list empty.
pub fn default_lists() -> BTreeMap<Resource, Vec<String>> {
    let mut rbac = positive_rbac();
    let (role, binding) = observer_grants();
    rbac.cluster_roles.push(role);
    rbac.cluster_bindings.push(binding);
    let mut lists: BTreeMap<Resource, Vec<String>> = Resource::ALL.into_iter().map(|resource| (resource, Vec::new())).collect();
    lists.insert(Resource::ClusterRoles, rbac.cluster_roles);
    lists.insert(Resource::ClusterRoleBindings, rbac.cluster_bindings);
    lists.insert(Resource::Roles, rbac.roles);
    lists.insert(Resource::RoleBindings, rbac.role_bindings);
    lists.insert(Resource::ServiceAccounts, rbac.accounts);
    lists.insert(Resource::ResourceQuotas, vec![quota_item("run-quota", NAMESPACE, HARD, USED)]);
    lists.insert(Resource::Namespaces, ["default", "kube-system", NAMESPACE]
        .iter()
        .map(|space| format!(r#"{{"metadata": {{"name": "{space}"}}}}"#))
        .collect());
    lists
}

// ------------------------------------------------------------------------------------------ the scripted apiserver

/// One request the scripted apiserver saw.
#[derive(Clone, Debug)]
pub struct Req {
    pub at: Duration,
    pub target: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub accept: String,
    pub conn: u64,
}

impl Req {
    pub fn param(&self, key: &str) -> Option<&str> {
        self.query.get(key).map(String::as_str)
    }
}

/// What the scripted apiserver answers.
#[derive(Clone, Debug)]
pub enum Reply {
    /// A complete answer with Content-Length, then close_notify and the close.
    Answer { status: u16, content_type: String, body: Vec<u8> },
    /// Bytes written as they are (framing cases), then close_notify and the close.
    Raw(Vec<u8>),
    /// The 200 head of a watch stream; the stream then gets the scripted bookmarks and events.
    Stream,
    /// No answer at all.
    Hang,
    /// The TCP connection is reset.
    Reset,
    /// The reply after a delay (the connection is silent meanwhile).
    Delay(Duration, Box<Reply>),
}

pub fn answer(status: u16, content_type: &str, body: &[u8]) -> Reply {
    Reply::Answer { status, content_type: content_type.to_string(), body: body.to_vec() }
}

pub fn json(status: u16, body: &str) -> Reply {
    answer(status, "application/json", body.as_bytes())
}

/// A scheduled action of the scripted apiserver.
pub enum Action {
    /// A data event on every open stream of the resource (the revision advances).
    Change(Resource),
    /// Unrelated writes: the revision advances by this much.
    Bump(u64),
    /// The streams of the resource send their final chunk and close.
    EndStream(Resource),
    /// Every stream sends its final chunk and closes.
    EndAll,
    /// A raw line (with its LF) on the resource's open streams.
    Line(Resource, String),
    /// Any change of the apiserver's state.
    Do(Box<dyn FnMut(&mut Api)>),
}

/// An open watch stream.
#[derive(Clone, Debug)]
pub struct StreamInfo {
    pub conn: u64,
    pub resource: Resource,
    /// The resourceVersion it was opened at.
    pub opened: u64,
}

pub type Hook = Box<dyn FnMut(&Req, &mut Api) -> Option<Reply>>;

/// The scripted apiserver's state.
pub struct Api {
    /// The current revision.
    pub rv: u64,
    pub marker: String,
    /// The ADM-4 sample lines of the exposition.
    pub samples: Vec<String>,
    pub extra_metrics: Vec<String>,
    pub git_version: String,
    pub readyz: (u16, String),
    pub lists: BTreeMap<Resource, Vec<String>>,
    /// Discovery: each served version of admissionregistration.k8s.io and the resource names it lists.
    pub admission_versions: Vec<(String, Vec<String>)>,
    pub bookmark_every: Duration,
    /// Streams whose bookmarks stay at their opening resourceVersion.
    pub stuck: BTreeSet<Resource>,
    /// Streams that get no bookmark.
    pub quiet: BTreeSet<Resource>,
    pub streams: Vec<StreamInfo>,
    pub schedule: Vec<(Duration, Action)>,
    pub hook: Option<Hook>,
    pub log: Vec<Req>,
    /// Pending writes to stream connections: (conn, bytes, close after).
    pub outbox: Vec<(u64, Vec<u8>, bool)>,
}

/// The six kinds of admissionregistration.k8s.io/v1 in B1's specs, with their status subresources.
pub fn admission_v1_names() -> Vec<String> {
    ["validatingwebhookconfigurations", "mutatingwebhookconfigurations", "mutatingadmissionpolicies",
     "mutatingadmissionpolicies/status", "mutatingadmissionpolicybindings", "validatingadmissionpolicies",
     "validatingadmissionpolicies/status", "validatingadmissionpolicybindings"]
        .iter()
        .map(|name| name.to_string())
        .collect()
}

pub fn sample(plugin: &str, hash: &str) -> String {
    format!(r#"apiserver_manifest_admission_config_controller_last_config_info{{apiserver_id_hash="{APISERVER_ID}",hash="{hash}",plugin="{plugin}"}} 1"#)
}

impl Api {
    pub fn new() -> Api {
        Api {
            rv: 1000,
            marker: MARKER.to_string(),
            samples: vec![sample(PLUGIN, &pinned_hash())],
            extra_metrics: vec!["apiserver_request_total{code=\"200\",verb=\"LIST\"} 4242".to_string()],
            git_version: "v1.37.1".to_string(),
            readyz: (200, "ok".to_string()),
            lists: default_lists(),
            admission_versions: vec![("v1".to_string(), admission_v1_names())],
            bookmark_every: Duration::from_secs(20),
            stuck: BTreeSet::new(),
            quiet: BTreeSet::new(),
            streams: Vec::new(),
            schedule: Vec::new(),
            hook: None,
            log: Vec::new(),
            outbox: Vec::new(),
        }
    }

    /// The exposition text.
    pub fn exposition(&self) -> String {
        let mut text = String::from("# HELP process_start_time_seconds Start time of the process.\n# TYPE process_start_time_seconds gauge\n");
        text.push_str(&format!("process_start_time_seconds {}\n", self.marker));
        text.push_str("# TYPE apiserver_manifest_admission_config_controller_last_config_info gauge\n");
        for line in self.samples.iter().chain(self.extra_metrics.iter()) {
            text.push_str(line);
            text.push('\n');
        }
        text
    }

    /// A list body of `resource` at `rv` with at most `limit` items.
    pub fn list_body(&self, resource: Resource, rv: u64, limit: Option<usize>) -> String {
        let (kind, api_version) = resource.list_kind();
        let items = self.lists.get(&resource).cloned().unwrap_or_default();
        let items: Vec<String> = items.into_iter().take(limit.unwrap_or(usize::MAX)).collect();
        format!(r#"{{"kind": "{kind}", "apiVersion": "{api_version}", "metadata": {{"resourceVersion": "{rv}"}}, "items": [{}]}}"#,
                items.join(", "))
    }

    fn resource_of(req: &Req) -> Option<Resource> {
        Resource::ALL.into_iter().find(|resource| {
            let rendered = requests::list(*resource, &Mode::Fresh).target;
            let (path, query) = rendered.split_once('?').unwrap_or((rendered.as_str(), ""));
            let selector = query.strip_prefix("fieldSelector=");
            path == req.path && selector == req.query.get("fieldSelector").map(String::as_str)
        })
    }

    /// The default answer to a request.
    pub fn respond(&mut self, req: &Req) -> Reply {
        if let Some(mut hook) = self.hook.take() {
            let reply = hook(req, self);
            self.hook = Some(hook);
            if let Some(reply) = reply {
                return reply;
            }
        }
        match req.path.as_str() {
            requests::READYZ => answer(self.readyz.0, "text/plain; charset=utf-8", self.readyz.1.as_bytes()),
            requests::METRICS => answer(200, "text/plain; version=0.0.4; charset=utf-8", self.exposition().as_bytes()),
            requests::VERSION => json(200, &format!(r#"{{"major": "1", "minor": "37", "gitVersion": "{}", "platform": "linux/amd64"}}"#,
                                                     self.git_version)),
            "/apis/admissionregistration.k8s.io" => {
                let versions: Vec<String> = self
                    .admission_versions
                    .iter()
                    .map(|(version, _)| format!(r#"{{"groupVersion": "admissionregistration.k8s.io/{version}", "version": "{version}"}}"#))
                    .collect();
                json(200, &format!(r#"{{"kind": "APIGroup", "apiVersion": "v1", "name": "admissionregistration.k8s.io", "versions": [{}]}}"#,
                                   versions.join(", ")))
            }
            path if path.starts_with("/apis/admissionregistration.k8s.io/") && path.matches('/').count() == 3 => {
                let version = &path["/apis/admissionregistration.k8s.io/".len()..];
                match self.admission_versions.iter().find(|(served, _)| served == version) {
                    Some((_, names)) => {
                        let resources: Vec<String> = names.iter().map(|name| format!(r#"{{"name": "{name}", "namespaced": false}}"#)).collect();
                        json(200, &format!(r#"{{"kind": "APIResourceList", "apiVersion": "v1", "groupVersion": "admissionregistration.k8s.io/{version}", "resources": [{}]}}"#,
                                           resources.join(", ")))
                    }
                    None => json(404, r#"{"kind": "Status", "code": 404}"#),
                }
            }
            "/api/v1/namespaces" if req.param("limit") == Some("1") => {
                json(200, &self.list_body(Resource::Namespaces, self.rv, Some(1)))
            }
            _ => {
                let Some(resource) = Api::resource_of(req) else { return json(404, r#"{"kind": "Status", "code": 404}"#) };
                if req.param("watch") == Some("true") {
                    return Reply::Stream;
                }
                if req.param("limit") == Some("1") {
                    return json(200, &self.list_body(resource, self.rv, Some(1)));
                }
                let rv = match (req.param("resourceVersionMatch"), req.param("resourceVersion")) {
                    (Some("Exact"), Some(version)) => version.parse().unwrap_or(self.rv),
                    _ => self.rv,
                };
                json(200, &self.list_body(resource, rv, None))
            }
        }
    }

    /// A watch line as one chunk.
    pub fn chunk(line: &str) -> Vec<u8> {
        let mut bytes = format!("{:x}\r\n", line.len() + 1).into_bytes();
        bytes.extend_from_slice(line.as_bytes());
        bytes.extend_from_slice(b"\n\r\n");
        bytes
    }

    pub fn bookmark(resource: Resource, rv: u64) -> String {
        let (_, api_version) = resource.list_kind();
        format!(r#"{{"type": "BOOKMARK", "object": {{"kind": "{}", "apiVersion": "{api_version}", "metadata": {{"resourceVersion": "{rv}"}}}}}}"#,
                requests::watch_kind(resource))
    }

    pub fn event(kind_of: &str, resource: Resource, rv: u64) -> String {
        format!(r#"{{"type": "{kind_of}", "object": {{"kind": "{}", "metadata": {{"name": "x", "resourceVersion": "{rv}"}}}}}}"#,
                requests::watch_kind(resource))
    }

    fn send_to(&mut self, resource: Option<Resource>, bytes: &[u8], close: bool) {
        let conns: Vec<u64> = self
            .streams
            .iter()
            .filter(|stream| resource.is_none_or(|resource| stream.resource == resource))
            .map(|stream| stream.conn)
            .collect();
        for conn in conns {
            self.outbox.push((conn, bytes.to_vec(), close));
        }
        if close {
            self.streams.retain(|stream| !resource.is_none_or(|resource| stream.resource == resource));
        }
    }

    fn run_action(&mut self, action: &mut Action) {
        match action {
            Action::Change(resource) => {
                self.rv += 1;
                let line = Api::event("MODIFIED", *resource, self.rv);
                self.send_to(Some(*resource), &Api::chunk(&line), false);
            }
            Action::Bump(by) => self.rv += *by,
            Action::EndStream(resource) => self.send_to(Some(*resource), b"0\r\n\r\n", true),
            Action::EndAll => self.send_to(None, b"0\r\n\r\n", true),
            Action::Line(resource, line) => {
                let line = line.clone();
                self.send_to(Some(*resource), &Api::chunk(&line), false);
            }
            Action::Do(change) => change(self),
        }
    }

    /// The bookmarks of one tick: each open stream (not quiet) at the current revision, or a stuck one at its opening.
    pub fn bookmarks(&mut self) {
        let streams = self.streams.clone();
        for stream in streams {
            if self.quiet.contains(&stream.resource) {
                continue;
            }
            let rv = if self.stuck.contains(&stream.resource) { stream.opened } else { self.rv };
            let line = Api::bookmark(stream.resource, rv);
            self.outbox.push((stream.conn, Api::chunk(&line), false));
        }
    }
}

impl Default for Api {
    fn default() -> Api {
        Api::new()
    }
}

// ------------------------------------------------------------------------------------------ the fake Wire

/// A raw server: given the client's first flight, the bytes it answers (then the close).
pub type RawServer = Box<dyn FnMut(&[u8]) -> Vec<u8>>;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum State {
    Fresh,
    Answered,
    Streaming,
    Hung,
    Dead,
}

/// One fake TCP connection with its scripted TLS server.
pub struct FakeConn {
    pub tls: Option<ServerConnection>,
    pub out: VecDeque<u8>,
    pub request: Vec<u8>,
    pub state: State,
    pub eof: bool,
    pub reset: bool,
    pub first: Option<Vec<u8>>,
    pub peer: Option<Vec<u8>>,
}

/// What the fake network shares with the test.
pub struct Lab {
    pub base: Instant,
    pub elapsed: Duration,
    /// Seconds added to the wall clock (a step), and whether it reads before the epoch.
    pub wall_shift: i64,
    pub wall_before_epoch: bool,
    pub conns: BTreeMap<u64, FakeConn>,
    pub next: u64,
    pub server: Arc<ServerConfig>,
    pub api: Api,
    pub refuse_connects: u32,
    pub in_progress: bool,
    pub poll_fail_at: Option<Duration>,
    pub first_flights: Vec<Vec<u8>>,
    pub raw_server: Option<RawServer>,
    pub peers: Vec<Vec<u8>>,
    pub connects: usize,
    pub closes: usize,
    pub next_tick: Duration,
    /// Replies due later: (at, connection, reply, resource, opening resourceVersion).
    pub delayed: Vec<(Duration, u64, Reply, Option<Resource>, u64)>,
}

pub type SharedLab = Rc<RefCell<Lab>>;

/// The fake `Wire`.
pub struct FakeWire(pub SharedLab);

impl Lab {
    pub fn now(&self) -> Instant {
        self.base + self.elapsed
    }

    /// The requests seen so far whose target starts with `prefix`.
    pub fn requests(&self, prefix: &str) -> Vec<Req> {
        self.api.log.iter().filter(|req| req.target.starts_with(prefix)).cloned().collect()
    }

    fn flush(conn: &mut FakeConn) {
        if let Some(tls) = conn.tls.as_mut() {
            let mut bytes = Vec::new();
            while tls.wants_write() {
                if tls.write_tls(&mut bytes).is_err() {
                    break;
                }
            }
            conn.out.extend(bytes);
        }
    }

    fn write_plain(conn: &mut FakeConn, bytes: &[u8]) {
        if let Some(tls) = conn.tls.as_mut() {
            let _ = tls.writer().write_all(bytes);
        }
        Lab::flush(conn);
    }

    fn close_server(conn: &mut FakeConn) {
        if let Some(tls) = conn.tls.as_mut() {
            tls.send_close_notify();
        }
        Lab::flush(conn);
        conn.eof = true;
        conn.state = State::Dead;
    }

    fn apply(&mut self, number: u64, reply: Reply, resource: Option<Resource>, opened: u64) {
        let Some(conn) = self.conns.get_mut(&number) else { return };
        match reply {
            Reply::Answer { status, content_type, body } => {
                let mut bytes = format!("HTTP/1.1 {status} Scripted\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
                                        body.len())
                    .into_bytes();
                bytes.extend_from_slice(&body);
                Lab::write_plain(conn, &bytes);
                Lab::close_server(conn);
            }
            Reply::Raw(bytes) => {
                Lab::write_plain(conn, &bytes);
                Lab::close_server(conn);
            }
            Reply::Stream => {
                Lab::write_plain(conn, b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n");
                conn.state = State::Streaming;
                if let Some(resource) = resource {
                    self.api.streams.push(StreamInfo { conn: number, resource, opened });
                }
            }
            Reply::Hang => conn.state = State::Hung,
            Reply::Delay(after, inner) => {
                conn.state = State::Hung;
                let at = self.elapsed + after;
                self.delayed.push((at, number, *inner, resource, opened));
            }
            Reply::Reset => {
                conn.reset = true;
                conn.state = State::Dead;
            }
        }
    }

    /// The stream writes the apiserver queued.
    fn deliver(&mut self) {
        for (number, bytes, close) in std::mem::take(&mut self.api.outbox) {
            if let Some(conn) = self.conns.get_mut(&number) {
                if conn.state == State::Streaming {
                    Lab::write_plain(conn, &bytes);
                    if close {
                        Lab::close_server(conn);
                    }
                }
            }
        }
    }

    /// The scheduled actions and bookmark ticks due at the current time.
    fn run_due(&mut self) {
        loop {
            let now = self.elapsed;
            let mut progressed = false;
            if let Some(index) = self.api.schedule.iter().position(|(at, _)| *at <= now) {
                let (_, mut action) = self.api.schedule.remove(index);
                self.api.run_action(&mut action);
                progressed = true;
            }
            if self.next_tick <= now {
                self.api.bookmarks();
                self.next_tick += self.api.bookmark_every;
                progressed = true;
            }
            if let Some(index) = self.delayed.iter().position(|(at, ..)| *at <= now) {
                let (_, number, reply, resource, opened) = self.delayed.remove(index);
                self.apply(number, reply, resource, opened);
                progressed = true;
            }
            self.deliver();
            if !progressed {
                break;
            }
        }
    }

    fn next_event(&self) -> Duration {
        let mut next = self.next_tick;
        for (at, _) in &self.api.schedule {
            next = next.min(*at);
        }
        for (at, ..) in &self.delayed {
            next = next.min(*at);
        }
        next
    }

    fn handle_request(&mut self, number: u64) {
        let Some(conn) = self.conns.get_mut(&number) else { return };
        if conn.state != State::Fresh {
            return;
        }
        let Some(end) = conn.request.windows(4).position(|window| window == b"\r\n\r\n") else { return };
        let head = String::from_utf8_lossy(&conn.request[..end]).to_string();
        conn.state = State::Answered;
        let mut lines = head.split("\r\n");
        let target = lines.next().and_then(|line| line.split(' ').nth(1)).unwrap_or("").to_string();
        let accept = lines.find_map(|line| line.strip_prefix("Accept: ")).unwrap_or("").to_string();
        let (path, query_text) = target.split_once('?').unwrap_or((target.as_str(), ""));
        let query: BTreeMap<String, String> = query_text
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                (key.to_string(), value.to_string())
            })
            .collect();
        let req = Req { at: self.elapsed, target: target.clone(), path: path.to_string(), query, accept, conn: number };
        self.api.log.push(req.clone());
        let reply = self.api.respond(&req);
        let resource = Api::resource_of(&req);
        let opened = req.param("resourceVersion").and_then(|version| version.parse().ok()).unwrap_or(self.api.rv);
        self.apply(number, reply, resource, opened);
    }
}

impl Wire for FakeWire {
    fn connect(&mut self, _address: &InetAddress) -> Result<(ConnId, Connecting), i32> {
        let mut lab = self.0.borrow_mut();
        lab.connects += 1;
        if lab.refuse_connects > 0 {
            lab.refuse_connects -= 1;
            return Err(111);
        }
        let number = lab.next;
        lab.next += 1;
        let tls = if lab.raw_server.is_some() {
            None
        } else {
            // No limit on the scripted server's unsent plaintext (rustls's default is 64 KiB), so large lists go out whole.
            let mut server = ServerConnection::new(lab.server.clone()).expect("a server");
            server.set_buffer_limit(None);
            Some(server)
        };
        lab.conns.insert(number, FakeConn { tls, out: VecDeque::new(), request: Vec::new(), state: State::Fresh, eof: false,
                                            reset: false, first: None, peer: None });
        let started = if lab.in_progress { Connecting::InProgress } else { Connecting::Connected };
        Ok((ConnId(number), started))
    }

    fn connect_result(&mut self, conn: ConnId) -> Result<(), i32> {
        if self.0.borrow().conns.contains_key(&conn.0) { Ok(()) } else { Err(9) }
    }

    fn recv(&mut self, conn: ConnId, buffer: &mut [u8]) -> Transfer {
        let mut lab = self.0.borrow_mut();
        let Some(fake) = lab.conns.get_mut(&conn.0) else { return Transfer::Failed(9) };
        if fake.reset {
            return Transfer::Failed(104);
        }
        if fake.out.is_empty() {
            return if fake.eof { Transfer::Eof } else { Transfer::WouldBlock };
        }
        let count = buffer.len().min(fake.out.len());
        for (slot, byte) in buffer.iter_mut().zip(fake.out.drain(..count)) {
            *slot = byte;
        }
        Transfer::Data(count)
    }

    fn send(&mut self, conn: ConnId, bytes: &[u8]) -> Transfer {
        let mut lab = self.0.borrow_mut();
        let lab = &mut *lab;
        let Some(fake) = lab.conns.get_mut(&conn.0) else { return Transfer::Failed(9) };
        if fake.reset || fake.state == State::Dead && fake.eof {
            return Transfer::Failed(32);
        }
        if fake.first.is_none() {
            fake.first = Some(bytes.to_vec());
            lab.first_flights.push(bytes.to_vec());
            if let Some(raw) = lab.raw_server.as_mut() {
                let answer = raw(bytes);
                fake.out.extend(answer);
                fake.eof = true;
                fake.state = State::Dead;
                return Transfer::Data(bytes.len());
            }
        }
        let Some(tls) = fake.tls.as_mut() else { return Transfer::Data(bytes.len()) };
        let mut slice = bytes;
        let mut failed = false;
        while !slice.is_empty() {
            match tls.read_tls(&mut slice) {
                Ok(0) => break,
                Ok(_) => {
                    if tls.process_new_packets().is_err() {
                        failed = true;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if fake.peer.is_none() {
            if let Some(leaf) = tls.peer_certificates().and_then(|chain| chain.first()) {
                fake.peer = Some(leaf.as_ref().to_vec());
                lab.peers.push(leaf.as_ref().to_vec());
            }
        }
        let mut chunk = [0u8; 4096];
        loop {
            match tls.reader().read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(count) => fake.request.extend_from_slice(&chunk[..count]),
            }
        }
        Lab::flush(fake);
        if failed {
            fake.eof = true;
            fake.state = State::Dead;
            return Transfer::Data(bytes.len());
        }
        let number = conn.0;
        lab.handle_request(number);
        Transfer::Data(bytes.len())
    }

    fn shutdown_write(&mut self, _conn: ConnId) -> bool {
        true
    }

    fn close(&mut self, conn: ConnId) {
        let mut lab = self.0.borrow_mut();
        lab.closes += 1;
        lab.conns.remove(&conn.0);
        lab.api.streams.retain(|stream| stream.conn != conn.0);
    }

    fn wait(&mut self, interests: &[(ConnId, Interest)], _peers: PeerWatch, until: Instant) -> Result<Woken, PollError> {
        let mut lab = self.0.borrow_mut();
        if lab.poll_fail_at.is_some_and(|at| lab.elapsed >= at) {
            return Err(PollError(9));
        }
        let ready = |lab: &Lab| -> Vec<(ConnId, Ready)> {
            interests
                .iter()
                .filter_map(|(conn, interest)| {
                    let fake = lab.conns.get(&conn.0)?;
                    let readable = interest.readable && (!fake.out.is_empty() || fake.eof || fake.reset);
                    let found = Ready { readable, writable: interest.writable, error: fake.reset, hangup: fake.eof && fake.out.is_empty() };
                    (found.readable || found.writable || found.error || found.hangup).then_some((*conn, found))
                })
                .collect()
        };
        let found = ready(&lab);
        if !found.is_empty() {
            return Ok(Woken { conns: found, ..Woken::default() });
        }
        let target = until.saturating_duration_since(lab.base).min(lab.next_event()).max(lab.elapsed);
        lab.elapsed = target;
        lab.run_due();
        Ok(Woken { conns: ready(&lab), ..Woken::default() })
    }

    fn now(&self) -> Instant {
        self.0.borrow().now()
    }

    fn wall_seconds(&self) -> Option<u64> {
        let lab = self.0.borrow();
        if lab.wall_before_epoch {
            return None;
        }
        let seconds = wall_start() as i64 + lab.elapsed.as_secs() as i64 + lab.wall_shift;
        u64::try_from(seconds).ok()
    }
}

/// HE-004-I01a: the apiserver rig has no I01 peer (no epoch built here attaches the I01 service); the I01 tests script
/// their own peers.
impl PeerOps for FakeWire {
    fn accept_peer(&mut self) -> AcceptResult {
        AcceptResult::Nothing
    }

    fn peer_creds(&mut self, _peer: PeerId) -> Result<PeerCreds, i32> {
        Err(9)
    }

    fn peer_proc_open(&mut self, _peer: PeerId) -> Result<(), i32> {
        Err(9)
    }

    fn peer_proc_read(&mut self, _peer: PeerId) -> Result<ProcIdentity, i32> {
        Err(9)
    }

    fn peer_exe(&mut self, _peer: PeerId) -> Result<ExeLink, i32> {
        Err(9)
    }

    fn peer_alive(&mut self, _peer: PeerId) -> bool {
        false
    }

    fn peer_recv(&mut self, _peer: PeerId, _buffer: &mut [u8]) -> PeerRecv {
        PeerRecv::Failed(9)
    }

    fn peer_close(&mut self, _peer: PeerId) {}
}

// ------------------------------------------------------------------------------------------ the rig

/// A scripted apiserver, its PKI and the fake network.
pub struct Rig {
    pub lab: SharedLab,
    pub pki: Rc<Pki>,
    pub config: ObserverConfig,
}

thread_local! {
    static PKI: Rc<Pki> = Rc::new(pki());
}

pub fn shared_pki() -> Rc<Pki> {
    PKI.with(Rc::clone)
}

impl Rig {
    /// A healthy apiserver; the configuration expires 600 s after the start (so a healthy epoch ends with 94).
    pub fn new() -> Rig {
        let pki = shared_pki();
        let server = apiserver_config(&pki, &pki.apiserver);
        let lab = Rc::new(RefCell::new(Lab {
            base: Instant::now(),
            elapsed: Duration::ZERO,
            wall_shift: 0,
            wall_before_epoch: false,
            conns: BTreeMap::new(),
            next: 1,
            server,
            api: Api::new(),
            refuse_connects: 0,
            in_progress: false,
            poll_fail_at: None,
            first_flights: Vec::new(),
            raw_server: None,
            peers: Vec::new(),
            connects: 0,
            closes: 0,
            next_tick: Duration::from_secs(20),
            delayed: Vec::new(),
        }));
        Rig { lab, pki, config: config_for(Duration::from_secs(600)) }
    }

    pub fn api<R>(&self, change: impl FnOnce(&mut Api) -> R) -> R {
        change(&mut self.lab.borrow_mut().api)
    }

    pub fn lab<R>(&self, change: impl FnOnce(&mut Lab) -> R) -> R {
        change(&mut self.lab.borrow_mut())
    }

    /// Schedules an action at `at` after the start.
    pub fn at(&self, at: Duration, action: Action) {
        self.lab.borrow_mut().api.schedule.push((at, action));
    }

    /// Answers requests with `hook` first (`None`: the default answer).
    pub fn hook(&self, hook: impl FnMut(&Req, &mut Api) -> Option<Reply> + 'static) {
        self.lab.borrow_mut().api.hook = Some(Box::new(hook));
    }

    pub fn epoch_with(&self, settings: Settings) -> Epoch<FakeWire> {
        let tls = observer_tls(&self.pki, &self.pki.serving_ca);
        let closure = Closure::embedded().expect("the embedded closure");
        Epoch::new(FakeWire(self.lab.clone()), self.config.clone(), tls, closure, settings)
    }

    pub fn epoch(&self) -> Epoch<FakeWire> {
        self.epoch_with(Settings { per_spec_progress: false, trace: true })
    }

    /// Runs an epoch to its exit.
    pub fn run(&self) -> (ObserverExit, Epoch<FakeWire>) {
        let mut epoch = self.epoch();
        let exit = epoch.run();
        (exit, epoch)
    }

    /// The fake time since the start.
    pub fn elapsed(&self) -> Duration {
        self.lab.borrow().elapsed
    }

    pub fn requests(&self, prefix: &str) -> Vec<Req> {
        self.lab.borrow().requests(prefix)
    }
}

impl Default for Rig {
    fn default() -> Rig {
        Rig::new()
    }
}

/// The snapshots of a trace, as (time, sequence, resourceVersion).
pub fn snapshots(trace: &[(Duration, Trace)]) -> Vec<(Duration, u64, u64)> {
    trace
        .iter()
        .filter_map(|(at, entry)| match entry {
            Trace::Snapshot { sequence, resource_version } => Some((*at, *sequence, *resource_version)),
            _ => None,
        })
        .collect()
}

/// Whether the trace holds an entry matching `wanted`.
pub fn traced(trace: &[(Duration, Trace)], wanted: impl Fn(&Trace) -> bool) -> bool {
    trace.iter().any(|(_, entry)| wanted(entry))
}

/// The availability changes of a trace, as (time, available).
pub fn availability(trace: &[(Duration, Trace)]) -> Vec<(Duration, bool)> {
    trace
        .iter()
        .filter_map(|(at, entry)| match entry {
            Trace::Available(available) => Some((*at, *available)),
            _ => None,
        })
        .collect()
}
