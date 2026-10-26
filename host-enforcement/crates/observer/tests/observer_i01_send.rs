//! HE-004-I01B5 DESIGN-I01B5 rev 5 sections 4.2, 4.3, 5 and 7 (I5D-13 (ii), I5E-1, I3D-6; MON-I01B5-STOPS' four
//! conditions): the send path end to end, the I01 service over a fake `PeerOps` that records every `peer_send`, on the
//! I01 digest contract v2's complete positive (`contracts/i01-digests-v2/vectors.json`, edge record v11's row 74: the
//! `qual` snapshot, the enrolled record, the `passing` capture and S1's triple, as `observer_i01_answer.rs` reads them).
//! `derive` takes ADM-4's loaded hash exactly as the epoch's derive statement passes it,
//! `record.loaded_hash().map_or(Value::Null, Value::str)`, from a `check_loaded_manifest` record.
//! - (i) With a v4-loaded record, a request and a passed round, the bytes `peer_send` receives are exactly
//!   `i01_answer::answer`'s, and the public `self_check` passes on them; the session stays open, its idle bound renewed.
//! - (ii) A record with no loaded hash and (iii) one whose loaded hash differs from the pin refuse "rendered hash
//!   differs", and (iv) a `sealedAdmission` of four members, or one with a `namespace` member, refuses as malformed;
//!   each closes with nothing sent. The configuration Value as the epoch writes it (three top-level members, the sealed
//!   values exactly `ipFamily`, `serviceCIDR`, `defaultTolerationSeconds`) is the vector's.
//! - The exact boundary (I5E-1): a session made ready at the receipt plus 2 s closes not served, and one past its outer
//!   bound closes at the bound, nothing sent; one made ready a millisecond earlier is answered.
//! - The session's continuation (I3D-6): a sequence-2 request naming the first answer's digest is answered and passes
//!   `self_check` with the first observation as `previous`; a chain gap, the first answer's challenge reused and a clock
//!   rollback each close; `self_check`'s own refusal (a generation that drifted between two answers, which cannot arise
//!   within one process), `answer`'s refusal and a failed send each close with nothing more sent.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::sha256;
use planeon_observer::admission::{check_loaded_manifest, Adm4Input, Adm4Record, BindingId, MetricSample, ObservationBinding,
                                  Verdict, ACCEPTED_KUBERNETES_VERSION};
use planeon_observer::client::{AcceptResult, Availability, CaptureGate, ExeLink, Passed, PeerCreds, PeerId, PeerOps, PeerReady,
                               PeerRecv, PeerSent, PeerService, ProcIdentity, Ready, Round, SnapshotView};
use planeon_observer::enrolled::{ServerClass, ServerIdentity};
use planeon_observer::i01_answer::{self, CaptureFacts, Derived, ANSWER_ROLLBACK_TEXT, RESTART_TEXT};
use planeon_observer::i01_digest::{DigestKey, RENDERED_HASH_DIFFERS};
use planeon_observer::i01_request::{request_schema, I01Binding, I01Request, RequestRefusal};
use planeon_observer::i01_service::{Closed, I01Service, I01_EXCHANGE_DEADLINE, IDLE_BOUND, OUTER_BOUND};
use planeon_observer::inputs::{Inputs, ListBody, ListInput, Resource};
use planeon_observer::kernel_text::utc_seconds;
use planeon_observer::snapshot::Closure;

const VECTORS: &[u8] = include_bytes!("../../../contracts/i01-digests-v2/vectors.json");
const LABEL: &str = "system_u:system_r:planeon_server_t:s0";
const INTERPRETER: &str = "/opt/planeon/python/3.12.14/bin/python3.12";
const CGROUP_REL: &str = "planeon.slice/planeon-proxy-server.service";
const CGROUP: &[u8] = b"0::/planeon.slice/planeon-proxy-server.service\n";
const READY: Ready = Ready { readable: true, writable: false, error: false, hangup: false };
const PEER: PeerId = PeerId(1);
/// The triple's observedAt, the first answer's wall reading.
const OBSERVED_AT: &str = "2026-09-08T00:00:01Z";
const PLUGIN: &str = "planeon-admission";
/// The contract's eleven snapshot lists and B1's closed-set entry for each.
const LISTS: [(&str, Resource); 11] = [
    ("namespaces", Resource::Namespaces),
    ("resourceQuotas", Resource::ResourceQuotas),
    ("limitRanges", Resource::LimitRanges),
    ("serviceAccounts", Resource::ServiceAccounts),
    ("networkPolicies", Resource::NetworkPolicies),
    ("roles", Resource::Roles),
    ("roleBindings", Resource::RoleBindings),
    ("clusterRoles", Resource::ClusterRoles),
    ("clusterRoleBindings", Resource::ClusterRoleBindings),
    ("validatingAdmissionPolicies", Resource::ValidatingAdmissionPolicies),
    ("validatingAdmissionPolicyBindings", Resource::ValidatingAdmissionPolicyBindings),
];

fn member<'a>(value: &'a Value, name: &str) -> &'a Value {
    value.get(name).unwrap_or_else(|| panic!("{name} is missing"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    member(value, name).as_str().unwrap_or_else(|| panic!("{name} is not text"))
}

fn parse(bytes: &[u8]) -> Value {
    json::parse(std::str::from_utf8(bytes).expect("UTF-8")).expect("strict JSON")
}

/// `value` with the member `name` of its top-level object set to `new`.
fn with(value: &Value, name: &str, new: Value) -> Value {
    let mut copy = value.clone();
    match &mut copy {
        Value::Object(object) => object.insert(JStr::new(name), new),
        _ => panic!("not an object"),
    }
    copy
}

fn millis(text: &str) -> u64 {
    utc_seconds(text).expect("a canonical UTC text") * 1000
}

/// B1's list inputs for a snapshot's lists, each as the apiserver serves it under its closed-set request.
fn list_inputs(lists: &Value) -> Vec<ListInput> {
    LISTS
        .iter()
        .filter_map(|&(name, resource)| {
            let items = lists.get(name)?;
            let (kind, api_version) = resource.list_kind();
            let mut list = Object::new();
            list.insert(JStr::new("kind"), Value::str(&kind));
            list.insert(JStr::new("apiVersion"), Value::str(&api_version));
            list.insert(JStr::new("metadata"), Value::Object(Object::new()));
            list.insert(JStr::new("items"), items.clone());
            Some(ListInput { spec: resource.spec(), body: ListBody::Served(Value::Object(list)) })
        })
        .collect()
}

/// The configuration Value as the epoch's pinned statement writes it (DESIGN-I01B5 rev 5 section 3.1, rev 5's three
/// sealed members): `qualificationNamespace`, `pinnedManifestHash` and `sealedAdmission` exactly
/// `{ipFamily, serviceCIDR, defaultTolerationSeconds}`, the seconds an exact integer.
fn epoch_configuration(namespace: &str, pin: &str, ip_family: &str, service_cidr: &str, seconds: u64) -> Value {
    let mut sealed = Object::new();
    sealed.insert(JStr::new("ipFamily"), Value::str(ip_family));
    sealed.insert(JStr::new("serviceCIDR"), Value::str(service_cidr));
    sealed.insert(JStr::new("defaultTolerationSeconds"), Value::int(seconds as i64));
    let mut configuration = Object::new();
    configuration.insert(JStr::new("qualificationNamespace"), Value::str(namespace));
    configuration.insert(JStr::new("pinnedManifestHash"), Value::str(pin));
    configuration.insert(JStr::new("sealedAdmission"), Value::Object(sealed));
    Value::Object(configuration)
}

/// The complete positive's inputs.
struct Fixture {
    vectors: Value,
    snapshot: Value,
    record: Value,
    binding: Value,
    quota: Value,
    generation: String,
}

impl Fixture {
    fn complete() -> Fixture {
        let vectors = parse(VECTORS);
        let complete = member(&vectors, "complete");
        let fixtures = member(&vectors, "fixtures");
        let snapshot = member(member(fixtures, "snapshots"), text(complete, "snapshot")).clone();
        let record = member(fixtures, "record").clone();
        let binding = member(complete, "binding").clone();
        let observation = member(complete, "observation");
        let quota = member(observation, "quota").clone();
        let generation = text(observation, "generation").to_string();
        Fixture { vectors, snapshot, record, binding, quota, generation }
    }

    fn complete_member(&self, name: &str) -> &Value {
        member(member(&self.vectors, "complete"), name)
    }

    fn configuration(&self) -> &Value {
        member(&self.snapshot, "configuration")
    }

    fn pin(&self) -> &str {
        text(self.configuration(), "pinnedManifestHash")
    }

    /// ADM-4's record over one sample of the plugin with `loaded` as its hash (none: no sample), the configuration's
    /// pin as the pinned hash.
    fn adm4(&self, loaded: Option<&str>) -> Adm4Record {
        let samples = loaded
            .map(|hash| MetricSample { plugin: PLUGIN.to_string(), apiserver_id_hash: format!("sha256:{}", "1".repeat(64)),
                                       hash: hash.to_string() })
            .into_iter()
            .collect();
        let input = Adm4Input {
            pinned_hash: self.pin().to_string(),
            expected_plugin: PLUGIN.to_string(),
            samples,
            kubernetes_version: ACCEPTED_KUBERNETES_VERSION.to_string(),
            binding: ObservationBinding { id: BindingId::Nonce("0123456789abcdef0123456789abcdef".to_string()),
                                          window_start: "2026-09-08T00:00:00Z".to_string(),
                                          window_end: "2026-09-08T00:00:01Z".to_string() },
        };
        check_loaded_manifest(&input).expect("the ADM-4 input is well formed")
    }

    /// `derive` as the epoch's derive statement calls it, with `configuration`, the ADM-4 record's loaded hash and the
    /// configuration window 00:00:00Z to 00:10:00Z.
    fn derive_with(&self, configuration: &Value, record: &Adm4Record) -> Derived {
        let lists = Inputs::new(list_inputs(member(&self.snapshot, "lists"))).expect("the snapshot's lists");
        let closure = Closure::embedded().expect("the embedded closure reads");
        i01_answer::derive(&lists, member(&self.snapshot, "resourceVersion"), configuration,
                           &record.loaded_hash().map_or(Value::Null, Value::str), &self.record, &closure, &self.binding,
                           &self.quota, &self.generation, millis("2026-09-08T00:00:00Z") / 1000,
                           millis("2026-09-08T00:10:00Z") / 1000)
            .unwrap_or_else(|refusal| panic!("the derivations are built: {refusal}"))
    }

    /// The positive's derivations, with a v4-loaded record.
    fn derived(&self) -> Derived {
        self.derive_with(self.configuration(), &self.adm4(Some(self.pin())))
    }

    fn request(&self) -> I01Request {
        request_schema(self.complete_member("request")).expect("the triple's request")
    }

    /// The triple's request with its sequence, challenge and previous digest set.
    fn continuation(&self, sequence: i64, challenge: &str, previous: &str) -> Value {
        let request = with(self.complete_member("request"), "sequence", Value::int(sequence));
        let request = with(&request, "challenge", Value::str(challenge));
        with(&request, "previousObservationDigest", Value::str(previous))
    }

    fn binding_gate(&self) -> I01Binding {
        I01Binding::from_config(&self.binding).expect("the triple's binding")
    }

    /// The passing capture's one set: its slots, its two ages, the record's digest.
    fn passing(&self) -> (Vec<(String, bool)>, u64, i64, String) {
        let capture = member(member(member(&self.vectors, "fixtures"), "captures"), "passing");
        let set = member(capture, "sets").as_array().and_then(|sets| sets.first()).expect("one set");
        let answer = member(capture, "answer");
        let count = |value: &Value, name: &str| member(value, name).as_int().and_then(|int| int.to_i64()).expect("a count");
        let slots = member(set, "slots").as_object().expect("the slots").iter()
            .map(|(slot, state)| (slot.as_str().expect("a slot name").to_string(), state.as_str() == Some("TAKEN")))
            .collect();
        let mono = u64::try_from(count(answer, "monotonicMs") - count(set, "scheduledMonotonicMs")).expect("an age");
        let wall = count(answer, "wallMs") - count(set, "startedWallMs");
        (slots, mono, wall, sha256::prefixed(&json::canonical(&self.record).expect("canonical bytes")))
    }

    /// The passing capture as `CaptureFacts` (for the expected answers and refusals).
    fn facts(&self) -> CaptureFacts {
        let (slots, mono_age_ms, wall_age_ms, record_digest) = self.passing();
        CaptureFacts { completed: true, expired: false, scheduled_after_now: false, slots, mono_age_ms, wall_age_ms,
                       record_digest }
    }

    /// The passing capture as the epoch's latest capture set, its ages the passing ones at `now` and `wall_ms`.
    fn gate(&self, now: Instant, wall_ms: u64) -> CaptureGate {
        let (slots, mono, wall, record_digest) = self.passing();
        CaptureGate { scheduled: Some(now - Duration::from_millis(mono)),
                      set_started_ms: wall_ms - u64::try_from(wall).expect("an age"), slots, record_digest, expired: false }
    }
}

/// A label as the kernel delivers it: its bytes and one trailing NUL.
fn kernel(label: &str) -> Vec<u8> {
    [label.as_bytes(), b"\0".as_slice()].concat()
}

/// The peer side: one accept, a server process that passes custody, the queued datagrams, every send recorded.
struct FakePeer {
    accepts: VecDeque<AcceptResult>,
    recvs: VecDeque<(Vec<u8>, PeerRecv)>,
    alive: bool,
    sent: Vec<Vec<u8>>,
    send: PeerSent,
    closed: Vec<PeerId>,
}

impl FakePeer {
    fn new() -> FakePeer {
        FakePeer { accepts: VecDeque::from([AcceptResult::Peer(PEER)]), recvs: VecDeque::new(), alive: true, sent: Vec::new(),
                   send: PeerSent::Sent, closed: Vec::new() }
    }
}

fn process() -> ProcIdentity {
    ProcIdentity { start_time: 4_242, cgroup: CGROUP.to_vec(), label: kernel(LABEL) }
}

impl PeerOps for FakePeer {
    fn accept_peer(&mut self) -> AcceptResult {
        self.accepts.pop_front().unwrap_or(AcceptResult::Nothing)
    }

    fn peer_creds(&mut self, _peer: PeerId) -> Result<PeerCreds, i32> {
        Ok(PeerCreds { pid: 812, uid: 0, gid: 0, label: kernel(LABEL) })
    }

    fn peer_proc_open(&mut self, _peer: PeerId) -> Result<(), i32> {
        Ok(())
    }

    fn peer_proc_read(&mut self, _peer: PeerId) -> Result<ProcIdentity, i32> {
        Ok(process())
    }

    fn peer_exe(&mut self, _peer: PeerId) -> Result<ExeLink, i32> {
        Ok(ExeLink(INTERPRETER.as_bytes().to_vec()))
    }

    fn peer_alive(&mut self, _peer: PeerId) -> bool {
        self.alive
    }

    fn peer_recv(&mut self, _peer: PeerId, buffer: &mut [u8]) -> PeerRecv {
        let Some((bytes, answer)) = self.recvs.pop_front() else { return PeerRecv::WouldBlock };
        buffer[..bytes.len()].copy_from_slice(&bytes);
        answer
    }

    fn peer_close(&mut self, peer: PeerId) {
        self.closed.push(peer);
    }

    fn peer_send(&mut self, _peer: PeerId, bytes: &[u8]) -> PeerSent {
        self.sent.push(bytes.to_vec());
        self.send
    }
}

/// The enrolled server, its window 00:00:00Z to 00:10:00Z.
fn server() -> ServerIdentity {
    let from = utc_seconds("2026-09-08T00:00:00Z").expect("UTC");
    ServerIdentity { uid: 0, gid: 0, process_label: LABEL.to_string(), cgroup_rel: CGROUP_REL.to_string(),
                     class: ServerClass::Observed, interpreter: INTERPRETER.to_string(), valid_from: from, expires_at: from + 600 }
}

/// A service holding the triple's binding, a session accepted at `base`.
fn session(fixture: &Fixture, wall_ms: u64) -> (I01Service, FakePeer, Instant) {
    let mut service = I01Service::new(server(), fixture.binding_gate());
    let mut ops = FakePeer::new();
    let base = Instant::now();
    service.serve_peer_step(&mut ops, Some(wall_ms), base, PeerReady::Listener(READY));
    assert!(service.session_open());
    (service, ops, base)
}

/// One request datagram read at `at`; it must pass and wait.
fn receive(service: &mut I01Service, ops: &mut FakePeer, request: &Value, wall_ms: u64, at: Instant) {
    let bytes = json::canonical(request).expect("canonical bytes");
    ops.recvs.push_back((bytes.clone(), PeerRecv::Data { length: bytes.len(), pid: 812, uid: 0, gid: 0, security: kernel(LABEL) }));
    service.serve_peer_step(ops, Some(wall_ms), at, PeerReady::Peer(PEER, READY));
    assert_eq!((service.peer_pending(), service.last_closed()), (Some(at), None), "the request passed and waits");
}

/// The epoch's pushes for phase 1: the snapshot view holding `derived`, an availability with a round started
/// `started` (passed), and the capture set.
fn push(service: &mut I01Service, fixture: &Fixture, derived: Derived, started: Instant, at: Instant, wall_ms: u64) {
    service.peer_snapshot_view(SnapshotView { phase: 1, mark: 100, fresh_stamp: started, derived: Ok(derived) });
    service.peer_availability(Availability { phase: 1, established: true, fresh: true,
                                             round: Some(Round::Passed(Passed { started, mark: 100, stamp: at })) });
    service.peer_capture_view(fixture.gate(at, wall_ms));
}

/// The first answer: the triple's request received 100 ms after the accept, a round started 10 ms after it, answered at
/// 300 ms. The session, its fake and the sent bytes.
fn first_answer(fixture: &Fixture) -> (I01Service, FakePeer, Instant, Vec<u8>) {
    let wall_ms = millis(OBSERVED_AT);
    let (mut service, mut ops, base) = session(fixture, wall_ms);
    let received = base + Duration::from_millis(100);
    receive(&mut service, &mut ops, fixture.complete_member("request"), wall_ms, received);
    let at = base + Duration::from_millis(300);
    push(&mut service, fixture, fixture.derived(), received + Duration::from_millis(10), at, wall_ms);
    assert_eq!(service.peer_plan(at).deadline, Some(at), "ready: the plan wakes at once");
    service.serve_peer_deadlines(&mut ops, Some(wall_ms), at);
    assert_eq!(ops.sent.len(), 1, "{:?}", service.last_closed());
    let bytes = ops.sent[0].clone();
    (service, ops, at, bytes)
}

#[test]
fn i_a_request_and_a_passed_round_get_exactly_answers_bytes_which_the_public_self_check_passes() {
    let fixture = Fixture::complete();
    // The ADM-4 record is v4-loaded: its loaded hash is the snapshot's and the configuration's pin.
    let record = fixture.adm4(Some(fixture.pin()));
    assert_eq!(record.verdict(), Verdict::Match);
    assert_eq!(record.loaded_hash(), Some(text(&fixture.snapshot, "adm4LoadedHash")));
    assert_ne!(record.digest(), text(&fixture.snapshot, "adm4LoadedHash"), "the record's own digest is not the loaded hash");
    let (service, ops, at, bytes) = first_answer(&fixture);
    let wall_ms = millis(OBSERVED_AT);
    let expected = i01_answer::answer(&fixture.derived(), &fixture.request(), &fixture.facts(), wall_ms, None)
        .expect("the complete positive is answered");
    assert_eq!(bytes, expected, "exactly answer's bytes");
    let observation = parse(&bytes);
    assert_eq!(i01_answer::self_check(&observation, &fixture.request(), &fixture.binding, wall_ms / 1000, None), Ok(()));
    // The session stays open (Q-I01B5D-3 (a)), the request answered, the idle bound renewed from the answering wake.
    assert!(service.session_open() && service.last_closed().is_none() && service.peer_pending().is_none());
    assert_eq!(service.peer_plan(at).deadline, Some(at + IDLE_BOUND));
    assert!(ops.closed.is_empty());
}

#[test]
fn the_configuration_value_as_the_epoch_writes_it_is_the_vectors() {
    // MON-I01B5-STOPS (stop 2): three top-level members, the namespace among them, and exactly the three SEALED_VALUES.
    let fixture = Fixture::complete();
    let configuration = fixture.configuration();
    let sealed = member(configuration, "sealedAdmission");
    let seconds = member(sealed, "defaultTolerationSeconds").as_int().and_then(|int| int.to_u64()).expect("seconds");
    let written = epoch_configuration(text(configuration, "qualificationNamespace"), fixture.pin(), text(sealed, "ipFamily"),
                                      text(sealed, "serviceCIDR"), seconds);
    assert!(json::json_eq(&written, configuration));
    assert_eq!(sealed.as_object().map(Object::len), Some(3));
}

/// The service's close and sends for a session whose snapshot view holds `derived`: nothing sent, `answer`'s refusal.
fn refused_with(fixture: &Fixture, derived: Derived) -> (Closed, usize) {
    let wall_ms = millis(OBSERVED_AT);
    let (mut service, mut ops, base) = session(fixture, wall_ms);
    let received = base + Duration::from_millis(100);
    receive(&mut service, &mut ops, fixture.complete_member("request"), wall_ms, received);
    let at = base + Duration::from_millis(300);
    push(&mut service, fixture, derived, received + Duration::from_millis(10), at, wall_ms);
    service.serve_peer_deadlines(&mut ops, Some(wall_ms), at);
    assert!(!service.session_open());
    (service.last_closed().expect("closed"), ops.sent.len())
}

#[test]
fn ii_iii_iv_a_loaded_hash_absent_or_differing_and_four_sealed_members_refuse_with_nothing_sent() {
    let fixture = Fixture::complete();
    let first = |derived: &Derived| i01_answer::refusals(derived, &fixture.facts()).first().copied();
    // (ii) No loaded hash (no sample: UNAVAILABLE): Null reaches derive, and the render's hash is refused.
    let absent = fixture.adm4(None);
    assert_eq!((absent.verdict(), absent.loaded_hash()), (Verdict::Unavailable, None));
    assert_eq!(first(&fixture.derive_with(fixture.configuration(), &absent)), Some(RENDERED_HASH_DIFFERS));
    assert_eq!(refused_with(&fixture, fixture.derive_with(fixture.configuration(), &absent)),
               (Closed::Answer(RENDERED_HASH_DIFFERS), 0));
    // (iii) A loaded hash other than the pin (MISMATCH).
    let other = format!("sha256:{}", "a".repeat(64));
    let differing = fixture.adm4(Some(&other));
    assert_eq!((differing.verdict(), differing.loaded_hash()), (Verdict::Mismatch, Some(other.as_str())));
    assert_eq!(refused_with(&fixture, fixture.derive_with(fixture.configuration(), &differing)),
               (Closed::Answer(RENDERED_HASH_DIFFERS), 0));
    // (iv) sealedAdmission with a fourth member, the namespace, and one with the namespace in a member's place.
    let configuration = fixture.configuration();
    let sealed = member(configuration, "sealedAdmission");
    let malformed = DigestKey::AdmissionPolicy.malformed();
    for changed in [with(sealed, "namespace", member(configuration, "qualificationNamespace").clone()),
                    {
                        let mut three = sealed.as_object().cloned().expect("an object");
                        three.remove(&JStr::new("defaultTolerationSeconds"));
                        three.insert(JStr::new("namespace"), member(configuration, "qualificationNamespace").clone());
                        Value::Object(three)
                    }] {
        let configuration = with(configuration, "sealedAdmission", changed);
        let derived = fixture.derive_with(&configuration, &fixture.adm4(Some(fixture.pin())));
        assert_eq!(first(&derived), Some(malformed));
        assert_eq!(refused_with(&fixture, fixture.derive_with(&configuration, &fixture.adm4(Some(fixture.pin())))),
                   (Closed::Answer(malformed), 0));
    }
}

#[test]
fn no_answer_leaves_a_wake_at_or_after_the_exchange_deadline_or_past_the_outer_bound() {
    // I5E-1: the same ready session, its views pushed late, served at the receipt plus 1.999 s (answered) and at the
    // receipt plus 2 s (not served, nothing sent).
    let fixture = Fixture::complete();
    let wall_ms = millis(OBSERVED_AT);
    for (after, sent) in [(Duration::from_millis(1_999), 1), (I01_EXCHANGE_DEADLINE, 0)] {
        let (mut service, mut ops, base) = session(&fixture, wall_ms);
        let received = base + Duration::from_millis(100);
        receive(&mut service, &mut ops, fixture.complete_member("request"), wall_ms, received);
        let at = received + after;
        push(&mut service, &fixture, fixture.derived(), received + Duration::from_millis(10), at, wall_ms);
        service.serve_peer_deadlines(&mut ops, Some(wall_ms), at);
        assert_eq!(ops.sent.len(), sent, "{after:?}");
        if sent == 0 {
            assert_eq!((service.last_closed(), service.session_open()), (Some(Closed::NotServed), false));
        }
    }
    // Past the outer bound: a request received 899.5 s after the accept, ready at 900 s, closes at the bound.
    let (mut service, mut ops, base) = session(&fixture, wall_ms);
    let received = base + OUTER_BOUND - Duration::from_millis(500);
    receive(&mut service, &mut ops, fixture.complete_member("request"), wall_ms, received);
    let at = base + OUTER_BOUND;
    push(&mut service, &fixture, fixture.derived(), received + Duration::from_millis(10), at, wall_ms);
    service.serve_peer_deadlines(&mut ops, Some(wall_ms), at);
    assert_eq!((service.last_closed(), ops.sent.len()), (Some(Closed::Bound), 0));
}

#[test]
fn a_continuation_is_answered_against_the_first_answer_and_checked_with_it_as_previous() {
    // I3D-6: sequence 2, a new challenge, the first answer's digest, at 00:00:02Z.
    let fixture = Fixture::complete();
    let (mut service, mut ops, at, first) = first_answer(&fixture);
    let digest = sha256::prefixed(&first);
    let second = fixture.continuation(2, &"3".repeat(64), &digest);
    let wall_ms = millis("2026-09-08T00:00:02Z");
    let received = at + Duration::from_millis(500);
    receive(&mut service, &mut ops, &second, wall_ms, received);
    let answered = received + Duration::from_millis(100);
    push(&mut service, &fixture, fixture.derived(), received + Duration::from_millis(10), answered, wall_ms);
    service.serve_peer_deadlines(&mut ops, Some(wall_ms), answered);
    let checked = request_schema(&second).expect("the second request's schema");
    let expected = i01_answer::answer(&fixture.derived(), &checked, &fixture.facts(), wall_ms,
                                      Some(millis(OBSERVED_AT) / 1000)).expect("the continuation is answered");
    assert_eq!(ops.sent, vec![first.clone(), expected.clone()]);
    assert_eq!(text(&parse(&expected), "previousObservationDigest"), digest);
    assert_eq!(i01_answer::self_check(&parse(&expected), &checked, &fixture.binding, wall_ms / 1000, Some(&parse(&first))),
               Ok(()));
    assert!(service.session_open());
}

#[test]
fn a_chain_gap_a_reused_challenge_and_a_clock_rollback_each_close_with_nothing_more_sent() {
    let fixture = Fixture::complete();
    let fresh = "3".repeat(64);
    let first_challenge = text(fixture.complete_member("request"), "challenge").to_string();
    for (sequence, challenge, wall, expected) in [
        (3, fresh.clone(), "2026-09-08T00:00:02Z", Closed::Request(RequestRefusal::Chain("a request out of sequence"))),
        (2, first_challenge, "2026-09-08T00:00:02Z", Closed::Request(RequestRefusal::Chain("a challenge repeated"))),
        (2, fresh.clone(), "2026-09-08T00:00:00Z", Closed::Answer(ANSWER_ROLLBACK_TEXT)),
    ] {
        let (mut service, mut ops, at, first) = first_answer(&fixture);
        let request = fixture.continuation(sequence, &challenge, &sha256::prefixed(&first));
        let wall_ms = millis(wall);
        let received = at + Duration::from_millis(500);
        let bytes = json::canonical(&request).expect("canonical bytes");
        ops.recvs.push_back((bytes.clone(), PeerRecv::Data { length: bytes.len(), pid: 812, uid: 0, gid: 0,
                                                             security: kernel(LABEL) }));
        service.serve_peer_step(&mut ops, Some(wall_ms), received, PeerReady::Peer(PEER, READY));
        if service.session_open() {
            let answered = received + Duration::from_millis(100);
            push(&mut service, &fixture, fixture.derived(), received + Duration::from_millis(10), answered, wall_ms);
            service.serve_peer_deadlines(&mut ops, Some(wall_ms), answered);
        }
        assert_eq!((service.last_closed(), service.session_open(), ops.sent.len()), (Some(expected), false, 1));
    }
}

#[test]
fn self_check_s_own_refusal_answer_s_refusal_and_a_failed_send_close() {
    let fixture = Fixture::complete();
    // self_check's own refusal: the generation drifted between the two answers (VPO's restart, drift or reused
    // challenge, which needs `previous`); answer, which applies no chain rule, passes it.
    let (mut service, mut ops, at, first) = first_answer(&fixture);
    let mut drifted = Fixture::complete();
    let last = if drifted.generation.ends_with('0') { "1" } else { "0" };
    drifted.generation = format!("{}{last}", &drifted.generation[..drifted.generation.len() - 1]);
    assert_ne!(drifted.generation, fixture.generation);
    let second = fixture.continuation(2, &"3".repeat(64), &sha256::prefixed(&first));
    let wall_ms = millis("2026-09-08T00:00:02Z");
    let received = at + Duration::from_millis(500);
    receive(&mut service, &mut ops, &second, wall_ms, received);
    let answered = received + Duration::from_millis(100);
    push(&mut service, &fixture, drifted.derived(), received + Duration::from_millis(10), answered, wall_ms);
    let checked = request_schema(&second).expect("the schema");
    assert!(i01_answer::answer(&drifted.derived(), &checked, &fixture.facts(), wall_ms, Some(millis(OBSERVED_AT) / 1000))
        .is_ok());
    service.serve_peer_deadlines(&mut ops, Some(wall_ms), answered);
    assert_eq!((service.last_closed(), ops.sent.len()), (Some(Closed::Answer(RESTART_TEXT)), 1));
    // answer's refusal: the capture set expired, so every gated value fails its gate.
    let wall_ms = millis(OBSERVED_AT);
    let (mut service, mut ops, base) = session(&fixture, wall_ms);
    let received = base + Duration::from_millis(100);
    receive(&mut service, &mut ops, fixture.complete_member("request"), wall_ms, received);
    let at = base + Duration::from_millis(300);
    push(&mut service, &fixture, fixture.derived(), received + Duration::from_millis(10), at, wall_ms);
    service.peer_capture_view(CaptureGate { expired: true, ..fixture.gate(at, wall_ms) });
    let expired = CaptureFacts { expired: true, ..fixture.facts() };
    let refusal = i01_answer::refusals(&fixture.derived(), &expired).first().copied().expect("a refusal");
    service.serve_peer_deadlines(&mut ops, Some(wall_ms), at);
    assert_eq!((service.last_closed(), ops.sent.len()), (Some(Closed::Answer(refusal)), 0));
    // A failed send (EPIPE): not served, the session closed.
    let (mut service, mut ops, base) = session(&fixture, wall_ms);
    ops.send = PeerSent::Failed(32);
    let received = base + Duration::from_millis(100);
    receive(&mut service, &mut ops, fixture.complete_member("request"), wall_ms, received);
    let at = base + Duration::from_millis(300);
    push(&mut service, &fixture, fixture.derived(), received + Duration::from_millis(10), at, wall_ms);
    service.serve_peer_deadlines(&mut ops, Some(wall_ms), at);
    assert_eq!((service.last_closed(), service.session_open()), (Some(Closed::NotServed), false));
}
