//! The observation epoch (HE-004C DESIGN-C section 2; owner decisions Q-HE4C-1, Q-HE4C-5, Q-HE4C-6, Q-HE4C-7,
//! Q-HE4C-11 and Q-HE4C-14, all (a); MODEL_DEFINED R106 and R111-R117). One epoch is the process's lifetime: the
//! process keeps no durable state and ends with a distinct status at the first loss of continuity.
//!
//! 1. Start: the restart marker `S0` (the single `process_start_time_seconds` sample of `/metrics`), then OR07's hook
//!    until it answers 200 `ok`, polled every 1 s within 300 s (80; 82 if still refused). Until the epoch's first 200
//!    (from either request) a 401 or 403 means "poll again" (the cold start, D1-4, D2-4); afterwards it is 82 at once.
//! 2. Snapshot (120 s with its restarts; 93, or 83 after a transport failure, or 89 while the quotas stay unsettled):
//!    discovery of `admissionregistration.k8s.io` (NotServed attested over every served version; a kind served only
//!    at another version gets no pair, so B1's `Missing` refuses), the lists at one resourceVersion `R` (the first served
//!    spec read fresh, `R` decimal and at least every earlier mark, every other list `Exact` at `R` and answering `R`),
//!    `/version`, then one `/metrics` scrape (the marker still `S0`, the ADM-4 samples). Each list body passes the
//!    16 MiB aggregate and the node-count cap before it is parsed (84). Then, in order: `Inputs::new` (86), the
//!    byte-aware weighted expansion guard (99), `produce_snapshot` and `Closure::check` (87), OR02, OR05 and OR06 (88),
//!    quota headroom (89), ADM-4 (96, then 90 or 91). The inputs are dropped after the checks; the `Observation` keeps
//!    `R`, its freshness mark, the ADM-4 record and digest, the headroom (since HE-004-I01a with each unit's quota
//!    pair) and the dropped non-resource rules.
//! 3. Watching: one watch per served spec from `R` with bookmarks, used only to detect change or continuity loss. A
//!    change (or a line over 64 KiB) closes every watch and re-snapshots, no sooner than 1 s after the last snapshot
//!    started. A stream that ends gets the restart check (a scrape) and is reopened from its last mark; a reopen
//!    answered 410 is a gap (92), and three failed reopens in a row within 60 s are tolerated (83 past that). The
//!    first open after a snapshot answered 410 or 504 restarts the snapshot within its deadline.
//! 4. The 60 s cycle (each starts 60 s after the previous start, or when that cycle ends if later): the progress read
//!    `F` (`GET /api/v1/namespaces?limit=1`, stamped at its request start), with `PER_SPEC_PROGRESS` one `limit=1` probe
//!    per served spec, then the scrape (marker, then B1's `check_loaded_manifest` on a fresh `Adm4Input`).
//! 5. The progress rule: every stream must deliver a bookmark at or beyond `F` within 150 s of `F`'s stamp, or the view
//!    is unavailable and a fresh snapshot runs (three in a row with no `F` passed by every stream between them: 98).
//!    `F` and `R` never go backwards (85); a bookmark below its stream's mark is ignored. The view is available only
//!    while every stream is established and the freshness mark is at most 210 s old.
//!
//! Every exit also records why in [`Epoch::reason`]. `notAfter` reached exits 94; a wall clock before the epoch or past
//! the year 9999 exits 97; a poller failure exits 95.
//!
//! HE-004D1 (DESIGN-D1 section 16; owner decisions Q-HE4D1-6 and -7 (a), Q-HE4D1-D2 (a); MODEL_DEFINED R131) attaches
//! the kernel captures with [`Epoch::with_captures`]; without it nothing below runs and the epoch is HE-004C's.
//! - **One set per cycle, right after its scrape.** In the cycle scrape's answer, after the marker check and the ADM-4
//!   record replace the observation's, the epoch runs one capture set synchronously, scheduled at the cycle's scheduled
//!   start (the previous cycle's actual start + 60 s). A cycle whose scrape escalates takes no set; a set's failures are
//!   slot states and never end the epoch.
//! - **The drain (R2-2, R3-2).** The set only marks the wire for draining. `watch_loop` first finishes the current
//!   poll's batch in order, then, before the next progress check, runs zero-timeout polls, processing each poll's events
//!   in order, until a poll returns no stream event, at most 8 polls, and clears the mark, so a bookmark that arrived
//!   during a set is credited before its deadline is judged (a ninth poll's worth costs availability only). A trigger
//!   from the batch ends the watch phase before any drain poll, and one from a drain poll ends it at once; either way
//!   the mark is cleared when the watch phase ends (and again when the next one starts), so no drain carries over.
//! - **Expiry (D1-8, R2-4, R3-6).** The loop wakes at the record's `expiresAt - 3 s` (the engine's wall clock) and
//!   turns every slot Expired; no set starts after that. [`Epoch::capture_view`] derives Expired at read time in every
//!   phase, and the first observation of expiry is latched, so a wall clock stepped back cannot revive a capture.
//!
//! HE-004-I01a (DESIGN-I01A sections 5 and 14): [`run`] builds the I01 service from the server identity `serve`
//! passes (`I01Service::new`) and attaches it to the client ([`Epoch::with_peer_service`]), so every wait of every
//! phase serves I01; a wait that ends because the I01 listener failed persistently ends the epoch with
//! [`ObserverExit::Listener`] (status 35) instead of the poller's 95.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use i05_protocol::json::Value;
use rustls::ClientConfig;

use crate::admission::{check_loaded_manifest, Adm4Input, Adm4Record, BindingId, MetricSample, ObservationBinding, Verdict};
use crate::capture::{CaptureCycle, CaptureViewState};
use crate::client::{Client, Event, Failure, Handle, Kind, PeerOps, PeerService, Scraped, Wire};
use crate::config::{ObserverConfig, MAX_WALL_SECONDS};
use crate::enrolled::ServerIdentity;
use crate::exposition::Exposition;
use crate::http::{self, Answer, Request, LIST_BODY_LIMIT, SMALL_BODY_LIMIT, SNAPSHOT_BODY_LIMIT};
use crate::i01_service::I01Service;
use crate::inputs::{InputError, Inputs, ListBody, ListInput, Resource};
use crate::operational::{check_or02, check_or05, check_or06, OperationalRefusal};
use crate::quota::{self, Headroom, QuotaError, QuotaPairs};
use crate::rbac::{produce_snapshot, ProduceError};
use crate::requests::{self, MarkError, Mode};
use crate::snapshot::Closure;
use crate::utc;
use crate::watch::{self, decimal};

/// The per-spec progress probe fallback (section 9.5, D2-6): built and host-tested, off. A reviewed packet flips it
/// only after T04 shows idle bookmarks do not reach `F` within `T`, and goes to the owner through the lane monitor
/// (D3-4).
pub const PER_SPEC_PROGRESS: bool = false;
/// OR07's budget, with `S0` and the cold start's 401/403 polling.
pub const OR07_BUDGET: Duration = Duration::from_secs(300);
/// The polling interval of OR07 and `S0`.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// One snapshot, restarts included.
pub const SNAPSHOT_DEADLINE: Duration = Duration::from_secs(120);
/// The pause before a snapshot restarts.
pub const RESTART_PAUSE: Duration = Duration::from_secs(1);
/// The least interval between snapshot starts (coalescing).
pub const COALESCE: Duration = Duration::from_secs(1);
/// The cycle's period.
pub const CYCLE: Duration = Duration::from_secs(60);
/// The progress bound `T`.
pub const PROGRESS_BOUND: Duration = Duration::from_secs(150);
/// The freshness age the view's availability allows.
pub const FRESHNESS_BOUND: Duration = Duration::from_secs(210);
/// Failed opens of one stream in a row, at most, and the window they must fit.
pub const REOPEN_LIMIT: u32 = 3;
pub const REOPEN_WINDOW: Duration = Duration::from_secs(60);
/// The pause between a stream's failed open and the next.
pub const REOPEN_PAUSE: Duration = Duration::from_secs(1);
/// Staleness snapshots in a row, at most.
pub const STALE_LIMIT: u32 = 3;
/// The weighted expansion guard's cap (R117).
pub const EXPANSION_CAP: u64 = 40_000;
/// The node-count cap over one snapshot's lists (R117).
pub const NODE_CAP: usize = 1_000_000;
/// The longest wait of the watch loop without another deadline.
const IDLE_WAKE: Duration = Duration::from_secs(3_600);
/// The most zero-timeout polls of one drain after a capture set (R3-2).
pub const DRAIN_POLLS: u32 = 8;

/// Why the epoch ended (section 14's statuses 80-99; `status::observation` maps each).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserverExit {
    Readyz,
    ApiserverRestart,
    ReadRefused,
    Unreachable,
    Answer,
    Consistency,
    Inputs,
    Rbac,
    Operational,
    Quota,
    Adm4Mismatch,
    Adm4Unavailable,
    WatchGap,
    Deadline,
    ConfigExpired,
    Poll,
    Adm4Input,
    Clock,
    Stale,
    Expansion,
    /// HE-004-I01a: the I01 listener failed persistently (twelve faults in a row).
    Listener,
}

/// The epoch's settings: production uses `PER_SPEC_PROGRESS` and no trace; the tests flip the fallback and record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub per_spec_progress: bool,
    pub trace: bool,
}

impl Settings {
    pub fn production() -> Settings {
        Settings { per_spec_progress: PER_SPEC_PROGRESS, trace: false }
    }
}

/// What a test trace records (only with `Settings::trace`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trace {
    /// OR07 answered 200 `ok` (and `S0` is read).
    Ready,
    /// A snapshot passed every check.
    Snapshot { sequence: u64, resource_version: u64 },
    /// The view's availability changed.
    Available(bool),
    /// A cycle started.
    Cycle,
    /// A progress read gave `F`.
    Progress(u64),
    /// The freshness mark moved to this mark.
    Fresh(u64),
    /// A change on a stream.
    Change(Resource),
    /// A stream ended.
    StreamEnd(Resource),
    /// A stream was re-established after an end or a failed open.
    Reopened(Resource),
    /// A staleness snapshot (the count in a row).
    Stale(u32),
    /// The record of a cycle's ADM-4 check replaced the previous one.
    Adm4,
    /// A capture set ran (HE-004D1): its sequence, the taken slots and the others.
    Captures { sequence: u64, taken: usize, not_taken: usize },
}

/// The in-memory observation (Q-HE4-10 (a)); its encoding is HE-004-I01's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub sequence: u64,
    pub resource_version: u64,
    /// The latest mark every served stream has passed, and the monotonic stamp of the request that read it.
    pub fresh_mark: u64,
    pub fresh_stamp: Instant,
    pub record: Adm4Record,
    pub digest: String,
    pub headroom: Headroom,
    /// HE-004-I01a (DESIGN-I01A section 9): per unit, the least-headroom key's `floor(hard)` and capped `ceil(used)`.
    pub quota: QuotaPairs,
    pub dropped_non_resource_rules: usize,
}

/// Why a snapshot attempt restarts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cause {
    /// A transport failure (status 83 at the deadline).
    Transport,
    /// An exchange deadline, 429, 503, or 410 or 504 on an `Exact` list (93 at the deadline).
    Retry,
    /// Unsettled quotas (89 at the deadline).
    Unsettled,
}

/// A snapshot attempt's stop.
enum Stop {
    Restart(Cause),
    Exit(ObserverExit),
}

impl From<ObserverExit> for Stop {
    fn from(exit: ObserverExit) -> Stop {
        Stop::Exit(exit)
    }
}

/// Why the watch phase hands back to a snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Trigger {
    /// A change (coalesced: no sooner than 1 s after the last snapshot started).
    Change,
    /// A failed check of the cycle or a stream end ("a full snapshot").
    Full,
    /// The progress rule failed.
    Stale,
    /// The first open after a snapshot answered 410 or 504: the snapshot restarts within its deadline.
    InitialOpen,
}

/// What MutatingAdmissionPolicy discovery found for one resource name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Served {
    /// `v1` lists the name.
    Listed,
    /// No served version lists it: `ListBody::NotServed`.
    NotServed,
    /// Only another version lists it: no pair (B1's `Missing`, 86).
    OtherVersionOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamState {
    Opening { initial: bool },
    Established,
    /// Ended, waiting for the restart check.
    Ended,
    /// Waiting to reopen after a failed open.
    Waiting { at: Instant, initial: bool },
}

struct Stream {
    resource: Resource,
    handle: Option<Handle>,
    state: StreamState,
    /// The highest mark: the resume point and the progress mark.
    mark: u64,
    failures: u32,
    first_failure: Option<Instant>,
}

/// A fresh mark the streams must pass.
#[derive(Clone, Copy, Debug)]
struct Pending {
    mark: u64,
    stamp: Instant,
    deadline: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Task {
    Progress,
    Probe(Resource),
    CycleScrape,
    EndCheck,
}

struct Probe {
    task: Task,
    handle: Handle,
    started: Instant,
    wall_start: Option<u64>,
    /// The streams an end check covers (ended before it started).
    covers: Vec<usize>,
}

/// The epoch's state (see the module documentation).
pub struct Epoch<W: Wire> {
    client: Client<W>,
    config: ObserverConfig,
    closure: Closure,
    settings: Settings,
    origin: Instant,
    reason: &'static str,
    trace: Vec<(Duration, Trace)>,
    marker: Option<String>,
    first_200: bool,
    git_version: String,
    observation: Option<Observation>,
    sequence: u64,
    /// Every `R`, every `F` and every passed bookmark of the epoch, at most this.
    highest_mark: u64,
    last_f: Option<u64>,
    cycle_f: Option<u64>,
    last_snapshot_start: Option<Instant>,
    open_deadline: Option<Instant>,
    served: Vec<Resource>,
    streams: Vec<Stream>,
    pending: Vec<Pending>,
    stale_count: u32,
    probe: Option<Probe>,
    queue: VecDeque<Task>,
    cycle_active: bool,
    next_cycle: Option<Instant>,
    available: bool,
    /// HE-004D1: the capture engine, the expiry latch, the drain mark, the current cycle's scheduled start, and each
    /// drain's poll count (the tests' reading).
    captures: Option<Box<dyn CaptureCycle>>,
    capture_expired: Cell<bool>,
    drain_due: bool,
    cycle_scheduled: Option<Instant>,
    drains: Vec<u32>,
}

/// The number of structural tokens (`{`, `[`, `:` and `,`) outside string literals of a JSON text: every parsed value
/// or key is preceded by its own token, so its values are at most this plus one (the node-count cap, D2-7).
pub fn structural_tokens(body: &[u8]) -> usize {
    let (mut count, mut in_string, mut escaped) = (0usize, false, false);
    for &byte in body {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' | b':' | b',' => count = count.saturating_add(1),
            _ => {}
        }
    }
    count
}

/// A rule's weight (R117, D3-1): 1 plus, over every element of its `apiGroups`, `resources`, `verbs`, `resourceNames`
/// and `nonResourceURLs` lists, 1 + the element's UTF-8 bytes / 64 rounded up. A non-object rule, a missing or non-list
/// member and a non-string element count 0 (B1 refuses them next).
fn rule_weight(rule: &Value) -> Option<u64> {
    let Some(members) = rule.as_object() else { return Some(0) };
    let mut weight = 1u64;
    for key in ["apiGroups", "resources", "verbs", "resourceNames", "nonResourceURLs"] {
        let Some(items) = members.get(key).and_then(Value::as_array) else { continue };
        for item in items {
            let Some(text) = item.as_str() else { continue };
            let bytes = u64::try_from(text.len()).ok()?;
            weight = weight.checked_add(1)?.checked_add(bytes.div_ceil(64))?;
        }
    }
    Some(weight)
}

/// A role's weight: the sum of its rules' weights (a missing or malformed `rules` counts 0).
fn role_weight(role: &Value) -> Option<u64> {
    let Some(rules) = role.get("rules").and_then(Value::as_array) else { return Some(0) };
    rules.iter().try_fold(0u64, |total, rule| total.checked_add(rule_weight(rule)?))
}

/// The byte-aware weighted expansion guard's sum (R117, D2-1, D3-1): over every ClusterRoleBinding and RoleBinding,
/// |subjects| x (1 + the weight of the role its `roleRef` names, resolved as B1 resolves it: a ClusterRole by name, or
/// in a RoleBinding a Role of its namespace); a missing or malformed piece counts 0. `None` when the sum overflows.
pub fn expansion_weight(inputs: &Inputs) -> Option<u64> {
    let items = |resource: Resource| inputs.items(resource).unwrap_or(&[]);
    let name = |item: &Value| crate::inputs::object_name(item).map(str::to_string);
    let mut cluster_roles: BTreeMap<String, u64> = BTreeMap::new();
    for role in items(Resource::ClusterRoles) {
        if let Some(key) = name(role) {
            cluster_roles.insert(key, role_weight(role)?);
        }
    }
    let mut roles: BTreeMap<(String, String), u64> = BTreeMap::new();
    for role in items(Resource::Roles) {
        if let (Some(space), Some(key)) = (crate::inputs::object_namespace(role), name(role)) {
            roles.insert((space.to_string(), key), role_weight(role)?);
        }
    }
    let mut total = 0u64;
    for (binding, namespaced) in items(Resource::ClusterRoleBindings)
        .iter()
        .map(|binding| (binding, false))
        .chain(items(Resource::RoleBindings).iter().map(|binding| (binding, true)))
    {
        let subjects = binding.get("subjects").and_then(Value::as_array).map_or(0, <[Value]>::len);
        let reference = binding.get("roleRef");
        let kind = reference.and_then(|value| value.get("kind")).and_then(Value::as_str);
        let target = reference.and_then(|value| value.get("name")).and_then(Value::as_str);
        let group_ok = reference.and_then(|value| value.get("apiGroup")).and_then(Value::as_str)
            == Some("rbac.authorization.k8s.io");
        let weight = match (group_ok, kind, target) {
            (true, Some("ClusterRole"), Some(target)) => cluster_roles.get(target).copied().unwrap_or(0),
            (true, Some("Role"), Some(target)) if namespaced => crate::inputs::object_namespace(binding)
                .and_then(|space| roles.get(&(space.to_string(), target.to_string())).copied())
                .unwrap_or(0),
            _ => 0,
        };
        let subjects = u64::try_from(subjects).ok()?;
        total = total.checked_add(subjects.checked_mul(weight.checked_add(1)?)?)?;
    }
    Some(total)
}

/// The epoch with production settings, the capture engine and the I01 service for `server` (HE-004-I01a), run to its
/// exit (`serve`'s last step).
pub fn run<W: Wire + PeerOps>(wire: W, config: ObserverConfig, tls: Arc<ClientConfig>, closure: Closure,
                              captures: Box<dyn CaptureCycle>, server: ServerIdentity) -> ObserverExit {
    Epoch::new(wire, config, tls, closure, Settings::production())
        .with_captures(captures)
        .with_peer_service(Box::new(I01Service::new(server)))
        .run()
}

fn after(now: Instant, by: Duration) -> Instant {
    now.checked_add(by).unwrap_or(now)
}

impl<W: Wire + PeerOps> Epoch<W> {
    pub fn new(wire: W, config: ObserverConfig, tls: Arc<ClientConfig>, closure: Closure, settings: Settings) -> Epoch<W> {
        let client = Client::new(wire, tls, config.address, &config.authority);
        let origin = client.now();
        Epoch {
            client,
            config,
            closure,
            settings,
            origin,
            reason: "",
            trace: Vec::new(),
            marker: None,
            first_200: false,
            git_version: String::new(),
            observation: None,
            sequence: 0,
            highest_mark: 0,
            last_f: None,
            cycle_f: None,
            last_snapshot_start: None,
            open_deadline: None,
            served: Vec::new(),
            streams: Vec::new(),
            pending: Vec::new(),
            stale_count: 0,
            probe: None,
            queue: VecDeque::new(),
            cycle_active: false,
            next_cycle: None,
            available: false,
            captures: None,
            capture_expired: Cell::new(false),
            drain_due: false,
            cycle_scheduled: None,
            drains: Vec::new(),
        }
    }

    /// Attaches the capture engine (HE-004D1): one set per cycle, the drain, the expiry wake.
    pub fn with_captures(mut self, captures: Box<dyn CaptureCycle>) -> Epoch<W> {
        self.captures = Some(captures);
        self
    }

    /// Attaches the I01 service (HE-004-I01a): the client's every later wait serves it.
    pub fn with_peer_service(mut self, service: Box<dyn PeerService>) -> Epoch<W> {
        self.client.serve_peers(service);
        self
    }

    /// The latest capture view: `Current` only while the engine's wall clock is before `expiresAt - 3 s`, `Expired`
    /// from then on whatever the clock later says (the latch, R3-6); `None` without captures.
    pub fn capture_view(&self) -> Option<CaptureViewState<'_>> {
        let captures = self.captures.as_ref()?;
        if self.capture_expired.get() || captures.expired_now() {
            self.capture_expired.set(true);
            return Some(CaptureViewState::Expired);
        }
        Some(CaptureViewState::Current(captures.view()))
    }

    /// The poll count of each drain so far (the tests' reading).
    pub fn drains(&self) -> &[u32] {
        &self.drains
    }

    /// The expiry wake's work: once the engine's wall clock reaches `expiresAt - 3 s`, latch and turn every slot
    /// Expired.
    fn check_capture_expiry(&mut self) {
        let Some(captures) = self.captures.as_mut() else { return };
        if !self.capture_expired.get() && captures.expired_now() {
            self.capture_expired.set(true);
            captures.expire();
        }
    }

    /// One capture set right after a cycle's scrape (section 16); it only marks the wire for draining.
    fn capture_cycle(&mut self) {
        self.check_capture_expiry();
        if self.capture_expired.get() {
            return;
        }
        let now = self.client.now();
        let scheduled = self.cycle_scheduled.unwrap_or(now);
        let Some(captures) = self.captures.as_mut() else { return };
        captures.capture_set(scheduled);
        let view = captures.view();
        let (sequence, (taken, not_taken)) = (view.sequence, view.counts());
        self.note(Trace::Captures { sequence, taken, not_taken });
        self.drain_due = true;
    }

    /// After the batch: zero-timeout polls, each poll's events in order, until one returns no stream event, at most
    /// `DRAIN_POLLS`; the mark is cleared.
    fn drain(&mut self) -> Result<Option<Trigger>, ObserverExit> {
        let mut polls = 0u32;
        while polls < DRAIN_POLLS {
            polls = polls.saturating_add(1);
            let events = self.client.poll(self.client.now()).map_err(|_| self.poll_failed())?;
            let streamed = events.iter().any(|(handle, _)| self.streams.iter().any(|stream| stream.handle == Some(*handle)));
            for (handle, event) in events {
                if let Some(trigger) = self.on_event(handle, event)? {
                    self.drains.push(polls);
                    return Ok(Some(trigger));
                }
            }
            if !streamed {
                break;
            }
        }
        self.drains.push(polls);
        self.drain_due = false;
        Ok(None)
    }

    /// Why the epoch ended (set with the exit).
    pub fn reason(&self) -> &'static str {
        self.reason
    }

    /// The test trace (empty unless `Settings::trace`).
    pub fn trace(&self) -> &[(Duration, Trace)] {
        &self.trace
    }

    /// The latest observation.
    pub fn observation(&self) -> Option<&Observation> {
        self.observation.as_ref()
    }

    /// The client (the tests read their fake wire through it).
    pub fn client(&self) -> &Client<W> {
        &self.client
    }

    fn note(&mut self, entry: Trace) {
        if self.settings.trace {
            let at = self.client.now().saturating_duration_since(self.origin);
            self.trace.push((at, entry));
        }
    }

    fn fail(&mut self, exit: ObserverExit, why: &'static str) -> ObserverExit {
        self.reason = why;
        exit
    }

    /// A failed wait: the I01 listener's persistent failure (35) when the client names it, else the poller's (95).
    fn poll_failed(&mut self) -> ObserverExit {
        if self.client.listener_failed() {
            return self.fail(ObserverExit::Listener, "the I01 listener failed persistently");
        }
        self.fail(ObserverExit::Poll, "the poller failed")
    }

    /// Runs the epoch to its exit; there is no normal end.
    pub fn run(&mut self) -> ObserverExit {
        let exit = match self.epoch() {
            Ok(never) => match never {},
            Err(exit) => exit,
        };
        self.client.close_all();
        exit
    }

    fn epoch(&mut self) -> Result<std::convert::Infallible, ObserverExit> {
        self.start()?;
        let mut trigger = None;
        loop {
            let now = self.client.now();
            let deadline = match trigger {
                Some(Trigger::InitialOpen) => {
                    self.client.pause(after(now, RESTART_PAUSE)).map_err(|_| self.poll_failed())?;
                    self.open_deadline.unwrap_or_else(|| after(now, SNAPSHOT_DEADLINE))
                }
                _ => {
                    if let Some(last) = self.last_snapshot_start {
                        self.client.pause(after(last, COALESCE)).map_err(|_| self.poll_failed())?;
                    }
                    after(self.client.now(), SNAPSHOT_DEADLINE)
                }
            };
            self.last_snapshot_start = Some(self.client.now());
            self.snapshot(deadline)?;
            self.open_deadline = Some(deadline);
            trigger = Some(self.watch()?);
        }
    }

    /// The wall clock's checks at every step: 97 for an unusable clock, 94 once `notAfter` is reached.
    fn check_clock(&mut self) -> Result<(), ObserverExit> {
        match self.client.wall_seconds() {
            Some(wall) if wall <= MAX_WALL_SECONDS => {
                if self.config.expired(wall) {
                    return Err(self.fail(ObserverExit::ConfigExpired, "the configuration's notAfter is reached"));
                }
                Ok(())
            }
            _ => Err(self.fail(ObserverExit::Clock, "the wall clock is before the epoch or past the year 9999")),
        }
    }

    // ------------------------------------------------------------------------------------------ start: S0 and OR07

    /// Step 1: `S0`, then OR07, polled every 1 s within 300 s with the cold start rule.
    fn start(&mut self) -> Result<(), ObserverExit> {
        let deadline = after(self.client.now(), OR07_BUDGET);
        let mut refused = false;
        loop {
            self.check_clock()?;
            let attempt = self.client.now();
            if attempt >= deadline {
                return Err(if refused {
                    self.fail(ObserverExit::ReadRefused, "401 or 403 still at the end of OR07's cold start window")
                } else {
                    self.fail(ObserverExit::Readyz, "OR07 did not answer 200 ok within 300 s")
                });
            }
            let refusal = if self.marker.is_none() { self.start_scrape(deadline)? } else { self.start_readyz(deadline)? };
            match refusal {
                Poll::Done => {
                    self.note(Trace::Ready);
                    return Ok(());
                }
                Poll::Next => {
                    refused = false;
                    continue;
                }
                Poll::Again { refused: by_rbac } => refused = by_rbac,
            }
            let resume = after(attempt, POLL_INTERVAL).min(deadline);
            self.client.pause(resume).map_err(|_| self.poll_failed())?;
        }
    }

    /// The cold start rule for a 401 or 403 of `/readyz` or the `S0` scrape.
    fn cold_refusal(&mut self) -> Result<Poll, ObserverExit> {
        if self.first_200 {
            return Err(self.fail(ObserverExit::ReadRefused, "401 or 403 after the epoch's first 200"));
        }
        Ok(Poll::Again { refused: true })
    }

    fn start_scrape(&mut self, deadline: Instant) -> Result<Poll, ObserverExit> {
        let event = self.client.run(&requests::metrics(), Kind::Scrape, deadline).map_err(|_| self.poll_failed())?;
        match event {
            Event::Scraped(Scraped::Exposition(Ok(exposition))) => {
                let Ok(marker) = exposition.marker() else {
                    return Err(self.fail(ObserverExit::Answer, "zero or several restart-marker samples"));
                };
                self.marker = Some(marker.to_string());
                self.first_200 = true;
                Ok(Poll::Next)
            }
            Event::Scraped(Scraped::Exposition(Err(_))) => Err(self.fail(ObserverExit::Answer, "a malformed exposition")),
            Event::Scraped(Scraped::Status(401 | 403)) => self.cold_refusal(),
            Event::Scraped(Scraped::Status(404 | 410)) => Err(self.fail(ObserverExit::Answer, "the S0 scrape answered 404 or 410")),
            Event::Scraped(Scraped::Status(status)) if status == 429 || (500..=599).contains(&status) => {
                Ok(Poll::Again { refused: false })
            }
            Event::Scraped(Scraped::Status(_)) => Err(self.fail(ObserverExit::Answer, "the S0 scrape answered another status")),
            Event::Failed(Failure::Transport | Failure::Deadline | Failure::Idle) => Ok(Poll::Again { refused: false }),
            Event::Failed(_) => Err(self.fail(ObserverExit::Answer, "the S0 scrape's framing was refused")),
            _ => Err(self.fail(ObserverExit::Answer, "the S0 scrape ended unexpectedly")),
        }
    }

    fn start_readyz(&mut self, deadline: Instant) -> Result<Poll, ObserverExit> {
        let event = self.client.run(&requests::readyz(), Kind::Answer(SMALL_BODY_LIMIT), deadline).map_err(|_| self.poll_failed())?;
        match event {
            Event::Answer(answer) => match answer.status {
                200 => {
                    self.first_200 = true;
                    if http::media_is(answer.content_type.as_deref(), http::ACCEPT_TEXT) && answer.body == b"ok" {
                        Ok(Poll::Done)
                    } else {
                        Err(self.fail(ObserverExit::Answer, "OR07 answered 200 without exactly ok"))
                    }
                }
                401 | 403 => self.cold_refusal(),
                404 => Err(self.fail(ObserverExit::Readyz, "OR07's hook is absent (404): RBAC is not an authorizer")),
                410 => Err(self.fail(ObserverExit::Answer, "OR07 answered 410")),
                status if status == 429 || (500..=599).contains(&status) => Ok(Poll::Again { refused: false }),
                _ => Err(self.fail(ObserverExit::Answer, "OR07 answered another status")),
            },
            Event::Failed(Failure::Transport | Failure::Deadline | Failure::Idle) => Ok(Poll::Again { refused: false }),
            Event::Failed(_) => Err(self.fail(ObserverExit::Answer, "OR07's framing was refused")),
            _ => Err(self.fail(ObserverExit::Answer, "OR07 ended unexpectedly")),
        }
    }

    // ------------------------------------------------------------------------------------------ the snapshot

    fn stop(&mut self, exit: ObserverExit, why: &'static str) -> Stop {
        Stop::Exit(self.fail(exit, why))
    }

    /// Step 2 with its restarts, within `deadline`.
    fn snapshot(&mut self, deadline: Instant) -> Result<(), ObserverExit> {
        let mut last = Cause::Retry;
        loop {
            self.check_clock()?;
            let now = self.client.now();
            if now >= deadline {
                return Err(match last {
                    Cause::Transport => self.fail(ObserverExit::Unreachable, "the snapshot deadline, after a transport failure"),
                    Cause::Unsettled => self.fail(ObserverExit::Quota, "the quotas stayed unsettled to the snapshot deadline"),
                    Cause::Retry => self.fail(ObserverExit::Deadline, "the snapshot deadline"),
                });
            }
            match self.snapshot_once(deadline) {
                Ok(()) => return Ok(()),
                Err(Stop::Exit(exit)) => return Err(exit),
                Err(Stop::Restart(cause)) => {
                    last = cause;
                    let resume = after(self.client.now(), RESTART_PAUSE).min(deadline);
                    self.client.pause(resume).map_err(|_| self.poll_failed())?;
                }
            }
        }
    }

    /// One snapshot request answered in full: a 200 JSON answer, or a restart or exit by section 5.3's snapshot column.
    fn snapshot_answer(&mut self, request: &Request, body: usize, exact: bool, deadline: Instant) -> Result<Answer, Stop> {
        self.check_clock()?;
        let event = self.client.run(request, Kind::Answer(body), deadline).map_err(|_| Stop::Exit(self.poll_failed()))?;
        match event {
            Event::Answer(answer) => match answer.status {
                200 if http::media_is(answer.content_type.as_deref(), http::ACCEPT_JSON) => Ok(answer),
                200 => Err(self.stop(ObserverExit::Answer, "a 200 answer that is not application/json")),
                401 | 403 => Err(self.stop(ObserverExit::ReadRefused, "a snapshot read was refused (401 or 403)")),
                410 | 504 if exact => Err(Stop::Restart(Cause::Retry)),
                429 | 503 => Err(Stop::Restart(Cause::Retry)),
                404 => Err(self.stop(ObserverExit::Answer, "a snapshot read answered 404")),
                _ => Err(self.stop(ObserverExit::Answer, "a snapshot read answered another status")),
            },
            Event::Failed(Failure::Transport) => Err(Stop::Restart(Cause::Transport)),
            Event::Failed(Failure::Deadline | Failure::Idle) => Err(Stop::Restart(Cause::Retry)),
            Event::Failed(_) => Err(self.stop(ObserverExit::Answer, "a snapshot answer's framing was refused")),
            _ => Err(self.stop(ObserverExit::Answer, "a snapshot read ended unexpectedly")),
        }
    }

    /// Discovery (section 6.4): the served state of the two MutatingAdmissionPolicy kinds.
    fn discovery(&mut self, deadline: Instant) -> Result<(Served, Served), Stop> {
        let group = self.snapshot_answer(&requests::discovery_group(), SMALL_BODY_LIMIT, false, deadline)?;
        let versions = match requests::group_versions(&group.body) {
            Ok(versions) => versions,
            Err(error) => return Err(self.stop(ObserverExit::Answer, error.0)),
        };
        let mut lists: Vec<(String, Vec<String>)> = Vec::with_capacity(versions.len());
        for version in versions {
            let answer = self.snapshot_answer(&requests::discovery_version(&version), SMALL_BODY_LIMIT, false, deadline)?;
            match requests::resource_names(&answer.body, &version) {
                Ok(names) => lists.push((version, names)),
                Err(error) => return Err(self.stop(ObserverExit::Answer, error.0)),
            }
        }
        let served = |name: &str| {
            let by = |version: &(String, Vec<String>)| version.1.iter().any(|listed| listed == name);
            if lists.iter().any(|version| version.0 == requests::ADMISSION_VERSION && by(version)) {
                Served::Listed
            } else if lists.iter().any(by) {
                Served::OtherVersionOnly
            } else {
                Served::NotServed
            }
        };
        Ok((served(Resource::MutatingAdmissionPolicies.resource()), served(Resource::MutatingAdmissionPolicyBindings.resource())))
    }

    /// One snapshot attempt (section 6.5's order, then section 14's checks).
    fn snapshot_once(&mut self, deadline: Instant) -> Result<(), Stop> {
        let (policies, bindings) = self.discovery(deadline)?;
        let mut pairs: Vec<ListInput> = Vec::with_capacity(Resource::ALL.len());
        let mut served: Vec<Resource> = Vec::with_capacity(Resource::ALL.len());
        let mut fresh: Option<(String, u64, Instant)> = None;
        let (mut total, mut nodes) = (0usize, 0usize);
        for resource in Resource::ALL {
            let state = match resource {
                Resource::MutatingAdmissionPolicies => policies,
                Resource::MutatingAdmissionPolicyBindings => bindings,
                _ => Served::Listed,
            };
            match state {
                Served::NotServed => {
                    pairs.push(ListInput { spec: resource.spec(), body: ListBody::NotServed });
                    continue;
                }
                Served::OtherVersionOnly => continue,
                Served::Listed => {}
            }
            let mode = match &fresh {
                None => Mode::Fresh,
                Some((version, _, _)) => Mode::Exact(version.clone()),
            };
            let started = self.client.now();
            let exact = matches!(mode, Mode::Exact(_));
            let answer = self.snapshot_answer(&requests::list(resource, &mode), LIST_BODY_LIMIT, exact, deadline)?;
            total = total.saturating_add(answer.body.len());
            if total > SNAPSHOT_BODY_LIMIT {
                return Err(self.stop(ObserverExit::Answer, "one snapshot's list bodies exceed 16 MiB together"));
            }
            nodes = nodes.saturating_add(structural_tokens(&answer.body));
            if nodes > NODE_CAP {
                return Err(self.stop(ObserverExit::Answer, "one snapshot's lists exceed the node-count cap"));
            }
            let value = match requests::document(&answer.body) {
                Ok(value) => value,
                Err(error) => return Err(self.stop(ObserverExit::Answer, error.0)),
            };
            drop(answer);
            let version = requests::list_resource_version(&value).map(str::to_string);
            match &fresh {
                None => {
                    let Some((text, mark)) = version.and_then(|text| decimal(&text).map(|mark| (text, mark))) else {
                        return Err(self.stop(ObserverExit::Consistency, "the fresh list's resourceVersion is not decimal"));
                    };
                    if mark < self.highest_mark {
                        return Err(self.stop(ObserverExit::Consistency, "a new snapshot's R is below an earlier mark"));
                    }
                    fresh = Some((text, mark, started));
                }
                Some((expected, _, _)) => {
                    if version.as_deref() != Some(expected.as_str()) {
                        return Err(self.stop(ObserverExit::Consistency, "an Exact list answered another resourceVersion"));
                    }
                }
            }
            served.push(resource);
            pairs.push(ListInput { spec: resource.spec(), body: ListBody::Served(value) });
        }
        let Some((_, mark, stamp)) = fresh else {
            return Err(self.stop(ObserverExit::Answer, "no list was read"));
        };
        let version = self.snapshot_answer(&requests::version(), SMALL_BODY_LIMIT, false, deadline)?;
        let git_version = match requests::git_version(&version.body) {
            Ok(text) => text,
            Err(error) => return Err(self.stop(ObserverExit::Answer, error.0)),
        };
        let (exposition, window) = self.snapshot_scrape(deadline)?;
        self.git_version = git_version;
        let observation = self.check_snapshot(pairs, exposition.samples, window, mark, stamp)?;
        self.highest_mark = self.highest_mark.max(mark);
        self.served = served;
        self.sequence = observation.sequence;
        self.note(Trace::Snapshot { sequence: observation.sequence, resource_version: mark });
        self.observation = Some(observation);
        Ok(())
    }

    /// The snapshot's final scrape: the marker still `S0`; the samples and the wall readings of the window.
    fn snapshot_scrape(&mut self, deadline: Instant) -> Result<(Exposition, (Option<u64>, Option<u64>)), Stop> {
        self.check_clock()?;
        let wall_start = self.client.wall_seconds();
        let event = self.client.run(&requests::metrics(), Kind::Scrape, deadline).map_err(|_| Stop::Exit(self.poll_failed()))?;
        let wall_end = self.client.wall_seconds();
        let exposition = match event {
            Event::Scraped(Scraped::Exposition(Ok(exposition))) => exposition,
            Event::Scraped(Scraped::Exposition(Err(_))) => return Err(self.stop(ObserverExit::Answer, "a malformed exposition")),
            Event::Scraped(Scraped::Status(401 | 403)) => {
                return Err(self.stop(ObserverExit::ReadRefused, "the snapshot scrape was refused (401 or 403)"));
            }
            Event::Scraped(Scraped::Status(429 | 503)) => return Err(Stop::Restart(Cause::Retry)),
            Event::Scraped(Scraped::Status(_)) => return Err(self.stop(ObserverExit::Answer, "the snapshot scrape answered another status")),
            Event::Failed(Failure::Transport) => return Err(Stop::Restart(Cause::Transport)),
            Event::Failed(Failure::Deadline | Failure::Idle) => return Err(Stop::Restart(Cause::Retry)),
            Event::Failed(_) => return Err(self.stop(ObserverExit::Answer, "the snapshot scrape's framing was refused")),
            _ => return Err(self.stop(ObserverExit::Answer, "the snapshot scrape ended unexpectedly")),
        };
        self.check_marker(&exposition).map_err(Stop::Exit)?;
        Ok((exposition, (wall_start, wall_end)))
    }

    /// The restart marker of an exposition against `S0`: 84 for zero or several samples, 81 for another text.
    fn check_marker(&mut self, exposition: &Exposition) -> Result<(), ObserverExit> {
        let Ok(marker) = exposition.marker() else {
            return Err(self.fail(ObserverExit::Answer, "zero or several restart-marker samples"));
        };
        if self.marker.as_deref() != Some(marker) {
            return Err(self.fail(ObserverExit::ApiserverRestart, "the restart marker differs from S0"));
        }
        Ok(())
    }

    /// ADM-4 (sections 8.3-8.5): a fresh `Adm4Input` from the configuration, the samples, the snapshot's `gitVersion`
    /// and the window; 97 for an unusable clock, 96 for `Adm4InputError`, 90 and 91 for the verdicts.
    fn adm4(&mut self, samples: Vec<MetricSample>, window: (Option<u64>, Option<u64>)) -> Result<(Adm4Record, String), ObserverExit> {
        let Some((window_start, window_end)) = utc::window(window.0, window.1) else {
            return Err(self.fail(ObserverExit::Clock, "the ADM-4 window's wall clock cannot be rendered"));
        };
        let input = Adm4Input {
            pinned_hash: self.config.pinned_manifest_hash.clone(),
            expected_plugin: self.config.expected_plugin.clone(),
            samples,
            kubernetes_version: self.git_version.clone(),
            binding: ObservationBinding { id: BindingId::Nonce(self.config.nonce.clone()), window_start, window_end },
        };
        let Ok(record) = check_loaded_manifest(&input) else {
            return Err(self.fail(ObserverExit::Adm4Input, "check_loaded_manifest refused its input"));
        };
        match record.verdict() {
            Verdict::Match => {
                let digest = record.digest();
                Ok((record, digest))
            }
            Verdict::Mismatch => Err(self.fail(ObserverExit::Adm4Mismatch, "the loaded admission manifest hash differs")),
            Verdict::Unavailable => Err(self.fail(ObserverExit::Adm4Unavailable, "the ADM-4 verdict is UNAVAILABLE")),
        }
    }

    fn input_exit(&mut self, _error: &InputError) -> Stop {
        self.stop(ObserverExit::Inputs, "B1 refused the list inputs")
    }

    /// Section 14's checks in order, on one snapshot's inputs; the observation.
    fn check_snapshot(&mut self, pairs: Vec<ListInput>, samples: Vec<MetricSample>, window: (Option<u64>, Option<u64>),
                      mark: u64, stamp: Instant) -> Result<Observation, Stop> {
        let inputs = match Inputs::new(pairs) {
            Ok(inputs) => inputs,
            Err(error) => return Err(self.input_exit(&error)),
        };
        if expansion_weight(&inputs).is_none_or(|weight| weight > EXPANSION_CAP) {
            return Err(self.stop(ObserverExit::Expansion, "the weighted expansion guard exceeds 40,000"));
        }
        let namespace = self.config.namespace.clone();
        let produced = match produce_snapshot(&inputs, &namespace) {
            Ok(produced) => produced,
            Err(ProduceError::Input(error)) => return Err(self.input_exit(&error)),
            Err(_) => return Err(self.stop(ObserverExit::Rbac, "B1's producer refused the RBAC lists")),
        };
        if self.closure.check(&produced.snapshot, &namespace).is_err() {
            return Err(self.stop(ObserverExit::Rbac, "the RBAC snapshot check refused"));
        }
        let dropped = produced.dropped_non_resource_rules;
        drop(produced);
        for check in [check_or02, check_or05, check_or06] {
            match check(&inputs) {
                Ok(()) => {}
                Err(OperationalRefusal::Input(error)) => return Err(self.input_exit(&error)),
                Err(_) => return Err(self.stop(ObserverExit::Operational, "an operational rule (OR02, OR05, OR06) refused")),
            }
        }
        let quotas = match inputs.items(Resource::ResourceQuotas) {
            Ok(items) => quota::quota(items, &namespace),
            Err(error) => return Err(self.input_exit(&error)),
        };
        let quotas = match quotas {
            Ok(quotas) => quotas,
            Err(QuotaError::Unsettled) => return Err(Stop::Restart(Cause::Unsettled)),
            Err(QuotaError::Refused(why)) => return Err(self.stop(ObserverExit::Quota, why)),
        };
        drop(inputs);
        let (record, digest) = self.adm4(samples, window).map_err(Stop::Exit)?;
        Ok(Observation {
            sequence: self.sequence.saturating_add(1),
            resource_version: mark,
            fresh_mark: mark,
            fresh_stamp: stamp,
            record,
            digest,
            headroom: quotas.headroom,
            quota: quotas.pairs,
            dropped_non_resource_rules: dropped,
        })
    }

    // ------------------------------------------------------------------------------------------ watching

    fn resource_version(&self) -> u64 {
        self.observation.as_ref().map_or(0, |observation| observation.resource_version)
    }

    fn open_stream(&mut self, index: usize, initial: bool) {
        let Some(stream) = self.streams.get(index) else { return };
        let request = requests::list(stream.resource, &Mode::Watch(stream.mark.to_string()));
        let handle = self.client.open(&request, Kind::Watch);
        if let Some(stream) = self.streams.get_mut(index) {
            stream.handle = Some(handle);
            stream.state = StreamState::Opening { initial };
        }
    }

    /// Step 3 to 5: the watch phase until a snapshot is needed.
    fn watch(&mut self) -> Result<Trigger, ObserverExit> {
        let mark = self.resource_version();
        self.streams = self
            .served
            .iter()
            .map(|resource| Stream { resource: *resource, handle: None, state: StreamState::Opening { initial: true },
                                     mark, failures: 0, first_failure: None })
            .collect();
        self.pending.clear();
        self.cycle_f = None;
        self.probe = None;
        self.queue.clear();
        self.cycle_active = false;
        self.drain_due = false;
        if self.next_cycle.is_none() {
            self.next_cycle = self.observation.as_ref().map(|observation| after(observation.fresh_stamp, CYCLE));
        }
        for index in 0..self.streams.len() {
            self.open_stream(index, true);
        }
        let trigger = self.watch_loop();
        self.drain_due = false;
        self.client.close_all();
        self.probe = None;
        self.queue.clear();
        self.cycle_active = false;
        self.set_available(false);
        trigger
    }

    fn watch_loop(&mut self) -> Result<Trigger, ObserverExit> {
        loop {
            self.check_clock()?;
            self.check_capture_expiry();
            let now = self.client.now();
            for index in 0..self.streams.len() {
                if let Some(StreamState::Waiting { at, initial }) = self.streams.get(index).map(|stream| stream.state) {
                    if at <= now {
                        self.open_stream(index, initial);
                    }
                }
            }
            if let Some(trigger) = self.check_progress(now)? {
                return Ok(trigger);
            }
            if self.probe.is_none() {
                if self.queue.is_empty() && !self.cycle_active && self.next_cycle.is_some_and(|at| at <= now) {
                    self.start_cycle(now);
                }
                if let Some(task) = self.queue.pop_front() {
                    self.start_probe(task);
                }
            }
            let available = self.view_available(now);
            self.set_available(available);
            let wake = self.wake(now);
            let events = self.client.poll(wake).map_err(|_| self.poll_failed())?;
            for (handle, event) in events {
                if let Some(trigger) = self.on_event(handle, event)? {
                    return Ok(trigger);
                }
            }
            if self.drain_due {
                if let Some(trigger) = self.drain()? {
                    return Ok(trigger);
                }
            }
        }
    }

    fn view_available(&self, now: Instant) -> bool {
        !self.streams.is_empty()
            && self.streams.iter().all(|stream| stream.state == StreamState::Established)
            && self.observation.as_ref().is_some_and(|observation| {
                now.saturating_duration_since(observation.fresh_stamp) <= FRESHNESS_BOUND
            })
    }

    fn set_available(&mut self, available: bool) {
        if available != self.available {
            self.available = available;
            self.note(Trace::Available(available));
        }
    }

    /// Whether the view is available now (the tests' reading).
    pub fn available(&self) -> bool {
        self.available
    }

    fn wake(&self, now: Instant) -> Instant {
        let mut wake = after(now, IDLE_WAKE);
        if self.probe.is_none() && !self.cycle_active {
            if let Some(at) = self.next_cycle {
                wake = wake.min(at);
            }
        }
        for stream in &self.streams {
            if let StreamState::Waiting { at, .. } = stream.state {
                wake = wake.min(at);
            }
        }
        if let Some(pending) = self.pending.first() {
            wake = wake.min(pending.deadline);
        }
        if self.available {
            if let Some(observation) = &self.observation {
                wake = wake.min(after(observation.fresh_stamp, FRESHNESS_BOUND + Duration::from_millis(1)));
            }
        }
        if let Some(wall) = self.client.wall_seconds() {
            let left = self.config.not_after.saturating_sub(wall);
            wake = wake.min(after(now, Duration::from_secs(left)));
        }
        if !self.capture_expired.get() {
            if let Some(at) = self.captures.as_ref().and_then(|captures| captures.expiry_wake()) {
                wake = wake.min(at);
            }
        }
        wake.max(now)
    }

    fn start_cycle(&mut self, now: Instant) {
        self.cycle_active = true;
        self.cycle_scheduled = Some(self.next_cycle.unwrap_or(now));
        self.next_cycle = Some(after(now, CYCLE));
        self.cycle_f = None;
        self.note(Trace::Cycle);
        self.queue.push_back(Task::Progress);
        if self.settings.per_spec_progress {
            for resource in self.served.clone() {
                self.queue.push_back(Task::Probe(resource));
            }
        }
        self.queue.push_back(Task::CycleScrape);
    }

    fn start_probe(&mut self, task: Task) {
        let (request, kind) = match task {
            Task::Progress => (requests::progress(), Kind::Answer(SMALL_BODY_LIMIT)),
            Task::Probe(resource) => (requests::list(resource, &Mode::Probe), Kind::Answer(LIST_BODY_LIMIT)),
            Task::CycleScrape | Task::EndCheck => (requests::metrics(), Kind::Scrape),
        };
        let covers = if task == Task::EndCheck {
            self.streams.iter().enumerate().filter(|(_, stream)| stream.state == StreamState::Ended).map(|(index, _)| index).collect()
        } else {
            Vec::new()
        };
        let started = self.client.now();
        let wall_start = self.client.wall_seconds();
        let handle = self.client.open(&request, kind);
        self.probe = Some(Probe { task, handle, started, wall_start, covers });
    }

    /// The progress rule's deadlines: the oldest fresh mark not yet passed by every stream.
    fn check_progress(&mut self, now: Instant) -> Result<Option<Trigger>, ObserverExit> {
        if !self.pending.first().is_some_and(|pending| pending.deadline <= now) {
            return Ok(None);
        }
        self.stale_count = self.stale_count.saturating_add(1);
        let count = self.stale_count;
        self.note(Trace::Stale(count));
        if count >= STALE_LIMIT {
            return Err(self.fail(ObserverExit::Stale, "three staleness snapshots in a row"));
        }
        Ok(Some(Trigger::Stale))
    }

    /// The fresh marks every stream has passed: the freshness mark moves to the latest of them.
    fn advance_fresh(&mut self) {
        let Some(low) = self.streams.iter().map(|stream| stream.mark).min() else { return };
        let Some(passed) = self.pending.iter().filter(|pending| pending.mark <= low).next_back().copied() else { return };
        self.pending.retain(|pending| pending.mark > low);
        self.stale_count = 0;
        if let Some(observation) = self.observation.as_mut() {
            observation.fresh_mark = passed.mark;
            observation.fresh_stamp = passed.stamp;
        }
        self.note(Trace::Fresh(passed.mark));
    }

    fn on_event(&mut self, handle: Handle, event: Event) -> Result<Option<Trigger>, ObserverExit> {
        if self.probe.as_ref().is_some_and(|probe| probe.handle == handle) {
            if !event.ends() {
                return Ok(None);
            }
            let Some(probe) = self.probe.take() else { return Ok(None) };
            return self.on_probe(probe, event);
        }
        let Some(index) = self.streams.iter().position(|stream| stream.handle == Some(handle)) else { return Ok(None) };
        self.on_stream(index, event)
    }

    fn on_stream(&mut self, index: usize, event: Event) -> Result<Option<Trigger>, ObserverExit> {
        let now = self.client.now();
        let Some(stream) = self.streams.get_mut(index) else { return Ok(None) };
        let resource = stream.resource;
        let state = stream.state;
        match event {
            Event::Established => {
                let reopened = !matches!(state, StreamState::Opening { initial: true }) || stream.failures > 0;
                stream.state = StreamState::Established;
                stream.failures = 0;
                stream.first_failure = None;
                if reopened {
                    self.note(Trace::Reopened(resource));
                }
                if self.streams.iter().all(|stream| stream.state == StreamState::Established) {
                    self.open_deadline = None;
                }
                Ok(None)
            }
            Event::Line(line) => match watch::classify(&line, requests::watch_kind(resource)) {
                watch::Event::Change => {
                    self.note(Trace::Change(resource));
                    Ok(Some(Trigger::Change))
                }
                watch::Event::Bookmark(mark) => {
                    if mark > stream.mark {
                        stream.mark = mark;
                        self.highest_mark = self.highest_mark.max(mark);
                        self.advance_fresh();
                    }
                    Ok(None)
                }
                watch::Event::Gap(why) => Err(self.fail(ObserverExit::WatchGap, why)),
            },
            Event::LongLine => {
                self.note(Trace::Change(resource));
                Ok(Some(Trigger::Change))
            }
            Event::Refused(status) => {
                let initial = matches!(state, StreamState::Opening { initial: true });
                match status {
                    401 | 403 => Err(self.fail(ObserverExit::ReadRefused, "a watch open was refused (401 or 403)")),
                    410 | 504 if initial => Ok(Some(Trigger::InitialOpen)),
                    410 => Err(self.fail(ObserverExit::WatchGap, "a watch reopen answered 410")),
                    429 | 503 | 504 => self.failed_open(index, now),
                    _ => Err(self.fail(ObserverExit::Answer, "a watch open answered another status")),
                }
            }
            Event::Failed(Failure::Framing(_) | Failure::Media) => {
                Err(self.fail(ObserverExit::Answer, "a watch answer's framing was refused"))
            }
            Event::Final | Event::Failed(Failure::Transport | Failure::Idle | Failure::Deadline) => {
                if state == StreamState::Established {
                    stream.state = StreamState::Ended;
                    stream.handle = None;
                    self.note(Trace::StreamEnd(resource));
                    if !self.queue.contains(&Task::EndCheck) {
                        self.queue.push_front(Task::EndCheck);
                    }
                    Ok(None)
                } else {
                    self.failed_open(index, now)
                }
            }
            Event::Answer(_) | Event::Scraped(_) => Ok(None),
        }
    }

    /// A failed open of a stream: retried after 1 s; past three in a row, or past 60 s since the first, 83.
    fn failed_open(&mut self, index: usize, now: Instant) -> Result<Option<Trigger>, ObserverExit> {
        let Some(stream) = self.streams.get_mut(index) else { return Ok(None) };
        let initial = matches!(stream.state, StreamState::Opening { initial: true } | StreamState::Waiting { initial: true, .. });
        stream.handle = None;
        let first = *stream.first_failure.get_or_insert(now);
        stream.failures = stream.failures.saturating_add(1);
        if stream.failures > REOPEN_LIMIT || now.saturating_duration_since(first) > REOPEN_WINDOW {
            return Err(self.fail(ObserverExit::Unreachable, "a stream's reopen bound was exceeded"));
        }
        stream.state = StreamState::Waiting { at: after(now, REOPEN_PAUSE), initial };
        Ok(None)
    }

    /// The outcome of a cycle answer or an end check (section 7.3): 82 for 401 or 403, anything else not valid a full
    /// snapshot.
    fn escalate(&mut self, status: Option<u16>) -> Result<Option<Trigger>, ObserverExit> {
        match status {
            Some(401 | 403) => Err(self.fail(ObserverExit::ReadRefused, "a cycle or end-check read was refused (401 or 403)")),
            _ => Ok(Some(Trigger::Full)),
        }
    }

    fn on_probe(&mut self, probe: Probe, event: Event) -> Result<Option<Trigger>, ObserverExit> {
        match probe.task {
            Task::Progress | Task::Probe(_) => {
                let answer = match event {
                    Event::Answer(answer) => answer,
                    _ => return self.escalate(None),
                };
                if answer.status != 200 {
                    return self.escalate(Some(answer.status));
                }
                if !http::media_is(answer.content_type.as_deref(), http::ACCEPT_JSON) {
                    return self.escalate(None);
                }
                let read = match probe.task {
                    Task::Probe(resource) => requests::probe_mark(&answer.body, resource),
                    _ => requests::progress_mark(&answer.body),
                };
                let mark = match read {
                    Ok(mark) => mark,
                    Err(MarkError::Answer(why)) => return Err(self.fail(ObserverExit::Answer, why)),
                    Err(MarkError::Consistency(why)) => return Err(self.fail(ObserverExit::Consistency, why)),
                };
                if let Task::Probe(_) = probe.task {
                    if self.cycle_f.is_some_and(|fresh| mark < fresh) {
                        return Err(self.fail(ObserverExit::Consistency, "a per-spec probe's mark is below F"));
                    }
                    self.highest_mark = self.highest_mark.max(mark);
                    return Ok(None);
                }
                let floor = self.last_f.unwrap_or(0).max(self.resource_version());
                if mark < floor {
                    return Err(self.fail(ObserverExit::Consistency, "a fresh mark F went backwards"));
                }
                self.last_f = Some(mark);
                self.cycle_f = Some(mark);
                self.highest_mark = self.highest_mark.max(mark);
                self.note(Trace::Progress(mark));
                self.pending.push(Pending { mark, stamp: probe.started, deadline: after(probe.started, PROGRESS_BOUND) });
                self.advance_fresh();
                Ok(None)
            }
            Task::CycleScrape | Task::EndCheck => {
                let wall_end = self.client.wall_seconds();
                let exposition = match event {
                    Event::Scraped(Scraped::Exposition(Ok(exposition))) => exposition,
                    Event::Scraped(Scraped::Exposition(Err(_))) => {
                        return Err(self.fail(ObserverExit::Answer, "a malformed exposition"));
                    }
                    Event::Scraped(Scraped::Status(status)) => return self.escalate(Some(status)),
                    _ => return self.escalate(None),
                };
                self.check_marker(&exposition)?;
                if probe.task == Task::EndCheck {
                    for index in probe.covers {
                        if self.streams.get(index).is_some_and(|stream| stream.state == StreamState::Ended) {
                            self.open_stream(index, false);
                        }
                    }
                    return Ok(None);
                }
                self.cycle_active = false;
                let (record, digest) = self.adm4(exposition.samples, (probe.wall_start, wall_end))?;
                if let Some(observation) = self.observation.as_mut() {
                    observation.record = record;
                    observation.digest = digest;
                }
                self.note(Trace::Adm4);
                self.capture_cycle();
                Ok(None)
            }
        }
    }
}

/// One attempt of the start's polling.
enum Poll {
    /// OR07 answered 200 `ok`.
    Done,
    /// `S0` was read: go on to OR07 at once.
    Next,
    /// Poll again after the interval (`refused`: the answer was 401 or 403).
    Again { refused: bool },
}
