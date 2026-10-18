//! HE-004C DESIGN-C sections 2, 7-10, 14 and 16 (R117), end to end on the fake wire with the scripted apiserver: a
//! MATCH snapshot then watching; every status of section 14 reached; each row of section 7.3 for the 60 s cycle and the
//! stream-end check; the cold start; one resourceVersion (85); snapshot restarts; coalescing; the restart marker at each
//! read point; ADM-4 mid-watch; the progress rule (unavailable, re-snapshot, 98, `fresh_as_of`); the view while a stream
//! reopens; the weighted expansion guard and the node-count cap at their bounds; a slipped cycle; marks that go
//! backwards; the per-spec probe fallback; the grants of section 12.1 accepted by B1's check; the ADM-4 window.

mod b1_rbac_support;
mod b1_support;
mod c_support;

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use b1_rbac_support::{cluster_binding, cluster_role, rule, user, Rbac};
use c_support::*;
use i05_protocol::json;
use planeon_observer::admission::Verdict;
use planeon_observer::config::{check_lifetime, LifetimeError, ObserverConfig};
use planeon_observer::credentials::observer_inputs;
use planeon_observer::inputs::{Inputs, ListBody, ListInput, Resource};
use planeon_observer::observe::{expansion_weight, structural_tokens, ObserverExit, Settings, Trace, EXPANSION_CAP, NODE_CAP};
use planeon_observer::rbac::produce_snapshot;
use planeon_observer::signed_config::{load_from, LoadError};
use planeon_observer::snapshot::Closure;
use planeon_observer::status;

fn secs(value: u64) -> Duration {
    Duration::from_secs(value)
}

/// A counter shared with a hook.
fn counter() -> Rc<Cell<u32>> {
    Rc::new(Cell::new(0))
}

fn is_metrics(req: &Req) -> bool {
    req.path == "/metrics"
}

fn is_readyz(req: &Req) -> bool {
    req.path == "/readyz/poststarthook/rbac/bootstrap-roles"
}

fn is_progress(req: &Req) -> bool {
    req.path == "/api/v1/namespaces" && req.param("limit") == Some("1")
}

fn is_exact(req: &Req) -> bool {
    req.param("resourceVersionMatch") == Some("Exact")
}

fn is_watch(req: &Req) -> bool {
    req.param("watch") == Some("true")
}

/// The first snapshot list request (the fresh one).
fn is_fresh_list(req: &Req) -> bool {
    req.path == "/api/v1/limitranges" && req.query.is_empty()
}

fn status_reply(status: u16) -> Reply {
    json(status, r#"{"kind": "Status"}"#)
}

fn exit_of(rig: &Rig) -> (ObserverExit, String) {
    let (exit, epoch) = rig.run();
    (exit, epoch.reason().to_string())
}

// ------------------------------------------------------------------------------------------ the healthy epoch

#[test]
fn a_match_snapshot_then_watching_until_not_after() {
    let rig = Rig::new();
    rig.api(|api| api.schedule.push((secs(30), Action::Bump(5))));
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    assert_eq!(status::observation(&exit), 94);
    let trace = epoch.trace();
    assert!(traced(trace, |entry| *entry == Trace::Ready));
    assert_eq!(snapshots(trace), vec![(secs(0), 1, 1000)]);
    assert_eq!(availability(trace).first(), Some(&(secs(0), true)));
    // Cycles every 60 s from the snapshot's stamp; F read each time; fresh_as_of advances once the streams pass it.
    let cycles: Vec<Duration> = trace.iter().filter(|(_, entry)| *entry == Trace::Cycle).map(|(at, _)| *at).collect();
    assert_eq!(cycles, (1..=9).map(|k| secs(60 * k)).collect::<Vec<_>>());
    assert!(traced(trace, |entry| *entry == Trace::Progress(1005)));
    assert!(traced(trace, |entry| *entry == Trace::Fresh(1005)));
    let observation = epoch.observation().expect("an observation");
    assert_eq!((observation.sequence, observation.resource_version, observation.fresh_mark), (1, 1000, 1005));
    assert_eq!(observation.record.verdict(), Verdict::Match);
    assert_eq!(observation.record.loaded_hash(), Some(pinned_hash().as_str()));
    assert_eq!(observation.digest, observation.record.digest());
    assert_eq!((observation.headroom.pods, observation.headroom.config_maps, observation.headroom.services), (8, 9, 5));
    assert_eq!((observation.headroom.cpu_millis, observation.headroom.memory_bytes,
                observation.headroom.ephemeral_storage_bytes), (1500, 3 << 30, 10 << 30));
    // The positive's non-resource rules and the observer's own are dropped and counted.
    assert!(observation.dropped_non_resource_rules >= 1);
    // One watch per served spec (20) from R, and the requests exactly as rendered.
    let watches = rig.requests("/").into_iter().filter(is_watch).collect::<Vec<_>>();
    assert_eq!(watches.len(), 20);
    assert!(watches.iter().all(|req| req.param("resourceVersion") == Some("1000") && req.param("allowWatchBookmarks") == Some("true")));
    let lists = rig.requests("/").into_iter().filter(is_exact).count();
    assert_eq!(lists, 19);
}

#[test]
fn the_grants_of_section_12_1_bound_to_the_observer_are_accepted_by_b1() {
    let lists = default_lists();
    let api = Api::new();
    let pairs: Vec<ListInput> = Resource::ALL
        .into_iter()
        .map(|resource| ListInput { spec: resource.spec(),
                                    body: ListBody::Served(json::parse(&api.list_body(resource, 7, None)).expect("JSON")) })
        .collect();
    assert!(lists[&Resource::ClusterRoles].iter().any(|role| role.contains("planeon:policy-observer")));
    let inputs = Inputs::new(pairs).expect("complete inputs");
    let produced = produce_snapshot(&inputs, NAMESPACE).expect("a snapshot");
    assert_eq!(Closure::embedded().expect("closure").check(&produced.snapshot, NAMESPACE), Ok(()));
    // The observer's entry holds exactly its resource rules (the non-resource rule is dropped and counted).
    let text = String::from_utf8(json::canonical(&produced.snapshot).expect("canonical")).expect("UTF-8");
    assert!(text.contains(r#""name":"planeon:policy-observer""#));
    assert!(produced.dropped_non_resource_rules >= 1);
}

#[test]
fn the_adm4_window_starts_before_it_ends_within_one_second() {
    let rig = Rig::new();
    let (_, epoch) = rig.run();
    let record = &epoch.observation().expect("an observation").record;
    let document = json::parse(std::str::from_utf8(&record.canonical()).expect("UTF-8")).expect("JSON");
    let binding = document.get("observationBinding").expect("binding");
    let start = binding.get("windowStart").and_then(|value| value.as_str()).expect("start").to_string();
    let end = binding.get("windowEnd").and_then(|value| value.as_str()).expect("end").to_string();
    assert!(start < end, "{start} {end}");
    assert_eq!(binding.get("nonce").and_then(|value| value.as_str()), Some(NONCE));
    // The last cycle's scrape at 540 s (fake wall 2026-06-01T00:09:00Z, answered at once) gives end = start + 1.
    assert_eq!((start.as_str(), end.as_str()), ("2026-06-01T00:09:00Z", "2026-06-01T00:09:01Z"));
}

// ------------------------------------------------------------------------------------------ section 14's statuses

#[test]
fn the_setup_statuses_are_reached_by_their_library_calls() {
    // 11 and 12: the signed configuration's read and key (the observer's key is empty until HE-008).
    let missing = format!("{}/he004c/absent", env!("CARGO_TARGET_TMPDIR"));
    assert_eq!(load_from(&missing, &[7; 32]), Err(LoadError::Read));
    assert_eq!(status::config_load(&LoadError::Read), 11);
    let dir = format!("{}/he004c/observe-keys", env!("CARGO_TARGET_TMPDIR"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    std::fs::write(format!("{dir}/config.json"), b"{}").expect("document");
    std::fs::write(format!("{dir}/config.json.sig"), [0u8; 64]).expect("signature");
    let refused = load_from(&dir, planeon_observer::signed_config::COMPILED_KEY).expect_err("an empty key refuses");
    assert_eq!(status::config_load(&refused), 12);
    // 13: the parse; 14 and 97: the lifetime.
    assert!(ObserverConfig::parse(b"{}").is_err());
    assert_eq!(status::CONFIG_CHECK, 13);
    let config = config_for(secs(600));
    assert_eq!(check_lifetime(&config, Some(config.not_after)).map_err(|error| status::lifetime(&error)), Err(14));
    assert_eq!(check_lifetime(&config, None).map_err(|error| status::lifetime(&error)), Err(97));
    assert_eq!(check_lifetime(&config, Some(wall_start())), Ok(()));
    assert_eq!(check_lifetime(&config, Some(config.not_before - 1)), Err(LifetimeError::Outside));
    // 20: a credential that cannot be opened.
    assert!(observer_inputs(&config.credentials).is_err());
    assert_eq!(status::CREDENTIALS, 20);
    // 21: a key that does not match the leaf.
    let pki = shared_pki();
    let mut wrong = identity(&pki);
    wrong.key = zeroize::Zeroizing::new(pki.apiserver_key.pkcs8.clone());
    assert!(planeon_observer::tls::client_config(wrong, pki.serving_ca.clone(), fixed_time()).is_err());
    assert_eq!(status::TLS_SETUP, 21);
    // 22: the embedded closure's bytes are pinned, so its setup refusal is unreachable here; its status is its own.
    assert!(Closure::embedded().is_ok());
    assert_eq!(status::CLOSURE, 22);
    // 24: the Linux poller (linux_net, not built on this host); its status is its own.
    assert_eq!(status::SOCKETS, 24);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn readyz_absent_is_80_at_once_and_never_ready_is_80_at_300_s() {
    let rig = Rig::new();
    rig.api(|api| api.readyz = (404, "".to_string()));
    assert_eq!(exit_of(&rig).0, ObserverExit::Readyz);
    assert_eq!(rig.elapsed(), secs(0));
    let rig = Rig::new();
    rig.api(|api| api.readyz = (500, "[-]poststarthook/rbac/bootstrap-roles failed: reason withheld".to_string()));
    assert_eq!(exit_of(&rig).0, ObserverExit::Readyz);
    assert_eq!(rig.elapsed(), secs(300));
    assert_eq!(rig.requests("/readyz").len(), 300);
    // A 200 whose body is not exactly ok is 84.
    let rig = Rig::new();
    rig.api(|api| api.readyz = (200, "ok\n".to_string()));
    assert_eq!(exit_of(&rig).0, ObserverExit::Answer);
}

#[test]
fn the_cold_start_polls_through_401_and_403_until_the_first_200() {
    // 403 then 200 within 300 s carries on.
    let rig = Rig::new();
    rig.hook(|req, _| (req.at < secs(50) && (is_metrics(req) || is_readyz(req))).then(|| status_reply(403)));
    assert_eq!(exit_of(&rig).0, ObserverExit::ConfigExpired);
    // 429, then 403, then 200 carries on (a 429 does not end the window).
    let rig = Rig::new();
    rig.hook(|req, _| {
        if !is_metrics(req) {
            return None;
        }
        if req.at < secs(10) {
            Some(status_reply(429))
        } else if req.at < secs(20) {
            Some(status_reply(403))
        } else {
            None
        }
    });
    assert_eq!(exit_of(&rig).0, ObserverExit::ConfigExpired);
    // 403 throughout: 82 at the end of the window.
    let rig = Rig::new();
    rig.hook(|req, _| (is_metrics(req) || is_readyz(req)).then(|| status_reply(401)));
    assert_eq!(exit_of(&rig).0, ObserverExit::ReadRefused);
    assert_eq!(rig.elapsed(), secs(300));
    // 403 after the first 200 (the S0 scrape): 82 at once.
    let rig = Rig::new();
    rig.hook(|req, _| is_readyz(req).then(|| status_reply(403)));
    assert_eq!(exit_of(&rig).0, ObserverExit::ReadRefused);
    assert_eq!(rig.elapsed(), secs(0));
    // A refused snapshot read after OR07: 82 at once.
    let rig = Rig::new();
    rig.hook(|req, _| is_exact(req).then(|| status_reply(403)));
    assert_eq!(exit_of(&rig).0, ObserverExit::ReadRefused);
}

#[test]
fn every_epoch_status_80_to_99_is_reached() {
    // 81: the snapshot's final scrape sees another marker.
    let rig = Rig::new();
    let scrapes = counter();
    let seen = scrapes.clone();
    rig.hook(move |req, api| {
        if is_metrics(req) {
            seen.set(seen.get() + 1);
            if seen.get() == 2 {
                api.marker = "1.7801999e+09".to_string();
            }
        }
        None
    });
    assert_eq!(exit_of(&rig).0, ObserverExit::ApiserverRestart);
    // 83: every snapshot read reset (transport) to the deadline.
    let rig = Rig::new();
    rig.hook(|req, _| (!is_metrics(req) && !is_readyz(req)).then_some(Reply::Reset));
    assert_eq!(exit_of(&rig).0, ObserverExit::Unreachable);
    assert_eq!(rig.elapsed(), secs(120));
    // 84: a list answers 404.
    let rig = Rig::new();
    rig.hook(|req, _| (req.path == "/api/v1/secrets").then(|| status_reply(404)));
    assert_eq!(exit_of(&rig).0, ObserverExit::Answer);
    // 86: the MutatingAdmissionPolicy kinds served only at v1beta1 (no pair: B1's Missing).
    let rig = Rig::new();
    rig.api(|api| {
        let v1: Vec<String> = admission_v1_names().into_iter().filter(|name| !name.starts_with("mutatingadmissionpolic")).collect();
        api.admission_versions = vec![("v1".to_string(), v1),
                                      ("v1beta1".to_string(), vec!["mutatingadmissionpolicies".to_string(),
                                                                   "mutatingadmissionpolicybindings".to_string()])];
    });
    assert_eq!(exit_of(&rig).0, ObserverExit::Inputs);
    // 87: a binding to a role that does not exist.
    let rig = Rig::new();
    rig.api(|api| api.lists.get_mut(&Resource::ClusterRoleBindings).expect("list")
        .push(cluster_binding("dangling", "no-such-role", &[user("alice")])));
    assert_eq!(exit_of(&rig).0, ObserverExit::Rbac);
    // 88: OR05, a service-account token exists.
    let rig = Rig::new();
    rig.api(|api| api.lists.insert(Resource::ServiceAccountTokenSecrets,
                                   vec![r#"{"metadata": {"name": "token", "namespace": "unit-namespace"}}"#.to_string()]));
    assert_eq!(exit_of(&rig).0, ObserverExit::Operational);
    // 89: used above hard.
    let rig = Rig::new();
    rig.api(|api| api.lists.insert(Resource::ResourceQuotas, vec![quota_item("q", NAMESPACE, HARD, &USED.replace("\"pods\": \"2\"", "\"pods\": \"11\""))]));
    assert_eq!(exit_of(&rig).0, ObserverExit::Quota);
    // 90 and 91: the loaded hash differs; a foreign plugin's sample.
    let rig = Rig::new();
    rig.api(|api| api.samples = vec![sample(PLUGIN, &format!("sha256:{}", "b".repeat(64)))]);
    assert_eq!(exit_of(&rig).0, ObserverExit::Adm4Mismatch);
    let rig = Rig::new();
    rig.api(|api| api.samples.push(sample("another-plugin", &pinned_hash())));
    assert_eq!(exit_of(&rig).0, ObserverExit::Adm4Unavailable);
    // 92: an ERROR event.
    let rig = Rig::new();
    rig.at(secs(30), Action::Line(Resource::Roles, r#"{"type": "ERROR", "object": {"kind": "Status", "code": 500}}"#.to_string()));
    assert_eq!(exit_of(&rig).0, ObserverExit::WatchGap);
    // 93: the snapshot's scrape answers 429 to the deadline.
    let rig = Rig::new();
    let scrapes = counter();
    let seen = scrapes.clone();
    rig.hook(move |req, _| {
        if is_metrics(req) {
            seen.set(seen.get() + 1);
            return (seen.get() > 1).then(|| status_reply(429));
        }
        None
    });
    assert_eq!(exit_of(&rig).0, ObserverExit::Deadline);
    assert_eq!(rig.elapsed(), secs(120));
    // 94: notAfter (the healthy epoch). 95: the poller fails.
    let rig = Rig::new();
    rig.lab(|lab| lab.poll_fail_at = Some(secs(45)));
    assert_eq!(exit_of(&rig).0, ObserverExit::Poll);
    // 96: a nonce outside the binding's form (a configuration not built by the parse) makes B1 refuse its input.
    let mut rig = Rig::new();
    rig.config.nonce = "NOT-HEX".to_string();
    assert_eq!(exit_of(&rig).0, ObserverExit::Adm4Input);
    // 97: a wall clock before the epoch, and one past the year 9999.
    let rig = Rig::new();
    rig.lab(|lab| lab.wall_before_epoch = true);
    assert_eq!(exit_of(&rig).0, ObserverExit::Clock);
    let rig = Rig::new();
    rig.lab(|lab| lab.wall_shift = 253_402_300_800 - wall_start() as i64);
    assert_eq!(exit_of(&rig).0, ObserverExit::Clock);
    // Each exit has its own status in 80-99.
    let all = [ObserverExit::Readyz, ObserverExit::ApiserverRestart, ObserverExit::ReadRefused, ObserverExit::Unreachable,
               ObserverExit::Answer, ObserverExit::Consistency, ObserverExit::Inputs, ObserverExit::Rbac, ObserverExit::Operational,
               ObserverExit::Quota, ObserverExit::Adm4Mismatch, ObserverExit::Adm4Unavailable, ObserverExit::WatchGap,
               ObserverExit::Deadline, ObserverExit::ConfigExpired, ObserverExit::Poll, ObserverExit::Adm4Input, ObserverExit::Clock,
               ObserverExit::Stale, ObserverExit::Expansion];
    assert_eq!(all.iter().map(status::observation).collect::<Vec<u8>>(), (80..=99).collect::<Vec<u8>>());
}

// ------------------------------------------------------------------------------------------ one resourceVersion and restarts

#[test]
fn an_exact_answer_at_another_resource_version_or_a_non_decimal_r_is_85() {
    let rig = Rig::new();
    rig.hook(|req, api| (req.path == "/api/v1/namespaces" && is_exact(req)).then(|| json(200, &api.list_body(Resource::Namespaces, 1001, None))));
    assert_eq!(exit_of(&rig).0, ObserverExit::Consistency);
    for version in ["abc", "", "123456789012345678901", "18446744073709551616", "-1"] {
        let rig = Rig::new();
        rig.hook(move |req, api| is_fresh_list(req).then(|| {
            json(200, &api.list_body(Resource::LimitRanges, 7, None).replace("\"resourceVersion\": \"7\"",
                                                                             &format!("\"resourceVersion\": \"{version}\"")))
        }));
        assert_eq!(exit_of(&rig).0, ObserverExit::Consistency, "{version}");
    }
    // The largest u64 is decimal.
    let rig = Rig::new();
    rig.api(|api| api.rv = u64::MAX);
    assert_eq!(exit_of(&rig).0, ObserverExit::ConfigExpired);
}

#[test]
fn snapshot_restarts_within_the_deadline() {
    // 410, 504, 429 and 503 on an Exact list restart the snapshot after 1 s; the snapshot then completes.
    for code in [410u16, 504, 429, 503] {
        let rig = Rig::new();
        let answered = counter();
        let seen = answered.clone();
        rig.hook(move |req, _| {
            if req.path == "/api/v1/resourcequotas" && is_exact(req) && seen.get() == 0 {
                seen.set(1);
                return Some(status_reply(code));
            }
            None
        });
        let (exit, epoch) = rig.run();
        assert_eq!(exit, ObserverExit::ConfigExpired, "{code}: {}", epoch.reason());
        assert_eq!(snapshots(epoch.trace()).len(), 1, "{code}");
        assert_eq!(rig.requests("/api/v1/limitranges").iter().filter(|req| req.query.is_empty()).count(), 2, "{code}");
        assert_eq!(snapshots(epoch.trace())[0].0, secs(1), "{code}: restarted after 1 s");
    }
    // 410 or 504 on the fresh list or another request is 84; a transport failure restarts.
    for code in [410u16, 504] {
        let rig = Rig::new();
        rig.hook(move |req, _| is_fresh_list(req).then(|| status_reply(code)));
        assert_eq!(exit_of(&rig).0, ObserverExit::Answer, "{code}");
    }
    let rig = Rig::new();
    let resets = counter();
    let seen = resets.clone();
    rig.hook(move |req, _| {
        if req.path == "/version" && seen.get() < 3 {
            seen.set(seen.get() + 1);
            return Some(Reply::Reset);
        }
        None
    });
    assert_eq!(exit_of(&rig).0, ObserverExit::ConfigExpired);
    // An unsettled quota restarts until it settles; one that never settles is 89 at the deadline.
    let rig = Rig::new();
    let unsettled = counter();
    let seen = unsettled.clone();
    rig.hook(move |req, _| {
        if req.path == "/api/v1/resourcequotas" && is_exact(req) && seen.get() < 2 {
            seen.set(seen.get() + 1);
            let version = req.param("resourceVersion").unwrap_or("0").to_string();
            let item = format!(r#"{{"metadata": {{"name": "q", "namespace": "{NAMESPACE}"}}, "spec": {{"hard": {HARD}}}, "status": {{"hard": {{}}, "used": {{}}}}}}"#);
            return Some(json(200, &format!(r#"{{"kind": "ResourceQuotaList", "apiVersion": "v1", "metadata": {{"resourceVersion": "{version}"}}, "items": [{item}]}}"#)));
        }
        None
    });
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    assert_eq!(snapshots(epoch.trace())[0].0, secs(2));
    let rig = Rig::new();
    rig.api(|api| api.lists.insert(Resource::ResourceQuotas, vec![format!(
        r#"{{"metadata": {{"name": "q", "namespace": "{NAMESPACE}"}}, "spec": {{"hard": {HARD}}}}}"#)]));
    let (exit, epoch) = rig.run();
    assert_eq!((exit, rig.elapsed()), (ObserverExit::Quota, secs(120)), "{}", epoch.reason());
}

#[test]
fn a_change_re_snapshots_no_sooner_than_1_s_after_the_last_start() {
    let rig = Rig::new();
    rig.at(secs(100), Action::Change(Resource::Roles));
    rig.at(Duration::from_millis(100_400), Action::Change(Resource::ClusterRoles));
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    let taken = snapshots(epoch.trace());
    assert_eq!(taken.iter().map(|(at, sequence, _)| (*at, *sequence)).collect::<Vec<_>>(),
               vec![(secs(0), 1), (secs(100), 2), (secs(101), 3)]);
    assert_eq!(taken.iter().map(|(_, _, version)| *version).collect::<Vec<_>>(), vec![1000, 1001, 1002]);
    assert!(traced(epoch.trace(), |entry| *entry == Trace::Change(Resource::Roles)));
    // The view is unavailable between the change and the new snapshot's watches.
    let changes = availability(epoch.trace());
    assert!(changes.contains(&(secs(100), false)));
}

// ------------------------------------------------------------------------------------------ the restart marker

#[test]
fn a_changed_restart_marker_exits_81_at_each_read_point() {
    // At the end of a snapshot: see every_epoch_status_80_to_99_is_reached. In a 60 s cycle:
    let rig = Rig::new();
    rig.at(secs(90), Action::Do(Box::new(|api: &mut Api| api.marker = "1.7802000e+09".to_string())));
    assert_eq!(exit_of(&rig).0, ObserverExit::ApiserverRestart);
    assert_eq!(rig.elapsed(), secs(120));
    // After a stream end (the restart check, before the reopen):
    let rig = Rig::new();
    rig.at(secs(90), Action::Do(Box::new(|api: &mut Api| api.marker = "1.7802000e+09".to_string())));
    rig.at(secs(90), Action::EndStream(Resource::Roles));
    assert_eq!(exit_of(&rig).0, ObserverExit::ApiserverRestart);
    assert_eq!(rig.elapsed(), secs(90));
    // Zero or several markers, or a malformed one, is 84.
    for lines in [vec![], vec!["process_start_time_seconds 1", "process_start_time_seconds 2"],
                  vec!["process_start_time_seconds{a=\"b\"} 1"], vec!["process_start_time_seconds NaN"]] {
        let rig = Rig::new();
        let lines: Vec<String> = lines.iter().map(|line| line.to_string()).collect();
        rig.hook(move |req, api| is_metrics(req).then(|| {
            let mut text = api.exposition().lines().filter(|line| !line.starts_with("process_start")).collect::<Vec<_>>().join("\n");
            text.push('\n');
            for line in &lines {
                text.push_str(line);
                text.push('\n');
            }
            answer(200, "text/plain; version=0.0.4", text.as_bytes())
        }));
        assert_eq!(exit_of(&rig).0, ObserverExit::Answer);
    }
}

// ------------------------------------------------------------------------------------------ section 7.3's rows

#[test]
fn each_row_of_section_7_3_for_the_cycle() {
    // ADM-4 mid-watch: a foreign sample appearing is 91, a changed loaded hash 90.
    let rig = Rig::new();
    rig.at(secs(90), Action::Do(Box::new(|api: &mut Api| api.samples.push(sample("another-plugin", &pinned_hash())))));
    assert_eq!((exit_of(&rig).0, rig.elapsed()), (ObserverExit::Adm4Unavailable, secs(120)));
    let rig = Rig::new();
    rig.at(secs(90), Action::Do(Box::new(|api: &mut Api| api.samples = vec![sample(PLUGIN, &format!("sha256:{}", "c".repeat(64)))])));
    assert_eq!((exit_of(&rig).0, rig.elapsed()), (ObserverExit::Adm4Mismatch, secs(120)));
    // A cycle's ADM-4 record replaces the snapshot's.
    let rig = Rig::new();
    let (_, epoch) = rig.run();
    assert!(traced(epoch.trace(), |entry| *entry == Trace::Adm4));
    // 401 or 403 on the progress read or the scrape: 82.
    for target in ["progress", "metrics"] {
        let rig = Rig::new();
        rig.hook(move |req, _| (req.at >= secs(60) && if target == "progress" { is_progress(req) } else { is_metrics(req) })
            .then(|| status_reply(403)));
        assert_eq!((exit_of(&rig).0, rig.elapsed()), (ObserverExit::ReadRefused, secs(60)), "{target}");
    }
    // A progress answer that is not a NamespaceList of v1 is 84; a resourceVersion missing, not decimal or above
    // 2^64-1 is 85.
    for (body, exit) in [(r#"{"kind": "PodList", "apiVersion": "v1", "metadata": {"resourceVersion": "1000"}, "items": []}"#, ObserverExit::Answer),
                         (r#"{"kind": "NamespaceList", "apiVersion": "v2", "metadata": {"resourceVersion": "1000"}, "items": []}"#, ObserverExit::Answer),
                         (r#"[1, 2]"#, ObserverExit::Answer),
                         (r#"{"kind": "NamespaceList", "apiVersion": "v1", "metadata": {}, "items": []}"#, ObserverExit::Consistency),
                         (r#"{"kind": "NamespaceList", "apiVersion": "v1", "metadata": {"resourceVersion": "1e3"}, "items": []}"#, ObserverExit::Consistency),
                         (r#"{"kind": "NamespaceList", "apiVersion": "v1", "metadata": {"resourceVersion": "18446744073709551616"}, "items": []}"#, ObserverExit::Consistency)] {
        let rig = Rig::new();
        rig.hook(move |req, _| is_progress(req).then(|| json(200, body)));
        assert_eq!(exit_of(&rig).0, exit, "{body}");
    }
    // An F below R or below the previous F is 85 (marks never go backwards).
    let rig = Rig::new();
    rig.hook(|req, api| is_progress(req).then(|| json(200, &api.list_body(Resource::Namespaces, 999, Some(1)))));
    assert_eq!(exit_of(&rig).0, ObserverExit::Consistency);
    let rig = Rig::new();
    rig.at(secs(30), Action::Bump(10));
    rig.hook(|req, api| (is_progress(req) && req.at >= secs(120)).then(|| json(200, &api.list_body(Resource::Namespaces, 1005, Some(1)))));
    assert_eq!((exit_of(&rig).0, rig.elapsed()), (ObserverExit::Consistency, secs(120)));
    // 404, 410, 429, 503, another status, a framing refusal, a transport failure or the 30 s deadline: the view is
    // unavailable and a full snapshot runs, whose own checks decide (here they pass).
    for reply in [status_reply(404), status_reply(410), status_reply(429), status_reply(503), status_reply(500),
                  Reply::Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}".to_vec()),
                  answer(200, "text/html", b"{}"), Reply::Reset, Reply::Hang] {
        for target in ["progress", "metrics"] {
            let rig = Rig::new();
            let fired = counter();
            let seen = fired.clone();
            let once = reply.clone();
            rig.hook(move |req, _| {
                let hit = req.at >= secs(60) && if target == "progress" { is_progress(req) } else { is_metrics(req) };
                if hit && seen.get() == 0 {
                    seen.set(1);
                    return Some(once.clone());
                }
                None
            });
            let (exit, epoch) = rig.run();
            assert_eq!(exit, ObserverExit::ConfigExpired, "{target} {reply:?}: {}", epoch.reason());
            assert_eq!(snapshots(epoch.trace()).len(), 2, "{target} {reply:?}");
        }
    }
}

#[test]
fn each_row_of_section_7_3_for_the_stream_end_check() {
    // A valid check reopens the ended stream from its mark.
    let rig = Rig::new();
    rig.at(secs(30), Action::Bump(3));
    rig.at(secs(90), Action::EndStream(Resource::Roles));
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    assert!(traced(epoch.trace(), |entry| *entry == Trace::StreamEnd(Resource::Roles)));
    assert!(traced(epoch.trace(), |entry| *entry == Trace::Reopened(Resource::Roles)));
    let reopen: Vec<Req> = rig.requests("/apis/rbac.authorization.k8s.io/v1/roles").into_iter().filter(is_watch).collect();
    assert_eq!(reopen.len(), 2);
    assert_eq!(reopen[1].param("resourceVersion"), Some("1003"), "resumed from the last bookmark");
    // 401 or 403 on the check: 82; a malformed exposition: 84; another status, a framing refusal, a transport failure or
    // the deadline: a full snapshot.
    for (reply, expected) in [(status_reply(403), Some(ObserverExit::ReadRefused)),
                              (answer(200, "text/plain; version=0.0.4", b"process_start_time_seconds 1"), Some(ObserverExit::Answer)),
                              (status_reply(503), None), (status_reply(404), None), (Reply::Reset, None), (Reply::Hang, None),
                              (answer(200, "application/json", b"{}"), None)] {
        let rig = Rig::new();
        rig.at(secs(90), Action::EndStream(Resource::Roles));
        let once = reply.clone();
        let fired = counter();
        let seen = fired.clone();
        rig.hook(move |req, _| {
            if is_metrics(req) && req.at >= secs(90) && seen.get() == 0 {
                seen.set(1);
                return Some(once.clone());
            }
            None
        });
        let (exit, epoch) = rig.run();
        match expected {
            Some(exit_wanted) => assert_eq!(exit, exit_wanted, "{reply:?}"),
            None => {
                assert_eq!(exit, ObserverExit::ConfigExpired, "{reply:?}: {}", epoch.reason());
                assert_eq!(snapshots(epoch.trace()).len(), 2, "{reply:?}");
            }
        }
    }
}

// ------------------------------------------------------------------------------------------ the progress rule

#[test]
fn the_progress_rule_re_snapshots_a_stuck_stream_and_exits_98_after_three() {
    // fresh_as_of advances while every stream passes each F.
    let rig = Rig::new();
    for k in 1..10 {
        rig.at(secs(30 + 60 * (k - 1)), Action::Bump(2));
    }
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    let fresh: Vec<u64> = epoch.trace().iter().filter_map(|(_, entry)| match entry { Trace::Fresh(mark) => Some(*mark), _ => None }).collect();
    assert!(fresh.len() >= 8 && fresh.windows(2).all(|pair| pair[0] <= pair[1]), "{fresh:?}");
    // One stream whose bookmarks stop advancing: unavailable and re-snapshot, three in a row: 98.
    let mut rig = Rig::new();
    rig.config = config_for(secs(3_600));
    rig.api(|api| {
        api.stuck.insert(Resource::Roles);
        for k in 0..60 {
            api.schedule.push((secs(30 + 30 * k), Action::Bump(1)));
        }
    });
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::Stale, "{}", epoch.reason());
    let stale: Vec<(Duration, u32)> = epoch.trace().iter().filter_map(|(at, entry)| match entry { Trace::Stale(count) => Some((*at, *count)), _ => None }).collect();
    assert_eq!(stale.iter().map(|(_, count)| *count).collect::<Vec<_>>(), vec![1, 2, 3]);
    // The first: F read at 60 s, not passed by the stuck stream within 150 s.
    assert_eq!(stale[0].0, secs(210));
    assert_eq!(snapshots(epoch.trace()).len(), 3);
    assert!(availability(epoch.trace()).contains(&(secs(210), false)));
    // A lower bookmark is ignored: no exit, no progress, and the resume point stays the highest mark.
    let rig = Rig::new();
    rig.at(secs(30), Action::Bump(4));
    rig.at(secs(50), Action::Line(Resource::Roles, Api::bookmark(Resource::Roles, 1001)));
    rig.at(secs(90), Action::EndStream(Resource::Roles));
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    let reopen: Vec<Req> = rig.requests("/apis/rbac.authorization.k8s.io/v1/roles").into_iter().filter(is_watch).collect();
    assert_eq!(reopen[1].param("resourceVersion"), Some("1004"));
}

#[test]
fn the_view_is_unavailable_while_a_stream_reopens() {
    let rig = Rig::new();
    rig.at(secs(90), Action::EndStream(Resource::Roles));
    rig.hook(|req, _| (is_watch(req) && req.path.ends_with("/roles") && req.at >= secs(90)).then(|| Reply::Delay(secs(5), Box::new(Reply::Stream))));
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    let changes = availability(epoch.trace());
    assert_eq!(&changes[..3], &[(secs(0), true), (secs(90), false), (secs(95), true)]);
}

#[test]
fn a_slipped_cycle_makes_the_view_unavailable_past_210_s_then_available_again() {
    // Bookmarks only when scripted; the per-spec probes, each answered after 5 s, make a cycle last about 100 s, so the
    // cycle after the first starts at about 160 s (D2-2).
    let rig = Rig::new();
    rig.lab(|lab| lab.next_tick = secs(100_000));
    rig.api(|api| {
        api.bookmark_every = secs(100_000);
        api.schedule.push((secs(10), Action::Bump(10)));
        api.schedule.push((secs(100), Action::Do(Box::new(|api: &mut Api| api.bookmarks()))));
        api.schedule.push((secs(150), Action::Bump(10)));
        api.schedule.push((secs(290), Action::Do(Box::new(|api: &mut Api| api.bookmarks()))));
        api.schedule.push((secs(390), Action::Do(Box::new(|api: &mut Api| api.bookmarks()))));
        api.schedule.push((secs(490), Action::Do(Box::new(|api: &mut Api| api.bookmarks()))));
    });
    let delayed = Rc::new(Cell::new(true));
    let on = delayed.clone();
    rig.hook(move |req, api| {
        if on.get() && req.param("limit") == Some("1") && !is_progress(req) {
            let resource = Resource::ALL.into_iter().find(|resource| {
                let target = planeon_observer::requests::list(*resource, &planeon_observer::requests::Mode::Probe).target;
                target == req.target
            })?;
            return Some(Reply::Delay(secs(5), Box::new(json(200, &api.list_body(resource, api.rv, Some(1))))));
        }
        None
    });
    let mut epoch = rig.epoch_with(Settings { per_spec_progress: true, trace: true });
    let exit = epoch.run();
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    let cycles: Vec<Duration> = epoch.trace().iter().filter(|(_, entry)| *entry == Trace::Cycle).map(|(at, _)| *at).collect();
    // Nineteen probes are answered after 5 s; the Namespaces probe is the progress read's own request, answered at once.
    assert_eq!(&cycles[..2], &[secs(60), secs(155)]);
    let changes = availability(epoch.trace());
    // Available from the snapshot; past 270 s (F1's stamp, 60 s, plus 210 s) unavailable; available again at 290 s once
    // the streams pass the slipped cycle's F.
    assert_eq!(&changes[..3], &[(secs(0), true), (Duration::from_millis(270_001), false), (secs(290), true)]);
    assert_eq!(snapshots(epoch.trace()).len(), 1, "no staleness: every F was passed within 150 s");
}

#[test]
fn the_per_spec_probe_fallback_runs_one_limit_1_read_per_served_spec_each_cycle() {
    let rig = Rig::new();
    let mut epoch = rig.epoch_with(Settings { per_spec_progress: true, trace: true });
    assert_eq!(epoch.run(), ObserverExit::ConfigExpired, "{}", epoch.reason());
    // Each cycle: the progress read and one probe per served spec; the Namespaces probe is the same request as the
    // progress read (`GET /api/v1/namespaces?limit=1`).
    let reads: Vec<Req> = rig.requests("/").into_iter().filter(|req| req.param("limit") == Some("1")).collect();
    assert_eq!(reads.len(), 21 * 9);
    assert_eq!(reads.iter().filter(|req| is_progress(req)).count(), 2 * 9);
    let probes: Vec<Req> = reads.into_iter().filter(|req| !is_progress(req)).collect();
    assert_eq!(probes.len(), 19 * 9);
    let secrets: Vec<&Req> = probes.iter().filter(|req| req.path == "/api/v1/secrets").collect();
    assert_eq!(secrets.len(), 2 * 9);
    assert!(secrets.iter().all(|req| req.param("fieldSelector").is_some()
        && req.accept == "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"));
    // A probe's mark below F is 85; production keeps the fallback off.
    assert!(!planeon_observer::observe::PER_SPEC_PROGRESS);
    let rig = Rig::new();
    rig.at(secs(30), Action::Bump(10));
    rig.hook(|req, api| (req.path == "/api/v1/limitranges" && req.param("limit") == Some("1")).then(|| {
        json(200, &api.list_body(Resource::LimitRanges, 1003, Some(1)))
    }));
    let mut epoch = rig.epoch_with(Settings { per_spec_progress: true, trace: true });
    assert_eq!(epoch.run(), ObserverExit::Consistency);
}

#[test]
fn a_new_r_below_the_highest_mark_is_85() {
    let rig = Rig::new();
    rig.at(secs(30), Action::Bump(10));
    rig.at(secs(100), Action::Change(Resource::Roles));
    // The second snapshot's fresh list answers a revision below the epoch's highest mark (F = 1010 at 60 s).
    rig.hook(|req, api| (is_fresh_list(req) && req.at >= secs(100)).then(|| json(200, &api.list_body(Resource::LimitRanges, 1005, None))));
    assert_eq!(exit_of(&rig).0, ObserverExit::Consistency);
}

// ------------------------------------------------------------------------------------------ memory (R117)

fn default_inputs(api: &Api) -> Inputs {
    let pairs: Vec<ListInput> = Resource::ALL
        .into_iter()
        .map(|resource| ListInput { spec: resource.spec(),
                                    body: ListBody::Served(json::parse(&api.list_body(resource, 7, None)).expect("JSON")) })
        .collect();
    Inputs::new(pairs).expect("complete inputs")
}

/// Pads the RBAC lists to exactly `target` weight units with a ClusterRole of non-policy reads bound to Users and an
/// empty ClusterRole bound to more Users.
fn pad_to(api: &mut Api, target: u64) {
    let base = expansion_weight(&default_inputs(api)).expect("a weight");
    let resources = format!("[{}]", (0..100).map(|index| format!("\"configmaps{index:03}\"")).collect::<Vec<_>>().join(", "));
    // Weight of the read role: 1 + "" (1) + "get" (2) + 100 names of 13 bytes (2 each) = 204; per subject 205.
    let per_subject = 205u64;
    let left = target - base;
    let (wide, rest) = (left / per_subject, left % per_subject);
    let subjects = |prefix: &str, count: u64| (0..count).map(|index| user(&format!("{prefix}-{index}"))).collect::<Vec<_>>();
    let lists = &mut api.lists;
    lists.get_mut(&Resource::ClusterRoles).expect("roles").push(cluster_role("pad-read", &[rule(r#"[""]"#, &resources, r#"["get"]"#)]));
    lists.get_mut(&Resource::ClusterRoles).expect("roles").push(cluster_role("pad-none", &[]));
    lists.get_mut(&Resource::ClusterRoleBindings).expect("bindings").push(cluster_binding("pad-read", "pad-read", &subjects("reader", wide)));
    if rest > 0 {
        lists.get_mut(&Resource::ClusterRoleBindings).expect("bindings").push(cluster_binding("pad-none", "pad-none", &subjects("idle", rest)));
    }
    assert_eq!(expansion_weight(&default_inputs(api)), Some(target));
}

#[test]
fn the_weighted_expansion_guard_at_40_000_and_40_001() {
    let api = Api::new();
    let base = expansion_weight(&default_inputs(&api)).expect("a weight");
    assert!(base < EXPANSION_CAP / 4, "{base}");
    for (target, exit) in [(EXPANSION_CAP, ObserverExit::ConfigExpired), (EXPANSION_CAP + 1, ObserverExit::Expansion)] {
        let rig = Rig::new();
        rig.api(|api| pad_to(api, target));
        assert_eq!(exit_of(&rig).0, exit, "{target}");
    }
    // One rule listing many resources bound to many subjects (D2-1), and one rule holding a long string bound to
    // three subjects (D3-1): 99.
    let rig = Rig::new();
    rig.api(|api| {
        let resources = format!("[{}]", (0..2_000).map(|index| format!("\"r{index}\"")).collect::<Vec<_>>().join(", "));
        api.lists.get_mut(&Resource::ClusterRoles).expect("roles").push(cluster_role("wide", &[rule(r#"[""]"#, &resources, r#"["get"]"#)]));
        let subjects: Vec<String> = (0..10).map(|index| user(&format!("w-{index}"))).collect();
        api.lists.get_mut(&Resource::ClusterRoleBindings).expect("bindings").push(cluster_binding("wide", "wide", &subjects));
    });
    assert_eq!(exit_of(&rig).0, ObserverExit::Expansion);
    let rig = Rig::new();
    rig.api(|api| {
        let long = format!("[\"{}\"]", "x".repeat(1 << 20));
        api.lists.get_mut(&Resource::ClusterRoles).expect("roles").push(cluster_role("long", &[rule(r#"[""]"#, &long, r#"["get"]"#)]));
        let subjects: Vec<String> = (0..3).map(|index| user(&format!("l-{index}"))).collect();
        api.lists.get_mut(&Resource::ClusterRoleBindings).expect("bindings").push(cluster_binding("long", "long", &subjects));
    });
    assert_eq!(exit_of(&rig).0, ObserverExit::Expansion);
    // The weight follows the bytes: a 1 MiB element weighs 1 + 16,384.
    let mut rbac = Rbac::default();
    rbac.cluster_roles.push(cluster_role("long", &[rule(r#"[""]"#, &format!("[\"{}\"]", "x".repeat(1 << 20)), r#"["get"]"#)]));
    rbac.cluster_bindings.push(cluster_binding("long", "long", &[user("one")]));
    assert_eq!(expansion_weight(&rbac.inputs()), Some(1 + (1 + 1 + 16_385 + 2)));
}

#[test]
fn the_node_count_cap_at_1_000_000_and_one_over() {
    let api = Api::new();
    let base: usize = Resource::ALL.into_iter().map(|resource| structural_tokens(api.list_body(resource, 7, None).as_bytes())).sum();
    // One LimitRange item with an array of n zeros adds its own tokens: `{"metadata": {"name": "big", "namespace": ".."},
    // "spec": [0, 0, ...]}` is 7 tokens for n = 1 (the item's comma-free first place) plus n - 1 commas.
    let item = |count: usize| format!(r#"{{"metadata": {{"name": "big", "namespace": "{NAMESPACE}"}}, "spec": [{}]}}"#,
                                      vec!["0"; count].join(","));
    let probe = structural_tokens(item(1).as_bytes());
    for (total, exit) in [(NODE_CAP, ObserverExit::ConfigExpired), (NODE_CAP + 1, ObserverExit::Answer)] {
        let count = total - base - probe + 1;
        let rig = Rig::new();
        let text = item(count);
        rig.api(|api| api.lists.insert(Resource::LimitRanges, vec![text.clone()]));
        let check: usize = Resource::ALL.into_iter().map(|resource| rig.api(|api| structural_tokens(api.list_body(resource, 7, None).as_bytes()))).sum();
        assert_eq!(check, total);
        assert_eq!(exit_of(&rig).0, exit, "{total}");
    }
}

#[test]
fn one_snapshots_list_bodies_together_are_at_most_16_mib() {
    let rig = Rig::new();
    let big = format!(r#"{{"metadata": {{"name": "big", "namespace": "{NAMESPACE}"}}, "data": "{}"}}"#, "y".repeat(3_500_000));
    rig.api(|api| {
        for resource in [Resource::LimitRanges, Resource::NetworkPolicies, Resource::Roles, Resource::ServiceAccounts] {
            let mut items = api.lists.get(&resource).cloned().unwrap_or_default();
            items.push(big.replace("\"big\"", &format!("\"big-{resource:?}\"")));
            api.lists.insert(resource, items);
        }
    });
    // Four lists of about 3.5 MiB pass (14 MiB), so does each single one; a fifth one passes 16 MiB together: 84.
    let (exit, epoch) = rig.run();
    assert_ne!(exit, ObserverExit::Answer, "{}", epoch.reason());
    let rig = Rig::new();
    rig.api(|api| {
        for resource in [Resource::LimitRanges, Resource::NetworkPolicies, Resource::Roles, Resource::ServiceAccounts,
                         Resource::ResourceQuotas] {
            let mut items = api.lists.get(&resource).cloned().unwrap_or_default();
            items.push(big.replace("\"big\"", &format!("\"big-{resource:?}\"")));
            api.lists.insert(resource, items);
        }
    });
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::Answer, "{}", epoch.reason());
    assert!(epoch.reason().contains("16 MiB"), "{}", epoch.reason());
}
