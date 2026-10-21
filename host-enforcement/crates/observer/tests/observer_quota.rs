//! HE-004C DESIGN-C section 10 (Q-HE4C-7 (a); D1-8): the quantity parser (every suffix and exponent, exact at the 10^-9
//! scale, finer than 1n and overflow refused), the exact comparison (`limits.cpu` hard 1500m with used 1200m passes,
//! 1501m refuses), conservative rounding only for the headroom figures, whole counts, the settled rule, used above hard,
//! a missing unit and the headroom minimum. The epoch's restarts on an unsettled quota and 89 are in
//! `observer_observe.rs`.

use i05_protocol::json::{self, Value};
use planeon_observer::quota::{headroom, parse_quantity, Headroom, QuotaError, MAX_FIGURE, MAX_NANO, NANO, UNITS};

const NAMESPACE: &str = "q-space";

fn quota(name: &str, namespace: &str, spec: &str, hard: &str, used: &str) -> String {
    format!(r#"{{"metadata": {{"name": "{name}", "namespace": "{namespace}"}}, "spec": {{"hard": {spec}}}, "status": {{"hard": {hard}, "used": {used}}}}}"#)
}

fn settled(name: &str, hard: &str, used: &str) -> String {
    quota(name, NAMESPACE, hard, hard, used)
}

fn items(texts: &[String]) -> Vec<Value> {
    texts.iter().map(|text| json::parse(text).expect("JSON")).collect()
}

const SIX: &str = r#""pods": "10", "configmaps": "20", "services": "5", "requests.cpu": "2", "requests.memory": "1Gi", "requests.ephemeral-storage": "2Gi""#;
const SIX_USED: &str = r#""pods": "3", "configmaps": "0", "services": "5", "requests.cpu": "250m", "requests.memory": "100Mi", "requests.ephemeral-storage": "1G""#;

#[test]
fn every_suffix_and_exponent() {
    for (text, nano) in [
        ("0", 0i128), ("1", NANO), ("1500", 1500 * NANO), ("0.5", NANO / 2), ("1.25", 1_250_000_000),
        ("1n", 1), ("1u", 1_000), ("1m", 1_000_000), ("1500m", 1_500_000_000), ("1k", 1_000 * NANO), ("1M", 1_000_000 * NANO),
        ("1G", 1_000_000_000 * NANO), ("1T", 1_000_000_000_000 * NANO), ("1P", 1_000_000_000_000_000 * NANO),
        ("1E", 1_000_000_000_000_000_000 * NANO), ("1Ki", 1_024 * NANO), ("1Mi", (1 << 20) * NANO), ("1Gi", (1 << 30) * NANO),
        ("1Ti", (1 << 40) * NANO), ("1Pi", (1 << 50) * NANO), ("1Ei", (1 << 60) * NANO), ("1.5Ki", 1_536 * NANO),
        ("0.001Ki", 1_024_000_000), ("1e3", 1_000 * NANO), ("1E3", 1_000 * NANO), ("1e+3", 1_000 * NANO), ("5e-1", NANO / 2),
        ("1e-9", 1), ("2.5e2", 250 * NANO), ("000123", 123 * NANO), ("0.000000001", 1),
    ] {
        assert_eq!(parse_quantity(text), Some(nano), "{text}");
    }
}

#[test]
fn finer_than_1n_overflow_and_other_forms_refuse() {
    for text in ["0.1n", "1e-10", "0.0000000001", "1.5n", "0.0000000001Ki", "9223372036854775809", "9Ei", "1e19", "1e100", "1e1000",
                 "-1", "+1", ".5", "1.", "", "1e", "e3", "1 Gi", "1gi", "1KI", "1Ki ", "1x", "1.2.3", "Infinity", "0x10",
                 "9".repeat(39).as_str()] {
        assert_eq!(parse_quantity(text), None, "{text}");
    }
    // The largest quantity, 2^63 base units, is accepted (also as 8Ei; 0.0001Ki is an exact 102,400,000n); one nano
    // more is not.
    assert_eq!(parse_quantity("8Ei"), Some(MAX_NANO));
    assert_eq!(parse_quantity("0.0001Ki"), Some(102_400_000));
    assert_eq!(parse_quantity("9223372036854775808"), Some(MAX_NANO));
    assert_eq!(parse_quantity("9223372036854775808.000000001"), None);
    // `E` alone is exa, `E3` an exponent; zero is zero whatever its exponent.
    assert_eq!(parse_quantity("2E"), Some(2_000_000_000_000_000_000 * NANO));
    assert_eq!(parse_quantity("0e999"), Some(0));
}

#[test]
fn the_comparison_is_exact_and_the_headroom_rounds_conservatively() {
    let hard = format!(r#"{{{SIX}, "limits.cpu": "1500m"}}"#);
    let used = format!(r#"{{{SIX_USED}, "limits.cpu": "1200m"}}"#);
    let figures = headroom(&items(&[settled("a", &hard, &used)]), NAMESPACE).expect("used <= hard");
    assert_eq!(figures, Headroom { pods: 7, config_maps: 20, services: 0, cpu_millis: 1_750, memory_bytes: (1 << 30) - 100 * (1 << 20),
                                   ephemeral_storage_bytes: (2 << 30) - 1_000_000_000 });
    let used = format!(r#"{{{SIX_USED}, "limits.cpu": "1501m"}}"#);
    assert_eq!(headroom(&items(&[settled("a", &hard, &used)]), NAMESPACE), Err(QuotaError::Refused("a quota's used exceeds its hard")));
    // Rounding only for the figures: a CPU hard of 1500500n floors to 1 millicore; a used of 1n rounds up to 1.
    let hard = r#"{"pods": "1", "configmaps": "1", "services": "1", "cpu": "1500500n", "memory": "1001", "ephemeral-storage": "1"}"#;
    let used = r#"{"pods": "0", "configmaps": "0", "services": "0", "cpu": "1n", "memory": "0.5", "ephemeral-storage": "0"}"#;
    let figures = headroom(&items(&[settled("b", hard, used)]), NAMESPACE).expect("passes");
    assert_eq!((figures.cpu_millis, figures.memory_bytes), (0, 1_000));
    // Counts are whole.
    let hard = r#"{"pods": "1500m", "configmaps": "1", "services": "1", "cpu": "1", "memory": "1", "ephemeral-storage": "1"}"#;
    let used = r#"{"pods": "0", "configmaps": "0", "services": "0", "cpu": "0", "memory": "0", "ephemeral-storage": "0"}"#;
    assert_eq!(headroom(&items(&[settled("c", hard, used)]), NAMESPACE), Err(QuotaError::Refused("a count quota holds a fraction")));
    assert_eq!(UNITS.len(), 6);
}

#[test]
fn settled_used_above_hard_missing_keys_and_units() {
    let six = format!("{{{SIX}}}");
    let used = format!("{{{SIX_USED}}}");
    // Unsettled: status.hard not yet spec.hard (other keys, or other values).
    let other = six.replace("\"pods\": \"10\"", "\"pods\": \"11\"");
    assert_eq!(headroom(&items(&[quota("u", NAMESPACE, &other, &six, &used)]), NAMESPACE), Err(QuotaError::Unsettled));
    assert_eq!(headroom(&items(&[quota("u", NAMESPACE, &six, "{}", "{}")]), NAMESPACE), Err(QuotaError::Unsettled));
    // Equal by exact value, whatever the spelling, is settled.
    let spelled = six.replace("\"1Gi\"", "\"1024Mi\"");
    assert!(headroom(&items(&[quota("s", NAMESPACE, &spelled, &six, &used)]), NAMESPACE).is_ok());
    // used holds every key of hard.
    let short = used.replace(", \"services\": \"5\"", "");
    assert_eq!(headroom(&items(&[settled("m", &six, &short)]), NAMESPACE),
               Err(QuotaError::Refused("a quota's status.used lacks a key of status.hard")));
    // Each unit bounded by some quota key.
    let no_storage = six.replace(", \"requests.ephemeral-storage\": \"2Gi\"", "");
    assert_eq!(headroom(&items(&[settled("n", &no_storage, &used)]), NAMESPACE),
               Err(QuotaError::Refused("a unit of I01 is bounded by no quota key")));
    assert_eq!(headroom(&[], NAMESPACE), Err(QuotaError::Refused("a unit of I01 is bounded by no quota key")));
    // Another namespace's quota does not count.
    assert_eq!(headroom(&items(&[quota("o", "other", &six, &six, &used)]), NAMESPACE),
               Err(QuotaError::Refused("a unit of I01 is bounded by no quota key")));
    // Malformed quantities and maps refuse.
    let bad = six.replace("\"10\"", "\"ten\"");
    assert!(matches!(headroom(&items(&[settled("b", &bad, &used)]), NAMESPACE), Err(QuotaError::Refused(_))));
    let bad = format!(r#"{{"metadata": {{"name": "x", "namespace": "{NAMESPACE}"}}, "spec": {{"hard": []}}}}"#);
    assert!(matches!(headroom(&items(&[bad]), NAMESPACE), Err(QuotaError::Refused(_))));
}

#[test]
fn the_headroom_is_the_minimum_over_the_covering_keys() {
    let six = format!("{{{SIX}}}");
    let used = format!("{{{SIX_USED}}}");
    let tight = r#"{"count/pods": "4", "cpu": "300m"}"#;
    let tight_used = r#"{"count/pods": "2", "cpu": "100m"}"#;
    let figures = headroom(&items(&[settled("a", &six, &used), settled("b", tight, tight_used)]), NAMESPACE).expect("passes");
    assert_eq!((figures.pods, figures.cpu_millis), (2, 200));
    assert_eq!(figures.config_maps, 20);
    // A figure above 2^53 - 1 refuses.
    let huge = six.replace("\"10\"", "\"9007199254740999\"");
    assert_eq!(headroom(&items(&[settled("h", &huge, &used)]), NAMESPACE), Err(QuotaError::Refused("a headroom figure is above 2^53-1")));
    // HE-004-I01a (DESIGN-I01A section 9, review r4 I4-3): the chosen key's recorded floor(hard) is held to 2^53 - 1 as
    // well, so this edge, whose headroom alone fits, now refuses; a chosen hard of exactly 2^53 - 1 passes.
    let edge = six.replace("\"10\"", &format!("\"{}\"", MAX_FIGURE + 3));
    assert_eq!(headroom(&items(&[settled("e", &edge, &used)]), NAMESPACE),
               Err(QuotaError::Refused("a recorded quota figure is above 2^53-1")));
    let top = six.replace("\"10\"", &format!("\"{}\"", MAX_FIGURE));
    assert_eq!(headroom(&items(&[settled("t", &top, &used)]), NAMESPACE).map(|figures| figures.pods), Ok(MAX_FIGURE - 3));
}
