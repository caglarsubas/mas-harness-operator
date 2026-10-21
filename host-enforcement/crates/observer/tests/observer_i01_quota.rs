//! HE-004-I01a DESIGN-I01A sections 9 and 15 (MODEL_DEFINED's HE-004-I01a section): the quota pair I01 will publish. Per
//! unit the covering key with the least headroom is chosen (a tie to the key whose quota object's name sorts first, then
//! to the key's name); its pair is `floor(hard)` and `min(ceil(used), floor(hard))` in the unit's scale, so the pair
//! never overstates the headroom and never shows `used > hard`; the chosen key's recorded values are bounded by 2^53 - 1
//! (89), while an unchosen key above it (100Pi beside 8Gi) does not refuse.

use i05_protocol::json::{self, Value};
use planeon_observer::quota::{headroom, quota, Pair, QuotaError, QuotaPairs, MAX_FIGURE};

const NAMESPACE: &str = "q-space";

fn settled(name: &str, hard: &str, used: &str) -> String {
    format!(r#"{{"metadata": {{"name": "{name}", "namespace": "{NAMESPACE}"}}, "spec": {{"hard": {hard}}}, "status": {{"hard": {hard}, "used": {used}}}}}"#)
}

fn items(texts: &[String]) -> Vec<Value> {
    texts.iter().map(|text| json::parse(text).expect("JSON")).collect()
}

const SIX: &str = r#""pods": "10", "configmaps": "20", "services": "5", "requests.cpu": "2", "requests.memory": "1Gi", "requests.ephemeral-storage": "2Gi""#;
const SIX_USED: &str = r#""pods": "3", "configmaps": "0", "services": "5", "requests.cpu": "250m", "requests.memory": "100Mi", "requests.ephemeral-storage": "1G""#;

fn six() -> (String, String) {
    (format!("{{{SIX}}}"), format!("{{{SIX_USED}}}"))
}

#[test]
fn each_unit_records_its_key_s_floor_of_hard_and_capped_ceiling_of_used() {
    let (hard, used) = six();
    let found = quota(&items(&[settled("a", &hard, &used)]), NAMESPACE).expect("passes");
    assert_eq!(found.pairs, QuotaPairs {
        pods: Pair { hard: 10, used: 3 },
        config_maps: Pair { hard: 20, used: 0 },
        services: Pair { hard: 5, used: 5 },
        cpu_millis: Pair { hard: 2_000, used: 250 },
        memory_bytes: Pair { hard: 1 << 30, used: 100 << 20 },
        ephemeral_storage_bytes: Pair { hard: 2 << 30, used: 1_000_000_000 },
    });
    // The pair never overstates: hard - used is the headroom, unit by unit.
    let room = found.headroom;
    let pairs = found.pairs;
    for (pair, figure) in [(pairs.pods, room.pods), (pairs.config_maps, room.config_maps), (pairs.services, room.services),
                           (pairs.cpu_millis, room.cpu_millis), (pairs.memory_bytes, room.memory_bytes),
                           (pairs.ephemeral_storage_bytes, room.ephemeral_storage_bytes)] {
        assert_eq!(pair.hard - pair.used, figure);
    }
    assert_eq!(headroom(&items(&[settled("a", &hard, &used)]), NAMESPACE), Ok(room));
    // floor(hard) and ceil(used): a CPU hard of 1500500n is 1 millicore, a used of 1n rounds up to 1; a memory hard of
    // 1001 bytes with 0.5 used records 1001 and 1. A used whose ceiling passes the floor of hard is capped at it.
    let hard = r#"{"pods": "1", "configmaps": "1", "services": "1", "cpu": "1500500n", "memory": "1001", "ephemeral-storage": "1"}"#;
    let used = r#"{"pods": "0", "configmaps": "0", "services": "0", "cpu": "1n", "memory": "0.5", "ephemeral-storage": "0"}"#;
    let found = quota(&items(&[settled("b", hard, used)]), NAMESPACE).expect("passes");
    assert_eq!((found.pairs.cpu_millis, found.pairs.memory_bytes), (Pair { hard: 1, used: 1 }, Pair { hard: 1_001, used: 1 }));
    let used = r#"{"pods": "0", "configmaps": "0", "services": "0", "cpu": "1000500n", "memory": "0", "ephemeral-storage": "0"}"#;
    let found = quota(&items(&[settled("c", hard, used)]), NAMESPACE).expect("exact used <= hard passes");
    assert_eq!((found.pairs.cpu_millis, found.headroom.cpu_millis), (Pair { hard: 1, used: 1 }, 0), "ceil(used) 2 capped at 1");
}

#[test]
fn the_least_headroom_key_is_chosen_and_a_tie_goes_to_the_first_quota_then_key_name() {
    let (hard, used) = six();
    // The least headroom wins whatever the names: quota z's count/pods (room 1) over a's pods (room 7).
    let tight = r#"{"count/pods": "5", "cpu": "300m"}"#;
    let tight_used = r#"{"count/pods": "4", "cpu": "100m"}"#;
    let found = quota(&items(&[settled("a", &hard, &used), settled("z", tight, tight_used)]), NAMESPACE).expect("passes");
    assert_eq!((found.pairs.pods, found.pairs.cpu_millis), (Pair { hard: 5, used: 4 }, Pair { hard: 300, used: 100 }));
    // A tie between quotas: the one whose name sorts first (a, room 7) over b (room 7), whatever their order in the list.
    let other = r#"{"pods": "8"}"#;
    let other_used = r#"{"pods": "1"}"#;
    for order in [[settled("b", other, other_used), settled("a", &hard, &used)], [settled("a", &hard, &used), settled("b", other, other_used)]] {
        assert_eq!(quota(&items(&order), NAMESPACE).map(|found| found.pairs.pods), Ok(Pair { hard: 10, used: 3 }));
    }
    // A tie inside one quota: count/pods sorts before pods.
    let both = hard.replace("\"pods\": \"10\"", "\"pods\": \"10\", \"count/pods\": \"9\"");
    let both_used = used.replace("\"pods\": \"3\"", "\"pods\": \"3\", \"count/pods\": \"2\"");
    assert_eq!(quota(&items(&[settled("a", &both, &both_used)]), NAMESPACE).map(|found| found.pairs.pods),
               Ok(Pair { hard: 9, used: 2 }));
}

#[test]
fn only_the_chosen_key_is_held_to_2_to_the_53_minus_1() {
    let (hard, used) = six();
    // The chosen key's floor(hard) at 2^53: 89, though its headroom fits.
    let big = hard.replace("\"10\"", &format!("\"{}\"", MAX_FIGURE + 1));
    let big_used = used.replace("\"pods\": \"3\"", &format!("\"pods\": \"{}\"", MAX_FIGURE - 1));
    assert_eq!(quota(&items(&[settled("a", &big, &big_used)]), NAMESPACE).map(|found| found.pairs),
               Err(QuotaError::Refused("a recorded quota figure is above 2^53-1")));
    // At exactly 2^53 - 1 it passes.
    let top = hard.replace("\"10\"", &format!("\"{}\"", MAX_FIGURE));
    assert_eq!(quota(&items(&[settled("a", &top, &used)]), NAMESPACE).map(|found| found.pairs.pods),
               Ok(Pair { hard: MAX_FIGURE, used: 3 }));
    // An unchosen covering key of 100Pi beside the chosen 8Gi does not refuse; nor does a limits.memory of 100Pi.
    let wide = hard.replace("\"requests.memory\": \"1Gi\"",
                            "\"requests.memory\": \"8Gi\", \"memory\": \"100Pi\", \"limits.memory\": \"100Pi\"");
    let wide_used = used.replace("\"requests.memory\": \"100Mi\"",
                                 "\"requests.memory\": \"1Gi\", \"memory\": \"1Gi\", \"limits.memory\": \"1Gi\"");
    let found = quota(&items(&[settled("a", &wide, &wide_used)]), NAMESPACE).expect("the unchosen key is not bounded");
    assert_eq!(found.pairs.memory_bytes, Pair { hard: 8 << 30, used: 1 << 30 });
    assert_eq!(found.headroom.memory_bytes, 7 << 30);
}
