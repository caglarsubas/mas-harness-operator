//! Quota headroom (HE-004C DESIGN-C section 10, owner decision Q-HE4C-7 (a); MODEL_DEFINED R115), over the snapshot's
//! ResourceQuotas list (a closed-set entry) filtered to the qualification namespace. R10-defined, since no contract
//! states the key mapping (D-section 4.4). In order:
//!
//! 1. Settled: for every quota, `status.hard` equals `spec.hard` (the same keys, quantities equal by exact value);
//!    otherwise the snapshot is unsettled and restarts (status 89 at the snapshot deadline).
//! 2. For every key of every quota, `status.used` holds the key and `used <= hard`, compared exactly at the 10^-9 scale
//!    in i128 (D1-8): no rounding here.
//! 3. Each of I01's six units is bounded: at least one quota carries a key of its mapping.
//! 4. Headroom: per unit, the minimum over the covering keys of `max(0, floor(hard) - ceil(used))` in the unit; the
//!    conservative rounding applies only here. HE-004-I01 compares it with the whole-run requested headroom.
//!
//! Quantities: digits with an optional fraction, then an optional suffix (`n`, `u`, `m`, `k`, `M`, `G`, `T`, `P`, `E`,
//! `Ki` to `Ei`) or an exponent `e`/`E` with a signed integer; the exact value at the 10^-9 scale. A value finer than
//! `1n` or above 2^63 base units refuses; counts must be whole; the six figures lie in 0 to 2^53-1. Every refusal is
//! status 89. Requests versus limits (whether `limits.*` keys must also bound the resource units) is a W03 distribution
//! check item; `limits.*` keys are still held to step 2.

use std::collections::BTreeMap;

use i05_protocol::json::{Object, Value};

use crate::inputs::object_namespace;

/// One base unit at the 10^-9 scale.
pub const NANO: i128 = 1_000_000_000;
/// The largest quantity, 2^63 base units, at the 10^-9 scale.
pub const MAX_NANO: i128 = (1i128 << 63) * NANO;
/// The largest recorded headroom figure, 2^53 - 1.
pub const MAX_FIGURE: u64 = (1 << 53) - 1;

/// How a unit's figure is counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scale {
    /// A whole count of objects.
    Count,
    /// Thousandths of the base unit (CPU millicores).
    Millis,
    /// Base units (bytes).
    Base,
}

/// I01's six units (`channel.schema.json`), each with the quota keys that bound it (R10-defined mapping).
pub const UNITS: [(&str, Scale, [&str; 2]); 6] = [
    ("pods", Scale::Count, ["pods", "count/pods"]),
    ("configMaps", Scale::Count, ["configmaps", "count/configmaps"]),
    ("services", Scale::Count, ["services", "count/services"]),
    ("cpuMillis", Scale::Millis, ["requests.cpu", "cpu"]),
    ("memoryBytes", Scale::Base, ["requests.memory", "memory"]),
    ("ephemeralStorageBytes", Scale::Base, ["requests.ephemeral-storage", "ephemeral-storage"]),
];

/// The per-unit headroom recorded in the observation, in `UNITS` order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Headroom {
    pub pods: u64,
    pub config_maps: u64,
    pub services: u64,
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub ephemeral_storage_bytes: u64,
}

/// Why the quotas refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaError {
    /// A quota's `status.hard` is not yet its `spec.hard`: the snapshot restarts (89 at its deadline).
    Unsettled,
    /// Status 89.
    Refused(&'static str),
}

/// The exact value of a quantity at the 10^-9 scale, or `None` outside the strict form or its bounds.
pub fn parse_quantity(text: &str) -> Option<i128> {
    let bytes = text.as_bytes();
    let integer_end = bytes.iter().position(|byte| !byte.is_ascii_digit()).unwrap_or(bytes.len());
    if integer_end == 0 {
        return None;
    }
    let mut digits: Vec<u8> = bytes.get(..integer_end)?.to_vec();
    let mut rest = bytes.get(integer_end..)?;
    let mut fraction = 0i32;
    if let Some(after) = rest.strip_prefix(b".") {
        let end = after.iter().position(|byte| !byte.is_ascii_digit()).unwrap_or(after.len());
        if end == 0 {
            return None;
        }
        digits.extend_from_slice(after.get(..end)?);
        fraction = i32::try_from(end).ok()?;
        rest = after.get(end..)?;
    }
    if digits.len() > 38 {
        return None;
    }
    // The suffix: a decimal power of ten, a binary power of two, or an exponent.
    let (ten, two): (i32, u32) = match rest {
        b"" => (0, 0),
        b"n" => (-9, 0),
        b"u" => (-6, 0),
        b"m" => (-3, 0),
        b"k" => (3, 0),
        b"M" => (6, 0),
        b"G" => (9, 0),
        b"T" => (12, 0),
        b"P" => (15, 0),
        b"E" => (18, 0),
        b"Ki" => (0, 10),
        b"Mi" => (0, 20),
        b"Gi" => (0, 30),
        b"Ti" => (0, 40),
        b"Pi" => (0, 50),
        b"Ei" => (0, 60),
        _ => {
            let exponent = rest.strip_prefix(b"e").or_else(|| rest.strip_prefix(b"E"))?;
            let (negative, number) = match exponent.split_first() {
                Some((b'-', number)) => (true, number),
                Some((b'+', number)) => (false, number),
                _ => (false, exponent),
            };
            if number.is_empty() || number.len() > 3 || !number.iter().all(u8::is_ascii_digit) {
                return None;
            }
            let value = std::str::from_utf8(number).ok()?.parse::<i32>().ok()?;
            (if negative { -value } else { value }, 0)
        }
    };
    let mut mantissa: i128 = 0;
    for digit in digits {
        mantissa = mantissa.checked_mul(10)?.checked_add(i128::from(digit - b'0'))?;
    }
    if mantissa == 0 {
        return Some(0);
    }
    let scaled = mantissa.checked_mul(1i128.checked_shl(two)?)?;
    let power = 9i32.checked_sub(fraction)?.checked_add(ten)?;
    let value = if power >= 0 {
        scaled.checked_mul(10i128.checked_pow(u32::try_from(power).ok()?)?)?
    } else {
        let divisor = 10i128.checked_pow(u32::try_from(power.checked_neg()?).ok()?)?;
        if scaled % divisor != 0 {
            return None; // finer than 1n
        }
        scaled / divisor
    };
    (value <= MAX_NANO).then_some(value)
}

/// A quota map (`spec.hard`, `status.hard` or `status.used`): absent is empty; present, an object of quantity texts.
fn quantities(holder: Option<&Value>, key: &str) -> Result<BTreeMap<String, i128>, QuotaError> {
    let Some(map) = holder.and_then(|holder| holder.get(key)) else { return Ok(BTreeMap::new()) };
    let Some(members) = map.as_object() else { return Err(QuotaError::Refused("a quota map is not an object")) };
    parse_map(members)
}

fn parse_map(members: &Object) -> Result<BTreeMap<String, i128>, QuotaError> {
    let mut out = BTreeMap::new();
    for (name, value) in members.iter() {
        let (Some(name), Some(text)) = (name.as_str(), value.as_str()) else {
            return Err(QuotaError::Refused("a quota quantity is not text"));
        };
        let quantity = parse_quantity(text).ok_or(QuotaError::Refused("a quota quantity is outside the strict form"))?;
        out.insert(name.to_string(), quantity);
    }
    Ok(out)
}

/// The floor and ceiling of a value at the 10^-9 scale in a unit of `divisor` nano units.
fn floor_in(value: i128, divisor: i128) -> i128 {
    value / divisor
}

fn ceil_in(value: i128, divisor: i128) -> i128 {
    (value + divisor - 1) / divisor
}

/// The headroom of the quotas in `namespace` among the ResourceQuotas list's items (see the module documentation).
pub fn headroom(items: &[Value], namespace: &str) -> Result<Headroom, QuotaError> {
    let mut quotas = Vec::new();
    for item in items.iter().filter(|item| object_namespace(item) == Some(namespace)) {
        let spec_hard = quantities(item.get("spec"), "hard")?;
        let status = item.get("status");
        let hard = quantities(status, "hard")?;
        let used = quantities(status, "used")?;
        quotas.push((spec_hard, hard, used));
    }
    // 1. Settled.
    if quotas.iter().any(|(spec_hard, hard, _)| spec_hard != hard) {
        return Err(QuotaError::Unsettled);
    }
    // 2. used <= hard for every key, exactly.
    for (_, hard, used) in &quotas {
        for (key, limit) in hard {
            match used.get(key) {
                Some(amount) if amount <= limit => {}
                Some(_) => return Err(QuotaError::Refused("a quota's used exceeds its hard")),
                None => return Err(QuotaError::Refused("a quota's status.used lacks a key of status.hard")),
            }
        }
    }
    // 3 and 4. Each unit bounded, and its headroom.
    let mut figures = [0u64; 6];
    for (slot, (_, scale, keys)) in figures.iter_mut().zip(UNITS.iter()) {
        let mut best: Option<i128> = None;
        for (_, hard, used) in &quotas {
            for key in keys {
                let (Some(limit), Some(amount)) = (hard.get(*key), used.get(*key)) else { continue };
                let room = match scale {
                    Scale::Count => {
                        if limit % NANO != 0 || amount % NANO != 0 {
                            return Err(QuotaError::Refused("a count quota holds a fraction"));
                        }
                        limit / NANO - amount / NANO
                    }
                    Scale::Millis => floor_in(*limit, NANO / 1_000) - ceil_in(*amount, NANO / 1_000),
                    Scale::Base => floor_in(*limit, NANO) - ceil_in(*amount, NANO),
                };
                let room = room.max(0);
                best = Some(best.map_or(room, |current| current.min(room)));
            }
        }
        let Some(room) = best else { return Err(QuotaError::Refused("a unit of I01 is bounded by no quota key")) };
        *slot = u64::try_from(room).ok().filter(|figure| *figure <= MAX_FIGURE).ok_or(QuotaError::Refused(
            "a headroom figure is above 2^53-1",
        ))?;
    }
    let [pods, config_maps, services, cpu_millis, memory_bytes, ephemeral_storage_bytes] = figures;
    Ok(Headroom { pods, config_maps, services, cpu_millis, memory_bytes, ephemeral_storage_bytes })
}
