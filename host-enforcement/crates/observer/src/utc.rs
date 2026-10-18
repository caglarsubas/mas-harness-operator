//! Wall-clock seconds and their canonical UTC text `YYYY-MM-DDTHH:MM:SSZ` (HE-004C DESIGN-C sections 8.3 and 11;
//! MODEL_DEFINED R113): the ADM-4 window's two ends and the configuration's lifetime read the wall clock as whole
//! seconds since the epoch, and B1's `check_loaded_manifest` takes canonical UTC times. The date is computed with
//! H. Hinnant's civil-from-days algorithm. A clock before the epoch or past 9999-12-31T23:59:59Z cannot be rendered:
//! `None`, which the observer maps to status 97 (unreachable with a sane clock, but mapped). Portable and pure except
//! [`wall_seconds`], which reads the realtime clock (`clock_gettime`, in the OBSERVER row).

use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::MAX_WALL_SECONDS;

/// The wall clock in whole seconds since the epoch (floored), or `None` before the epoch.
pub fn wall_seconds() -> Option<u64> {
    SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|elapsed| elapsed.as_secs())
}

/// The civil date (year, month 1-12, day 1-31) of a day count since 1970-01-01 (H. Hinnant's algorithm, for days in
/// 0..=2,932,896, the range of years 1970-9999).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// The canonical UTC text of `seconds` since the epoch, or `None` past 9999-12-31T23:59:59Z.
pub fn canonical_utc(seconds: u64) -> Option<String> {
    if seconds > MAX_WALL_SECONDS {
        return None;
    }
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    let (year, month, day) = civil_from_days(days);
    Some(format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, rest / 3_600, rest % 3_600 / 60, rest % 60))
}

/// The ADM-4 observation window (DESIGN-C section 8.3, Q-HE4C-4 (a)): the start is the floored wall second when the
/// scrape's request started, the end `max(end, start) + 1` from the floored wall second when its answer completed, so
/// the start is strictly before the end even within one second or under a step back. `None` (status 97) when either
/// reading is before the epoch or an end cannot be rendered.
pub fn window(start: Option<u64>, end: Option<u64>) -> Option<(String, String)> {
    let (start, end) = (start?, end?);
    let last = end.max(start).checked_add(1)?;
    Some((canonical_utc(start)?, canonical_utc(last)?))
}
