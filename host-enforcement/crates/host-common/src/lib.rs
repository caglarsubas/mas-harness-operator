//! Closed configuration shared by the host-enforcement modules (HE-001 scaffold).
//!
//! Thread counts come from configuration, never from the host (W03 plan TR-PARALLELISM).
#![forbid(unsafe_code)]

use std::num::NonZeroU16;

/// The scaffold's whole configuration: one `worker_threads=N` line, 1 <= N <= 1024.
#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    pub worker_threads: NonZeroU16,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    Missing,
    Duplicate,
    Unknown,
    Invalid,
}

pub fn parse(text: &str) -> Result<Config, ConfigError> {
    let mut worker_threads = None;
    for line in text.lines().filter(|line| !line.is_empty()) {
        let (key, value) = line.split_once('=').ok_or(ConfigError::Invalid)?;
        if key != "worker_threads" {
            return Err(ConfigError::Unknown);
        }
        if worker_threads.is_some() {
            return Err(ConfigError::Duplicate);
        }
        let count: u16 = value.parse().map_err(|_| ConfigError::Invalid)?;
        if count > 1024 {
            return Err(ConfigError::Invalid);
        }
        worker_threads = Some(NonZeroU16::new(count).ok_or(ConfigError::Invalid)?);
    }
    worker_threads.map(|worker_threads| Config { worker_threads }).ok_or(ConfigError::Missing)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_one_bounded_thread_count() {
        assert_eq!(parse("worker_threads=4\n").unwrap().worker_threads.get(), 4);
    }

    #[test]
    fn refuses_everything_else() {
        for text in ["", "worker_threads=0", "worker_threads=1025", "worker_threads=x", "threads=4",
                     "worker_threads=4\nworker_threads=4", "worker_threads"] {
            assert!(parse(text).is_err(), "{text:?}");
        }
    }
}
