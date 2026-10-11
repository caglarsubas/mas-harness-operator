//! The gate's resolved inputs for one generation (the vectors' `configs`): its generation and initial state, the
//! peer-qualification digest, the signed endpoint, the signed profile's manifests, the runs, the observed probe
//! workers and the bindings of earlier generations.
//!
//! The model's three input refusals come first, in its order and wording (a run manifest outside the signed profile; a
//! manifest digest in two runs; a manifest identity resolving to more than one manifest), then the priorBindings shape
//! ("an incomplete priorBindings record"). A field of the wrong type or an unknown field is refused before them
//! (R10-defined: the model would raise KeyError or TypeError, or ignore it).

use std::collections::{BTreeMap, BTreeSet};

use i05_protocol::json::{Object, Value};
use i05_protocol::{Kind, Manifest};

use crate::types::State;

/// One run's resolved binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub binding_digest: String,
    pub case_id: String,
    pub request_digest: String,
    pub server_certificate_digest: String,
    pub manifests: Vec<String>,
}

/// The bindings of earlier generations, from their durable BIND records.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PriorBindings {
    pub execution_ids: BTreeSet<String>,
    pub run_nonces: BTreeSet<String>,
    pub manifest_digests: BTreeSet<String>,
    pub manifest_identities: BTreeSet<String>,
}

/// A validated configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub generation: String,
    pub state: State,
    pub peer_qualification_digest: String,
    pub endpoint: String,
    /// The signed profile, keyed by manifest digest.
    pub manifests: BTreeMap<String, Manifest>,
    /// The runs, keyed by run nonce.
    pub runs: BTreeMap<String, Run>,
    pub observed_workers: BTreeSet<(i64, i64)>,
    pub prior: PriorBindings,
}

/// A refused configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl ConfigError {
    pub fn message(&self) -> &str {
        &self.0
    }
}

fn refuse<T>(message: &str) -> Result<T, ConfigError> {
    Err(ConfigError(message.to_string()))
}

const FIELDS: [&str; 9] = ["generation", "brokerChallenge", "state", "peerQualificationDigest", "endpoint", "manifests",
                           "runs", "observedWorkers", "priorBindings"];

fn text(object: &Object, key: &str) -> Result<String, ConfigError> {
    match object.get(key).and_then(Value::as_str) {
        Some(value) => Ok(value.to_string()),
        None => refuse(&format!("configuration field {key} is missing or not text")),
    }
}

fn object<'a>(value: Option<&'a Value>, what: &str) -> Result<&'a Object, ConfigError> {
    value.and_then(Value::as_object).map_or_else(|| refuse(&format!("configuration field {what} is not an object")), Ok)
}

fn text_list(value: Option<&Value>, what: &str) -> Result<Vec<String>, ConfigError> {
    let Some(items) = value.and_then(Value::as_array) else {
        return refuse(&format!("configuration field {what} is not a list"));
    };
    items
        .iter()
        .map(|item| item.as_str().map(str::to_string))
        .collect::<Option<Vec<String>>>()
        .map_or_else(|| refuse(&format!("configuration field {what} holds a value that is not text")), Ok)
}

impl Config {
    /// Parses and validates a configuration document.
    pub fn from_value(document: &Value) -> Result<Config, ConfigError> {
        let root = object(Some(document), "configuration")?;
        for (key, _) in root.iter() {
            if !key.as_str().is_some_and(|name| FIELDS.contains(&name)) {
                return refuse("unknown configuration field");
            }
        }
        let generation = text(root, "generation")?;
        let state = State::parse(&text(root, "state")?).map_or_else(|| refuse("configuration field state is not a state"), Ok)?;
        let peer_qualification_digest = text(root, "peerQualificationDigest")?;
        let endpoint = text(root, "endpoint")?;
        let mut manifests = BTreeMap::new();
        for (digest, entry) in object(root.get("manifests"), "manifests")?.iter() {
            let digest = digest.as_str().map_or_else(|| refuse("a manifest digest is not text"), Ok)?;
            let entry = object(Some(entry), "manifests entry")?;
            let kind = Kind::parse(&text(entry, "kind")?).map_or_else(|| refuse("a manifest kind is not renderable"), Ok)?;
            let size = entry.get("size").and_then(Value::as_int).and_then(|size| size.to_u64());
            let size = size.map_or_else(|| refuse("a manifest size is not a byte count"), Ok)?;
            manifests.insert(digest.to_string(), Manifest {
                api_version: text(entry, "apiVersion")?,
                kind,
                namespace: text(entry, "namespace")?,
                name: text(entry, "name")?,
                digest: text(entry, "digest")?,
                size,
            });
        }
        let mut runs = BTreeMap::new();
        for (nonce, entry) in object(root.get("runs"), "runs")?.iter() {
            let nonce = nonce.as_str().map_or_else(|| refuse("a run nonce is not text"), Ok)?;
            let entry = object(Some(entry), "runs entry")?;
            runs.insert(nonce.to_string(), Run {
                binding_digest: text(entry, "bindingDigest")?,
                case_id: text(entry, "caseId")?,
                request_digest: text(entry, "requestDigest")?,
                server_certificate_digest: text(entry, "serverCertificateDigest")?,
                manifests: text_list(entry.get("manifests"), "runs manifests")?,
            });
        }
        let Some(workers) = root.get("observedWorkers").and_then(Value::as_array) else {
            return refuse("configuration field observedWorkers is not a list");
        };
        let mut observed_workers = BTreeSet::new();
        for worker in workers {
            let pair = worker.as_array().unwrap_or_default();
            match pair {
                [pid, ticks] => match (pid.as_int().and_then(|v| v.to_i64()), ticks.as_int().and_then(|v| v.to_i64())) {
                    (Some(pid), Some(ticks)) => {
                        observed_workers.insert((pid, ticks));
                    }
                    _ => return refuse("an observed worker is not a [pid, startTicks] pair of integers"),
                },
                _ => return refuse("an observed worker is not a [pid, startTicks] pair of integers"),
            }
        }
        // The model's input refusals, in its order.
        let listed: Vec<&String> = runs.values().flat_map(|run| run.manifests.iter()).collect();
        if !listed.iter().all(|digest| manifests.contains_key(*digest)) {
            return refuse("a run manifest is not in the signed profile");
        }
        if listed.iter().collect::<BTreeSet<_>>().len() != listed.len() {
            return refuse("a manifest digest resolves to more than one run");
        }
        let identities: Vec<String> = listed.iter().filter_map(|digest| manifests.get(*digest)).map(Manifest::identity).collect();
        if identities.iter().collect::<BTreeSet<_>>().len() != identities.len() {
            return refuse("a manifest identity resolves to more than one manifest");
        }
        let prior = match root.get("priorBindings") {
            Some(Value::Object(prior))
                if prior.len() == 4
                    && ["executionIds", "runNonces", "manifestDigests", "manifestIdentities"]
                        .iter()
                        .all(|key| matches!(prior.get(key), Some(Value::Array(_)))) =>
            {
                prior
            }
            _ => return refuse("an incomplete priorBindings record"),
        };
        let set = |key: &str| -> Result<BTreeSet<String>, ConfigError> {
            Ok(text_list(prior.get(key), "priorBindings")?.into_iter().collect())
        };
        let prior = PriorBindings {
            execution_ids: set("executionIds")?,
            run_nonces: set("runNonces")?,
            manifest_digests: set("manifestDigests")?,
            manifest_identities: set("manifestIdentities")?,
        };
        Ok(Config { generation, state, peer_qualification_digest, endpoint, manifests, runs, observed_workers, prior })
    }
}
