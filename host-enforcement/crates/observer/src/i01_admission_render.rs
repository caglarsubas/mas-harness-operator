//! The A2 render (HE-004-I01B1; DESIGN-I01B rev 3 section 2 and DESIGN-I01B1 rev 2; the monitor's Q-I01B-15 (a)),
//! moved to admission v4 in place by HE-004-I01B4 (DESIGN-I01B4 rev 2 section 2.1; the monitor's Q-I01B4-11):
//! admission v4's static ValidatingAdmissionPolicy objects and their bindings, rendered from the four sealed values,
//! with the sealed directory's one file and its hash, as the I01 digest contract v2 renders them
//! (`contracts/i01-digests-v2/README.md` sections 4.1 and 5.1) with admission v4's frozen model (`a2_objects`,
//! `manifest_file_bytes` and
//! `manifest_directory_hash`, harness-onion `scripts/admission_semantics_v4.py` at `675daccb`, read as text). A pure
//! logic module under the I01 logic whitelist (`tools/gate.py`, I01_LOGIC_PATHS): no file is read, no system call
//! beyond allocation, every function total, no panic, and no caller in the binary (G-I01B-1).
//!
//! - [`a2_objects`]: a policy for each of the three qualification kinds, matching their CREATE requests inside the
//!   qualification namespace; a guard policy that refuses all API writes to admission policies, their bindings and the
//!   webhook configurations; and a Deny binding for each policy; all ordered as the model orders them.
//!   The sealed values enter only the namespace selector, the Service allocation rule and the Pod tolerations rule.
//! - [`manifest_file_bytes`]: the directory's one file, a v1 List of those objects, canonical JSON (i05-protocol's
//!   encoder, which equals the model's).
//! - [`render`]: the objects and the directory's hash over that one file under its fixed name ([`MANIFEST_FILE`]),
//!   reusing `admission::manifest_directory_hash`. It fits `i01_digest`'s render argument, so the digest's callers (the
//!   tests in HE-004-I01B1) hand it in; `i01_digest` checks the sealed values before it and the two hashes after it.
//! - The replay (`tests/observer_i01_render_replay.rs`) holds it to admission v4's vectors (the vendored
//!   `planeon-a2.json` byte for byte) and to the contract v2's admission vectors.
//!
//! Admission v4 renders as admission v3 did, with the same kinds, names, file name, hashing and the three places the
//! sealed values enter, except in the Pod policy: A2-POD-PULL-POLICY requires `'Never'` where v3 required `'Always'`,
//! and A2-POD-EMPTYDIR is its last row (18 CEL rows in all; the Pod policy 10).

use i05_protocol::json::Doc;

use crate::admission::manifest_directory_hash;
use crate::i01_digest::{Rendered, SealedAdmission};

/// The sealed directory's one file (admission v4's `MANIFEST_FILE`, as v3's).
pub const MANIFEST_FILE: &str = "planeon-a2.json";
/// The static objects' name suffix and the bindings' name part (admission v4's `STATIC_SUFFIX`, `BINDING_SUFFIX`).
const STATIC_SUFFIX: &str = ".static.k8s.io";
const BINDING_SUFFIX: &str = "-binding";
/// The objects' API version and kinds.
const API_VERSION: &str = "admissionregistration.k8s.io/v1";
const POLICY_KIND: &str = "ValidatingAdmissionPolicy";
const BINDING_KIND: &str = "ValidatingAdmissionPolicyBinding";
/// The qualification kinds in the model's order (`KINDS`), each with its policy's name (`POLICY_NAMES`) and resource.
const KINDS: [(&str, &str, &str); 3] = [
    ("Pod", "planeon-a2-pod.static.k8s.io", "pods"),
    ("ConfigMap", "planeon-a2-configmap.static.k8s.io", "configmaps"),
    ("Service", "planeon-a2-service.static.k8s.io", "services"),
];
/// The guard policy (`GUARD_NAME`) and the admission resources it guards (`ADMISSION_RESOURCES`).
const GUARD_NAME: &str = "planeon-a2-admission-objects.static.k8s.io";
const ADMISSION_RESOURCES: [&str; 6] = [
    "validatingadmissionpolicies", "validatingadmissionpolicybindings", "mutatingadmissionpolicies",
    "mutatingadmissionpolicybindings", "validatingwebhookconfigurations", "mutatingwebhookconfigurations",
];
/// The Pod echo annotations (`ECHO`), in the model's order, each as the manifest's echo rule names them: the
/// annotation key, then the Pod field it echoes.
const ECHO: [(&str, &str); 3] = [
    ("planeon.ai/a2-containers", "containers"),
    ("planeon.ai/a2-init-containers", "initContainers"),
    ("planeon.ai/a2-volumes", "volumes"),
];
/// The two NoExecute taints the Pod tolerations rule names (`NOT_READY`, `UNREACHABLE`).
const NOT_READY: &str = "node.kubernetes.io/not-ready";
const UNREACHABLE: &str = "node.kubernetes.io/unreachable";
/// The root-CA publisher's ConfigMap and user (`PUBLISHER_CONFIGMAP`, `PUBLISHER_USER`).
const PUBLISHER_CONFIGMAP: &str = "kube-root-ca.crt";
const PUBLISHER_USER: &str = "system:serviceaccount:kube-system:root-ca-cert-publisher";
/// No label or annotation key in a Kubernetes-reserved prefix (`RESERVED_CEL`).
const RESERVED_CEL: &str = "(!has(object.metadata.labels) || \
                            object.metadata.labels.all(k, !k.matches('^([^/]*\\\\.)?(kubernetes|k8s)\\\\.io/'))) && \
                            (!has(object.metadata.annotations) || \
                            object.metadata.annotations.all(k, !k.matches('^([^/]*\\\\.)?(kubernetes|k8s)\\\\.io/')))";
/// The guard's one validation message.
const GUARD_MESSAGE: &str = "A2-GUARD admission objects are written only through the sealed manifest directory";

/// The A2 render of the sealed values: the eight objects and the sealed directory's hash over its one file
/// (`sha256:<hex>`). `None` only if the hash has no value, which one named file never gives.
pub fn render(sealed: &SealedAdmission) -> Option<Rendered> {
    let objects = a2_objects(sealed);
    let bytes = manifest_list(&objects).canonical();
    let directory_hash = manifest_directory_hash(&[(MANIFEST_FILE, bytes.as_slice())]).ok()?;
    Some(Rendered { objects: objects.iter().map(Doc::to_value).collect(), directory_hash })
}

/// The bytes of the sealed directory's single file (the model's `manifest_file_bytes`): the static objects as the
/// items of a v1 List, encoded in canonical JSON.
pub fn manifest_file_bytes(sealed: &SealedAdmission) -> Vec<u8> {
    manifest_list(&a2_objects(sealed)).canonical()
}

/// The static policy and binding objects of the sealed directory (the model's `a2_objects`): one policy per
/// qualification kind, matching CREATE of its v1 resource in the qualification namespace, the guard over every API
/// write of an admission object, then one binding per policy, named with `-binding` before the static suffix,
/// validation action Deny. Static: no paramKind, no matchConditions, failurePolicy Fail.
pub fn a2_objects(sealed: &SealedAdmission) -> Vec<Doc> {
    let selector = Doc::object(vec![(
        "matchExpressions",
        Doc::Array(vec![Doc::object(vec![
            ("key", Doc::str("kubernetes.io/metadata.name")),
            ("operator", Doc::str("In")),
            ("values", texts(&[sealed.namespace.as_str()])),
        ])]),
    )]);
    let mut policies: Vec<(&str, Doc)> = Vec::with_capacity(KINDS.len().saturating_add(1));
    for (kind, name, resource) in KINDS {
        let rules = Doc::object(vec![
            ("apiGroups", texts(&[""])),
            ("apiVersions", texts(&["v1"])),
            ("operations", texts(&["CREATE"])),
            ("resources", texts(&[resource])),
        ]);
        let constraints = Doc::object(vec![
            ("matchPolicy", Doc::str("Exact")),
            ("namespaceSelector", selector.clone()),
            ("resourceRules", Doc::Array(vec![rules])),
        ]);
        policies.push((name, policy(name, constraints, validations(kind, sealed))));
    }
    let guard_rules = Doc::object(vec![
        ("apiGroups", texts(&["admissionregistration.k8s.io"])),
        ("apiVersions", texts(&["*"])),
        ("operations", texts(&["CREATE", "UPDATE", "DELETE"])),
        ("resources", texts(&ADMISSION_RESOURCES)),
    ]);
    let guard_constraints =
        Doc::object(vec![("matchPolicy", Doc::str("Exact")), ("resourceRules", Doc::Array(vec![guard_rules]))]);
    let guard = Doc::object(vec![
        ("expression", Doc::str("false")),
        ("reason", Doc::str("Forbidden")),
        ("message", Doc::str(GUARD_MESSAGE)),
    ]);
    policies.push((GUARD_NAME, policy(GUARD_NAME, guard_constraints, vec![guard])));
    let mut objects = Vec::with_capacity(policies.len().saturating_mul(2));
    let mut bindings = Vec::with_capacity(policies.len());
    for (name, object) in policies {
        let binding_name = name.replace(STATIC_SUFFIX, &format!("{BINDING_SUFFIX}{STATIC_SUFFIX}"));
        bindings.push(Doc::object(vec![
            ("apiVersion", Doc::str(API_VERSION)),
            ("kind", Doc::str(BINDING_KIND)),
            ("metadata", Doc::object(vec![("name", Doc::str(&binding_name))])),
            ("spec", Doc::object(vec![("policyName", Doc::str(name)), ("validationActions", texts(&["Deny"]))])),
        ]));
        objects.push(object);
    }
    objects.extend(bindings);
    objects
}

/// A list of text items.
fn texts(items: &[&str]) -> Doc {
    Doc::Array(items.iter().copied().map(Doc::str).collect())
}

/// One static policy: its name, failurePolicy Fail, its match constraints and its validations.
fn policy(name: &str, constraints: Doc, validations: Vec<Doc>) -> Doc {
    Doc::object(vec![
        ("apiVersion", Doc::str(API_VERSION)),
        ("kind", Doc::str(POLICY_KIND)),
        ("metadata", Doc::object(vec![("name", Doc::str(name))])),
        ("spec", Doc::object(vec![
            ("failurePolicy", Doc::str("Fail")),
            ("matchConstraints", constraints),
            ("validations", Doc::Array(validations)),
        ])),
    ])
}

/// The v1 List the directory's one file holds.
fn manifest_list(objects: &[Doc]) -> Doc {
    Doc::object(vec![
        ("apiVersion", Doc::str("v1")),
        ("kind", Doc::str("List")),
        ("items", Doc::Array(objects.to_vec())),
    ])
}

/// A Pod echo rule for one field (the model's `_echo_cel`).
fn echo_cel(field: &str, key: &str) -> String {
    let render = if field == "volumes" { "v.name" } else { "v.name + '=' + v.image" };
    format!("has(object.metadata.annotations) && '{key}' in object.metadata.annotations && \
             object.metadata.annotations['{key}'] == (has(object.spec.{field}) ? \
             object.spec.{field}.map(v, {render}).join(',') : '')")
}

/// A kind's validations in the model's order (admission v4's `_validations`), each `{expression, message, reason}`
/// with reason Forbidden: the ConfigMap rules (the publisher's one exception first), or the reserved-key rule then the
/// Service or Pod rules, the Pod rules ending with A2-POD-PULL-POLICY (pulled `'Never'`) and A2-POD-EMPTYDIR (every
/// emptyDir bounded), v4's two Pod rows. Each row is written as the manifest holds it: its CEL expression, then its
/// rule id.
fn validations(kind: &str, sealed: &SealedAdmission) -> Vec<Doc> {
    let publisher = format!("object.metadata.name == '{PUBLISHER_CONFIGMAP}'");
    let rows: Vec<(String, &str)> = match kind {
        "ConfigMap" => vec![
            (format!("!({publisher}) || (request.userInfo.username == '{PUBLISHER_USER}' && has(object.data) && \
                      object.data.size() == 1 && 'ca.crt' in object.data && !has(object.binaryData) && \
                      !has(object.metadata.labels) && (!has(object.metadata.annotations) || \
                      object.metadata.annotations.all(k, k == 'kubernetes.io/description')))"),
             "A2-CM-PUBLISHER"),
            (format!("{publisher} || ({RESERVED_CEL})"), "A2-RESERVED"),
            (format!("{publisher} || (has(object.immutable) && object.immutable == true)"), "A2-CM-IMMUTABLE"),
        ],
        "Service" => vec![
            (RESERVED_CEL.to_string(), "A2-RESERVED"),
            ("object.spec.type == 'ClusterIP' && !has(object.spec.externalIPs) && !has(object.spec.externalName) && \
              !has(object.spec.loadBalancerIP) && !has(object.spec.loadBalancerSourceRanges) && \
              !has(object.spec.loadBalancerClass) && !has(object.spec.healthCheckNodePort) && \
              object.spec.ports.all(p, !has(p.nodePort))"
                 .to_string(),
             "A2-SVC-TYPE"),
            (format!("object.spec.ipFamilyPolicy == 'SingleStack' && object.spec.ipFamilies.size() == 1 && \
                      object.spec.ipFamilies[0] == '{}' && object.spec.clusterIPs.size() == 1 && \
                      object.spec.clusterIP == object.spec.clusterIPs[0] && object.spec.clusterIP != 'None' && \
                      cidr('{}').containsIP(object.spec.clusterIP)",
                     sealed.ip_family, sealed.service_cidr),
             "A2-SVC-ALLOCATION"),
            ("object.spec.sessionAffinity == 'None' && object.spec.internalTrafficPolicy == 'Cluster'".to_string(),
             "A2-SVC-DEFAULTS"),
        ],
        _ => {
            let toleration = format!("t.operator == 'Exists' && t.effect == 'NoExecute' && has(t.tolerationSeconds) && \
                                      t.tolerationSeconds == {} && !has(t.value)",
                                     sealed.default_toleration_seconds);
            let echo: Vec<String> = ECHO.iter().map(|&(key, field)| echo_cel(field, key)).collect();
            vec![
                (RESERVED_CEL.to_string(), "A2-RESERVED"),
                (echo.join(" && "), "A2-POD-ECHO"),
                ("has(object.spec.automountServiceAccountToken) && object.spec.automountServiceAccountToken == false"
                     .to_string(),
                 "A2-POD-TOKEN"),
                ("!has(object.spec.imagePullSecrets) || object.spec.imagePullSecrets.size() == 0".to_string(),
                 "A2-POD-PULL-SECRETS"),
                ("!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.image))".to_string(),
                 "A2-POD-IMAGE-VOLUME"),
                (format!("has(object.spec.tolerations) && object.spec.tolerations.size() == 2 && \
                          object.spec.tolerations.exists_one(t, t.key == '{NOT_READY}' && {toleration}) && \
                          object.spec.tolerations.exists_one(t, t.key == '{UNREACHABLE}' && {toleration})"),
                 "A2-POD-TOLERATIONS"),
                ("has(object.spec.priority) && object.spec.priority == 0 && has(object.spec.preemptionPolicy) && \
                  object.spec.preemptionPolicy == 'PreemptLowerPriority' && !has(object.spec.priorityClassName)"
                     .to_string(),
                 "A2-POD-PRIORITY"),
                ("!has(object.spec.runtimeClassName) && !has(object.spec.overhead) && \
                  !has(object.spec.nodeName) && !has(object.spec.nodeSelector)"
                     .to_string(),
                 "A2-POD-PLACEMENT"),
                ("object.spec.containers.all(c, c.imagePullPolicy == 'Never') && \
                  (!has(object.spec.initContainers) || \
                  object.spec.initContainers.all(c, c.imagePullPolicy == 'Never'))"
                     .to_string(),
                 "A2-POD-PULL-POLICY"),
                ("!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.emptyDir) || \
                  (has(v.emptyDir.sizeLimit) && !has(v.emptyDir.medium)))"
                     .to_string(),
                 "A2-POD-EMPTYDIR"),
            ]
        }
    };
    rows.into_iter()
        .map(|(expression, code)| {
            Doc::object(vec![
                ("expression", Doc::Str(expression)),
                ("message", Doc::str(code)),
                ("reason", Doc::str("Forbidden")),
            ])
        })
        .collect()
}
