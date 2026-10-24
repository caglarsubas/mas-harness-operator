# The I01 digest contract (DIGEST-CONTRACT)

Schema `planeon.internal.policy-observation-digests/v1`. Adoption is recorded in the packet's status record, not here.
DATA_CHECK_ONLY: the reference model returns values, refusal texts or an empty error list, never a protected handle or
native acceptance, as I06 v4 and admission v3 do.

This contract fixes how the policy observer derives the I01 v1 answer's **seven projection objects** and **four
enforcement digests**, and what R10's HE-004-I01B vendors to port them (owner decision Q-HE4I1-2 (c)+(a); monitor
decisions Q-I01B-1..5 (a); owner decision Q-DIG-3 / Q-DIG-7 "Accept, check at T04"; monitor decisions Q-DIG-1, 2, 4-6
and 8-18). It changes no file of the I01 v1 wire. It cites the wire's pinned files by sha256:

| Key | Path | SHA-256 |
|---|---|---|
| CS | `architecture/policy-observation-inputs/channel.schema.json` | `fb69b77201d9b6275a19667a5f5770537f382ddb11309095733628c8430bdc0e` |
| PV | `architecture/policy-observation-inputs/vectors.json` | `1bfb46776636f800e38ab6a8f94a0989aa38513fb4a28ef18e61e732a115c124` |
| RD | `docs/alpha-2/POLICY_OBSERVATION_READINESS.md` | `65778040919c5eb7335f2c104d983ca920b877b1b123f961556a6bcae36d232c` |

## 0. Files, model and sources

| Path | What it is |
|---|---|
| `architecture/policy-observation-digests/README.md` | This contract text. |
| `architecture/policy-observation-digests/definitions.json` | The closed definitions: per projection and digest, the fixed identity, source, document shape, inputs, gates, refusal texts and residual ids; the capture-verdict data shape; the B1 refusals; the CS, PV and RD pins; the frozen models and inputs. It equals the model's `definitions()`. |
| `architecture/policy-observation-digests/vectors.json` | The vectors: helper vectors, per-key and per-digest vectors, capture-gate vectors, answer vectors and one complete I01 positive. |
| `scripts/policy_observation_digests.py` | The reference model: `projection_document`, `projection_digest`, `enforcement_digests`, `capture_gate`, `check_observation_digests`, `check_vectors` and `main`. |

**Imports.** The model imports `canonical`, `digest` and `_bounded` by name from `scripts/validate_proxy_contract.py`
(VPC), as the other validators do. Their behaviour is pinned by the helper vectors in `vectors.json` (canonical bytes,
digests and bounds), not by that file's sha256, because its packet list changes with every packet. The frozen models it
imports are pinned by file sha256 (`FROZEN_MODELS`, and `frozenModels` in `definitions.json`), and the model never edits
them: `scripts/admission_semantics_v3.py` (`a2_objects`, `manifest_file_bytes`, `manifest_directory_hash`),
`scripts/i06_backend_profile.py` and `scripts/i06_backend_profile_v4.py` (the closure check and the v4 role pin), with
what v4 imports (`scripts/i06_backend_profile_v3.py`, `scripts/native_qualification_v4.py`). I06 v1's closure inputs
(`architecture/i06-backend-profile/identity-closure.json`, `writer-inventory.json`, `upstream-bootstrap-rbac-v1.37.1.json`)
are pinned by sha256 too. The model defines the EffectiveRbac, closure and MutationBroker derivations, the network
document and the capture gate itself.

**Citation keys.** `HO:` is harness-onion at `30f41e6f` (the cited lines are unchanged since `26a8affb`); `R10:` is
mas-harness-operator at `dd7422ed`, with `obs/` = `host-enforcement/crates/observer/src/` and
`J` = `host-enforcement/crates/i05-protocol/src/json.rs`. Harness-onion abbreviations: VPO =
`scripts/validate_policy_observation.py`; VPC = `scripts/validate_proxy_contract.py`; PCR =
`docs/alpha-2/PROXY_CONTRACT_READINESS.md`; NQ = `docs/alpha-2/NATIVE_QUALIFICATION_READINESS.md`; BH =
`docs/alpha-2/BROKER_HANDOFF_READINESS.md`; PA = `architecture/policy-observation-amendment.json`; PPV =
`architecture/proxy-contract-inputs/vectors.json`; AS3 = `architecture/admission-semantics-v3/README.md`; AS3M =
`scripts/admission_semantics_v3.py`; K3 = `architecture/i07-policy-write-v3/policy-kinds.json`; I4R =
`architecture/i06-backend-profile-v4/README.md`; H53S = `architecture/host-interface-amendment-hs53/HOST_INTERFACE_SPEC.md`;
BD = `architecture/backend-distribution/README.md`; NP4R = `architecture/native-profile-v4/README.md`.

## 1. Scope

- **In:** this data-only contract; the supersession table (section 7); and edge record v10, which registers this
  contract's three data files and the proxy-contract vectors for HE-004-I01B.
- **Out:** any change to CS, PV or RD (pinned, `HO:PA:196-200`); any R10 file; the observer's permissions (I06 v4's
  pinned ClusterRole is unchanged); the configuration successor's format, which belongs to I01b (this contract names
  only the values it must carry, section 6); the generation's format; per-request freshness.
- **Inputs the observer already has.** Every input is one the observer already lists (`R10:obs/inputs.rs:88-140`), one
  its signed configuration carries or its successor must carry, a record value, or a capture verdict. The capture gate
  needs one value the capture engine does not hold today: each set's own scheduled start on the monotonic clock,
  recorded with the set (section 3.3). It needs no new permission and no new read.
- **Scope limits (refused, not residual):**
  - **one NetworkPolicy** in the qualification namespace in v1 (section 4.2); a release that binds several takes a List
    form for `networkPolicy` alone, through a contract revision;
  - **selector-free NetworkPolicies only** in v1 (section 4.4);
  - **direct RBAC grants only:** an aggregated ClusterRole that reaches the namespace refuses (section 4.5).

## 2. The snapshot and the binding

The model reads one **snapshot** and the **signed binding**:

- `snapshot` = `{resourceVersion, lists, configuration, adm4LoadedHash, record}`:
  - `lists`: the served list items of `namespaces`, `resourceQuotas`, `limitRanges`, `serviceAccounts`,
    `networkPolicies`, `roles`, `roleBindings`, `clusterRoles`, `clusterRoleBindings`, `validatingAdmissionPolicies`
    and `validatingAdmissionPolicyBindings`, all from one read at one resourceVersion (`resourceVersion`);
  - `configuration`: `qualificationNamespace`, `pinnedManifestHash`, and `sealedAdmission` =
    `{ipFamily, serviceCIDR, defaultTolerationSeconds}`, the three sealed admission values the configuration successor
    must carry (section 6);
  - `adm4LoadedHash`: ADM-4's loaded hash from the apiserver's ALPHA metric (`R10:obs/admission.rs:1-10`);
  - `record`: the enrolled `planeon.internal.native-qualification/v4` record.
- `binding`: the HE-008-signed copy of the release's observation binding. The model reads from it only the bound names
  of the one-object kinds and the profile's service-account subject; everything else is compared against (section 3.5).

## 3. Common rules

### 3.1 The projection document

- Every projection, including the synthetic ones, is PCR's five-member form (`HO:PCR:82-87`):
  `{apiVersion, kind, metadata: {name, namespace, uid}, spec}`. `metadata` is exactly those three members.
- **The identity is the contract's.** `apiVersion` and `kind` are fixed per key (section 4), never taken from a served
  list item, which usually omits them.
  - The three synthetic keys have contract names: `admissionpolicy`, `rbac`, `mutationbroker`. `metadata.namespace` is
    null for `admissionPolicy` and the configured qualification namespace for `rbac` and `mutationBroker`, as PV has
    them (`HO:PV:28-83`).
  - The four real keys take `metadata.name`, `metadata.namespace` and `metadata.uid` from the live object.
  - No identity member is ever read from the binding.
- No status, resourceVersion, managedFields, generation, creationTimestamp, labels, annotations or ownerReferences enters
  a document. No label or annotation of the four real kinds enters a document. The one annotation that changes
  enforcement is refused instead: the ServiceAccount annotation `kubernetes.io/enforce-mountable-secrets`
  (section 4.3). Namespace labels are handled where they matter: the Pod Security labels in section 4.1, and
  NetworkPolicy namespace selectors, which v1 refuses (section 4.4).
- **Kinds without `spec`.** `spec` holds exactly the kind's enforcement top-level keys as I07 v3's `topLevelKeys` lists
  them (`HO:K3:180-262`). The one such kind here is ServiceAccount: `automountServiceAccountToken`, `imagePullSecrets`
  and `secrets`. An absent key is absent, never null.
- **uids.** A real object's uid is the live object's. A synthetic projection's uid is the lowercase hex sha256 of
  `canonical({apiVersion, kind, name, namespace})` over its fixed identity: 64 characters, which fit
  `^[A-Za-z0-9-]{1,128}$` (`HO:CS:209-214`).
- **resourceVersion.** A real projection's observed `resourceVersion` is the object's own in the read; a synthetic one's
  is the read's.

### 3.2 Canonical bytes, exact values and the digest

- **Canonical bytes:** VPC's `canonical`, `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
  allow_nan=False)` UTF-8 (`HO:VPC:29-34`), which R10's i05-protocol encoder equals (`R10:J:10-12`).
- **Exact values.** Every document is taken over the apiserver's exact JSON values.
  - A float refuses: "<key>: float refused".
  - Then VPC's `_bounded` applies (`HO:VPC:104-122`): exact builtins, depth at most 16, its size budget, and its
    magnitude rule `abs(value) <= 2^53 - 1` (`HO:VPC:113-114`). Its integer refusal is "<key>: integer out of range"; a
    negative integer within the bound is accepted. Any other refusal of `_bounded` is "<key>: document bound exceeded".
- **Sorted sets.** Lists keep served order, except:
  - `sealedObjects` (section 4.1), sorted by `(kind, metadata.name)`, a total key since the rendered names are unique;
  - the RBAC subjects (sections 4.5 and 5.2), sorted by `(kind, name)`, one entry each;
  - each RBAC subject's rules, sorted and deduplicated by canonical bytes;
  - the NetworkPolicy documents of section 5.3, sorted by canonical bytes.
- **The digest** is `"sha256:" + hex(sha256(canonical(document)))`, matching `^sha256:[0-9a-f]{64}$` (`HO:CS:215-220`):
  `projection_digest(document)` = `"sha256:" + digest(canonical(document))`.
- **The served form.** A real projection is taken from the object as the apiserver serves it, after defaulting. HE-008
  captures the expected values from the sealed cluster at enrollment (section 6). Residual R-DEFAULTS (section 8).

### 3.3 One snapshot, and the capture gate at every answer

- Every projection and digest comes from one snapshot read at one resourceVersion, computed before the lists are dropped
  (`R10:obs/observe.rs:1010`).
- **Three values are capture-gated:** `mutationBroker` (section 4.6), the network document and
  `networkEnforcementDigest` (section 5.3), and `hostPreflightDigest` (section 5.4). Their documents are computed at the
  snapshot; **the gate is checked at every I01 answer**, not at the snapshot.
- **The gate.** A gated value is in an answer only if, at that answer:
  1. the **latest completed capture set** exists, and every capture slot the value requires is `TAKEN` in it;
  2. that set's **own scheduled start**, recorded with that set on the **monotonic clock** of the scheduled `Instant`,
     is at most 90 s before the answer, and never after it. The start is never the epoch's current `cycle_scheduled`,
     which advances when the next cycle starts (`R10:obs/observe.rs:1166`) and stays advanced when that cycle's scrape
     escalates and takes no set (`R10:obs/observe.rs:1319-1323`);
  3. the set's **wall age**, the answer's wall time minus the set's `set_started_ms` (`R10:obs/capture.rs:1250`), is
     neither negative nor over 90 s, so that neither clock's step or freeze can make an old set look young.
- **The bound.** 90 s is R10's 60 s cycle, plus the 5 s start bound, plus the 25 s set budget: `CYCLE`
  (`R10:obs/observe.rs:99`), `SCRAPE_TO_SET` (`R10:obs/capture.rs:55`) and `SET_BUDGET` (`R10:obs/capture.rs:53`). The
  set's scheduled start is the previous cycle's actual start + 60 s (`R10:obs/capture.rs:276`;
  `R10:obs/observe.rs:37-40`). A skipped or escalated cycle takes no set, so gated values refuse once the latest set is
  older than the bound, until the next set passes. That costs availability only.
- A later set without the required slots withdraws the values at once, until a set passes again. A slot from an earlier
  set never counts: each set resets every slot first (`R10:obs/capture.rs:1261`), and the view is replaced wholesale
  (`R10:obs/capture.rs:1333`). R10 runs a set synchronously in the epoch (`R10:obs/observe.rs:38-40`), so no answer sees
  a half-run set. An Expired view (`R10:obs/observe.rs:490-499`) is presented as a set whose slots are `EXPIRED`.
- **The sampling window.** A host change is seen only at the next capture set, within the 90 s bound above; T04 and
  HE-005 cover persistent state only.
- **The port.** R10 records the scheduled start beside the slots in its capture view and hands the view to the I01
  service, which today receives only the wall time and `now` (`R10:obs/client.rs:270-283`). The answer's wall time is
  a millisecond reading of the same wall clock as `set_started_ms`, handed to the I01 service with the view.
- **The capture verdicts as data** (the model's input, `definitions.json` `captureGate.dataShape`):

  ```
  {sets: [{scheduledMonotonicMs, startedWallMs, completed, slots: {<slot>: "TAKEN" | <other>}}],
   answer: {monotonicMs, wallMs}}
  ```

  Every number is an integer in 0..2^53 - 1. The latest completed set is the last entry of `sets` whose `completed` is
  true. The slots are `role/SERVER`, `role/OBSERVER`, `role/BROKER`, `role/WORKER`, `role/EFFECT_GATE`, `lifecycle` and
  `backend/<component>` for each of the record's `backendComponents`.
- **Refusal texts:** each gated value's own text (sections 4.6, 5.3, 5.4) when there is no completed set or a required
  slot is not `TAKEN`, and "<key>: capture set too old" when either age is outside 0..90 s.

### 3.4 Malformed input

An input of the wrong shape for a key (a served object without its `metadata` members, a missing configuration value,
malformed capture data) refuses "<key>: malformed input". B1's own malformed-object refusals have their own texts
(section 4.5).

### 3.5 Comparison with the signed binding

Each projection's identity `{apiVersion, kind, name, namespace, uid, projectionDigest}` must equal the binding's
(`HO:VPO:96-108`), and each enforcement digest the binding's `enforcementPins` member. A value that differs refuses:
"<key>: differs from the signed value". Nothing is echoed: the contract adds no echo, and the identity members are
never read from the binding.

## 4. The seven projections

| Key | Fixed identity | Source | Document `spec` |
|---|---|---|---|
| `admissionPolicy` | `admissionregistration.k8s.io/v1` ValidatingAdmissionPolicy `admissionpolicy`, namespace null | **Synthetic**: the four sealed values, rendered, and the qualification Namespace's Pod Security labels | section 4.1 |
| `resourceQuota` | `v1` ResourceQuota, the live name and namespace | the ResourceQuotas list (`R10:obs/inputs.rs:104`) | the served `spec` |
| `limitRange` | `v1` LimitRange, the live name and namespace | the LimitRanges list (`R10:obs/inputs.rs:102`) | the served `spec` |
| `serviceAccount` | `v1` ServiceAccount, the live name and namespace | the ServiceAccounts list (`R10:obs/inputs.rs:105`) | section 3.1's top-level keys |
| `rbac` | `planeon.internal/v1` EffectiveRbac `rbac`, the qualification namespace | **Synthetic**, from the four RBAC lists and the ServiceAccounts list | section 4.5 |
| `networkPolicy` | `networking.k8s.io/v1` NetworkPolicy, the live name and namespace | the NetworkPolicies list (`R10:obs/inputs.rs:106`) | the served `spec`, selector-free (section 4.4) |
| `mutationBroker` | `planeon.internal/v1` MutationBroker `mutationbroker`, the qualification namespace | **Synthetic**, from the enrolled v4 record's BROKER row, under the capture gate | section 4.6 |

### 4.1 `admissionPolicy`

- **Input:** the four sealed values admission v3's `a2_objects` reads (`HO:AS3M:441-474`): `namespace` (the
  configuration's `qualificationNamespace`), `ipFamily`, `serviceCIDR` and `defaultTolerationSeconds` (the three values
  the configuration successor must carry, signed by HE-008). They are exact values (section 3.2).
- **Rendering, bound to the loaded hash.** The model renders the eight objects with `a2_objects` and the directory's one
  file with `manifest_file_bytes` under the fixed file name `planeon-a2.json`
  (`HO:architecture/admission-semantics-v3/admission-manifests/planeon-a2.json`). It computes
  `manifest_directory_hash({"planeon-a2.json": bytes})` and requires it to equal **both** the signed
  `pinnedManifestHash` and ADM-4's loaded hash. Otherwise "admissionPolicy: rendered hash differs". The document exists
  only after both equalities hold, so its objects are exactly the bytes the apiserver loaded. The observer renders; it
  does not read the directory.
- **Unknown admission objects refuse,** over (kind, name): every listed ValidatingAdmissionPolicy must carry one of the
  four rendered policy names, and every listed ValidatingAdmissionPolicyBinding one of the four rendered binding names
  (`R10:obs/inputs.rs:132-137`). Otherwise "admissionPolicy: unknown admission object". Nothing rests on the apiserver
  reserving the `.static.k8s.io` suffix. The A2 guard denies every API write of an admission object
  (`HO:AS3M:459-468`), so such an object predates the guard. This is OR06's rule (`R10:obs/operational.rs:144-153`) with
  the eight rendered (kind, name) pairs allowed. A listed object with a rendered (kind, name) is not compared with the
  rendered object; it falls under R-ADM-LIST's suffix check (section 8).
- **The qualification Namespace** must be listed exactly once (`R10:obs/inputs.rs:103`), else "admissionPolicy:
  qualification namespace not listed".
- **The document:** `{apiVersion: "admissionregistration.k8s.io/v1", kind: "ValidatingAdmissionPolicy", metadata: {name:
  "admissionpolicy", namespace: null, uid: <derived>}, spec: {sealedObjects: [...], podSecurityLabels: {...}}}`:
  - `sealedObjects`: the eight rendered objects, four policies and four bindings, sorted by `(kind, metadata.name)`;
  - `podSecurityLabels`: the qualification Namespace's labels whose key starts with `pod-security.kubernetes.io/`, as an
    object; `{}` when there are none. These labels can override PodSecurity's configured level for the namespace:
    PodSecurity is an enabled plugin (`HO:architecture/admission-semantics-v3/allowlists.json:704`), and I06 v2 N6 asks
    for at least baseline in every namespace (`HO:docs/alpha-2/I06_BACKEND_PROFILE_V2.md:58`). HE-008 captures them at
    enrollment, so a change refuses through the digest.
- **Other namespaces' Pod Security labels are outside the I01 binding:** they govern only those namespaces' pods, under
  I06 v2 N6, carried to W02f and W02e.
- **Residuals:** R-ADM-LIST and R-PSA-CONFIG (section 8).

### 4.2 One object of a kind (`resourceQuota`, `limitRange`, `networkPolicy`)

Two checks, each with its own refusal:

- the count of the kind's objects in the qualification namespace is exactly 1, else "<key>: count is not one";
- that object's name equals the name the binding gives, else "<key>: name differs from the binding".

This matches the profile's exactly-one references for ResourceQuota and LimitRange (`HO:VPC:159-163`).
**networkPolicy is one object in v1.** The only NetworkPolicy form in I07 v3's vectors is the default-deny form
`{podSelector: {}, policyTypes: ["Ingress", "Egress"]}` (writer vector K19:
`HO:architecture/i07-policy-write-v3/vectors.json`, `kindChecks[18]`; the same spec in `kindChecks[19]` and
`renderChecks[4]`). A release that needs several NetworkPolicies takes the List form for `networkPolicy` alone, through
a contract revision. The document is the served object in section 3.1's form.

### 4.3 `serviceAccount`

The profile's subject's ServiceAccount (`HO:VPC:164-165`): the subject `system:serviceaccount:<namespace>:<name>`
names one object in the qualification namespace. The count of objects by that name is exactly 1, else
"serviceAccount: count is not one", and the name equals the binding's, else "serviceAccount: name differs from the
binding". Its `spec` holds the three top-level keys (section 3.1). If it carries the annotation
`kubernetes.io/enforce-mountable-secrets`, the projection refuses: "serviceAccount: enforce-mountable-secrets
annotation". No harness-onion file names that annotation, so the release never sets it.

### 4.4 `networkPolicy`'s form

v1 admits only selector-free NetworkPolicies, whose meaning does not depend on any label:

- `spec.podSelector` is exactly `{}` (it selects every pod in the namespace, whatever its labels);
- every peer in `spec.ingress[].from` and `spec.egress[].to` has `ipBlock` and no other member;
- every `port` in `spec.ingress[].ports` and `spec.egress[].ports` is an integer: a named (string) port resolves against
  pod container port names, so it refuses, and a port written as a string of digits is a string. A ports entry with no
  `port` (all ports) is admitted, and an integer `endPort` is admitted;
- only the members of the NetworkPolicy v1 API occur: `spec` = `{podSelector, policyTypes, ingress, egress}`, a rule =
  `{from | to, ports}`, a port = `{protocol, port, endPort}`;
- anything else refuses: "networkPolicy: selector form outside v1". That covers a non-empty `podSelector`, any
  `namespaceSelector` or `podSelector` peer, and a named port.

So relabelling a namespace or a pod cannot widen what the document allows, and no label residual is needed. An
`ipBlock` that overlaps the pod or Service ranges has implementation-defined pod-IP behaviour; R-NET-DATAPATH's T04
ruleset check covers it, and v1's bound policy is the default-deny form with no rules, so any added rule changes the
digest.

### 4.5 `rbac`

- **B1's refusals first.** Before computing either RBAC document (`rbac` and section 5.2's closure), the model refuses
  exactly where R10's B1 producer refuses (`R10:obs/rbac.rs`), in B1's order (ClusterRoles, Roles, ServiceAccounts,
  binding metadata, then the bindings sorted, each: roleRef, subjects, role resolution, aggregation, loopback):

  | Refusal | Rule | `R10:obs/rbac.rs` |
  |---|---|---|
  | "rbac: malformed subject namespace" | a ClusterRoleBinding ServiceAccount subject without a namespace (an empty namespace is absent) | :207, :212-214 |
  | "rbac: malformed subject kind" | a subject kind other than User, Group or ServiceAccount | :192-197 |
  | "rbac: malformed roleRef apiGroup" / "rbac: malformed roleRef kind" | a roleRef outside the RBAC group, or a ClusterRoleBinding naming a Role | :225-240 |
  | "rbac: role does not exist" | a dangling roleRef | :313-315 |
  | "rbac: malformed rule (non-resource URLs beside resources)" | a rule with nonResourceURLs beside resources | :141-143 |
  | "rbac: loopback user bound to a non-resource rule" | a non-resource rule bound directly to User `system:apiserver` | :319-322 |
  | "rbac: aggregated role reaches the namespace" | an aggregated ClusterRole bound by a RoleBinding in the qualification namespace or by any ClusterRoleBinding (OR03) | :316 |
  | "rbac: malformed <field>" | any other malformed object (`metadata`, `rules`, `rule`, `rule list`, `subjects`, `subject`, `subject name`, `roleRef`, `roleRef name`) | :109-147, :178-241, :258-292 |

  These refusals withhold both RBAC values.
- **A non-resource rule** is, as in B1, a rule with a non-empty `nonResourceURLs` list (`R10:obs/rbac.rs:133`, `:139`).
- **The subject key** is B1's (`R10:obs/rbac.rs:202-219`): a ServiceAccount subject is named
  `system:serviceaccount:<namespace>:<name>`, and a RoleBinding's ServiceAccount subject without a namespace takes the
  binding's. So `(kind, name)` is a total key, and same-named ServiceAccounts in two namespaces stay two subjects.
- **The subject set:** every subject of each RoleBinding in the qualification namespace, plus every subject of every
  ClusterRoleBinding, which OR03 treats as reaching every namespace (`R10:obs/rbac.rs:316`). Sorted by `(kind, name)`,
  one entry each.
- **Each subject's rules:** its effective rules in B1's rule shape `{apiGroups, resources, verbs, resourceNames, scope}`
  (`R10:obs/rbac.rs:153-161`), plus its non-resource rules as `{nonResourceURLs, verbs, scope}` entries. B1 drops these
  (`R10:obs/rbac.rs:5-7`, `:331-333`), so this document is the contract's own shape, not B1's snapshot.
  - A rule takes its binding's scope (`R10:obs/rbac.rs:323`): `CLUSTER` through a ClusterRoleBinding, the binding's
    namespace through a RoleBinding. Non-resource entries too: nothing rests on the authorizer ignoring non-resource
    rules granted through a RoleBinding.
  - `rbac` keeps the rules whose scope is the qualification namespace or `CLUSTER`; section 5.2's closure keeps all.
  - The rules are sorted and deduplicated by canonical bytes.
- **The entry** is `{kind, name, exists, effectiveRules}` in both RBAC documents. `exists` is B1's
  (`R10:obs/rbac.rs:272-278`, `:325-328`): true for User and Group; for a ServiceAccount, whether that ServiceAccount is
  listed.
- **The document's `spec`** is `{subjects: [<entry>, ...]}`, with no `schemaVersion`.
- The harness-onion reference model computes it, which closes "no harness-onion model computes effective RBAC"
  (`R10:obs/rbac.rs:1-3`).
- **Residual R-RBAC-COMPLETE** (section 8).

### 4.6 `mutationBroker`

- **First check: the v4 record's BROKER row carries what the document needs.** `$defs.roles.properties.BROKER` requires
  20 members: `executable`, `executableLabel`, `artifactDigest`, `interpreterPath`, `interpreterLabel`, `uid`, `gid`,
  `processLabel`, `namespaceInodes`, `cgroup`, `seccompMode`, `seccompDefaultAction`, `seccompFilterDigest`,
  `noNewPrivs`, `rlimitCore`, `capabilities`, `filePaths`, `bpfPrograms`, `listenEndpointIds` and
  `outboundEndpointIds`; `cgroup` requires 7. A row without exactly those refuses: "mutationBroker: broker row
  incomplete".
- **The document's `spec`** is these 14 members of the row: `executable`, `executableLabel`, `artifactDigest`, `uid`,
  `gid`, `processLabel`, `cgroup` without its `inode` (so `path`, `memoryMaxBytes`, `pidsMax`, `cpuQuotaMicros`,
  `cpuPeriodMicros` and `selinuxLabel`), `seccompMode`, `seccompDefaultAction`, `seccompFilterDigest`, `noNewPrivs`,
  `capabilities`, `listenEndpointIds` and `outboundEndpointIds`.
  - Left out because they change when the cgroup or the namespaces are recreated: `namespaceInodes` and `cgroup.inode`
    (the inode is OBSERVED per capture, `HO:NP4R:154`).
  - Left out because the schema fixes them as `null` for BROKER: `interpreterPath` and `interpreterLabel`.
  - Left out because section 5.4's record digest covers them: `rlimitCore`, `filePaths` and `bpfPrograms`.
- **The capture gate** (section 3.3): the document is in an answer only while the latest completed set's BROKER role
  capture has passed `check_capture` against the record (slot `role/BROKER` `TAKEN`; in R10, `Taken` in a `Current`
  view, `R10:obs/capture.rs:219-270`). Otherwise "mutationBroker: broker capture not passed", or "mutationBroker:
  capture set too old".
- **It never derives from the broker binding,** which pins the observation binding (`HO:BH:76-86`), so that would be a
  cycle. A value derived from the broker binding differs from the signed value and refuses.
- **Residual R-BROKER-LIVE** (section 8).

## 5. The four enforcement digests

### 5.1 `admissionFenceDigest`

The `manifest_directory_hash` of section 4.1 over the rendered bytes (`HO:AS3M:481-490`; `HO:AS3:208-213`), already in
`sha256:<hex>` form. It exists only after section 4.1's two equalities hold (else "admissionPolicy: rendered hash
differs"). It is not the ADM-4 record's digest, which is bound to its window.

### 5.2 `rbacClosureDigest`

- The digest of the canonical cluster-wide closure value
  `{schemaVersion: "planeon.internal.policy-observation-rbac-closure/v1", subjects: [<entry>, ...]}`:
  - every subject named by any RoleBinding or ClusterRoleBinding in the cluster, keyed as in section 4.5; an unbound
    ServiceAccount is not a subject;
  - each entry is section 4.5's `{kind, name, exists, effectiveRules}`, with all of the subject's rules at every scope,
    non-resource entries included with their binding's scope, sorted and deduplicated;
  - the subjects sorted by `(kind, name)`.
- It exists only after B1's refusals (section 4.5) and after I06's closure check and I06 v4's role pin both pass
  (`R10:obs/observe.rs:966-991`): the model runs `i06_backend_profile_v4.check_observer_snapshot` over B1's snapshot of
  the same lists (B1's shape, non-resource rules dropped) and the same read's ClusterRoles, ClusterRoleBindings and
  RoleBindings, with I06 v1's frozen closure inputs. Otherwise "rbacClosureDigest: I06 closure check not passed". Those
  checks are unchanged. The order: the closure first refuses a missing or ill-shaped qualification namespace with its
  own text, "rbacClosureDigest: malformed input"; then it refuses with rbac's texts, including "rbac: malformed input",
  and B1's (section 4.5); then it checks the `i06` input and runs the I06 checks.
- **The `i06` input.** I06 v1's frozen closure inputs are a caller-supplied argument `i06` = `{closure, inventory,
  bootstrap}`: the three files of `definitions.json` `frozenInputs` (`architecture/i06-backend-profile/identity-closure.json`,
  `writer-inventory.json` and `upstream-bootstrap-rbac-v1.37.1.json`), each parsed as JSON and pinned by path and
  sha256. A missing `i06`, or one without exactly those three members, refuses "rbacClosureDigest: malformed input"
  (section 3.4).
- HE-008's expected value comes from the sealed cluster at enrollment, so a closure-conformant change shows up as a
  digest mismatch. Residual R-RBAC-COMPLETE.

### 5.3 `networkEnforcementDigest`

- The digest of `canonical({networkPolicies: [...], agent: {executable, executableLabel, artifactDigest, processLabel,
  apiIdentities}})`:
  - `networkPolicies`: the qualification namespace's NetworkPolicy documents in section 3.1's form, each selector-free
    (section 4.4), sorted by canonical bytes; in v1 exactly one (section 4.2: "networkPolicy: count is not one",
    "networkPolicy: selector form outside v1"). This part refuses with networkPolicy's texts, including
    "networkPolicy: malformed input" and networkPolicy's exactness texts (section 3.2);
  - `agent`: from the enrolled v4 record's `backendComponents.NETWORK_POLICY_AGENT`, which carries those members,
    `cgroupPath` and `filePaths`, and no sealed flags.
- **The agent must exist.** The v4 schema requires only six backend components (`R10:obs/record_check.rs:43`). If
  `backendComponents.NETWORK_POLICY_AGENT`, or its member of `backendProfile.componentKeys`, is absent:
  "networkEnforcementDigest: no network policy agent". The document does not rely on SERVICE_PROXY.
- **The capture gate** (section 3.3): the network document and the digest are in an answer only while the latest
  completed set's NETWORK_POLICY_AGENT backend capture has passed `check_backend_capture` (slot
  `backend/NETWORK_POLICY_AGENT` `TAKEN`). Otherwise "networkEnforcementDigest: agent capture not passed", or
  "networkEnforcementDigest: capture set too old".
- The agent's `executableLabel`, `artifactDigest` and `apiIdentities` stay in the document, so it binds the release's
  agent identity. Residuals R-NET-AGENT and R-NET-DATAPATH (section 8).

### 5.4 `hostPreflightDigest`

- `"sha256:"` and the sha256 of the enrolled `native-qualification/v4` record's canonical bytes, the same value as
  configuration v2's `qualificationRecord.sha256` (`R10:obs/config.rs:20-27`). The record is an exact value
  (section 3.2).
- **The capture gate** (section 3.3): it is in an answer only while the latest completed set has passed against the
  record: every role capture (`check_capture`), the lifecycle capture (`check_lifecycle_capture`) and every backend
  capture (`check_backend_capture`), within the record's window; every slot `role/<ROLE>`, `lifecycle` and
  `backend/<component>` of the record is `TAKEN` (`R10:obs/capture.rs:219-270`). Otherwise "hostPreflightDigest:
  capture set not passed", or "hostPreflightDigest: capture set too old". So the value is never taken from configuration
  alone (`HO:RD:125-127`).
- **Succession:** NQ's definition (`HO:NQ:62-64`) names the v1 profile's record; for I01 under native-profile v4 the
  record is the v4 one. The hashing rule is unchanged.

## 6. The binding, the expected values, the readers and the lifecycle

- **Who computes.** HE-008 computes every expected value at enrollment from the sealed cluster with this contract's
  reference model: the seven projection identities and digests and the four enforcement pins. It signs them into the
  observer configuration successor that I01b defines, which also carries the three sealed admission values of section
  4.1 (`ipFamily`, `serviceCIDR`, `defaultTolerationSeconds`). The observer recomputes every value from live state at
  each snapshot, gates the three capture-gated values at every answer, and refuses a value that differs. Nothing is
  echoed (`HO:RD:125-127`).
- **The readers:**
  - the release author, who renders the seven `proxy-policy/<field>.json` files (section 7);
  - the capacity signer, whose preexisting references' `observedDigest` must equal the projection digest
    (`HO:VPO:100-106`, `HO:VPC:159-165`);
  - HE-008, which computes and signs the expected values;
  - the observer (R10's HE-004-I01B), which recomputes them.
- **The lifecycle.** Every value is computed from the sealed cluster after the policy objects exist, so the real
  objects' uids are known. The release's `proxy-policy/<field>.json` files, the capacity references and HE-008's signed
  values are all rendered from that one capture, with this model, so they hold the same bytes. An I07 write to a policy
  object during an active binding changes a live projection, and the observer refuses until new signed values exist.
- **No cycles:**
  - the mutationBroker document never reads the broker binding (section 4.6);
  - the release's and the binding's own digests are not inputs to any document;
  - the v4 record pins the profile digest (`record.profileDigest`; `HO:NQ:69-71`), and the profile's
    `mutationBrokerDigest` comes from the record's BROKER row. There is no byte cycle because the document holds nothing
    derived from the profile. The order is **capture, then profile, then record**. The binding refers to both the
    record and the profile, and neither refers back.
- **The generation.** This contract records only the rules it relies on: `policyGeneration` equals the observation's
  generation (`HO:VPO:129-130`); it is preserved along a chain (`HO:VPO:122-124`); changing effective controls
  invalidates it (`HO:RD:143-145`). Its format and signer are I01b's, including the 64-hex form against R10's store-name
  form.

## 7. Supersession table

| Pinned text | For I01 under this contract | Unchanged |
|---|---|---|
| RD's producer inputs: "independently loads the same dual-signed release and capacity" (`HO:RD:92-95`) | R10's observer reads the binding and expected values from the HE-008-signed configuration successor. HE-008 verifies the release and capacity at enrollment. | The release and its binding file stay as RD states, and HE-008's values must equal the release's binding. |
| RD's binding route (`HO:RD:75-83`) | The configuration successor carries a copy of the release-listed binding, signed by HE-008. | The binding's members and canonical digest (`HO:VPO:110-111`). |
| NQ's `hostPreflightDigest` record (`HO:NQ:62-64`) | The native-profile v4 record, emitted under section 5.4's capture gate. | The hashing rule. |
| PCR's projection form (`HO:PCR:82-87`) | Refined by section 3: the contract's fixed identities, the no-`spec` kind, synthetic uids, the sorted sets, the integer bound. | The five-member form. |
| PCR's release-listed projection files (`HO:PCR:87-90`): `campaigns/platform/linux-baseline/proxy-policy/<field>.json`, each pinned by its `<field>Digest` | Each file is exactly `canonical(document)` for its key, with no trailing newline, rendered with this model from the sealed cluster (section 6). The release author renders the three synthetic ones the same way. | The seven paths and the `<field>Digest` pins. |

## 8. Residuals, each with its T04 check or owner

| Id | What the observer cannot see | Check |
|---|---|---|
| R-ADM-LIST | Whether the static admission objects appear in API lists, and with what uid and content; whether the apiserver refuses an API object named with the `.static.k8s.io` suffix. A listed object with a rendered (kind, name) rests on this check. | T04 (owner) |
| R-PSA-CONFIG | PodSecurity's configured defaults and exemptions (usernames, runtimeClasses, namespaces) in the sealed admission configuration file (SC05, `--admission-control-config-file`, `HO:architecture/backend-distribution/selection.json`); with no Pod Security label on the namespace, its level is exactly that default | T04: the running PodSecurity configuration equals the enrolled file's, the record's APISERVER `backendFiles` row for the SC05 file |
| R-NET-DATAPATH | The live network datapath, including pod-IP behaviour for an `ipBlock` that overlaps the pod or Service ranges, and the running agent's flags against the sealed `--fail-open=false` and `--disable-nri` (`HO:BD:55`) | T04 (owner): the agent's programmed nftables ruleset enforces the namespace's NetworkPolicy; the flags are the sealed ones |
| R-NET-AGENT | The network agent's `executableLabel`, `artifactDigest` and `apiIdentities`, which its backend capture does not compare (`R10:obs/capture_check.rs:613-635`), and its running image (ENTRY_BOUND: domain entry plus the measured file, not the running image; `HO:NP4R:137-139`, `:253-258`). Custody link: `check_record` requires `artifactDigest` to equal the sha256 of the executable's `backendFiles` row (`R10:obs/record_check.rs:915`, `:592-594`), and each set compares the live file's `contentDigest` and verity with that row (`R10:obs/capture_check.rs:630-634`), so the `artifactDigest` check concerns only the running image. | T04-LABELS for `executableLabel`; T04: the running agent's executable content equals the record's `artifactDigest`; T04: the running agent's apiserver identities equal the record's `apiIdentities`; T04-ENTRYPOINT, T04-ENTRYPOINT-CENSUS and the matrix successor's `execute_no_trans` closure for the running image |
| R-DEFAULTS | Server defaulting of the real kinds' `spec` | T04, per kind (ResourceQuota, LimitRange, ServiceAccount, NetworkPolicy): the `spec` HE-008 captured at enrollment equals the `spec` served after an apiserver restart on v1.37.1 |
| R-RBAC-COMPLETE | Completeness by refusal, not expansion: RD's and BH's bar (aggregations, impersonation paths, indirect grants; `HO:RD:145-147`, `HO:BH:134-138`) is met by refusing any aggregated role that reaches the namespace and any impersonation grant outside the closure (I06 IC01/IC03); the `system:authenticated` limit (`HO:I4R:149-156`) | T04 (carried) |
| R-BROKER-LIVE | The BROKER document members its capture does not observe (`HO:NP4R:152-158`; `R10:obs/capture_check.rs:341-398`): the process image (LABEL_BOUND: bound by `processLabel` and the enrolled file's measurement); `executableLabel` (DECLARED_T04); `seccompFilterDigest` and `seccompDefaultAction` (DECLARED_T04, corroborated by the OBSERVED filter count); the cgroup's `selinuxLabel` (DECLARED_T04); `listenEndpointIds` and `outboundEndpointIds` (no class row; not compared by `check_capture`) | T04-SECCOMP-INSTALLED for the seccomp members; T04-LABELS for `executableLabel` and the cgroup's `selinuxLabel`; T04-ENTRYPOINT and T04-ENTRYPOINT-CENSUS for the image's binding (`HO:NP4R:116-130`, `:319-320`); HE-005 and T04 for the endpoints: the broker's bound and connected endpoints equal the record's `listenEndpointIds` and `outboundEndpointIds`, resolved through the record's `endpointTuples`; HE-005 for the broker's behaviour |

Not residuals:

- **Label selection in NetworkPolicies.** v1 refuses every selector form and named ports (section 4.4), and
  `podSelector: {}` selects every pod whatever its labels, so no pod-label residual is needed.
- **Pod Security labels on other namespaces** are outside the I01 binding (section 4.1).
- **Non-resource RBAC rules.** Both RBAC documents carry them (sections 4.5, 5.2).
- **One NetworkPolicy** is a scope limit (section 1), refused, not unseen.
- **The sampling window** between capture sets is within the accepted 90 s bound (section 3.3).

## 9. Refusal texts

Every refusal text is pinned in `definitions.json` (`refusalTexts`) and occurs in the vectors. `<key>` is the projection
or digest key.

| Text | Where |
|---|---|
| "<key>: float refused", "<key>: integer out of range", "<key>: document bound exceeded" | section 3.2 |
| "<key>: malformed input" | section 3.4 |
| "<key>: capture set too old" | section 3.3 |
| "<key>: differs from the signed value" | section 3.5 |
| "admissionPolicy: rendered hash differs", "admissionPolicy: unknown admission object", "admissionPolicy: qualification namespace not listed" | sections 4.1, 5.1 |
| "<key>: count is not one", "<key>: name differs from the binding" | sections 4.2, 4.3 |
| "serviceAccount: enforce-mountable-secrets annotation" | section 4.3 |
| "networkPolicy: selector form outside v1" | sections 4.4, 5.3 |
| "rbac: aggregated role reaches the namespace", "rbac: role does not exist", "rbac: loopback user bound to a non-resource rule", "rbac: malformed <field>" | section 4.5 |
| "rbacClosureDigest: I06 closure check not passed" | section 5.2 |
| "mutationBroker: broker row incomplete", "mutationBroker: broker capture not passed" | section 4.6 |
| "networkEnforcementDigest: no network policy agent", "networkEnforcementDigest: agent capture not passed" | section 5.3 |
| "hostPreflightDigest: capture set not passed" | section 5.4 |

For `rbac` and `rbacClosureDigest`, "float refused" and "integer out of range" cannot occur: both RBAC documents hold
only B1-validated strings and booleans, so those four texts are not pinned. VPO's single external text ("invalid
protected observation data") is untouched.

## 10. Vectors

`vectors.json` (`planeon.internal.policy-observation-digests-vectors/v1`, UNIT_VERIFICATION_ONLY,
`nativeAcceptance: false`) holds:

- **helper vectors** for VPC's `canonical`, `digest` and `_bounded` as this contract uses them: exact canonical bytes
  (key order, separators, non-ASCII and escaped characters), sha256 digests, the integer bound at 2^53 - 1 and
  -(2^53 - 1) and one past each, the depth bound and the size budget at and one past their limits;
- **fixtures:** the enrolled v4 record (native-profile v4's first positive record), a small `unit` snapshot, a
  `closure` snapshot whose RBAC lists hold, one binding and one role per subject, the subjects and rules of I06 v4's
  closure-conformant snapshot positive (with the observer's exact ClusterRole and binding), the `unit` binding (PV's),
  the derived `complete` binding, and a passing capture;
- **vectors:** each `{id, case, snapshot, binding, capture, ops, expect}`, the `ops` applied to the fixtures; `expect`
  pins projection documents, canonical bytes and digests, enforcement digests (with the RBAC closure's and the network
  document where small), gate verdicts, answer refusal lists, and the digest relations (`same`, `differs`) the case
  claims;
- **one complete I01 positive**: PV's binding, request and observation and PPV's positive profile, with the three
  synthetic uids, the seven policy digests, the three preexisting references' `observedDigest` and the four enforcement
  pins replaced by values the model derives from the `closure` snapshot, the record and the passing capture, and
  `profileDigest`, `bindingDigest` and `request.bindingDigest` recomputed. It is built for VPO's `validate_messages`
  unchanged: the model re-checks the members VPO binds (`profileDigest`, each projection's identity and digest against
  the profile and its references, `bindingDigest`, the observed projections and enforcement), and VPC's
  `validate_profile` accepts its profile.
- **The layer test runs both validators on the complete positive.** The packet's layer test (tests/test_policy_observation_digests.py, as the packet YAML names it), which the pre-check and verify run, asserts, with no skip, expected-failure mark or import guard: (1) validate_messages(complete.binding, complete.request, complete.observation, complete.profile, CS, complete.now, complete.previous) == [], with validate_messages imported from scripts/validate_policy_observation.py and CS read from architecture/policy-observation-inputs/channel.schema.json; (2) validate_profile(complete.profile, PPS) == [], with validate_profile imported from scripts/validate_proxy_contract.py and PPS read from architecture/proxy-contract-inputs/profile.schema.json; (3) each returns its refusal when one preexisting reference's observedDigest in complete.profile is changed. The model does not import VPO; these assertions are the only executable check that the complete positive fits the I01 wire, and a layer run that does not execute them fails.

The model replays every vector: `python3 -I -B scripts/policy_observation_digests.py` prints one summary line.

## 11. Reader duties

- **HE-004-I01B (R10) ports the model:** it builds the seven documents and four digests from one snapshot before
  dropping the lists; it records each capture set's own scheduled start (monotonic) beside the slots and checks the
  capture gate at every answer, against the latest completed set, the 90 s bound and the wall age; it compares the
  values with the configuration successor's signed values; it replays this contract's vectors and PV's binding and
  observation cases (with the registered PPV); and it carries the required I01Binding pin and the R1-1 send-path
  hardening.
- **The packet's layer test** (`tests/test_policy_observation_digests.py`), which the pre-check and verify run, executes
  section 10's three assertions on the complete positive (VPO's `validate_messages`, VPC's `validate_profile`, and each
  one's refusal when one preexisting reference's `observedDigest` changes), with no skip, expected-failure mark or
  import guard. A layer run that does not execute them fails.
- **HE-008** computes and signs the expected values and the three sealed admission values, and provisions the
  configuration successor.
- **The release author and the capacity signer** render and reference the projection files with this model.
- **T04** holds the checks of section 8.
