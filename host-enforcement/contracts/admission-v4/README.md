# POLICY-ADMISSION-SEMANTICS/v4 and A2 admission field allowlists — LPK-1 contract (DATA_CHECK_ONLY)

Alpha 2; 2026-10-24. Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW** (candidate c2; one combined
LPK-1 review, series `MET-LIVE-004/contract`, with `../proxy-profile-v2/`; source index in
`../linux-probe-kit-admission/`). This status line is the candidate line the README is reviewed with; `status.json`
governs.

v4 is the LPK-1 (LINUX-PROBE-KIT-ADMISSION, packet MET-LIVE-004) successor of the adopted contract
`../admission-semantics-v3/` (POLICY-ADMISSION-SEMANTICS/v3, ADOPTED_DATA_CONTRACT, MET-ENFORCE-015). Later layers pin
the v3 bytes (its authority, I01's digest contract, the compiled-filter and W03-plan validators, edge records v4-v10),
so v3 stays byte-identical and v4 is published beside it. The v3 README still reads
CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW; v3's `status.json` governs v3 (ADOPTED_DATA_CONTRACT), and the v3
README is not edited.

v4 is v3's model, rules and vectors with exactly these changes: every image is pulled `Never`; AlwaysPullImages is
pinned off, and an enabled plugin fails closed in A2; every emptyDir is bounded; a v3 claim is refused; and the sealed A2
set is re-rendered. Everything else is carried unchanged in meaning, and the rule table below lists every rule as KEPT,
CHANGED or NEW. Nothing here contacts an apiserver, compiles CEL, installs an admission configuration or grants
anything; all E01-E12 stay OPEN_UNPROVEN.

Decisions: the owner's Q-PK-3, "Never, pinned (Recommended)" (an admission successor requiring imagePullPolicy Never,
with AlwaysPullImages pinned off; the sealed bytes change only at a maintenance boot), Q-PK-4, "Upstream v1.37.1
(Recommended)", and "As steps (Recommended)" for the install path; the lane monitor's Q-LPK1-1 to Q-LPK1-12 and
Q-LPK1-D1 to Q-LPK1-D5. The design was adopted at rev 4 (MON-LPK1-ADOPT-REV4). Base: harness-onion main
`0ffa7db076a92e8bb341db4867557b894ecb5b27`.

## What v4 changes

| Change | v4 rule | Vectors |
|---|---|---|
| Pull policy at the signer | MC33 becomes "every image pinned by digest with `imagePullPolicy: Never`", text "MC33 every image is pinned by digest and pulled Never". The digest pattern is v3's. An omitted policy is refused, so pull-policy defaulting never applies. | N15, N16 (text), N37 (`Always`), N38 (omitted) |
| Pull policy in A2 | The rendered A2-POD-PULL-POLICY requires `'Never'` on every container and init container; its reference reading refuses "an image pull policy other than Never". | U04 (text), U06, F24, F25 |
| AlwaysPullImages pinned off | `final_object` keeps modelling the plugin's rewrite to `Always` for containers, init containers and image volumes. The pin is not a refusal inside `final_object`: v4's vectors carry `"alwaysPullImages": false` in the `server` block, and vectors that set it `true` show what happens if the pin drifts. The pin's refusal is claim evidence only: an A2 claim needs `alwaysPullImagesDisabled: true` (C28, checked right after C22). | E08 (replaced), U05 (intent annotated), Q23, Q24 |
| emptyDir bounds at the signer | MC42, new, after MC41 and before MC37 (below). | N39-N47, E15 |
| emptyDir in A2 | A2-POD-EMPTYDIR, new, last in the Pod policy (below). | F20-F23, U07, U08, S06c, S06d |
| Claims | C01 now says "cite POLICY-ADMISSION-SEMANTICS/v4 checks" and C03 "cite v4"; a v3 claim is refused with C04; an A2 claim needs C22, C28 and the v4 directory hash (C21); Q16 uses `…/v5` as the unknown version. | Q01-Q26 |
| The sealed directory | A new `admission-manifests/planeon-a2.json`, rendered by v4's model from the same four sealed values: 8322 bytes, sha256 `92c21612304cb704d13b506c1ae885d62a47c01f0ed0d284affe563aa1868e32`, directory hash `sha256:9b1ddc1096ff0d35fb4cd5a9e5e6b4248fefc5b75b5a06f862c59d85e028ca60` (v3's is `sha256:5aa2cdec0b8dc08c008b887e30b9954ffc46e7d779365f64db1adfd80656f189`). | H01-H04 |

## MC42, every emptyDir is bounded

MC42 applies to every v4 Pod manifest, not only profile v2 Pods. It comes after MC41 and before MC37, so MC37 stays
last. It acts only if the Pod has at least one volume with an `emptyDir` member; a Pod without an emptyDir is not
touched, and neither is its quantity form. The quantity form is the profile's decimal byte form,
`^[1-9][0-9]{0,14}$`, for every `sizeLimit` and, in a Pod with an emptyDir, for every `ephemeral-storage` limit. Binary
or decimal suffixes, exponents, milli units, zero and leading zeros are refused, so no rounding rule is needed.
This pattern, like every pattern v4 applies (those carried from v3 included), is read as the pinned G-JSONSCHEMA
bundle reads a schema `pattern`: by Python's `re` (`re.search` in the bundle, `re.match` here, with the same `^...$`
anchors), where `$` also matches before one trailing line feed. So `536870912` followed by one line feed passes it,
as a `sizeLimit` or a limit, and so does a name such as `probe-pod` followed by one. Admission v4, profile v2 and the
bundle read their patterns the same way, so profile v2 is never wider than v4; the apiserver's own quantity and name
validation refuses such a string (a reading of upstream, not verified at v1.37.1).

The refusal text is `MC42 every emptyDir is bounded: ` followed by the reason of the first check that fails:
1. for each emptyDir in volume order, a `sizeLimit` in decimal bytes ("a sizeLimit in decimal bytes"; an `emptyDir` that
   is not an object fails here too);
2. that emptyDir has no `medium` member, not even `""` ("no medium");
3. every container and every init container has an `ephemeral-storage` limit in decimal bytes ("an ephemeral-storage
   limit in decimal bytes on every container and init container"). MC34 (requests equal limits) runs earlier, so the
   request is present and equal too. A container or init container whose `resources` or `limits` is not an object
   has no such limit and fails this check. A `resources` that is empty or null is refused earlier by MC34, which v4
   carries from v3 unchanged; any other `resources` that is not an object makes that carried MC34 check raise an
   error instead of refusing (as in v3), so it never reaches this check;
4. the sum of the `sizeLimit`s is at most the sum of the containers' (`spec.containers`) `ephemeral-storage` limits
   ("the sizeLimits sum to at most the containers' ephemeral-storage limits").

Checks 1 and 2 run per emptyDir, in volume order: the first emptyDir takes check 1 and then check 2, and then the next
emptyDir does. Checks 3 and 4 run once, after every emptyDir has passed checks 1 and 2. N47 pins this order: two
emptyDirs, the first with `medium: Memory` and the second without a `sizeLimit`, refuse with "no medium".

Init containers must carry a limit (check 3), because they can write to the same emptyDir and an unlimited container
is unbounded on the node's disk. Their limits do not count toward the sum (check 4). Author's reading of upstream, not
verified at v1.37.1 and listed in `allowlists.json` `unverified`: the kubelet's Pod-level ephemeral-storage limit is the
larger of the containers' summed limits and the largest init container's limit, so the containers' sum never exceeds
it, and an emptyDir over its own `sizeLimit` is evicted on its own. The rule does not depend on that reading: MC42
checks a declared budget, not an eviction outcome.

Coverage (`constraintCoverage.MC42`): RECHECKED_BY_A2 A2-POD-EMPTYDIR for "sizeLimit present, medium absent";
SIGNER_GUARANTEED for the decimal forms, the ephemeral-storage limits and the sum. A2 compares no quantities, and the
apiserver re-emits quantities in canonical form.

The v3 positives PodInit and PodEnv carried `emptyDir: {}` and no ephemeral-storage limit. In v4 the `probe` container
gets `ephemeral-storage: "1073741824"` in limits and requests, PodInit's `setup` init container gets `"268435456"`, and
the `scratch` volume becomes `emptyDir: {"sizeLimit": "536870912"}`. The values are powers of two, so their canonical
re-emission is the same string (author's reading of `quantity.go`), and `final_object` needs no new re-emission rule.

## A2-POD-EMPTYDIR

The rendered expression is exactly:

`!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.emptyDir) || (has(v.emptyDir.sizeLimit) && !has(v.emptyDir.medium)))`

It is guarded: no runtime error on a Pod without volumes (E01, F20) or on a configMap, secret, downwardAPI or projected
volume (E14, F21). Unguarded, failurePolicy Fail would deny those Pods (S06d keeps that rendering out). It is last in the
Pod policy, after A2-POD-PULL-POLICY, so it comes after A2-POD-ECHO, and F03 (an injected `emptyDir: {}`) still refuses
with A2-POD-ECHO. Its message is `A2-POD-EMPTYDIR`, and its reference reading refuses "an emptyDir without a sizeLimit
or with a medium". The Pod policy's order is A2-RESERVED, A2-POD-ECHO, A2-POD-TOKEN, A2-POD-PULL-SECRETS,
A2-POD-IMAGE-VOLUME, A2-POD-TOLERATIONS, A2-POD-PRIORITY, A2-POD-PLACEMENT, A2-POD-PULL-POLICY, A2-POD-EMPTYDIR.

## AlwaysPullImages, pinned off

- **The model.** `final_object` keeps modelling the plugin's rewrite to `Always`, unchanged from v3, so the end-to-end
  vectors can show A2 failing closed. The pinned value is data: v4's `server` block carries `"alwaysPullImages": false`.
- **A2.** A2 requires `Never`, so an enabled plugin's rewrite to `Always` fails closed there. E08 is replaced:
  "AlwaysPullImages enabled despite the pin: it rewrites Never to Always, and A2 fails closed", expecting
  `A2-POD-PULL-POLICY an image pull policy other than Never`. Its final object is byte-equal to v3's E08 final object.
  If upstream's plugin also validates (its Validate path, `admission.go:173-178`), it refuses the same Pod; either way
  the Pod is refused. That last point is an author's reading, listed in `unverified`.
- **The named refusal.** The pin's refusal is claim evidence only. A v4 A2 claim needs `alwaysPullImagesDisabled: true`,
  checked right after C22: C28, "A2's pull-policy argument needs AlwaysPullImages disabled on the apiserver (pinned
  off)". C22's allowlist includes AlwaysPullImages, so C22 cannot say "pinned off". There is no separate server-facts
  check: the apiserver's plugin set reaches the contract only as claim evidence, as for C22 and C27.
- **U05** keeps `alwaysPullImages: true` and its expectation, `A2-POD-IMAGE-VOLUME`; its intent gains "(pinned off by
  v4; enabled here to show the rewrite)", and its final object is byte-equal to v3's.
- **Carried obligations** (neither file is edited here): I06 SC05's successor moves AlwaysPullImages from
  `ALLOWED_ADMISSION` to `FORBIDDEN_ADMISSION`, and its criteria row adds "AlwaysPullImages disabled"; W03-0 SC05's
  successor text names AlwaysPullImages in `--disable-admission-plugins` (`--disable-admission-plugins=AlwaysPullImages`,
  one item of that comma-separated list) and never in `--enable-admission-plugins`; HE-008's sealed APISERVER_FLAGS
  file carries that flag. `status.json` `carried` lists them as steps C1 and C2.

## Every rule, KEPT, CHANGED or NEW

| Rules | In v4 |
|---|---|
| MC00, MC01, MC02, MC03, MC04, MC05, MC06, MC10, MC11, MC20, MC21, MC22, MC30, MC31, MC32, MC34, MC35, MC36, MC37, MC38, MC39, MC40, MC41 | KEPT, texts byte-identical (MC38 "(AlwaysPullImages rewrites its pull policy)" included: still true of the plugin, and kept as defence in depth, because A2-POD-PULL-POLICY covers containers only and an image volume is a download path) |
| MC33 | CHANGED: pulled `Never` |
| MC42 | NEW, after MC41 and before MC37 |
| A2-RESERVED, A2-CM-PUBLISHER, A2-CM-IMMUTABLE, A2-SVC-TYPE, A2-SVC-ALLOCATION, A2-SVC-DEFAULTS, A2-POD-ECHO, A2-POD-TOKEN, A2-POD-PULL-SECRETS, A2-POD-IMAGE-VOLUME, A2-POD-TOLERATIONS, A2-POD-PRIORITY, A2-POD-PLACEMENT, A2-GUARD | KEPT, expressions byte-identical |
| A2-POD-PULL-POLICY | CHANGED: `'Never'` |
| A2-POD-EMPTYDIR | NEW, last in the Pod policy |
| S01-S06 (`check_a2_objects`) | KEPT; S06 now compares with v4's rendering |
| C00, C02, C10, C11, C12, C20, C21, C22, C23, C24, C25, C26, C27, C30, C31, C40, C41 | KEPT (C21 compares with the v4 directory hash in `pinned`) |
| C01, C03 | CHANGED texts: "cite POLICY-ADMISSION-SEMANTICS/v4 checks" and "cite v4" |
| C04 | NEW: "a v3 claim lacks the AlwaysPullImages evidence and pins the superseded sealed directory; cite v4", for every check, as C03 is |
| C28 | NEW: the AlwaysPullImages evidence, right after C22 |
| `final_object`, `manifest_file_bytes`, `manifest_directory_hash` | KEPT (the AlwaysPullImages rewrite is still modelled) |

## Owner decision (2026-10-08)

The A2 ValidatingAdmissionPolicy objects live in a **sealed admission manifest directory** (static policies, upstream
`ManifestBasedAdmissionControlConfig`, recommended by W02g OR08), and they are **run-independent**. This amends the W01
§3.2 wording "Its policy objects are policy kinds (written only through I07)": A2 is not written through I07 at all. It
changes only in the maintenance boot (W01 §5.5 M1), with the rest of the sealed control-plane configuration (W02g SC12
lists the admission manifest directory). The alternatives were API objects written through I07 (run-independent or per
run). They were not chosen because API-registered policies take effect through a cache refreshed about every second with
no activation barrier, and they cannot guard the admission objects themselves.

## Files

| File | Content |
|---|---|
| `README.md` | This text, including POLICY-ADMISSION-SEMANTICS/v4 |
| `allowlists.json` | v3's allowlists (`planeon.internal.admission-allowlists/v2`, no member added) with the v4 values: `semantics`; `constraintCoverage` MC33 (Never), MC42 and ALWAYS_PULL_IMAGES_PINNED_OFF (a non-MC key on the precedent of DISABLED_GATE_FIELDS); the AlwaysPullImages mutator row; Pod `ALLOWED_FIXED` (the emptyDir `sizeLimit` in canonical form), `RULED_OUT_BY_MANIFEST` (AlwaysPullImages pinned off, C28) and `CHECKED_BY_A2` (A2-POD-EMPTYDIR); two changed `upstreamFields` conditions and one new row (`spec.volumes[*].emptyDir.sizeLimit`); four new `unverified` entries. The Kubernetes citations (v1.37.1, commit `f78e722310e50bcaca9276be22276d9e91d91308`, 95 files with digests) are v3's |
| `admission-manifests/planeon-a2.json` | The one file of the sealed directory: a v1 List of four static ValidatingAdmissionPolicy objects and their four bindings, canonical JSON, rendered for the vectors' sealed values. 8322 bytes, sha256 `92c21612304cb704d13b506c1ae885d62a47c01f0ed0d284affe563aa1868e32` |
| `vectors.json` | 141 cases: 47 manifest-constraint cases, 23 end-to-end cases, 30 final-object cases (25 mutations, 5 root-CA publisher cases), 11 policy-object refusals, 4 directory-hash cases, 26 semantics claims |
| `status.json` | The contract state, review rounds, non-claims, carried steps, the predecessor record and the sealed block; it governs this README's status line |
| `../../scripts/admission_semantics_v4.py` | Reference model: `check_manifest`, `final_object`, `check_final`, `a2_objects`, `check_a2_objects`, `manifest_file_bytes`, `manifest_directory_hash`, `check_claim` |

v3's model `scripts/admission_semantics_v3.py` and its five files stay byte-identical, and v3's vectors keep replaying
through it.

## POLICY-ADMISSION-SEMANTICS/v1 (pinned, not met)

`docs/alpha-2/POLICY_OBSERVATION_READINESS.md` (SHA-256
`65778040919c5eb7335f2c104d983ca920b877b1b123f961556a6bcae36d232c`), lines 139-141:

> Before committing a mutation, its immutable admission guard rechecks current namespace/UID, effective RBAC, quotas,
> network policy and actual post-mutation manifest under the broker's serialized admission transaction.

No boundary of this design meets that sentence literally: a gate outside the apiserver cannot make an upstream storage
commit atomic with unrelated policy changes (W01 §3.1). A consumer claim citing v1 is refused (`check_claim` C01), one
citing v2 is refused (C03), and one citing v3 is refused (C04): v4 asks for evidence v2 and v3 lack.

## POLICY-ADMISSION-SEMANTICS/v4

"Before committing a mutation" becomes three named checks at named positions (A1-A3), plus A4, which is kept separate
because it is explicitly weaker.

- **A1 Gate admission (pre-forward linearization point).** Under the gate's generation lock the gate verifies the current
  generation ACTIVE, scope, deadline, observed policy generation and the stamped armed action (W01 §3.2). In I05 v3 terms
  (Decisions 4-6): ACTIVE with no pending drain is the observed policy generation (I07 is the only policy writer and any
  write first drains), the bound and unexpired execution and its run certificate are scope and deadline, and the stamp
  equals the armed action whose exact rendered request bytes arrive. It records the consumption (fsync and read
  back) and only then sends the first byte upstream. Nothing earlier is the admission event: not socket accept, TLS, the
  ARM_ACTION acknowledgement or a worker report.
- **A2 In-chain persist check (pre-persist).** Inside the sealed apiserver, after mutating admission and before
  persistence, the static ValidatingAdmissionPolicy for the object's kind runs. Its failurePolicy is Fail and its binding
  action is Deny. It sees the decoded final object, never the request bytes, and its CEL has no hash, so it does not
  compare bytes. It enforces "final object = the manifest A1 admitted + allowlisted server deltas" this way:
  1. Every field an enabled in-tree mutator can set on CREATE is one of these:
     - an allowed difference whose fixed value A2 checks where it is checkable;
     - an allowed server-chosen value (uid, creationTimestamp, managedFields, the Service allocation inside the sealed
       service CIDR);
     - ruled out by a manifest constraint. A2 re-checks some constraints on the final object; the others hold only
       because the signer enforced `check_manifest` and A1 admitted exactly the signed bytes.
       `allowlists.json` `constraintCoverage` says which is which (RECHECKED_BY_A2 or SIGNER_GUARANTEED). A2's guarantee
       therefore depends on the signer (W03, R12), and an A2 claim needs that evidence (`check_claim` C25), the
       separate disabled-gate evidence (C27) and, in v4, the AlwaysPullImages evidence (C28).
  2. The set of mutators is closed: W02g allows only the in-tree admission plugins, and the observer checks that no
     webhook or mutating-policy object exists (W02g SC05, OR06).
  3. A Pod also carries a shape echo: its container names and images, init containers and volume names, as annotations.
     A1 proves the echo is the signed one, and A2 compares it with the final object. An added container, init container
     or volume, or a changed image, fails A2 even though no allowed mutator makes such a change.

  The built-in quota and LimitRanger admission re-evaluate usage in the same chain. A2 replaces "actual post-mutation
  manifest" in the v1 sentence. The bound is this design's mutator set: a mutator that rewrote a field and its echo
  together would have to be one W02g's allowlist and OR06 exclude.
- **A3 Drain fence for policy writers.** No I07 WRITE_OBJECT, and no other writer of W01 §2, commits while any action
  admitted under the current generation lacks a durable terminal classification. The I05 v3 drain answer OPEN is that
  fence. PENDING means wait and HELD means no write. OPEN is a point-in-time answer, and the writer keeps evaluating the
  fence after it. An IO_AMBIGUOUS action holds the generation HELD.
- **A4 Urgent invalidation (explicitly weaker, recorded).** Revocation, peer death, storage failure or observation loss
  closes A1 immediately and does not wait for A3. An action already admitted may still be persisted after the
  invalidating change. It is recorded ADMITTED_BEFORE_INVALIDATION with its terminal or ambiguous outcome, never
  relabelled unadmitted, never retried, and its resources stay owned for exact-UID cleanup.

Resulting guarantee for normal operation: if a mutation reached DELIVERED_RESULT, no mediated policy write committed
between its A1 event and its upstream response. The final object it persisted differs from the signed manifest only by
the allowlisted deltas. What v4 does not claim: a distributed transaction, persistence before a lost response (that is
IO_AMBIGUOUS), ordering for controller side effects outside W01 §2.5, or byte equality at A2.

`check_claim` encodes which consumer claims v4 supports (vectors Q01-Q26):
- A1 only at the effect gate, with the durable consumption first, the ACTIVE and current policy generation, the exact
  rendering (C11), and the bound unexpired execution, its run certificate and the stamp equal to the armed action (C12);
- A2 only at the apiserver, with the loaded static-manifest hash equal to the sealed directory's, no webhook or
  mutating-policy objects, only allowlisted plugins, AlwaysPullImages disabled on the apiserver (C28), A1, the signer's constraint check
  (C25), the signer's disabled-gate check (C27), and the sealed qualification namespace;
- A3 only with the drain answer OPEN;
- A4 never as strict ordering.

## Manifest constraints (signed qualification manifests)

`check_manifest`. Each constraint removes a mutation, or a server-chosen value, that A2 could not tell apart from the
signed content (codes MC00-MC42):

| Kind | Constraint | Rules out |
|---|---|---|
| all | explicit DNS-label `metadata.name` and the qualification namespace; no generateName, uid, resourceVersion, generation, timestamps, managedFields, ownerReferences, finalizers, selfLink; no label or annotation key under `kubernetes.io/` or `k8s.io/` (or a subdomain); no status | name generation, namespace defaulting, metadata wipes, plugin labels and annotations |
| ConfigMap | `immutable: true` | — (no mutator touches a ConfigMap on CREATE) |
| Service | explicit `type: ClusterIP`; no clusterIP(s), ipFamilies, ipFamilyPolicy, external, node-port or load-balancer field, sessionAffinityConfig or trafficDistribution; sessionAffinity and internalTrafficPolicy omitted or the defaults | external exposure and pinned addresses; the allocation is server-chosen and checked by A2 |
| Pod | `automountServiceAccountToken: false` | the ServiceAccount token volume and mounts |
| Pod | no nodeName, nodeSelector, runtimeClassName, overhead, priority, priorityClassName, preemptionPolicy, tolerations, imagePullSecrets, ephemeralContainers, schedulingGates, resourceClaims, host namespaces or deprecated serviceAccount | PodTopologyLabels, RuntimeClass, Priority's class lookup, DefaultTolerationSeconds against manifest tolerations, ServiceAccount pull-secret copy |
| Pod | every image pinned by digest with `imagePullPolicy: Never` (v4); every container states equal requests and limits | pull-policy defaulting, LimitRanger defaults, requests copied from limits. AlwaysPullImages is pinned off (C28), and its rewrite fails A2-POD-PULL-POLICY |
| Pod | no mount at the token path and no `kube-api-access-*` volume | a look-alike token volume |
| Pod | no image volume (MC38) | AlwaysPullImages rewriting an image volume's pull policy (alwayspullimages/admission.go:76-81) |
| Pod | no pod-level `spec.resources` (MC39, v3) | DefaultPodLevelResources filling pod-level requests and hugepage limits |
| Pod | no `spec.affinity` and no `spec.topologySpreadConstraints` (MC40, v3) | matchLabelKeys and mismatchLabelKeys merged into affinity terms and spread-constraint selectors |
| Pod | every volume is emptyDir, configMap, secret, downwardAPI or projected, and a projected volume's sources are configMap, secret or downwardAPI (MC41, v3 round 2) | the scheme defaults of every other volume source (hostPath type, RBD, AzureDisk, ScaleIO, ephemeral claims, the projected token's expirationSeconds); the defaults of the allowed sources are modelled |
| Pod | every emptyDir has a `sizeLimit` in decimal bytes and no `medium`; in a Pod with an emptyDir, every container and init container has an `ephemeral-storage` limit in decimal bytes, and the sizeLimits sum to at most the containers' limits (MC42, v4) | an unbounded or memory-backed emptyDir |
| ConfigMap | not named `kube-root-ca.crt` (MC11) | a gate-created object with the publisher's reserved name |
| Pod | the shape echo annotations `planeon.ai/a2-containers`, `planeon.ai/a2-init-containers`, `planeon.ai/a2-volumes` equal the spec (`name=image` and volume names, comma-joined, in order; empty when none) | — (input to A2) |

The constraints are checked when manifests are signed and enrolled (W03, R12). The fields of disabled feature gates are
dropped silently by the apiserver before A2, so they are a signer obligation, not an A2 check and not part of
`check_manifest`: the signer refuses fields of feature gates the W02g profile pins off (SC15; `constraintCoverage`
DISABLED_GATE_FIELDS), and an A2 claim carries that as its own evidence, `disabledGateFieldsAbsentAtSigning` (C27).

## Other creators in the qualification namespace

A per-kind A2 policy matches every CREATE of its kind in the namespace, whoever creates it. W01 §2.5 lists one non-gate
creator of a matched kind there: kube-controller-manager's root-CA publisher, which keeps one ConfigMap,
`kube-root-ca.crt`, in every namespace (pkg/controller/certificates/rootcacertpublisher/publisher.go). Its object carries
the reserved annotation `kubernetes.io/description` and is not immutable. W02g SC06 requires per-controller credentials,
so its creator is `system:serviceaccount:kube-system:root-ca-cert-publisher`. The ConfigMap policy's first validation,
A2-CM-PUBLISHER, admits, from exactly that identity and only under that name, an object of the publisher's shape
(publisher.go:196-205):
- the name `kube-root-ca.crt`;
- only the data key `ca.crt`, with any value;
- no binaryData and no labels;
- at most the description annotation (it may be missing).

It does not pin the rest: `immutable: true`, finalizers or ownerReferences on that object are admitted. The exemption is
still bound to the one name and the one identity. A publisher-created immutable object would only block the publisher's
own update after a CA rotation (a liveness effect).

Any other creator using the name is refused, and the publisher identity gets no exemption for any other name (P01-P05).
The other ConfigMap validations skip only that name. No other non-gate creator of a Pod, ConfigMap or Service in the
qualification namespace is admitted.

## Allowed differences per kind

`allowlists.json` lists every upstream field with its disposition. In short:
- **Pod.** Fixed: generation 1; scheme defaults (dnsPolicy, restartPolicy, securityContext `{}`, terminationGracePeriodSeconds 30,
  schedulerName, enableServiceLinks, terminationMessagePath/Policy, port protocol, probe and volume defaults); quantities
  re-emitted in canonical form; serviceAccountName `default` when omitted and its alias; the two default NoExecute
  tolerations with the sealed seconds; priority 0 and PreemptLowerPriority; status phase Pending and qosClass; (v3) in
  containers and init containers, an env `fieldRef.apiVersion` of v1 and an env `fileKeyRef.optional` of false when
  omitted; (v3 round 2) `defaultMode` 420 on configMap, secret, downwardAPI and projected volumes and a `fieldRef.apiVersion`
  of v1 on downwardAPI items (also inside projected volumes) when omitted; (v4) an emptyDir `sizeLimit` re-emitted in
  canonical form (A2-POD-EMPTYDIR checks presence only). Server-chosen: uid, creationTimestamp,
  managedFields. Probe defaults (timeouts, periods, thresholds) are allowed fixed values that `final_object` does not
  model; the native comparison covers them (W03, T03).
- **ConfigMap.** Server-chosen uid, creationTimestamp, managedFields; `data: {}` when nil (invisible to the policy).
- **Service.** Fixed: sessionAffinity None, internalTrafficPolicy Cluster, port protocol TCP, targetPort = port,
  ipFamilyPolicy SingleStack, ipFamilies = the sealed family, `status.loadBalancer {}`. Server-chosen: uid,
  creationTimestamp, managedFields, one clusterIP equal to clusterIPs[0] inside the sealed service CIDR.

resourceVersion is set by storage after the policy and is not part of A2.

## The sealed directory (`admission-manifests/planeon-a2.json`)

`a2_objects` renders the objects from four sealed values: the qualification namespace, the service IP family and CIDR,
and the default toleration seconds. Those values come from the distribution's sealed configuration (W03); the vectors
use `planeon-qual`, IPv4, `10.96.0.0/12` and 300.

v4's rendering differs from v3's only in the Pod policy (A2-POD-PULL-POLICY requires `Never`, and A2-POD-EMPTYDIR
is added last). The file is 8322 bytes, sha256 `92c21612304cb704d13b506c1ae885d62a47c01f0ed0d284affe563aa1868e32`, and its directory hash is
`sha256:9b1ddc1096ff0d35fb4cd5a9e5e6b4248fefc5b75b5a06f862c59d85e028ca60`, pinned in `vectors.json` `pinned`. It supersedes v3's directory hash `sha256:5aa2cdec0b8dc08c008b887e30b9954ffc46e7d779365f64db1adfd80656f189`.
It is not installed: `status.json` `sealed` says it activates only at HS53 §5.5 M1 (maintenance boot) and M3
(re-enrollment), after the three sealed-bytes steps S1-S3 (below).

- One policy per kind: `planeon-a2-pod.static.k8s.io`, `planeon-a2-configmap.static.k8s.io` and
  `planeon-a2-service.static.k8s.io`. Each matches CREATE of its v1 resource in the qualification namespace
  (namespaceSelector on `kubernetes.io/metadata.name`) with matchPolicy Exact. It has no objectSelector (requester-
  controlled), no matchConditions (a false one skips the policy) and no paramKind, and failurePolicy is Fail. Each
  validation's message is its A2 code.
- `planeon-a2-admission-objects.static.k8s.io` denies every API CREATE, UPDATE and DELETE of validating and mutating
  admission policies, their bindings and both webhook configurations. Static policies run for all six; API-registered
  policies never run for the four admission-policy resources (generic/plugin.go:58-65). The status subresource is not
  matched, so the validatingadmissionpolicy status controller is unaffected. So admission objects can no longer be written through the API, I07 included. This
  closes the W02g note that RBAC cannot restrict ValidatingAdmissionPolicy names. W02c-F removes the
  ValidatingAdmissionPolicy and binding rows from I07's writable kinds, and W02c R2 (a name allowlist for I07 policy
  writes) becomes "no name is writable".
- One binding per policy, named `<policy>-binding.static.k8s.io`, with `validationActions: [Deny]` and no paramRef or
  matchResources.

`check_a2_objects` refuses any other structure (S01-S06), including any change to a rendered validation.
`manifest_directory_hash` reproduces the loader's directory hash (in file-name order, each non-empty `.yaml`, `.yml` or
`.json` file followed by a NUL byte). The apiserver exports that hash as
`apiserver_manifest_admission_config_controller_last_config_info` (ALPHA). The observer compares it with the pinned
hash before a generation becomes ACTIVE (claim Q06 versus Q07). The directory is reloaded on a filesystem event and at least every
minute (util/filesystem/watchuntil.go); a failed load keeps the previous configuration and its hash. Sealing and the
maintenance boot (W01 §5.5) are what keep it unchanged.

`check_final` is the reference reading of the CEL validations, in rendered order: A2-RESERVED, then the kind's checks,
except for ConfigMap, whose order is A2-CM-PUBLISHER, A2-RESERVED, A2-CM-IMMUTABLE. The Pod's order ends with
A2-POD-PULL-POLICY and then A2-POD-EMPTYDIR.
The CEL text is data for the native tests: the model does not compile or run CEL. Each validation avoids the CEL forms
the research could not confirm (schemaless list equality, mixed int/double equality). It uses sizes, `exists_one`,
`all`, `has`, `matches`, `join`, `request.userInfo.username` and the CIDR library. Where a CEL expression dereferences a
field without a `has()` guard, the reference reading requires the field: its absence is a runtime error, which
failurePolicy Fail denies (F17). Integers and booleans are compared by exact type (F18), and a malformed address is a
refusal (F19).

## Vectors

`vectors.json` holds v3's re-derived set (the table below) plus the new v4 cases, 141 in all. Its `server` block carries
`"alwaysPullImages": false`, and its `pinned` block the v4 directory hash and the namespace.
- **manifest** (N01-N47, 47): each constraint, refused with its MC code. New in v4: N37 (`Always`) and N38 (omitted) →
  MC33; N39 `emptyDir: {}`, N40 `512Mi`, N41 `medium: Memory`, N42 a container without an ephemeral-storage limit, N43
  an init container without one, N44 `1Gi`, N45 the sum over by one byte, N46 an init container's larger limit not
  counted, and N47 (two emptyDirs, the first with a medium and the second without a sizeLimit; "no medium") → MC42 with
  its reason.
- **endToEnd** (E01-E15 and U01-U08, 23): E01-E04, E13 and E14 admitted under the plain sealed cluster, with E02 and E13
  carrying the new limits and `sizeLimit`; E05-E12 cluster facts that make a mutator act, with E08 replaced (AlwaysPullImages
  enabled despite the pin: A2 refuses, fail closed); E15 (v4) a sum exactly equal to the limit, admitted; U01-U05 as in
  v3 (U04's text "…other than Never", U05's intent annotated); U06 (`Always` reaching the final object) →
  A2-POD-PULL-POLICY; U07 (`emptyDir: {}`) and U08 (a medium) → A2-POD-EMPTYDIR.
- **finalObject** (F01-F25 and P01-P05, 30): v3's cases with `Never` (F03 still A2-POD-ECHO, by order); F20 (no
  volumes) and F21 (PodVol's four sources) admitted by the guard; F22 (`emptyDir: {}`) and F23 (a medium) →
  A2-POD-EMPTYDIR; F24 (a container) and F25 (an init container) pulled `Always` → A2-POD-PULL-POLICY.
- **objects** (S01-S06d, 11): v3's mutations applied to v4's rendering; S06c (A2-POD-EMPTYDIR removed) and S06d (an
  unguarded A2-POD-EMPTYDIR) → S06.
- **directoryHash** (H01-H04, 4): the v4 file and its recomputed hashes.
- **claims** (Q01-Q26, 26): v3's claims at v4 semantics (below); Q23 (evidence absent) and Q24 (false) → C28; Q25 (a v3
  claim) → C04; Q26 (v4 with the old directory hash) → C21; Q16 uses `…/v5` as the unknown version.

## The v3 re-derivation table

v3's vectors keep replaying through the frozen v3 model (`scripts/admission_semantics_v3.py`, byte-identical): 114
cases. v4's 141 cases replay through v4's model.

| v3 item | In v4 | Why |
|---|---|---|
| Positives Pod, PodInit, PodEnv, PodVol | `imagePullPolicy: Never` everywhere | MC33 |
| PodInit, PodEnv | add `ephemeral-storage` limits and requests and a `sizeLimit` (MC42 above) | MC42 |
| N15, N16 expectations | "…pulled Never" | MC33 text |
| N19 (token-like name, `emptyDir: {}`) | unchanged, MC36 | MC36 precedes MC42 |
| N29 and the MC38 refusal text "(AlwaysPullImages rewrites its pull policy)" | KEPT byte-identical | still true of the plugin; MC38 stays as defence in depth, because A2-POD-PULL-POLICY covers containers only and an image volume is a download path |
| E02, E13 | admitted; new final objects: v3's with `imagePullPolicy: Never` on every container and init container, the `ephemeral-storage` entries in limits and requests, and the `scratch` emptyDir with its `sizeLimit`; nothing else changes | MC42 |
| E08 | replaced: refused, A2-POD-PULL-POLICY; its final object is byte-equal to v3's | AlwaysPullImages pinned off |
| U04 expectation | "…other than Never" | text |
| U05 | expectation kept; intent annotated; final object byte-equal to v3's | AlwaysPullImages pinned off |
| all other E and U final objects | v3's with `Always` replaced by `Never`, otherwise byte-equal | MC33 |
| F01-F19, P01-P05 | objects with `Never`; expectations kept (F03 still A2-POD-ECHO) | A2 order |
| S01-S06b | v3's mutation applied to v4's rendering | new Pod validations |
| H01-H03 | the v4 file and its recomputed hashes | new bytes |
| Q01, Q02 (C01 text), Q19 (C03 text) | "cite … v4" | successor |
| Q03, Q06, Q12, Q14 | semantics v4; A2 evidence adds `alwaysPullImagesDisabled`, hash v4 | C28, C21 |
| Q04, Q05, Q07, Q08, Q09, Q10, Q11, Q13, Q15, Q17, Q18, Q20, Q21, Q22 | semantics v4; expectations kept. The A2 cases (Q07-Q11, Q17, Q18, Q22) add `alwaysPullImagesDisabled: true` and move to the v4 directory hash, except Q07, which keeps its foreign hash (it proves C21) | at v3 semantics, v4 refuses each with C04; with the v3 hash, C21 comes first (Q08-Q10, Q17, Q18, Q22); without the evidence, C28 comes first (Q09, Q10, Q17, Q18, Q22) |
| Q16 | `…/v5` as the unknown version | v4 is now known |
| README Pod row "every image pinned by digest with `imagePullPolicy: Always` … rules out AlwaysPullImages" | "…with `imagePullPolicy: Never`; rules out pull-policy defaulting. AlwaysPullImages is pinned off (C28), and its rewrite fails A2-POD-PULL-POLICY" | MC33, C28 |
| README E05-E12 narrative "harmlessly, A2 admits: AlwaysPullImages with a manifest that already pulls Always" | "AlwaysPullImages enabled despite the pin: A2 refuses (fail closed)" | E08 |
| model docstrings of `final_object` and `check_claim` ("cite v3", the AlwaysPullImages comment) | v4 wording | successor |

Each of the 14 claims in the row above keeps its v3 expectation and reaches it through v4: Q04 C11, Q05 C10, Q07 C21,
Q08 C22, Q09 C23, Q10 C24, Q11 C20, Q13 C31, Q15 C40, Q17 C25, Q18 C26, Q20 C12, Q21 C12, Q22 C27. Put back at v3
semantics, all 14 give C04. With the v3 hash put back, Q08, Q09, Q10, Q17, Q18 and Q22 give C21; Q11 still gives C20,
which comes first. Without `alwaysPullImagesDisabled`, Q09, Q10, Q17, Q18 and Q22 give C28; Q07, Q08 and Q11 still give
C21, C22 and C20. So every one of v3's 22 claims has a row. Each of the 47 v3 cases whose v3 expectation differs
through v4 falls under a row: the 22 claims, and 25 manifest and end-to-end cases (N15-N21, N29, N31-N36, E01, E02,
E05-E09, E12-E14, U04), whose v3 positive pulls `Always`, so v4 refuses them with MC33 first.

`final_object` reproduces the upstream create path for the fields the allowlist lists, from the cited facts. It is a
reference simulation, not the apiserver: managedFields carry no fieldsV1 content (an unverified point), and the token
volume shape is abridged. The native tests (W03, T03) compare it against a real apiserver of the selected distribution.

## What stays open

- All E01-E12; the native A2 test against a real apiserver of the selected distribution, including CEL compilation and
  the unverified points in `allowlists.json` (W03). Four of them are new in v4 and are author's readings, not verified at
  v1.37.1: the emptyDir `sizeLimit` as a canonically re-emitted quantity; the kubelet's emptyDir and ephemeral-storage
  eviction accounting; the runtime-provided writable paths and the sandbox image; AlwaysPullImages' Validate path.
- The distribution's sealed values (namespace, service family and CIDR, toleration seconds) and the admission
  configuration's `staticManifestsDir` (W03).
- The observer's check of the loaded manifest hash before ACTIVE (W03, R12).
- I07 writes no admission objects (I07 v2 and v3); the guard policy denies them.
- The native comparison of the env, volume and probe defaults and of MC39-MC42's ruled-out deltas against a real
  apiserver (W03, T03).
- The signer and enrollment of manifests under these constraints (W03, R12).
- **The carried steps** (`status.json` `carried`). No kit install, LINUX-PROBE-KIT-001's included, happens before every
  step has landed. S1-S3 gate the sealed v4 bytes (an I01 successor that renders A2 with `admission_semantics_v4`; edge
  record v11 registering this README, `vectors.json` and `planeon-a2.json` for R10; R10's re-vendor of the A2 renderer).
  W1-W4 gate profile v2 on the wire (`../proxy-profile-v2/`). C1 and C2 gate v4 A2 claims (C28): I06 SC05's successor
  with AlwaysPullImages forbidden; W03-0 SC05's successor text and HE-008's sealed APISERVER_FLAGS with
  `--disable-admission-plugins=AlwaysPullImages`. Without C1 and C2, v4 is still safe, because an enabled plugin fails
  closed in A2, but it is not live: every Pod is refused, and no v4 A2 claim passes C28.
- **Non-claims:** nothing is installed or compiled; no apiserver is contacted; admission v3 and v2, profile v1, I06, I01
  and edge records v1-v10 are byte-identical; "pinned off" binds this contract only until I06's successor and HE-008
  carry it; profile v1 remains the wire's profile until the wire steps W1-W4 land.

The W02f and W02-ADM-F findings and their dispositions stay in `../admission-semantics-v3/README.md` and
`../admission-semantics-v2/README.md`. LPK-1's design was checked by the author's design proof (local, not published)
and four TOOLS design rounds, cited by sha256 in `../linux-probe-kit-admission/source-index.json`.
