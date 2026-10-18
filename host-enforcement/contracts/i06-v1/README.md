# I06 backend profile — W02g (MET-ENFORCE-006), round 2

Status: **CONTRACT_CANDIDATE**, awaiting the round-2 independent review. Round 1
(`review-round1.json`, reviewed bytes in `round1/`) returned CHANGES_REQUIRED with 3 MAJOR,
5 MINOR and 4 NOTE findings. Each is answered below. DATA_CHECK_ONLY: no cluster was
observed, nothing is installed and no distribution is selected. All E01-E12 stay
OPEN_UNPROVEN.

This part makes the I06 backend of `SEALED_SINGLE_NODE_CONTROL_PLANE_V1` (W01 spec
§2.1-§2.6, HOST-INTERFACE-DRAFT-002) concrete for Kubernetes v1.37.1. It gives:

- the selection criteria a distribution's evidence record must meet (W03 selects), with
  the record bound to its W02a backend profile;
- an inventory of every upstream controller and in-process apiserver writer, each with a
  disposition;
- the closed identity closure, including W01 review finding F1 (the apiserver's loopback
  identity in `system:masters`).

For I06 evidence it makes the W02a `unit-distribution` fixture test-only (W02a finding
P7(a)). The W02a-side parts of P7 are carried; see "Still open".

## Files

| File | Content |
|---|---|
| `criteria.json` | SC00-SC15 (evidence record), CL (closure derivation), IC01-IC05 (RBAC snapshot), OR01-OR08 (observer and operational rules) |
| `writer-inventory.json` | 49 kube-controller-manager controllers and 21 apiserver writers with profile, disposition and source line |
| `identity-closure.json` | 24 identities with their exact allowed grants and derivation |
| `upstream-bootstrap-rbac-v1.37.1.json` | Effective bootstrap RBAC of all 56 bound subjects, plus the unbound role `system:kubelet-api-admin`, derived from the upstream golden fixtures |
| `upstream-facts-v1.37.1.json` | Facts read from the v1.37.1 source with file and line citations; open points under `unverified` (unchanged since round 1) |
| `vectors.json` | One evidence and one snapshot positive, 11 accepted variants and 127 negatives, each negative pinned to its exact refusal |
| `scripts/i06_backend_profile.py` | Reference model: `check_inventory`, `check_closure`, `check_evidence`, `check_rbac_snapshot` |

## Baseline and sources

The baseline is Kubernetes tag v1.37.1 (commit `f78e722310e50bcaca9276be22276d9e91d91308`).
Facts come from static reading of that tree, with method and caveats in
`upstream-facts-v1.37.1.json` (`meta`, `unverified`). The round-1 reviewer fetched ten
files from upstream at the tag, all byte-identical to the tree read here.

Bootstrap RBAC is computed from the six default-feature-gate golden fixtures under
`plugin/pkg/auth/authorizer/rbac/bootstrappolicy/testdata/`, which upstream unit tests
assert against the code. Their SHA-256 digests are recorded. Each subject receives the
rules of every ClusterRoleBinding (scope `CLUSTER`) and RoleBinding (scope = its
namespace) that names it. Non-resource-URL rules are dropped.

Round 2 cites further v1.37.1 sources in `criteria.json`:

- the service-account signing endpoint and verification keys:
  `pkg/controlplane/apiserver/options/options.go`,
  `pkg/kubeapiserver/options/authentication.go`;
- static-pod URLs: `staging/src/k8s.io/kubelet/config/v1beta1/types.go`,
  `pkg/kubelet/kubelet.go`;
- emulated versions: the component-base compatibility registry.

## Policy-relevant grants

The model classifies each effective RBAC rule using upstream matching semantics: `*`
covers every resource and subresource, `*/x` covers any `<r>/x`, and verb `*` covers
special verbs. There are four categories:

- **POLICY_WRITE**: create, update, patch, delete or deletecollection on a policy kind.
  These are the §2.3 kinds plus `namespaces/finalize`, MutatingAdmissionPolicy and its
  binding, FlowSchema and PriorityLevelConfiguration.
- **STATUS_WRITE**: writes to the status of ResourceQuota, Namespace,
  ValidatingAdmissionPolicy, APIService, CustomResourceDefinition, FlowSchema or
  PriorityLevelConfiguration.
- **SPECIAL**: verbs that escalate or take over another identity:
  - `escalate` and `bind` on Roles and ClusterRoles;
  - legacy `impersonate` on core users, groups and serviceaccounts;
  - constrained `impersonate:<mode>` on `authentication.k8s.io` users, groups,
    serviceaccounts and nodes, plus `uids` and `userextras/<key>`;
  - `create` on `serviceaccounts/token`;
  - `approve`, `sign` and `attest` on signers, and `attest` on
    `admissionReviewAPIGroups`;
  - get, create, update, patch or delete on `nodes/proxy`, `nodes/log` and
    `nodes/checkpoint`, and `proxy` on nodes. These reach the kubelet API:
    `nodes/proxy` gives exec over a websocket GET, `nodes/log` serves node log files
    and `nodes/checkpoint` dumps container memory (round-1 F10);
  - `create` and `get` on `pods/exec` and `pods/attach`. `get` counts too because
    websocket exec needs `create` only while the default gate holds (round-1 F5).
- **WORKLOAD**: create, update or patch on pods, ephemeral containers,
  ReplicationControllers, Deployments, ReplicaSets, StatefulSets, DaemonSets, Jobs or
  CronJobs, at cluster scope or in `kube-system`. A new pod can run as any service
  account of its namespace. `kube-system` is the only namespace that holds closure
  service accounts.

## Decisions

1. **Baseline exactly v1.37.1 (SC14) with default feature gates (SC15).**
   - The inventory, closure and facts were derived from v1.37.1 only. A later patch
     release needs the builder rerun and a new revision.
   - Every Kubernetes component that takes `--feature-gates` is recorded separately,
     and each must keep the v1.37 defaults.
   - `--emulated-version` and `--min-compatibility-version` must stay unset, and
     `--runtime-config` must be empty.
2. **Webhook admission off (SC05).** Spec P6 requires only that the webhook and
   mutating-policy objects are absent. The profile also disables
   ValidatingAdmissionWebhook, MutatingAdmissionWebhook, MutatingAdmissionPolicy,
   ImagePolicyWebhook, NamespaceAutoProvision and AlwaysAdmit, and the observer still
   checks that the objects are absent (OR06).
   - Enabled plugins must come from a closed allowlist: the v1.37 default-on set minus
     the forbidden plugins, NodeRestriction, and four off-by-default plugins that only
     restrict requests.
   - NodeRestriction, CertificateApproval and CertificateSigning are required.
3. **Service-account tokens are minted only inside the apiserver (SC03).** P4 allowed the
   apiserver and controller-manager domains to read the signing key. This profile
   narrows it to the apiserver, because the controller-manager needs the key only for
   the disabled legacy token controller. The record also states:
   - there is no `--service-account-signing-endpoint` (ExternalServiceAccountTokenSigner,
     GA and locked on, would move signing into another process);
   - the only verification key is the public half of the signing key, because any other
     trusted key mints tokens for whoever holds its private half (round-1 F2);
   - there is exactly one issuer;
   - token lookup is on.
4. **Authentication closure (SC03).** P3 is extended:
   - front-proxy request-header authentication is off, because a front-proxy client
     certificate can assert any user and group, `system:masters` included;
   - JWT and webhook authenticators are off;
   - an authentication configuration file, if used, is sealed (SC12);
   - the host holds no cluster-admin credential, no private key of any CA a component
     trusts (cluster, front-proxy, kubelet client, datastore), and no bootstrap token.
     Counts are integers, not booleans (round-1 F11).
5. **Required-disabled controllers (SC06).** Ten controllers are disabled. Their reasons
   are in the inventory.
   - CSR signing, approving and cleaner, which share one account.
   - Bootstrap signer and token cleaner.
   - The legacy token controller and its cleaner.
   - ClusterRole aggregation, the only controller holding `escalate`.
   - The storage-version migrator, which has wildcard list and patch.
   - The ClusterTrustBundle publisher, which holds `attest`.

   Per-controller credentials are required; upstream defaults to the shared
   controller-manager identity.
6. **Dispositions of the policy-kind writers.**
   - `namespace-controller` and `serviceaccount-controller` are I07_TRIGGERED_ONLY.
   - `resourcequota-controller` and `validatingadmissionpolicy-status-controller` are
     STATUS_ONLY.
   - `garbage-collector-controller` is OWNERREF_RULE. Spec §2.5 understated its
     reach: it holds wildcard patch, update and delete, so OR02 requires that
     policy-kind objects carry no ownerReferences.
   - `rbac/bootstrap-roles` is STARTUP_BEFORE_INSPECTING. It reconciles the roles and
     bindings built into the pinned binary once per start: it adds missing rules and
     subjects, recreates a binding whose roleRef changed, may create `kube-system` and
     `kube-public`, and primes the aggregate-to-* roles and the public-info-viewer
     binding from existing objects (round-1 F9).
     - OR01: any apiserver restart during ACTIVE invalidates the generation.
     - OR07: the observer starts only after `/readyz/poststarthook/rbac/bootstrap-roles`
       succeeds.
   - The system-namespace and authentication-info controllers are
     SYSTEM_NAMESPACES_ONLY.
   - API Priority and Fairness configuration is AVAILABILITY_ONLY.
   - Autoregistration is LOCAL_APISERVICES_ONLY.
   - The apiextensions controllers are ABSENT_BY_PROFILE.
7. **Components bound to W02a (SC08).** The evidence record names its W02a backend
   profile. Its implementationId must equal the profile's under W02a's pattern, and its
   components must equal the profile's component keys: six required, with the service
   proxy and network-policy agent optional, as in W02a (round-1 F11). Each component:
   - is a separate process;
   - has W02a's confined process label;
   - has a canonical executable path (no `.` or `..`, no empty segment, no trailing
     `/`).

   No two components share an executable path or an artifact digest. This refuses one
   file under several names, and one multi-call binary copied under several names
   (round-1 F7). A rebuilt binary with different content is still accepted. Whether two
   distinct files run distinct code is outside a data check.
8. **Sealed configuration (SC12).** The sealed set must equal the profile's set exactly
   (round-1 F6):
   - control-plane flags and configuration;
   - component definitions and kubeconfigs;
   - the PKI trust bundles (client CA and service-account verification keys);
   - container-runtime and CNI configuration;
   - only when used: the authentication configuration, the admission manifest
     directory, the audit policy, and the service-proxy and network-policy-agent
     configuration.

   Auto-apply directories must be empty and sealed (P5).
9. **Kubelet (SC07).** It has no static pod source of any kind: neither `staticPodPath`
   nor `staticPodURL` with its header (round-1 F3). It has no certificate rotation or
   TLS bootstrap, no anonymous or read-only access, and uses Webhook authorization.
10. **Component API clients (SC10).** The service proxy authenticates as
    `system:kube-proxy` and the network-policy agent as `planeon:netpol-agent`, each
    only when its component is present. Both are host components with client
    certificates (P8), and neither holds a policy-relevant grant. SC09 forbids CRDs, so
    W03 can pick only an agent that uses built-in APIs alone.
11. **Test fixture (SC00, W02a P7(a)).** The `unit-distribution` fixture must carry
    `testOnly: true`. In production, neither its implementationId nor its distribution
    name qualifies. A production record needs its own W02a backend profile with the same
    implementationId (round-1 F8).

## Identity closure

Closure entries have one of four derivations, and CL pins every one (round-1 F1).

- **F1_LOOPBACK**: two entries.
  - Group `system:masters` has full authority.
  - User `system:apiserver` holds no RBAC grant. Its authority comes only from its
    membership in `system:masters`, so IC03 refuses any RBAC rule bound to the name
    (round-1 F12).

  `system:apiserver` is the apiserver's in-process loopback client (per-process random
  bearer token). The post-start hooks that write through the API run as it; in-process
  storage writers such as the peer-endpoint reconciler bypass the API. Both entries are
  sealed-TCB, P2 makes them unreachable from unlisted domains, and the observer
  re-verifies effective RBAC in every observation.
- **BOOTSTRAP_SUBJECT**: the grants must equal those derived from the subject's upstream
  bootstrap rules.
  - User entries are fixed: the controller-manager, the scheduler and kube-proxy.
  - `system:kube-controller-manager` holds `serviceaccounts/token` create at cluster
    scope, so it is TCB-equivalent to every service account.
  - Service-account entries must belong to an allowed controller in `kube-system`.
    Thirteen hold grants.
  - The wildcard verbs of `generic-garbage-collector` and `namespace-controller` cover
    `nodes/proxy`, `nodes/log`, `nodes/checkpoint`, `pods/exec` and `pods/attach`.
    Their entries record this, and they run inside the sealed controller-manager.
- **PROFILE**: a closed set of five planeon identities with fixed holders, presence and
  grants. The profile fixes every name, and W03 issues each credential (a client
  certificate from the off-host CA) with exactly that subject.
  - **Policy writer** (`planeon:policy-writer`, effect gate, must be present). Its
    grants are fixed by the model:
    - Roles, RoleBindings, ResourceQuotas, LimitRanges, ServiceAccounts and
      NetworkPolicies in the qualification namespace;
    - update and patch of that namespace object;
    - ValidatingAdmissionPolicies and their bindings at cluster scope;
    - `escalate` and `bind` only on exactly `planeon-gate-effect` and
      `planeon-policy-observer` (IC04).
  - **Effect gate** (`planeon:effect-gate`): no policy-relevant grant.
  - **Observer** (`planeon:policy-observer`): no policy-relevant grant.
  - **Apiserver kubelet client** (`planeon:apiserver-kubelet-client`): exactly the grants
    derived from the upstream `system:kubelet-api-admin` rules.
  - **Network-policy agent** (`planeon:netpol-agent`): no policy-relevant grant.
- **NODE_AUTHORIZER**: `system:nodes` holds no RBAC grant. The Node authorizer limits
  node `serviceaccounts/token` create to accounts of pods bound to that node. CSR create
  is inert while signing and approval are disabled.

The writer is narrower than §2.3's list of kinds. It writes no ClusterRoles,
ClusterRoleBindings, webhook configurations, APIServices, CRDs or CSR approvals. RBAC
cannot restrict the creation of a cluster-scoped ValidatingAdmissionPolicy by name, so
W02c's WRITE_OBJECT and the W02f observer must refuse unexpected names.

**Dormant bindings (IC02).** Bootstrap binds every controller role, but the
controller-manager creates `kube-system/<name>` only for controllers it starts. An
absent controller account may carry only the grants of its own bootstrap role, and of
its closure entry if it has one (round-1 F4). Anything else bound to it in advance is
refused, as is any grant bound to an absent account that has no bootstrap role. Only
service accounts can be absent.

**Snapshot rules (IC00-IC05).**

- The qualification namespace must be dedicated and must not be a system namespace.
- Service-account usernames must use kind `ServiceAccount`.
- A cluster-scope allowance covers the same grant in any namespace.
- A namespaced grant on a cluster-scoped kind is treated as a grant, so it is refused
  unless allowed.

## Round-1 findings and dispositions

| Finding | Disposition in round 2 |
|---|---|
| F1 MAJOR, PROFILE identities unconstrained | CL pins the five PROFILE identities (closed set, holder, presence, exact grants, writer `resourceNames` exactly the two roles), the three component users and the closure accounts; closure negatives C05-C17 cover each probe shape |
| F2 MAJOR, token minting outside RBAC | `serviceAccountTokens` in the record; SC03 refuses a signing endpoint, extra verification keys, a key that is not the signing key's public half, extra issuers and lookup off (E48-E52) |
| F3 MAJOR, static pods from a URL | `staticPodURL` and `staticPodURLHeader`; SC07 refuses both (E53, E54) |
| F4 MINOR, dormant accounts carry any grant | IC02 limits absent controller accounts to their bootstrap grants and entry (S28-S30) |
| F5 MINOR, emulation version | Per-component feature gates; emulated and minimum-compatibility versions unset; runtime-config empty (E27, E57-E59); `get` on `pods/exec` and `pods/attach` is SPECIAL (S31) |
| F6 MINOR, sealed vocabulary | Exact sealed set including authentication configuration, PKI trust bundles, runtime, CNI, agent and proxy configuration and the audit policy (E63-E66, A06, A07) |
| F7 MINOR, path aliases | Canonical paths and distinct artifact digests, bound to W02a (E38, E55, E56); decision 7 restated |
| F8 MINOR, P7 | Evidence bound to its W02a backend profile; production refuses the fixture's implementationId and distribution name; A02 uses a non-fixture identity (E60-E62); the W02a-side parts are carried |
| F9 NOTE, reconciler wording | Inventory reason and README reworded; OR07 added |
| F10 NOTE, unclassified paths | `nodes/log` and `nodes/checkpoint` are SPECIAL (S33, S34); VAP `paramKind` carried to W02f; audit policy sealed when used, and keeping token and secret bodies out of logs carried to W02e |
| F11 NOTE, loose checks | Integer and boolean checks (E67-E69); W02a's six-to-eight component rule (A05, E70, E71); SC14 pinned to v1.37.1 (E41) |
| F12 NOTE, loopback user grants | `system:apiserver` holds no RBAC grant in the closure; IC03 refuses any (S32) |

## Spec mapping

| Spec | Encoded by |
|---|---|
| P1 | SC01; the datastore socket type is W02e |
| P2 | SC02; the apiserver port type and `name_connect` matrix are W02e |
| P3 | SC03, SC04 (Node then RBAC from the sealed structured file; the binary default is AlwaysAllow) |
| P4 | SC03, SC06, SC07; IC01 for `serviceaccounts/token` |
| P5 | SC12 |
| P6 | SC05, OR06 |
| P7 | SC09 |
| P8 | SC10, closure |
| P9 | SC07 (no static pods), SC11 |
| P10 | Unchanged runtime rule, not a selection criterion |
| §2.3 | CL, IC01-IC05, closure |
| §2.5 | Inventory dispositions, OR02, OR03 |
| F1 | Closure F1_LOOPBACK entries, inventory `rbac/bootstrap-roles`, OR01, OR07 |

## Still open

- All E01-E12 and T01-T08.
- The SELinux matrix and port and socket types, including F2 (W02e). W02e also keeps
  token and secret bodies out of audit and node logs (round-1 F10).
- The I07 wire schema (W02c).
- Admission field allowlists, and forbidding VAP `paramKind` or classifying the param
  kind as a policy kind (W02f, round-1 F10). OR08 recommends sealed file-based admission
  manifests for the A2 policies.
- The distribution choice (W03). W03 issues the profile identities' credentials with the
  fixed names, and binds each W02a component's `apiIdentities` to the closure.
- Carried to W02a-F (W02a's own bytes are frozen in this packet):
  - P7(a): W02a's schema still accepts `unit-distribution` like a production profile;
    W03 removes it from production acceptance when it adds its profile.
  - P7(b): the type-name wording in the W02a README.
  - P7(c): nested backend cgroups.
  - The fixture names its network-policy agent identity as a service account, whereas
    this closure uses the host-component user `planeon:netpol-agent`.
- OR01-OR08 are operational rules for the observer and runtime. The model does not check
  them.
