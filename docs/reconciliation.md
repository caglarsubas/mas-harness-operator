# Foundation reconciliation

OP-003 provides the deterministic reconciliation core for the first tenant
foundation wave. The target namespace is an explicit trust boundary: it must be
created by an authorized administrator beforehand, must not be `default`, and
must equal the operator's configured watch namespace. This packet does not add a
ClusterRole or permission to create or mutate Namespace objects.

## Input and baseline

The canonical `FoundationPlan` binds organization, installation, generation,
target namespace, profile, bundle, signed release, and OP-002 verification
receipt digests. Resources are ordered in ordered waves. Every resource embeds
one canonical manifest whose digest and API identity are independently checked.

The first wave contains exactly one each of:

- non-automounted ServiceAccount;
- ingress-and-egress default-deny NetworkPolicy;
- bounded ResourceQuota and container LimitRange;
- namespaced, non-wildcard Role; and
- RoleBinding to the dedicated ServiceAccount in the same namespace.

No workload, Secret, PVC, cluster-scoped object, token request, SCC mutation, or
optional module is admitted. ConfigMaps in later foundation waves may contain
only the profile, bundle, and release digests.

## Apply, inventory, and recovery

The engine calls a typed apply port with field manager
`planeon-foundation-v1`, `force=false`, and `dryRun=false`. A caller can map that
port to Kubernetes server-side apply in a later live integration packet. OP-003
does not execute kubectl, Helm, or an API-server client.

Before each apply, a compare-and-swap inventory records the exact next resource.
After apply, its UID, resourceVersion, desired and observed digests, and fixed
apply time are durably recorded before the cursor advances. A restart validates
all binding and receipt history and resumes the first incomplete resource. The
only uncertain boundary may replay the same server-side apply identity and
digest; it cannot create a second logical resource or force ownership.

Tests inject a crash before apply, after apply but before receipt, after receipt,
before status, and after status for every applicable resource boundary. Every
case converges to the same inventory and evidence. Once inventory is complete,
subsequent reconciliations perform zero apply, store, or status writes.

## Status and evidence boundary

The outcome advances only to `HEALTH_CHECKING`. It emits all seven lifecycle
conditions in lexical order. `Ready` and `Healthy` remain `Unknown` with
`FOUNDATION_APPLIED_AWAITING_HEALTH`; no runtime state is inferred.

Evidence contains identifiers, digests, generation, counts, bounded reasons,
and caller-fixed whole-second UTC times only. It excludes manifests, annotations,
environment values, business payloads, credentials, and free-form errors.

The mandatory offline tests prove source behavior. Real Kubernetes apply and
installation are `NOT_RUN_ENV_UNAVAILABLE`; artifact publication, image build,
deployment, runtime, assurance, and tenant acceptance are separate and remain
`NOT_RUN_NOT_IN_PACKET`.
