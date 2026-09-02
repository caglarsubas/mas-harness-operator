# Offline preflight and signed-bundle verification

OP-002 adds a read-only gate before any cluster apply. It does not discover a
cluster, apply resources, update a HarnessInstallation, or infer readiness from
missing input.

The caller supplies canonical request and observation JSON documents. Evaluation
always returns the same eight ordered conditions: platform, architecture,
Kubernetes version range, allocatable capacity, storage-class presence,
connectivity mode, sandbox availability, and exact profile/bundle/release locks.
Any invalid or mismatched field blocks the gate.

`bundle-verifier` then closes the already-local release directory before a
mutation sink can run. It verifies canonical manifests, all declared files and
OCI blobs, immutable component references, selected-module and platform closure,
supply-chain decisions, trust sequence/time/role/revocation state, the approval,
and root plus component signatures. Cosign is the root-owned, digest-pinned local
binary and is invoked offline with direct argv. No online lookup or trust fallback
exists.

The CLI requires exactly these flags:

```text
bundle-verifier --request /absolute/request.json \
  --observation /absolute/observation.json \
  --bundle-root /absolute/signed-bundle \
  --verification-time 2026-09-02T12:00:00Z \
  --output /absolute/new-receipt.json
```

The output path must not exist. A canonical immutable `VERIFIED` receipt is
published atomically only after every check passes. Failures emit one bounded
reason code and leave the output absent. The Helm chart follows the same model:
read-only request, observation, and signed-bundle/trust inputs; one size-bounded
writable receipt volume; no service-account token, RBAC, Service, or egress.

Evidence axes remain separate: OP-002 proves source and offline verification.
Artifact publication, installation, deployment, runtime, assurance, and tenant
acceptance remain `NOT_RUN_NOT_IN_PACKET`.
