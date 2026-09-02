# Planeon Harness Operator

The Planeon Harness Operator is the installation boundary for the modular
multi-agent harness platform. `OP-001` provides a namespaced
`HarnessInstallation` API, an exact projection to the public lifecycle
contract, and a non-mutating controller-runtime shell.

This phase does not apply tenant workloads. Bundle preflight belongs to
`OP-002`; foundation reconciliation belongs to `OP-003`. The signed acceptance
rail is socket-free and reports real Kubernetes envtest, deployment, runtime,
assurance, and tenant acceptance as `NOT_RUN_ENV_UNAVAILABLE` or
`NOT_RUN_NOT_IN_PACKET`.

## Local verification

Only the root-owned launcher is authoritative:

```text
GITHUB_WORKSPACE=/opt/planeon/runner-work/<checkout> /opt/planeon/bin/harness-offline-launch
```

It executes the hash-pinned packet with outbound and loopback networking
denied. No cloud resource, hosted runner, paid API, API key, remote telemetry,
runtime download, Actions artifact/cache/package, or registry mutation is
required.
