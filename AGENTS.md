# Product execution boundary

- Implement exactly one hash-pinned task packet per branch and pull request.
- Touch only that packet's `allowedPaths`.
- Never mount, open, copy, or modify a warm-start checkout during product work.
- Use only the preinstalled root-owned trusted offline launcher in CI.
- Never add hosted runners, cloud provisioning, API-key requirements, runtime
  downloads, mutable artifact references, remote telemetry, Actions caches,
  packages, or uploaded artifacts.
- Keep source, CI, merge, exact-main, artifact, deployment, runtime, assurance,
  and tenant acceptance as separate evidence states.
- Merge only after every required ephemeral self-hosted check is green.
