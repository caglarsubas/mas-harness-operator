# Sol-High product execution rules

1. Implement exactly one hash-pinned task packet per branch and pull request.
2. Touch only that packet's `allowedPaths` and preserve every predecessor.
3. Never mount, open, copy, or modify a warm-start checkout during product work.
4. Product commands run only through the preinstalled root-owned trusted
   launcher and closed direct-argv dispatcher.
5. The bootstrap packet alone owns `Makefile`, `ci/run_make_target.py`, and the
   inert `PORTING.yaml` ledger. Later packets add only their exact descriptor.
6. Never add hosted runners, cloud provisioning, API-key requirements, runtime
   downloads, mutable references, external telemetry, Actions caches,
   packages, uploaded artifacts, or billable brokers.
7. Keep source, CI, merge, exact-main, artifact, deployment, runtime, assurance,
   and tenant acceptance as separate evidence states.
8. Merge only after every required fresh ephemeral self-hosted check is green.
