# Sol-High product execution rules

1. Implement exactly one hash-pinned task packet per branch and pull request.
2. Touch only that packet's `allowedPaths` and preserve every predecessor.
   Packets are never removed or reverted; a fix is a new packet.
3. Never mount, open, copy, or modify a warm-start checkout during product work.
4. Product commands run only through the preinstalled root-owned trusted
   launcher and closed direct-argv dispatcher.
5. `PORTING.yaml` stays the NO_AUTHORIZATION sentinel. `Makefile`,
   `ci/run_make_target.py` and the OP descriptors change only through an
   owner-decided packet (HE-000B retired the `prefetch` target, owner decision
   Q-HE3). Acceptance is each packet's `task-packets/<ID>.yaml`, run by the
   owner-operated verifier (owner decisions VX1-VX4); HE packets add no make
   descriptor.
6. Never add hosted runners, cloud provisioning, API-key requirements, runtime
   downloads, mutable references, external telemetry, Actions caches,
   packages, uploaded artifacts, or billable brokers.
7. Keep source, CI, merge, exact-main, artifact, deployment, runtime, assurance,
   and tenant acceptance as separate evidence states.
8. Merge only after every required fresh ephemeral self-hosted check is green.
