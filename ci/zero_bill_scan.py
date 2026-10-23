#!/usr/bin/env python3
"""Fail closed on executable billing, hosted-runner, download, or telemetry paths."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) == 2 else ".").resolve()
errors: list[str] = []
# Pinned upstream contract files whose own refusal rules name the service types the patterns below refuse (owner decision
# Q-HE4B1-ZB (a), 2026-10-18): the admission-v3 policy refuses LoadBalancer and NodePort services, so its text names them.
# Owner decision Q-I01B1-ZB, 2026-10-23 ("Two exact allowlist entries"): the I01 digest contract's vectors.json, which
# carries that policy's rendered objects, and R10's i01_admission_render.rs, which renders the same policy text from the
# sealed values. Any later edit of the render changes its bytes and must re-pin its entry here in the same packet.
# Exactly these paths with exactly these bytes are exempt from those two patterns only; every other pattern still applies
# to them, and a changed byte, or the same bytes at another path, fails as before.
SERVICE_TYPE_PATTERNS = (r"(?i)LoadBalancer", r"(?i)NodePort")
CONTRACT_ALLOWLIST = {
    "host-enforcement/contracts/admission-v3/admission-manifests/planeon-a2.json":
        "1096b3cc71c4fe6b5a17ed61e8bf8c17ee17fcf52b192503534d60aed9ce4741",
    "host-enforcement/contracts/admission-v3/vectors.json":
        "a3e2dc9818742ae2188e0e83cf91bb833be836115975b3fb23d5f280f6928cc1",
    "host-enforcement/contracts/i01-digests-v1/vectors.json":
        "bd9f04bd04fcccc584bcab341ec649bcead567fe349c57e30958eaaf2ea64f84",
    "host-enforcement/crates/observer/src/i01_admission_render.rs":
        "2e23e488b241cf28c5070174c87790bbdb8e22807b7800de3333148939fdabae",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


# Acceptance runs only in the owner-operated verifier (HE-000, owner decisions VX1-VX4): any workflow file is a hosted
# or self-hosted Actions path, and so a billing vector.
workflows = ROOT / ".github/workflows"
require(not workflows.exists() or (workflows.is_dir() and not any(workflows.iterdir())), "a GitHub Actions workflow exists")

containerfile = (ROOT / "Containerfile").read_text(encoding="utf-8")
require(not re.search(r"(?m)^\s*(RUN|ADD)\s", containerfile), "Containerfile may not install or download")
require("FROM scratch" in containerfile, "Containerfile base is not local scratch")

descriptor = json.loads((ROOT / "ci/targets/op-001.json").read_text(encoding="utf-8"))
serialized = json.dumps(descriptor, sort_keys=True).casefold()
for forbidden in ("curl", "wget", "docker", "podman", "kubectl", "helm", "npx", "npm", "pip", "go get", "go install", "download", "upload"):
    require(forbidden not in serialized, f"target descriptor contains forbidden executable/token: {forbidden}")

for path in sorted(ROOT.rglob("*")):
    if not path.is_file() or {".git", "target", "__pycache__"} & set(path.relative_to(ROOT).parts) or path.name in {"LICENSE", "go.sum"}:
        continue
    if path.resolve() == Path(__file__).resolve():
        continue
    if path.suffix not in {".go", ".py", ".sh", ".yaml", ".yml", ".json", ".rs", ".toml"} and path.name not in {"Containerfile", "Makefile"}:
        continue
    data = path.read_bytes()
    text = data.decode("utf-8")
    pinned = CONTRACT_ALLOWLIST.get(path.relative_to(ROOT).as_posix()) == hashlib.sha256(data).hexdigest()
    for pattern in (r"AKIA[0-9A-Z]{16}", r"(?i)(api[_-]?key|secret[_-]?key)\s*[:=]\s*['\"][^'\"]+", r"(?i)OTEL_EXPORTER_OTLP_ENDPOINT", *SERVICE_TYPE_PATTERNS):
        if pinned and pattern in SERVICE_TYPE_PATTERNS:
            continue
        if re.search(pattern, text):
            errors.append(f"{path.relative_to(ROOT)} contains prohibited executable configuration: {pattern}")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)
print("zero-bill scan passed: local-only tools, owner-operated verifier only, no paid/API-key/cloud/runtime-download path")
