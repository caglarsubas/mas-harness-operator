#!/usr/bin/env python3
"""Fail closed on executable billing, hosted-runner, download, or telemetry paths."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) == 2 else ".").resolve()
errors: list[str] = []


def require(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


# Acceptance runs only in the owner-operated verifier (HE-000, owner decisions VX1-VX4): any workflow file is a hosted
# or self-hosted Actions path, and so a billing vector.
workflows = ROOT / ".github/workflows"
require(not workflows.exists() or not any(workflows.iterdir()), "a GitHub Actions workflow exists")

containerfile = (ROOT / "Containerfile").read_text(encoding="utf-8")
require(not re.search(r"(?m)^\s*(RUN|ADD)\s", containerfile), "Containerfile may not install or download")
require("FROM scratch" in containerfile, "Containerfile base is not local scratch")

descriptor = json.loads((ROOT / "ci/targets/op-001.json").read_text(encoding="utf-8"))
serialized = json.dumps(descriptor, sort_keys=True).casefold()
for forbidden in ("curl", "wget", "docker", "podman", "kubectl", "helm", "npx", "npm", "pip", "go get", "go install", "download", "upload"):
    require(forbidden not in serialized, f"target descriptor contains forbidden executable/token: {forbidden}")

for path in sorted(ROOT.rglob("*")):
    if not path.is_file() or ".git" in path.parts or "target" in path.parts or "__pycache__" in path.parts or path.name in {"LICENSE", "go.sum"}:
        continue
    if path.resolve() == Path(__file__).resolve():
        continue
    if path.suffix not in {".go", ".py", ".sh", ".yaml", ".yml", ".json", ".rs", ".toml"} and path.name not in {"Containerfile", "Makefile"}:
        continue
    text = path.read_text(encoding="utf-8")
    for pattern in (r"AKIA[0-9A-Z]{16}", r"(?i)(api[_-]?key|secret[_-]?key)\s*[:=]\s*['\"][^'\"]+", r"(?i)OTEL_EXPORTER_OTLP_ENDPOINT", r"(?i)LoadBalancer", r"(?i)NodePort"):
        if re.search(pattern, text):
            errors.append(f"{path.relative_to(ROOT)} contains prohibited executable configuration: {pattern}")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)
print("zero-bill scan passed: local-only tools, owner-operated verifier only, no paid/API-key/cloud/runtime-download path")
