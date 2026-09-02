#!/usr/bin/env python3
"""Validation-only OP-001 prefetch; never installs or contacts a network."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = "226bad09b724e0e7f560fc5e6aa51382ef2d1e58"
PACKET_SHA256 = "9a64698615c1c1fa8ef899b50495d5249bec0a877f0e7f7a92e9058ef196b07b"
GO_INVENTORY_SHA256 = "198db2b91046d9b5dd473a78eaad7326c1f378da65bac5bab8a4a0d3038862d1"
MODULE_INVENTORY_SHA256 = "f99a2155f3c7a1ce0c2d5da3cf29b52af4cd8ff7df9640edb593188589b53a83"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"prefetch refused: {message}")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*arguments: str) -> str:
    return subprocess.run(arguments, cwd=ROOT, check=True, shell=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


def main() -> None:
    require("HARNESS_TASK_PACKET" not in os.environ, "packet path leaked to prefetch child")
    require("HARNESS_WARM_SOURCE_ROOTS" not in os.environ, "warm-source roots leaked to prefetch child")
    require(all(os.environ.get(name) == "1" for name in ("UV_OFFLINE", "UV_FROZEN", "UV_NO_SYNC")), "offline UV flags are required")
    require(os.environ.get("GOPROXY") == "off" and os.environ.get("GOSUMDB") == "off", "Go network resolution is not disabled")
    require(os.environ.get("GOTOOLCHAIN") == "local" and os.environ.get("GOWORK") == "off", "Go discovery is not closed")
    require(os.environ.get("GOMODCACHE") == "/opt/planeon/gomodcache/op-001", "module cache path changed")

    lock = json.loads((ROOT / "tools.lock").read_text(encoding="utf-8"))
    require(lock["planningBase"] == BASE, "planning base lock changed")
    require(lock["packet"] == {"id": "OP-001", "sha256": PACKET_SHA256}, "packet lock changed")
    require(lock["tools"]["go"]["inventorySha256"] == GO_INVENTORY_SHA256, "Go inventory authority changed")
    require(lock["tools"]["moduleCache"]["inventorySha256"] == MODULE_INVENTORY_SHA256, "module inventory authority changed")
    require(sha(Path(lock["tools"]["go"]["path"])) == lock["tools"]["go"]["sha256"], "Go binary changed")
    require(sha(Path(lock["tools"]["controllerGen"]["path"])) == lock["tools"]["controllerGen"]["sha256"], "controller-gen changed")
    require(run(lock["tools"]["go"]["path"], "version").startswith("go version go1.26.7 "), "Go version changed")
    require(run(lock["tools"]["controllerGen"]["path"], "--version") == "Version: v0.21.0", "controller-gen version changed")

    roots = run("git", "rev-list", "--max-parents=0", "HEAD").splitlines()
    require(len(roots) == 1 and roots[0] == BASE, "planning seed is not the sole root")
    require(run("git", "merge-base", "--is-ancestor", BASE, "HEAD") == "", "planning base is not an ancestor")

    modules = run(lock["tools"]["go"]["path"], "list", "-mod=readonly", "-m", "all").splitlines()
    module_map = {parts[0]: parts[1] for line in modules if len(parts := line.split()) >= 2}
    for name, version in lock["modules"].items():
        require(module_map.get(name) == version, f"module version changed: {name}")
    subprocess.run(["python3", "ci/validate_porting.py"], cwd=ROOT, check=True, shell=False)
    workflow = (ROOT / ".github/workflows/verify.yml").read_text(encoding="utf-8")
    require("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in workflow, "checkout pin changed")
    require("runs-on: [self-hosted, harness-engineering, ephemeral, credential-free]" in workflow, "runner labels changed")
    print("prefetch passed: exact ancestry, contracts, Go closure, workflow, and inert porting ledger")


if __name__ == "__main__":
    main()
