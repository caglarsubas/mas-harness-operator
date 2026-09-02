#!/usr/bin/env python3
"""Regenerate OP-001 artifacts in isolation and compare exact bytes."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATED = (
    Path("api/v1alpha1/zz_generated.deepcopy.go"),
    Path("config/crd/harness.planeon.ai_harnessinstallations.yaml"),
    Path("config/rbac/role.yaml"),
)


class GenerationError(ValueError):
    pass


def compare(path: Path, expected: bytes, actual: bytes) -> None:
    if expected != actual:
        raise GenerationError(f"generated artifact drift: {path}")


def generate(destination: Path) -> None:
    for relative in (Path("go.mod"), Path("go.sum")):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    for source_root in (Path("api/v1alpha1"), Path("internal/controller")):
        for source in sorted((ROOT / source_root).glob("*.go")):
            if source.name == "zz_generated.deepcopy.go" or source.name.endswith("_test.go"):
                continue
            target = destination / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    commands = (
        ["controller-gen", "object", "paths=./api/v1alpha1"],
        ["controller-gen", "crd:crdVersions=v1", "paths=./api/v1alpha1", "output:crd:dir=config/crd"],
        ["controller-gen", "rbac:roleName=harness-operator", "paths=./internal/controller", "output:rbac:dir=config/rbac"],
    )
    for command in commands:
        subprocess.run(command, cwd=destination, env=os.environ, check=True, shell=False)
    role_path = destination / "config/rbac/role.yaml"
    role = role_path.read_text(encoding="utf-8")
    role = role.replace("kind: ClusterRole", "kind: Role", 1)
    role = role.replace("  name: harness-operator\nrules:", "  name: harness-operator\n  namespace: planeon-system\nrules:", 1)
    role_path.write_text(role, encoding="utf-8", newline="\n")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="op001-generate-") as first_raw, tempfile.TemporaryDirectory(prefix="op001-generate-") as second_raw:
        first, second = Path(first_raw), Path(second_raw)
        generate(first)
        generate(second)
        for relative in GENERATED:
            committed = (ROOT / relative).read_bytes()
            first_bytes = (first / relative).read_bytes()
            second_bytes = (second / relative).read_bytes()
            compare(relative, committed, first_bytes)
            compare(relative, first_bytes, second_bytes)
            try:
                compare(relative, committed + b"\n# seeded-drift\n", first_bytes)
            except GenerationError:
                pass
            else:
                raise GenerationError(f"drift detector did not reject: {relative}")
    print("generated check passed: deepcopy, CRD, and namespaced RBAC are byte-identical")


if __name__ == "__main__":
    try:
        main()
    except GenerationError as exc:
        raise SystemExit(str(exc)) from exc
