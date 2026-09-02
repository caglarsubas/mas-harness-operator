#!/usr/bin/env python3
from pathlib import Path

import yaml

root = Path(__file__).resolve().parents[1]
ledger = yaml.safe_load((root / "PORTING.yaml").read_text(encoding="utf-8"))
expected = {
    "schemaVersion": "harness.planeon.ai/porting-ledger/v1alpha1",
    "repository": "mas-harness-operator",
    "authorizationStatus": "NO_AUTHORIZATION",
    "authorizations": [],
    "copiedPaths": [],
}
if ledger != expected:
    raise SystemExit("porting ledger refused: only the NO_AUTHORIZATION sentinel is permitted")
print("porting ledger passed: NO_AUTHORIZATION")
