from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class FoundationSecurityTests(unittest.TestCase):
    def test_fixture_is_namespaced_and_contains_the_exact_baseline(self) -> None:
        plan = json.loads((ROOT / "fixtures/foundation/valid-plan.json").read_text(encoding="utf-8"))
        self.assertNotEqual(plan["targetNamespace"], "default")
        self.assertEqual([wave["id"] for wave in plan["waves"]], ["foundation-baseline"])
        resources = plan["waves"][0]["resources"]
        self.assertEqual(
            sorted(resource["identity"]["kind"] for resource in resources),
            ["LimitRange", "NetworkPolicy", "ResourceQuota", "Role", "RoleBinding", "ServiceAccount"],
        )
        self.assertTrue(all(resource["identity"]["namespace"] == plan["targetNamespace"] for resource in resources))
        serialized = json.dumps(plan, sort_keys=True)
        for denied in ('"kind": "Namespace"', '"kind": "Secret"', '"kind": "ClusterRole"', '"kind": "Pod"', '"kind": "Deployment"', '"delete"', '"*"'):
            self.assertNotIn(denied, serialized)

    def test_engine_has_no_shell_cluster_client_or_force_path(self) -> None:
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for directory in ("internal/apply", "internal/inventory", "internal/evidence", "internal/controller/foundation")
            for path in sorted((ROOT / directory).glob("*.go"))
            if not path.name.endswith("_test.go")
        )
        for denied in ("os/exec", "exec.Command", "kubectl", "helm ", "Force: true", "DryRun: true", "client.Delete", "Namespace{"):
            self.assertNotIn(denied, sources)
        self.assertIn('FieldManager = "planeon-foundation-v1"', sources)
        self.assertIn("Force: false", sources)
        self.assertIn("DryRun: false", sources)

    def test_descriptor_is_local_direct_argv_only(self) -> None:
        descriptor = (ROOT / "ci/targets/op-003.json").read_text(encoding="utf-8").casefold()
        for denied in ("curl", "wget", "docker", "podman", "kubectl", "helm", "npx", "npm", "pip", "download", "upload", '"sh"', '"bash"'):
            self.assertNotIn(denied, descriptor)

    def test_evidence_axes_remain_separate(self) -> None:
        status = json.loads((ROOT / "fixtures/foundation/evidence-status.json").read_text(encoding="utf-8"))
        self.assertEqual(status["socketFreeReconciliation"], "PASS")
        self.assertEqual(status["liveKubernetesApply"], "NOT_RUN_ENV_UNAVAILABLE")
        self.assertEqual(status["installation"], "NOT_RUN_ENV_UNAVAILABLE")
        for axis in ("artifactPublication", "imageBuild", "deployment", "runtime", "assurance", "tenantAcceptance"):
            self.assertEqual(status[axis], "NOT_RUN_NOT_IN_PACKET")


if __name__ == "__main__":
    unittest.main()
