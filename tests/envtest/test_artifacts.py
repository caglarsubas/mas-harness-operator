from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class ArtifactTests(unittest.TestCase):
    def test_crd_is_namespaced_structural_and_status_separated(self) -> None:
        crd = yaml.safe_load((ROOT / "config/crd/harness.planeon.ai_harnessinstallations.yaml").read_text(encoding="utf-8"))
        self.assertEqual(crd["kind"], "CustomResourceDefinition")
        self.assertEqual(crd["spec"]["scope"], "Namespaced")
        self.assertEqual(crd["spec"]["names"]["kind"], "HarnessInstallation")
        version = crd["spec"]["versions"][0]
        self.assertEqual(version["name"], "v1alpha1")
        self.assertEqual(version["subresources"], {"status": {}})
        schema = version["schema"]["openAPIV3Schema"]["properties"]
        spec = schema["spec"]
        self.assertNotIn("state", spec["properties"])
        self.assertEqual(
            set(spec["required"]),
            {"organizationId", "harnessId", "profileDigest", "bundleDigest", "releaseDigest", "targetNamespace", "desiredGeneration", "trustRef"},
        )
        self.assertGreaterEqual(len(spec["x-kubernetes-validations"]), 8)
        phases = schema["status"]["properties"]["phase"]["enum"]
        self.assertEqual(len(phases), 16)
        self.assertEqual(len(set(phases)), 16)

    def test_generated_role_is_exact_namespaced_allowlist(self) -> None:
        documents = list(yaml.safe_load_all((ROOT / "config/rbac/role.yaml").read_text(encoding="utf-8")))
        self.assertEqual(len(documents), 1)
        role = documents[0]
        self.assertEqual(role["kind"], "Role")
        self.assertEqual(role["metadata"], {"name": "harness-operator", "namespace": "planeon-system"})
        allowed_groups = {"", "coordination.k8s.io", "harness.planeon.ai"}
        allowed_resources = {"events", "leases", "harnessinstallations", "harnessinstallations/status", "harnessinstallations/finalizers"}
        for rule in role["rules"]:
            self.assertTrue(set(rule["apiGroups"]) <= allowed_groups)
            self.assertTrue(set(rule["resources"]) <= allowed_resources)
            self.assertNotIn("*", rule["verbs"])
            self.assertFalse({"delete", "deletecollection", "bind", "escalate", "impersonate"} & set(rule["verbs"]))
        serialized = json.dumps(role)
        for denied in ("secrets", "nodes", "namespaces", "clusterroles", "pods/exec", "serviceaccounts/token"):
            self.assertNotIn(denied, serialized)

    def test_chart_and_image_are_hardened(self) -> None:
        values = yaml.safe_load((ROOT / "deploy/helm/operator/values.yaml").read_text(encoding="utf-8"))
        self.assertRegex(values["image"], r"@sha256:[0-9a-f]{64}$")
        self.assertNotEqual(values["watchNamespace"], "default")
        template = (ROOT / "deploy/helm/operator/templates/resources.yaml").read_text(encoding="utf-8")
        for required in (
            "kind: ServiceAccount", "kind: Role", "kind: RoleBinding", "kind: Deployment", "kind: Service",
            "automountServiceAccountToken: false", "runAsNonRoot: true", "type: RuntimeDefault",
            "allowPrivilegeEscalation: false", "readOnlyRootFilesystem: true", 'drop: ["ALL"]', "sizeLimit: 32Mi",
            "serviceAccountToken:", "expirationSeconds: 3600", "name: kube-root-ca.crt", "readOnly: true",
        ):
            self.assertIn(required, template)
        for denied in ("kind: ClusterRole", "kind: Namespace", "hostPath:", "privileged: true", "hostNetwork:", "hostPID:", "hostIPC:", "type: Load" + "Balancer", "type: Node" + "Port"):
            self.assertNotIn(denied, template)
        containerfile = (ROOT / "Containerfile").read_text(encoding="utf-8")
        self.assertIn("FROM scratch", containerfile)
        self.assertIn("USER 65532:65532", containerfile)
        self.assertNotIn("\nRUN ", containerfile)
        self.assertNotIn("\nADD ", containerfile)

    def test_evidence_axes_remain_honest(self) -> None:
        status = json.loads((ROOT / "tests/envtest/evidence-status.json").read_text(encoding="utf-8"))
        self.assertEqual(status["socketFreeControllerRuntime"], "PASS")
        self.assertEqual(status["realEnvtest"], "NOT_RUN_ENV_UNAVAILABLE")
        for axis in ("artifactPublication", "imageBuild", "installation", "deployment", "runtime", "assurance", "tenantAcceptance"):
            self.assertEqual(status[axis], "NOT_RUN_NOT_IN_PACKET")


if __name__ == "__main__":
    unittest.main()
