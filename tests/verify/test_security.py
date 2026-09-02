from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("packet_transport", ROOT / "ci/run_packet_argv.py")
assert SPEC and SPEC.loader
transport = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = transport
SPEC.loader.exec_module(transport)


class TransportTests(unittest.TestCase):
    def test_operator_packet_identity_is_repository_scoped(self) -> None:
        self.assertEqual(transport.packet_identity("id: OP-001\nrepository: mas-harness-operator\n"), "OP-001")
        self.assertEqual(transport.packet_identity("id: OP-002\nrepository: mas-harness-operator\n"), "OP-002")
        for invalid in (
            "id: CTRL-001\nrepository: mas-harness-operator\n",
            "id: OP-002\nrepository: foreign\n",
            "id: OP-002\nid: OP-001\nrepository: mas-harness-operator\n",
            "id: OP-002\nrepository: mas-harness-operator\nrepository: mas-harness-operator\n",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(transport.PacketError):
                transport.packet_identity(invalid)

    def test_shell_transport_and_mutated_packet_are_refused(self) -> None:
        with self.assertRaises(transport.PacketError):
            transport.command_arrays('commands: [["sh","-c","true"]]', "commands")
        with tempfile.TemporaryDirectory() as raw:
            packet = Path(raw) / "packet.yaml"
            packet.write_text("id: OP-002\n", encoding="utf-8")
            expected = hashlib.sha256(packet.read_bytes()).hexdigest()
            packet.write_text("id: OP-003\n", encoding="utf-8")
            with self.assertRaises(transport.PacketError):
                transport.verify_digest(packet, expected)

    def test_authority_paths_and_environment_are_not_forwarded(self) -> None:
        self.assertNotIn(transport.PACKET_ENV, transport.CHILD_ENV)
        self.assertNotIn("HARNESS_WARM_SOURCE_ROOTS", transport.CHILD_ENV)
        self.assertEqual(transport.GO_ENV["GOPROXY"], "off")
        self.assertEqual(transport.GO_ENV["GOSUMDB"], "off")


class SecurityTests(unittest.TestCase):
    def test_verifier_chart_is_digest_only_tokenless_and_non_networked(self) -> None:
        values = (ROOT / "deploy/helm/bundle-verifier/values.yaml").read_text(encoding="utf-8")
        image_line = next(line for line in values.splitlines() if line.startswith("image: "))
        self.assertRegex(image_line, r"@sha256:[0-9a-f]{64}$")
        resources = (ROOT / "deploy/helm/bundle-verifier/templates/resources.yaml").read_text(encoding="utf-8")
        required = (
            "kind: ServiceAccount", "kind: NetworkPolicy", "kind: Job", "automountServiceAccountToken: false",
            "runAsNonRoot: true", "type: RuntimeDefault", "allowPrivilegeEscalation: false",
            "readOnlyRootFilesystem: true", 'drop: ["ALL"]', "readOnly: true", "sizeLimit: 32Mi",
            "--verification-time", "--bundle-root", "--request", "--observation", "--output",
        )
        for item in required:
            self.assertIn(item, resources)
        for denied in ("kind: Role\n", "kind: RoleBinding\n", "kind: ClusterRole\n", "serviceAccountToken:", "\nkind: Service\n", "hostPath:", "hostNetwork:", "privileged: true"):
            self.assertNotIn(denied, resources)

    def test_signed_fixture_contains_no_private_key_and_all_references_are_immutable(self) -> None:
        fixture = ROOT / "fixtures/preflight/signed-valid"
        self.assertFalse(any(path.suffix == ".key" for path in fixture.rglob("*")))
        lock = json.loads((fixture / "bundle.lock.json").read_text(encoding="utf-8"))
        for component in lock["components"]:
            self.assertRegex(component["reference"], r"@sha256:[0-9a-f]{64}$")
            self.assertTrue((fixture / "oci/blobs/sha256" / component["artifactDigest"].removeprefix("sha256:")).is_file())

    def test_packet_descriptor_and_cli_have_no_network_or_shell_path(self) -> None:
        descriptor = (ROOT / "ci/targets/op-002.json").read_text(encoding="utf-8").casefold()
        for denied in ("curl", "wget", "docker", "podman", "kubectl", "helm", "npx", "npm", "pip", "download", "upload", '"sh"', '"bash"'):
            self.assertNotIn(denied, descriptor)
        cli = (ROOT / "cmd/bundle-verifier/main.go").read_text(encoding="utf-8")
        self.assertNotIn("exec.Command", cli)
        verifier = (ROOT / "internal/verify/verify.go").read_text(encoding="utf-8")
        self.assertIn('exec.CommandContext(ctx, CosignPath, "verify-blob"', verifier)
        self.assertIn('"--offline"', verifier)
        self.assertIn('command.Stdin = nil', verifier)


if __name__ == "__main__":
    unittest.main()
