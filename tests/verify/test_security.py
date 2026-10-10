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
    """The adopted launcher contract (HE-000): harness-onion's runner plus the six rust-host-enforcement names."""

    def test_inline_fields_are_single_json_lines(self) -> None:
        self.assertEqual(transport.load_json_field("prefetchCommands: []\n", "prefetchCommands"), [])
        for text in ("", "prefetchCommands: []\nprefetchCommands: []\n", "prefetchCommands: not-json\n", "prefetchCommands:\n"):
            with self.subTest(text=text), self.assertRaises(transport.PacketTransportError):
                transport.load_json_field(text, "prefetchCommands")

    def test_shell_environment_and_online_argv_are_refused(self) -> None:
        transport.validate_offline_argv(["go", "test", "./..."])
        for argv in (["sh", "-c", "true"], ["/usr/bin/env", "go", "test"], ["bash"], ["go", "install", "x"],
                     ["cargo", "fetch"], ["curl", "https://example.invalid"]):
            with self.subTest(argv=argv), self.assertRaises(transport.PacketTransportError):
                transport.validate_offline_argv(argv)

    def test_mutated_packet_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            packet = Path(raw) / "packet.yaml"
            packet.write_text("id: HE-000B\n", encoding="utf-8")
            expected = hashlib.sha256(packet.read_bytes()).hexdigest()
            transport.verify_packet_digest(packet, expected)
            packet.write_text("id: HE-001\n", encoding="utf-8")
            with self.assertRaises(transport.PacketTransportError):
                transport.verify_packet_digest(packet, expected)

    def test_execution_contract_is_exact(self) -> None:
        self.assertEqual(transport.EXPECTED_EXECUTION["wrapperArgv"], ["./ci/verify-offline.sh"])
        self.assertEqual(transport.EXPECTED_EXECUTION["isolation"], "OS_ENFORCED_DENY_ALL_OUTBOUND")
        self.assertEqual(transport.EXPECTED_EXECUTION["packetPathEnvironment"], transport.PACKET_ENVIRONMENT)
        self.assertEqual(transport.OFFLINE_ENVIRONMENT, {"UV_OFFLINE": "1", "UV_FROZEN": "1", "UV_NO_SYNC": "1"})

    def test_authority_paths_are_not_forwarded_and_profile_names_are(self) -> None:
        allow = transport.CHILD_ENVIRONMENT_ALLOWLIST
        self.assertNotIn(transport.PACKET_ENVIRONMENT, allow)
        self.assertNotIn("HARNESS_WARM_SOURCE_ROOTS", allow)
        self.assertLessEqual({"CARGO_NET_OFFLINE", "GOFLAGS", "GOMODCACHE", "GOPROXY", "GOSUMDB", "GOTOOLCHAIN"}, allow)
        scrubbed = transport.scrub_environment({"HARNESS_TASK_PACKET": "/x", "GOPROXY": "off", "AWS_SECRET_ACCESS_KEY": "k"})
        self.assertEqual(scrubbed, {"GOPROXY": "off"})

    def test_this_suite_never_calls_the_printing_entry_points(self) -> None:
        # The verifier counts every log line starting with its evidence prefixes; the runner's run_commands() and main()
        # print such lines, so this suite never calls them.
        source = Path(__file__).read_text(encoding="utf-8")
        for name in ("run_commands", "main"):
            self.assertNotIn("transport." + name + "(", source)


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
