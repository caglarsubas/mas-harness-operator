package verify

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fixtureRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", "..", "fixtures", "preflight", "signed-valid"))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func cloneObject(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestSupplyChainPolicyIsClosed(t *testing.T) {
	valid := map[string]any{
		"components": []any{map[string]any{
			"artifactDigest": "sha256:" + strings.Repeat("a", 64), "kind": "oci-image", "moduleId": "runtime-infrastructure", "platform": "linux/arm64",
			"sbomDigest": "sha256:" + strings.Repeat("b", 64), "license": map[string]any{"decision": "ACCEPTED", "expression": "Apache-2.0"}, "vulnerabilities": []any{},
		}},
		"models": []any{map[string]any{"decision": "ACCEPTED", "modelId": "model.none"}},
	}
	if err := validateSupplyChain(valid); err != nil {
		t.Fatal(err)
	}
	unlicensed := cloneObject(t, valid)
	unlicensed["components"].([]any)[0].(map[string]any)["license"].(map[string]any)["decision"] = "REJECTED"
	if reason := Reason(validateSupplyChain(unlicensed)); reason != "LICENSE_NOT_ACCEPTED" {
		t.Fatalf("unlicensed reason=%s", reason)
	}
	vulnerable := cloneObject(t, valid)
	vulnerable["components"].([]any)[0].(map[string]any)["vulnerabilities"] = []any{map[string]any{"disposition": "ACCEPTED_RISK", "id": "CVE-TEST", "severity": "CRITICAL"}}
	if reason := Reason(validateSupplyChain(vulnerable)); reason != "VULNERABILITY_UNRESOLVED" {
		t.Fatalf("vulnerability reason=%s", reason)
	}
	unacceptedModel := cloneObject(t, valid)
	unacceptedModel["models"].([]any)[0].(map[string]any)["decision"] = "REJECTED"
	if reason := Reason(validateSupplyChain(unacceptedModel)); reason != "MODEL_CUSTODY_NOT_ACCEPTED" {
		t.Fatalf("model reason=%s", reason)
	}
}

func TestTrustRoleTimeAndRevocationFailClosed(t *testing.T) {
	trust, _, err := readObject(fixtureRoot(t), "trust-bundle.json", []string{"keys", "revocations", "schemaVersion", "sequence", "trustBundleDigest"})
	if err != nil {
		t.Fatal(err)
	}
	when, _ := time.Parse(time.RFC3339, "2026-09-02T12:00:00Z")
	keys, _, err := validateTrust(fixtureRoot(t), trust, when)
	if err != nil || len(keys) != 2 {
		t.Fatalf("valid trust failed: %v", err)
	}
	wrongRole := cloneObject(t, trust)
	wrongRole["keys"].([]any)[0].(map[string]any)["roles"] = []any{"UNKNOWN"}
	if reason := Reason(func() error { _, _, err := validateTrust(fixtureRoot(t), wrongRole, when); return err }()); reason != "TRUST_KEYS_INVALID" {
		t.Fatalf("wrong role reason=%s", reason)
	}
	expired := cloneObject(t, trust)
	expired["keys"].([]any)[0].(map[string]any)["notAfter"] = "2026-09-02T12:00:00Z"
	if reason := Reason(func() error { _, _, err := validateTrust(fixtureRoot(t), expired, when); return err }()); reason != "TRUST_KEYS_INVALID" {
		t.Fatalf("expired reason=%s", reason)
	}
	revoked := cloneObject(t, trust)
	releaseID := ""
	for _, raw := range revoked["keys"].([]any) {
		key := raw.(map[string]any)
		roles, _ := stringList(key["roles"])
		if contains(roles, "BUNDLE_RELEASE") {
			releaseID = stringValue(key, "keyId")
		}
	}
	revoked["revocations"] = []any{map[string]any{"effectiveAt": "2026-09-02T12:00:00Z", "keyId": releaseID, "reasonDigest": "sha256:" + strings.Repeat("c", 64)}}
	remaining, _, err := validateTrust(fixtureRoot(t), revoked, when)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := remaining[releaseID]; exists {
		t.Fatal("effective revocation retained release key")
	}
}

func TestMutableComponentReferenceIsRejected(t *testing.T) {
	artifact := "sha256:" + strings.Repeat("a", 64)
	locked := map[string]any{"components": []any{map[string]any{"artifactDigest": artifact, "kind": "oci-image", "moduleId": "runtime-infrastructure", "platform": "linux/arm64", "reference": "operator.local/runtime-infrastructure:latest"}}}
	evidence := map[string]any{"components": []any{map[string]any{"artifactDigest": artifact, "kind": "oci-image", "license": map[string]any{"decision": "ACCEPTED", "expression": "Apache-2.0"}, "moduleId": "runtime-infrastructure", "platform": "linux/arm64", "sbomDigest": artifact, "vulnerabilities": []any{}}}}
	if reason := Reason(validateReleaseSubjects(locked, evidence)); reason != "COMPONENT_SET_INVALID" {
		t.Fatalf("mutable reference reason=%s", reason)
	}
}
