package foundation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func fixturePlan(t *testing.T) (Plan, []byte) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "fixtures", "foundation", "valid-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, _, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return plan, data
}

func clone(t *testing.T, plan Plan) Plan {
	t.Helper()
	data, _ := json.Marshal(plan)
	var result Plan
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func rewrite(t *testing.T, resource *Resource, mutate func(map[string]any)) {
	t.Helper()
	var manifest map[string]any
	if err := json.Unmarshal(resource.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	mutate(manifest)
	data, _ := json.Marshal(manifest)
	sum := sha256.Sum256(data)
	resource.Manifest = data
	resource.ManifestDigest = "sha256:" + hex.EncodeToString(sum[:])
}

func TestPlanParsingIsCanonicalAndDeterministic(t *testing.T) {
	plan, data := fixturePlan(t)
	first, firstDigest, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	_, secondDigest, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest || len(first.Waves) != 1 || len(first.Waves[0].Resources) != 6 || first.OrganizationID != plan.OrganizationID {
		t.Fatal("plan parse drift")
	}
	if _, _, err := Parse(append(append([]byte{}, data...), '\n')); Reason(err) != "PLAN_JSON_NOT_CANONICAL" {
		t.Fatalf("noncanonical reason=%s", Reason(err))
	}
	var generic map[string]any
	_ = json.Unmarshal(data, &generic)
	generic["unknown"] = true
	unknown, _ := json.Marshal(generic)
	if _, _, err := Parse(unknown); Reason(err) != "PLAN_FIELDS_INVALID" {
		t.Fatalf("unknown reason=%s", Reason(err))
	}
}

func TestPlanNegativeSecurityVectors(t *testing.T) {
	valid, _ := fixturePlan(t)
	vectors := []struct {
		name, want string
		mutate     func(*Plan)
	}{
		{"missing-baseline", "FOUNDATION_BASELINE_MISSING", func(plan *Plan) { plan.Waves[0].ID = "foundation-other" }},
		{"unsorted", "PLAN_RESOURCE_ORDER_INVALID", func(plan *Plan) {
			plan.Waves[0].Resources[0], plan.Waves[0].Resources[1] = plan.Waves[0].Resources[1], plan.Waves[0].Resources[0]
		}},
		{"duplicate", "PLAN_RESOURCE_DUPLICATED", func(plan *Plan) {
			plan.Waves = append(plan.Waves, Wave{ID: "foundation-copy", Resources: []Resource{plan.Waves[0].Resources[0]}})
		}},
		{"cross-namespace", "RESOURCE_SCOPE_INVALID", func(plan *Plan) { plan.Waves[0].Resources[0].Identity.Namespace = "other" }},
		{"default-namespace", "PLAN_NAMESPACE_INVALID", func(plan *Plan) { plan.TargetNamespace = "default" }},
		{"digest-drift", "RESOURCE_MANIFEST_DIGEST_MISMATCH", func(plan *Plan) { plan.Waves[0].Resources[0].ManifestDigest = "sha256:" + string(make([]byte, 64)) }},
		{"wildcard-rbac", "ROLE_WILDCARD_FORBIDDEN", func(plan *Plan) {
			for index := range plan.Waves[0].Resources {
				resource := &plan.Waves[0].Resources[index]
				if resource.Identity.Kind == "Role" {
					rewrite(t, resource, func(manifest map[string]any) {
						rule := manifest["spec"].(map[string]any)["rules"].([]any)[0].(map[string]any)
						rule["verbs"] = []any{"*"}
					})
				}
			}
		}},
		{"service-account-secret-field", "SERVICE_ACCOUNT_INSECURE", func(plan *Plan) {
			for index := range plan.Waves[0].Resources {
				resource := &plan.Waves[0].Resources[index]
				if resource.Identity.Kind == "ServiceAccount" {
					rewrite(t, resource, func(manifest map[string]any) {
						manifest["imagePullSecrets"] = []any{map[string]any{"name": "forbidden"}}
					})
				}
			}
		}},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			candidate := clone(t, valid)
			vector.mutate(&candidate)
			if reason := Reason(ValidatePlan(candidate)); reason != vector.want {
				t.Fatalf("reason=%s want=%s", reason, vector.want)
			}
		})
	}
}

func TestForbiddenKindsAndMutableConfigurationAreRejected(t *testing.T) {
	valid, _ := fixturePlan(t)
	secretManifest := map[string]any{"apiVersion": "v1", "data": map[string]any{"token": "redacted"}, "kind": "Secret", "metadata": map[string]any{"name": "forbidden", "namespace": valid.TargetNamespace}}
	secretBytes, _ := json.Marshal(secretManifest)
	secretSum := sha256.Sum256(secretBytes)
	secret := Resource{Identity: valid.Waves[0].Resources[0].Identity, Manifest: secretBytes, ManifestDigest: "sha256:" + hex.EncodeToString(secretSum[:])}
	secret.Identity.APIVersion = "v1"
	secret.Identity.Kind = "Secret"
	secret.Identity.Name = "forbidden"
	candidate := clone(t, valid)
	candidate.Waves = append(candidate.Waves, Wave{ID: "foundation-forbidden", Resources: []Resource{secret}})
	if reason := Reason(ValidatePlan(candidate)); reason != "RESOURCE_KIND_FORBIDDEN" {
		t.Fatalf("secret reason=%s", reason)
	}

	configManifest := map[string]any{"apiVersion": "v1", "data": map[string]any{"image": "registry.local/component:latest"}, "kind": "ConfigMap", "metadata": map[string]any{"name": "mutable", "namespace": valid.TargetNamespace}}
	configBytes, _ := json.Marshal(configManifest)
	configSum := sha256.Sum256(configBytes)
	config := Resource{Identity: valid.Waves[0].Resources[0].Identity, Manifest: configBytes, ManifestDigest: "sha256:" + hex.EncodeToString(configSum[:])}
	config.Identity.APIVersion = "v1"
	config.Identity.Kind = "ConfigMap"
	config.Identity.Name = "mutable"
	candidate = clone(t, valid)
	candidate.Waves = append(candidate.Waves, Wave{ID: "foundation-config", Resources: []Resource{config}})
	if reason := Reason(ValidatePlan(candidate)); reason != "CONFIG_MAP_INVALID" {
		t.Fatalf("mutable config reason=%s", reason)
	}
}
