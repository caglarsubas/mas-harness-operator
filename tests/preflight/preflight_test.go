package preflight_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/caglarsubas/mas-harness-operator/internal/preflight"
)

func fixture(t *testing.T, name string, target any) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "fixtures", "preflight", name))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatal(err)
	}
}

func load(t *testing.T) (preflight.Request, preflight.Observation) {
	var request preflight.Request
	var observation preflight.Observation
	fixture(t, "request.json", &request)
	fixture(t, "observation-supported.json", &observation)
	return request, observation
}

func TestSupportedFixtureIsDeterministic(t *testing.T) {
	request, observation := load(t)
	first, err := preflight.Evaluate(request, observation)
	if err != nil {
		t.Fatal(err)
	}
	second, err := preflight.Evaluate(request, observation)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || first.State != "PASS" || len(first.Conditions) != 8 {
		t.Fatalf("unexpected result: %+v", first)
	}
	firstBytes, _ := json.Marshal(first)
	secondBytes, _ := json.Marshal(second)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("result encoding changed across identical evaluations")
	}
	for _, condition := range first.Conditions {
		if condition.Status != "PASS" {
			t.Fatalf("condition blocked: %+v", condition)
		}
	}
}

func TestSupportedPlatformArchitectureAndVersionMatrix(t *testing.T) {
	request, observation := load(t)
	for _, platform := range []string{"k3s", "kubernetes", "openshift"} {
		for _, architecture := range []string{"amd64", "arm64"} {
			for _, version := range []string{request.MinimumVersion, request.MaximumVersion} {
				t.Run(platform+"-"+architecture+"-"+version, func(t *testing.T) {
					candidateRequest, candidateObservation := request, observation
					candidateRequest.SelectedModules = append([]string(nil), request.SelectedModules...)
					candidateObservation.StorageClasses = append([]string(nil), observation.StorageClasses...)
					candidateRequest.Platform, candidateObservation.Platform = platform, platform
					candidateRequest.Architecture, candidateObservation.Architecture = architecture, architecture
					candidateObservation.Version = version
					result, err := preflight.Evaluate(candidateRequest, candidateObservation)
					if err != nil || result.State != "PASS" {
						t.Fatalf("supported combination blocked: %+v err=%v", result, err)
					}
				})
			}
		}
	}
}

func TestEveryMismatchBlocks(t *testing.T) {
	request, supported := load(t)
	vectors := []struct {
		name, reason string
		mutate       func(*preflight.Observation)
	}{
		{"platform", "PLATFORM_MISMATCH", func(v *preflight.Observation) { v.Platform = "kubernetes" }},
		{"architecture", "ARCHITECTURE_MISMATCH", func(v *preflight.Observation) { v.Architecture = "amd64" }},
		{"version-low", "VERSION_UNSUPPORTED", func(v *preflight.Observation) { v.Version = "1.34" }},
		{"version-high", "VERSION_UNSUPPORTED", func(v *preflight.Observation) { v.Version = "1.38" }},
		{"cpu", "CAPACITY_INSUFFICIENT", func(v *preflight.Observation) { v.AllocatableCPUMilli = 1999 }},
		{"memory", "CAPACITY_INSUFFICIENT", func(v *preflight.Observation) { v.AllocatableMemoryBytes = 1 }},
		{"ephemeral", "CAPACITY_INSUFFICIENT", func(v *preflight.Observation) { v.AllocatableEphemeralBytes = 1 }},
		{"storage", "STORAGE_CLASS_UNAVAILABLE", func(v *preflight.Observation) { v.StorageClasses = []string{"odf"} }},
		{"network", "NETWORK_MODE_MISMATCH", func(v *preflight.Observation) { v.Connectivity = "silo" }},
		{"sandbox", "SANDBOX_UNAVAILABLE", func(v *preflight.Observation) { v.SandboxAvailable = false }},
		{"lock", "LOCK_BINDING_MISMATCH", func(v *preflight.Observation) {
			v.ReleaseDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		}},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			candidate := supported
			candidate.StorageClasses = append([]string(nil), supported.StorageClasses...)
			vector.mutate(&candidate)
			result, err := preflight.Evaluate(request, candidate)
			if err != nil {
				t.Fatal(err)
			}
			if result.State != "BLOCKED" {
				t.Fatal("mismatch passed")
			}
			found := false
			for _, condition := range result.Conditions {
				found = found || condition.ReasonCode == vector.reason
			}
			if !found {
				t.Fatalf("missing reason %s: %+v", vector.reason, result)
			}
		})
	}
}

func TestMalformedInputsFailClosed(t *testing.T) {
	request, observation := load(t)
	badRequest := request
	badRequest.SelectedModules = []string{"z", "a"}
	if _, err := preflight.Evaluate(badRequest, observation); err == nil {
		t.Fatal("unsorted modules accepted")
	}
	badObservation := observation
	badObservation.Version = "01.36"
	if _, err := preflight.Evaluate(request, badObservation); err == nil {
		t.Fatal("noncanonical version accepted")
	}
	badObservation = observation
	badObservation.StorageClasses = []string{"odf", "odf"}
	if _, err := preflight.Evaluate(request, badObservation); err == nil {
		t.Fatal("duplicate storage class accepted")
	}
	badRequest = request
	badRequest.MinimumCPUMilli = 0
	if _, err := preflight.Evaluate(badRequest, observation); err == nil {
		t.Fatal("missing capacity requirement accepted")
	}
	badObservation = observation
	badObservation.AllocatableMemoryBytes = -1
	if _, err := preflight.Evaluate(request, badObservation); err == nil {
		t.Fatal("negative observed quantity accepted")
	}
}
