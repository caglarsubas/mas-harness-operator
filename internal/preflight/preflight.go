package preflight

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Request struct {
	SchemaVersion         string   `json:"schemaVersion"`
	Platform              string   `json:"platform"`
	MinimumVersion        string   `json:"minimumVersion"`
	MaximumVersion        string   `json:"maximumVersion"`
	Architecture          string   `json:"architecture"`
	StorageClass          string   `json:"storageClass"`
	MinimumCPUMilli       int64    `json:"minimumCpuMilli"`
	MinimumMemoryBytes    int64    `json:"minimumMemoryBytes"`
	MinimumEphemeralBytes int64    `json:"minimumEphemeralBytes"`
	Connectivity          string   `json:"connectivity"`
	SandboxRequired       bool     `json:"sandboxRequired"`
	SelectedModules       []string `json:"selectedModules"`
	ProfileDigest         string   `json:"profileDigest"`
	BundleDigest          string   `json:"bundleDigest"`
	ReleaseDigest         string   `json:"releaseDigest"`
}

type Observation struct {
	SchemaVersion             string   `json:"schemaVersion"`
	Platform                  string   `json:"platform"`
	Version                   string   `json:"version"`
	Architecture              string   `json:"architecture"`
	StorageClasses            []string `json:"storageClasses"`
	AllocatableCPUMilli       int64    `json:"allocatableCpuMilli"`
	AllocatableMemoryBytes    int64    `json:"allocatableMemoryBytes"`
	AllocatableEphemeralBytes int64    `json:"allocatableEphemeralBytes"`
	Connectivity              string   `json:"connectivity"`
	SandboxAvailable          bool     `json:"sandboxAvailable"`
	ProfileDigest             string   `json:"profileDigest"`
	BundleDigest              string   `json:"bundleDigest"`
	ReleaseDigest             string   `json:"releaseDigest"`
}

type Condition struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	ReasonCode string `json:"reasonCode"`
}

type Result struct {
	SchemaVersion     string      `json:"schemaVersion"`
	State             string      `json:"state"`
	RequestDigest     string      `json:"requestDigest"`
	ObservationDigest string      `json:"observationDigest"`
	Conditions        []Condition `json:"conditions"`
}

var conditionOrder = []string{
	"PLATFORM_SUPPORTED", "ARCHITECTURE_MATCHED", "VERSION_SUPPORTED",
	"CAPACITY_AVAILABLE", "STORAGE_AVAILABLE", "NETWORK_MODE_MATCHED",
	"SANDBOX_AVAILABLE", "LOCK_BINDINGS_MATCHED",
}

func canonicalDigest(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validateRequest(request Request) error {
	if request.SchemaVersion != "harness.planeon.ai/preflight-request/v1alpha1" {
		return errors.New("PREFLIGHT_REQUEST_SCHEMA_INVALID")
	}
	if !oneOf(request.Platform, "kubernetes", "openshift", "k3s") || !oneOf(request.Architecture, "amd64", "arm64") || !oneOf(request.Connectivity, "connected", "bridge", "silo", "airgap") {
		return errors.New("PREFLIGHT_REQUEST_ENUM_INVALID")
	}
	if _, _, err := version(request.MinimumVersion); err != nil {
		return errors.New("PREFLIGHT_VERSION_INVALID")
	}
	if _, _, err := version(request.MaximumVersion); err != nil {
		return errors.New("PREFLIGHT_VERSION_INVALID")
	}
	if compareVersion(request.MinimumVersion, request.MaximumVersion) > 0 {
		return errors.New("PREFLIGHT_VERSION_RANGE_INVALID")
	}
	if request.StorageClass == "" || request.MinimumCPUMilli < 1 || request.MinimumMemoryBytes < 1 || request.MinimumEphemeralBytes < 1 {
		return errors.New("PREFLIGHT_CAPACITY_INVALID")
	}
	if len(request.SelectedModules) == 0 || !sortedUnique(request.SelectedModules) {
		return errors.New("PREFLIGHT_MODULES_INVALID")
	}
	for _, digest := range []string{request.ProfileDigest, request.BundleDigest, request.ReleaseDigest} {
		if !digestPattern.MatchString(digest) {
			return errors.New("PREFLIGHT_LOCK_INVALID")
		}
	}
	return nil
}

func validateObservation(observation Observation) error {
	if observation.SchemaVersion != "harness.planeon.ai/environment-observation/v1alpha1" {
		return errors.New("OBSERVATION_SCHEMA_INVALID")
	}
	if !oneOf(observation.Platform, "kubernetes", "openshift", "k3s") || !oneOf(observation.Architecture, "amd64", "arm64") || !oneOf(observation.Connectivity, "connected", "bridge", "silo", "airgap") {
		return errors.New("OBSERVATION_ENUM_INVALID")
	}
	if _, _, err := version(observation.Version); err != nil || !sortedUnique(observation.StorageClasses) || observation.AllocatableCPUMilli < 0 || observation.AllocatableMemoryBytes < 0 || observation.AllocatableEphemeralBytes < 0 {
		return errors.New("OBSERVATION_VALUE_INVALID")
	}
	for _, digest := range []string{observation.ProfileDigest, observation.BundleDigest, observation.ReleaseDigest} {
		if !digestPattern.MatchString(digest) {
			return errors.New("OBSERVATION_LOCK_INVALID")
		}
	}
	return nil
}

func Evaluate(request Request, observation Observation) (Result, error) {
	if err := validateRequest(request); err != nil {
		return Result{}, err
	}
	if err := validateObservation(observation); err != nil {
		return Result{}, err
	}
	conditions := map[string]Condition{}
	add := func(name string, passed bool, failedReason string) {
		condition := Condition{Name: name, Status: "PASS", ReasonCode: name}
		if !passed {
			condition.Status = "BLOCKED"
			condition.ReasonCode = failedReason
		}
		conditions[name] = condition
	}
	add("PLATFORM_SUPPORTED", request.Platform == observation.Platform, "PLATFORM_MISMATCH")
	add("ARCHITECTURE_MATCHED", request.Architecture == observation.Architecture, "ARCHITECTURE_MISMATCH")
	add("VERSION_SUPPORTED", compareVersion(observation.Version, request.MinimumVersion) >= 0 && compareVersion(observation.Version, request.MaximumVersion) <= 0, "VERSION_UNSUPPORTED")
	add("CAPACITY_AVAILABLE", observation.AllocatableCPUMilli >= request.MinimumCPUMilli && observation.AllocatableMemoryBytes >= request.MinimumMemoryBytes && observation.AllocatableEphemeralBytes >= request.MinimumEphemeralBytes, "CAPACITY_INSUFFICIENT")
	add("STORAGE_AVAILABLE", contains(observation.StorageClasses, request.StorageClass), "STORAGE_CLASS_UNAVAILABLE")
	add("NETWORK_MODE_MATCHED", request.Connectivity == observation.Connectivity, "NETWORK_MODE_MISMATCH")
	add("SANDBOX_AVAILABLE", !request.SandboxRequired || observation.SandboxAvailable, "SANDBOX_UNAVAILABLE")
	add("LOCK_BINDINGS_MATCHED", request.ProfileDigest == observation.ProfileDigest && request.BundleDigest == observation.BundleDigest && request.ReleaseDigest == observation.ReleaseDigest, "LOCK_BINDING_MISMATCH")
	ordered := make([]Condition, 0, len(conditionOrder))
	state := "PASS"
	for _, name := range conditionOrder {
		ordered = append(ordered, conditions[name])
		if conditions[name].Status != "PASS" {
			state = "BLOCKED"
		}
	}
	requestDigest, err := canonicalDigest(request)
	if err != nil {
		return Result{}, fmt.Errorf("PREFLIGHT_DIGEST_FAILED: %w", err)
	}
	observationDigest, err := canonicalDigest(observation)
	if err != nil {
		return Result{}, fmt.Errorf("PREFLIGHT_DIGEST_FAILED: %w", err)
	}
	return Result{SchemaVersion: "harness.planeon.ai/preflight-result/v1alpha1", State: state, RequestDigest: requestDigest, ObservationDigest: observationDigest, Conditions: ordered}, nil
}

func oneOf(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}

func sortedUnique(values []string) bool {
	if !sort.StringsAreSorted(values) {
		return false
	}
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return false
		}
	}
	return true
}

func contains(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

func version(value string) (int, int, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return 0, 0, errors.New("version must be major.minor")
	}
	major, firstErr := strconv.Atoi(parts[0])
	minor, secondErr := strconv.Atoi(parts[1])
	if firstErr != nil || secondErr != nil || major < 1 || minor < 0 || strconv.Itoa(major) != parts[0] || strconv.Itoa(minor) != parts[1] {
		return 0, 0, errors.New("version is not canonical")
	}
	return major, minor, nil
}

func compareVersion(left, right string) int {
	leftMajor, leftMinor, _ := version(left)
	rightMajor, rightMinor, _ := version(right)
	if leftMajor != rightMajor {
		return leftMajor - rightMajor
	}
	return leftMinor - rightMinor
}
