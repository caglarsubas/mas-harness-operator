package foundation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/caglarsubas/mas-harness-operator/internal/apply"
)

const PlanSchemaVersion = "harness.planeon.ai/foundation-plan/v1alpha1"

var (
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	stableIDPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$`)
	dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	waveIDPattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$`)
)

type Plan struct {
	SchemaVersion             string `json:"schemaVersion"`
	OrganizationID            string `json:"organizationId"`
	InstallationID            string `json:"installationId"`
	Generation                int64  `json:"generation"`
	TargetNamespace           string `json:"targetNamespace"`
	ProfileDigest             string `json:"profileDigest"`
	BundleDigest              string `json:"bundleDigest"`
	ReleaseDigest             string `json:"releaseDigest"`
	VerificationReceiptDigest string `json:"verificationReceiptDigest"`
	Waves                     []Wave `json:"waves"`
}

type Wave struct {
	ID        string     `json:"id"`
	Resources []Resource `json:"resources"`
}

type Resource struct {
	Identity       apply.Identity  `json:"identity"`
	ManifestDigest string          `json:"manifestDigest"`
	Manifest       json.RawMessage `json:"manifest"`
}

type Refusal struct{ Code string }

func (refusal Refusal) Error() string { return refusal.Code }

func refuse(code string) error { return Refusal{Code: code} }

func Parse(data []byte) (Plan, string, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var generic map[string]any
	if err := decoder.Decode(&generic); err != nil || generic == nil {
		return Plan{}, "", refuse("PLAN_JSON_INVALID")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Plan{}, "", refuse("PLAN_JSON_INVALID")
	}
	canonical, err := json.Marshal(generic)
	if err != nil || !bytes.Equal(canonical, data) {
		return Plan{}, "", refuse("PLAN_JSON_NOT_CANONICAL")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var plan Plan
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, "", refuse("PLAN_FIELDS_INVALID")
	}
	if err := ValidatePlan(plan); err != nil {
		return Plan{}, "", err
	}
	return plan, digest(data), nil
}

func Digest(plan Plan) string {
	encoded, _ := json.Marshal(plan)
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var generic map[string]any
	_ = decoder.Decode(&generic)
	canonical, _ := json.Marshal(generic)
	return digest(canonical)
}

func ValidatePlan(plan Plan) error {
	if plan.SchemaVersion != PlanSchemaVersion || !stableIDPattern.MatchString(plan.OrganizationID) || !stableIDPattern.MatchString(plan.InstallationID) || plan.Generation < 1 {
		return refuse("PLAN_IDENTITY_INVALID")
	}
	if !validNamespace(plan.TargetNamespace) {
		return refuse("PLAN_NAMESPACE_INVALID")
	}
	for _, value := range []string{plan.ProfileDigest, plan.BundleDigest, plan.ReleaseDigest, plan.VerificationReceiptDigest} {
		if !digestPattern.MatchString(value) {
			return refuse("PLAN_BINDING_INVALID")
		}
	}
	if len(plan.Waves) == 0 || plan.Waves[0].ID != "foundation-baseline" {
		return refuse("FOUNDATION_BASELINE_MISSING")
	}
	previousWave := ""
	identities := map[string]struct{}{}
	baseline := map[string]int{}
	for _, wave := range plan.Waves {
		if !waveIDPattern.MatchString(wave.ID) || wave.ID <= previousWave || len(wave.Resources) == 0 {
			return refuse("PLAN_WAVE_ORDER_INVALID")
		}
		previousWave = wave.ID
		previousResource := ""
		for _, resource := range wave.Resources {
			key := resource.Identity.Key()
			if key <= previousResource {
				return refuse("PLAN_RESOURCE_ORDER_INVALID")
			}
			previousResource = key
			if _, duplicate := identities[key]; duplicate {
				return refuse("PLAN_RESOURCE_DUPLICATED")
			}
			identities[key] = struct{}{}
			if resource.Identity.Namespace != plan.TargetNamespace || !validNamespace(resource.Identity.Namespace) || !validName(resource.Identity.Name) {
				return refuse("RESOURCE_SCOPE_INVALID")
			}
			if err := validateManifest(resource); err != nil {
				return err
			}
			if wave.ID == "foundation-baseline" {
				baseline[resource.Identity.Kind]++
			}
		}
	}
	required := []string{"LimitRange", "NetworkPolicy", "ResourceQuota", "Role", "RoleBinding", "ServiceAccount"}
	if len(plan.Waves[0].Resources) != len(required) {
		return refuse("FOUNDATION_BASELINE_INVALID")
	}
	for _, kind := range required {
		if baseline[kind] != 1 {
			return refuse("FOUNDATION_BASELINE_INVALID")
		}
	}
	return nil
}

func validateManifest(resource Resource) error {
	if !digestPattern.MatchString(resource.ManifestDigest) || digest(resource.Manifest) != resource.ManifestDigest {
		return refuse("RESOURCE_MANIFEST_DIGEST_MISMATCH")
	}
	var manifest map[string]any
	decoder := json.NewDecoder(bytes.NewReader(resource.Manifest))
	decoder.UseNumber()
	if err := decoder.Decode(&manifest); err != nil || manifest == nil {
		return refuse("RESOURCE_MANIFEST_INVALID")
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, resource.Manifest) {
		return refuse("RESOURCE_MANIFEST_INVALID")
	}
	metadata, ok := manifest["metadata"].(map[string]any)
	if !ok || !exactKeys(metadata, []string{"name", "namespace"}) || stringValue(manifest, "apiVersion") != resource.Identity.APIVersion || stringValue(manifest, "kind") != resource.Identity.Kind || stringValue(metadata, "namespace") != resource.Identity.Namespace || stringValue(metadata, "name") != resource.Identity.Name {
		return refuse("RESOURCE_IDENTITY_MISMATCH")
	}
	resourceType := resource.Identity.APIVersion + "/" + resource.Identity.Kind
	allowed := map[string]struct{}{
		"v1/ServiceAccount": {}, "v1/ConfigMap": {}, "v1/ResourceQuota": {}, "v1/LimitRange": {},
		"networking.k8s.io/v1/NetworkPolicy": {}, "rbac.authorization.k8s.io/v1/Role": {}, "rbac.authorization.k8s.io/v1/RoleBinding": {},
	}
	if _, ok := allowed[resourceType]; !ok {
		return refuse("RESOURCE_KIND_FORBIDDEN")
	}
	switch resourceType {
	case "v1/ServiceAccount":
		if !exactKeys(manifest, []string{"apiVersion", "automountServiceAccountToken", "kind", "metadata"}) || manifest["automountServiceAccountToken"] != false {
			return refuse("SERVICE_ACCOUNT_INSECURE")
		}
		return nil
	case "v1/ConfigMap":
		if !exactKeys(manifest, []string{"apiVersion", "data", "kind", "metadata"}) {
			return refuse("CONFIG_MAP_INVALID")
		}
		data, ok := manifest["data"].(map[string]any)
		if !ok {
			return refuse("CONFIG_MAP_INVALID")
		}
		return validateConfigMap(data)
	}
	if !exactKeys(manifest, []string{"apiVersion", "kind", "metadata", "spec"}) {
		return refuse("RESOURCE_MANIFEST_INVALID")
	}
	spec, ok := manifest["spec"].(map[string]any)
	if !ok {
		return refuse("RESOURCE_MANIFEST_INVALID")
	}
	switch resourceType {
	case "networking.k8s.io/v1/NetworkPolicy":
		return validateNetworkPolicy(spec)
	case "v1/ResourceQuota":
		return validateResourceQuota(spec)
	case "v1/LimitRange":
		return validateLimitRange(spec)
	case "rbac.authorization.k8s.io/v1/Role":
		return validateRole(spec)
	case "rbac.authorization.k8s.io/v1/RoleBinding":
		return validateRoleBinding(spec, resource.Identity.Namespace)
	default:
		return refuse("RESOURCE_KIND_FORBIDDEN")
	}
}

func validateNetworkPolicy(spec map[string]any) error {
	if !exactKeys(spec, []string{"egress", "ingress", "podSelector", "policyTypes"}) {
		return refuse("NETWORK_POLICY_INVALID")
	}
	selector, selectorOK := spec["podSelector"].(map[string]any)
	ingress, ingressOK := spec["ingress"].([]any)
	egress, egressOK := spec["egress"].([]any)
	policyTypes, typesOK := stringList(spec["policyTypes"])
	if !selectorOK || len(selector) != 0 || !ingressOK || len(ingress) != 0 || !egressOK || len(egress) != 0 || !typesOK || !equalStrings(policyTypes, []string{"Egress", "Ingress"}) {
		return refuse("NETWORK_POLICY_INVALID")
	}
	return nil
}

func validateResourceQuota(spec map[string]any) error {
	if !exactKeys(spec, []string{"hard"}) {
		return refuse("RESOURCE_QUOTA_INVALID")
	}
	hard, ok := spec["hard"].(map[string]any)
	required := []string{"configmaps", "limits.cpu", "limits.memory", "pods", "requests.cpu", "requests.memory", "services"}
	if !ok || !exactKeys(hard, required) {
		return refuse("RESOURCE_QUOTA_INVALID")
	}
	for _, key := range required {
		if stringValue(hard, key) == "" {
			return refuse("RESOURCE_QUOTA_INVALID")
		}
	}
	return nil
}

func validateLimitRange(spec map[string]any) error {
	if !exactKeys(spec, []string{"limits"}) {
		return refuse("LIMIT_RANGE_INVALID")
	}
	limits, ok := spec["limits"].([]any)
	if !ok || len(limits) != 1 {
		return refuse("LIMIT_RANGE_INVALID")
	}
	limit, ok := limits[0].(map[string]any)
	if !ok || !exactKeys(limit, []string{"default", "defaultRequest", "type"}) || stringValue(limit, "type") != "Container" {
		return refuse("LIMIT_RANGE_INVALID")
	}
	for _, field := range []string{"default", "defaultRequest"} {
		resources, ok := limit[field].(map[string]any)
		if !ok || !exactKeys(resources, []string{"cpu", "memory"}) || stringValue(resources, "cpu") == "" || stringValue(resources, "memory") == "" {
			return refuse("LIMIT_RANGE_INVALID")
		}
	}
	return nil
}

func validateRole(spec map[string]any) error {
	if !exactKeys(spec, []string{"rules"}) {
		return refuse("ROLE_INVALID")
	}
	rules, ok := spec["rules"].([]any)
	if !ok || len(rules) == 0 {
		return refuse("ROLE_INVALID")
	}
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok || !exactKeys(rule, []string{"apiGroups", "resources", "verbs"}) {
			return refuse("ROLE_INVALID")
		}
		groups, groupOK := stringList(rule["apiGroups"])
		resources, resourceOK := stringList(rule["resources"])
		verbs, verbOK := stringList(rule["verbs"])
		if !groupOK || !resourceOK || !verbOK || !sortedUnique(groups) || !sortedUnique(resources) || !sortedUnique(verbs) {
			return refuse("ROLE_INVALID")
		}
		for _, value := range append(append(append([]string{}, groups...), resources...), verbs...) {
			if value == "*" {
				return refuse("ROLE_WILDCARD_FORBIDDEN")
			}
		}
		for _, verb := range verbs {
			if verb == "delete" || verb == "deletecollection" || verb == "bind" || verb == "escalate" || verb == "impersonate" {
				return refuse("ROLE_VERB_FORBIDDEN")
			}
		}
		for _, resource := range resources {
			if resource == "secrets" || resource == "serviceaccounts/token" || resource == "pods/exec" {
				return refuse("ROLE_RESOURCE_FORBIDDEN")
			}
		}
	}
	return nil
}

func validateRoleBinding(spec map[string]any, namespace string) error {
	if !exactKeys(spec, []string{"roleRef", "subjects"}) {
		return refuse("ROLE_BINDING_INVALID")
	}
	roleRef, ok := spec["roleRef"].(map[string]any)
	if !ok || !exactKeys(roleRef, []string{"apiGroup", "kind", "name"}) || stringValue(roleRef, "apiGroup") != "rbac.authorization.k8s.io" || stringValue(roleRef, "kind") != "Role" || stringValue(roleRef, "name") == "" {
		return refuse("ROLE_BINDING_INVALID")
	}
	subjects, ok := spec["subjects"].([]any)
	if !ok || len(subjects) != 1 {
		return refuse("ROLE_BINDING_INVALID")
	}
	subject, ok := subjects[0].(map[string]any)
	if !ok || !exactKeys(subject, []string{"kind", "name", "namespace"}) || stringValue(subject, "kind") != "ServiceAccount" || stringValue(subject, "name") == "" || stringValue(subject, "namespace") != namespace {
		return refuse("ROLE_BINDING_INVALID")
	}
	return nil
}

func validateConfigMap(data map[string]any) error {
	if len(data) == 0 {
		return refuse("CONFIG_MAP_INVALID")
	}
	allowed := map[string]struct{}{"bundleDigest": {}, "profileDigest": {}, "releaseDigest": {}}
	for key, raw := range data {
		value, valueOK := raw.(string)
		if _, keyOK := allowed[key]; !keyOK || !valueOK || !digestPattern.MatchString(value) {
			return refuse("CONFIG_MAP_INVALID")
		}
	}
	return nil
}

func validNamespace(value string) bool {
	return value != "default" && len(value) <= 63 && dnsLabelPattern.MatchString(value)
}
func validName(value string) bool { return len(value) <= 63 && dnsLabelPattern.MatchString(value) }

func digest(data []byte) string {
	value := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(value[:])
}

func exactKeys(value map[string]any, expected []string) bool {
	if len(value) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}

func stringValue(value map[string]any, key string) string {
	result, _ := value[key].(string)
	return result
}

func stringList(value any) ([]string, bool) {
	raw, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, len(raw))
	for index, item := range raw {
		result[index], ok = item.(string)
		if !ok {
			return nil, false
		}
	}
	return result, true
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

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func Reason(err error) string {
	var refusal Refusal
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	if err == nil {
		return ""
	}
	if strings.HasPrefix(err.Error(), "FOUNDATION_") || strings.HasPrefix(err.Error(), "PLAN_") || strings.HasPrefix(err.Error(), "RESOURCE_") {
		return err.Error()
	}
	return "FOUNDATION_INTERNAL_ERROR"
}
