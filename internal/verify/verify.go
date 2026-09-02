package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/caglarsubas/mas-harness-operator/internal/preflight"
)

const CosignPath = "/opt/planeon/bin/cosign"
const CosignSHA256 = "e1775d26440ce3f57a95599d34d2b976c6400e06d1b31b6bea927f4857e3fe18"

var (
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	keyPattern       = regexp.MustCompile(`^key-[0-9a-f]{16}$`)
	referencePattern = regexp.MustCompile(`^[a-z0-9.-]+(?:/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$`)
)

type Refusal struct{ Code string }

func (error Refusal) Error() string { return error.Code }

func refuse(code string) error { return Refusal{Code: code} }

type Receipt struct {
	SchemaVersion      string                `json:"schemaVersion"`
	State              string                `json:"state"`
	ReleaseDigest      string                `json:"releaseDigest"`
	BundleLockDigest   string                `json:"bundleLockDigest"`
	EvidenceDigest     string                `json:"evidenceDigest"`
	TrustBundleDigest  string                `json:"trustBundleDigest"`
	RootManifestDigest string                `json:"rootManifestDigest"`
	SigningKeyID       string                `json:"signingKeyId"`
	ProfileID          string                `json:"profileId"`
	OrganizationID     string                `json:"organizationId"`
	Platform           string                `json:"platform"`
	VerificationTime   string                `json:"verificationTime"`
	ComponentCount     int                   `json:"componentCount"`
	VerifierDigest     string                `json:"verifierDigest"`
	RequestDigest      string                `json:"requestDigest"`
	ObservationDigest  string                `json:"observationDigest"`
	Conditions         []preflight.Condition `json:"conditions"`
}

type MutationSink interface {
	Admit(Receipt) error
}

type Verifier struct {
	MinimumTrustSequence int
}

func (verifier Verifier) VerifyBeforeApply(ctx context.Context, root string, verificationTime string, request preflight.Request, observation preflight.Observation, sink MutationSink) (Receipt, error) {
	receipt, err := verifier.Verify(ctx, root, verificationTime, request, observation)
	if err != nil {
		return Receipt{}, err
	}
	if sink != nil {
		if err := sink.Admit(receipt); err != nil {
			return Receipt{}, refuse("MUTATION_SINK_REFUSED")
		}
	}
	return receipt, nil
}

func (verifier Verifier) Verify(ctx context.Context, root string, verificationTime string, request preflight.Request, observation preflight.Observation) (Receipt, error) {
	preflightResult, err := preflight.Evaluate(request, observation)
	if err != nil {
		return Receipt{}, refuse("PREFLIGHT_INPUT_INVALID")
	}
	if preflightResult.State != "PASS" {
		return Receipt{}, refuse("PREFLIGHT_BLOCKED")
	}
	when, err := exactTime(verificationTime)
	if err != nil {
		return Receipt{}, err
	}
	base, err := exactDirectory(root)
	if err != nil {
		return Receipt{}, err
	}
	signed, _, err := readObject(base, "signed-release.json", []string{"approvalDigest", "bundleLockDigest", "evidenceDigest", "releaseDigest", "rootManifestDigest", "rootSignatureBundleDigest", "schemaVersion", "signingKeyId", "state", "trustBundleFileDigest"})
	if err != nil {
		return Receipt{}, err
	}
	if stringValue(signed, "schemaVersion") != "harness.planeon.ai/signed-release/v1alpha1" || stringValue(signed, "state") != "SIGNED" || selfDigest(signed, "releaseDigest") != stringValue(signed, "releaseDigest") {
		return Receipt{}, refuse("SIGNED_RELEASE_INVALID")
	}
	for _, field := range []string{"approvalDigest", "bundleLockDigest", "evidenceDigest", "releaseDigest", "rootManifestDigest", "rootSignatureBundleDigest", "trustBundleFileDigest"} {
		if !digestPattern.MatchString(stringValue(signed, field)) {
			return Receipt{}, refuse("SIGNED_RELEASE_INVALID")
		}
	}
	keyID := stringValue(signed, "signingKeyId")
	if !keyPattern.MatchString(keyID) {
		return Receipt{}, refuse("SIGNED_RELEASE_INVALID")
	}

	lock, lockBytes, err := readObject(base, "bundle.lock.json", []string{"blobs", "components", "ociLayoutDigest", "platforms", "profileDigest", "profileId", "schemaVersion", "selectedModules", "sourceIndexDigest", "state"})
	if err != nil {
		return Receipt{}, err
	}
	evidence, evidenceBytes, err := readObject(base, "supply-chain.evidence.json", []string{"bundleLockDigest", "components", "dispositionDigest", "evidenceDigest", "licensePolicyDigest", "modelManifestDigest", "models", "schemaVersion", "state", "vulnerabilityDatabaseDigest", "vulnerabilityPolicyDigest"})
	if err != nil {
		return Receipt{}, err
	}
	if stringValue(lock, "schemaVersion") != "harness.planeon.ai/bundle-lock/v1alpha1" || stringValue(lock, "state") != "BUILT_UNSIGNED" {
		return Receipt{}, refuse("BUNDLE_LOCK_INVALID")
	}
	lockDigest, evidenceDigest := sha(lockBytes), sha(evidenceBytes)
	if request.ProfileDigest != stringValue(lock, "profileDigest") || request.BundleDigest != lockDigest || request.ReleaseDigest != stringValue(signed, "releaseDigest") {
		return Receipt{}, refuse("PREFLIGHT_RELEASE_BINDING_INVALID")
	}
	if lockDigest != stringValue(signed, "bundleLockDigest") || evidenceDigest != stringValue(signed, "evidenceDigest") || lockDigest != stringValue(evidence, "bundleLockDigest") || selfDigest(evidence, "evidenceDigest") != stringValue(evidence, "evidenceDigest") || stringValue(evidence, "state") != "SCANNED" {
		return Receipt{}, refuse("SUPPLY_CHAIN_BINDING_INVALID")
	}
	if err := validateSupplyChain(evidence); err != nil {
		return Receipt{}, err
	}
	if err := validateReleaseSubjects(lock, evidence); err != nil {
		return Receipt{}, err
	}

	trust, trustBytes, err := readObject(base, "trust-bundle.json", []string{"keys", "revocations", "schemaVersion", "sequence", "trustBundleDigest"})
	if err != nil {
		return Receipt{}, err
	}
	trustDigest := sha(trustBytes)
	if stringValue(trust, "schemaVersion") != "harness.planeon.ai/release-trust-bundle/v1alpha1" || selfDigest(trust, "trustBundleDigest") != stringValue(trust, "trustBundleDigest") || trustDigest != stringValue(signed, "trustBundleFileDigest") {
		return Receipt{}, refuse("TRUST_BUNDLE_INVALID")
	}
	minimum := verifier.MinimumTrustSequence
	if minimum < 1 {
		minimum = 1
	}
	sequence, ok := integerValue(trust["sequence"])
	if !ok || sequence < int64(minimum) {
		return Receipt{}, refuse("TRUST_SEQUENCE_STALE")
	}
	keys, keyFiles, err := validateTrust(base, trust, when)
	if err != nil {
		return Receipt{}, err
	}
	releaseKey, ok := keys[keyID]
	if !ok || !contains(releaseKey.Roles, "BUNDLE_RELEASE") {
		return Receipt{}, refuse("TRUST_RELEASE_KEY_UNAVAILABLE")
	}

	manifest, manifestBytes, err := readObject(base, "release-manifest.json", []string{"approvalDigest", "bundleLockDigest", "components", "evidenceDigest", "organizationId", "profileId", "schemaVersion", "signingKeyId", "state", "trustBundleDigest", "verificationTime"})
	if err != nil {
		return Receipt{}, err
	}
	rootSignature, err := regularBytes(base, "release-manifest.sigstore.json")
	if err != nil {
		return Receipt{}, err
	}
	if stringValue(manifest, "schemaVersion") != "harness.planeon.ai/release-signing-manifest/v1alpha1" || stringValue(manifest, "state") != "AWAITING_SIGNATURE" || sha(manifestBytes) != stringValue(signed, "rootManifestDigest") || sha(rootSignature) != stringValue(signed, "rootSignatureBundleDigest") || stringValue(manifest, "bundleLockDigest") != lockDigest || stringValue(manifest, "evidenceDigest") != evidenceDigest || stringValue(manifest, "signingKeyId") != keyID || stringValue(manifest, "trustBundleDigest") != stringValue(trust, "trustBundleDigest") || stringValue(manifest, "verificationTime") != verificationTime || stringValue(manifest, "profileId") != stringValue(lock, "profileId") {
		return Receipt{}, refuse("RELEASE_MANIFEST_INVALID")
	}
	if err := verifySignature(ctx, base, releaseKey.PublicKeyFile, "release-manifest.sigstore.json", "release-manifest.json"); err != nil {
		return Receipt{}, err
	}

	approval, approvalBytes, err := readObject(base, "approval.json", []string{"approvalDigest", "approvalKeyId", "authority", "authorizedReleaseKeyIds", "bundleLockDigest", "evidenceDigest", "notAfter", "notBefore", "organizationId", "profileId", "schemaVersion", "trustBundleDigest"})
	if err != nil {
		return Receipt{}, err
	}
	approvalSignature, err := regularBytes(base, "approval.sigstore.json")
	if err != nil {
		return Receipt{}, err
	}
	_ = approvalSignature
	approvalKeyID := stringValue(approval, "approvalKeyId")
	approvalKey, ok := keys[approvalKeyID]
	if !ok || !contains(approvalKey.Roles, "RELEASE_APPROVAL") || selfDigest(approval, "approvalDigest") != stringValue(approval, "approvalDigest") || sha(approvalBytes) != stringValue(signed, "approvalDigest") || stringValue(manifest, "approvalDigest") != sha(approvalBytes) || stringValue(approval, "bundleLockDigest") != lockDigest || stringValue(approval, "evidenceDigest") != evidenceDigest || stringValue(approval, "profileId") != stringValue(lock, "profileId") || stringValue(approval, "organizationId") != stringValue(manifest, "organizationId") || stringValue(approval, "trustBundleDigest") != stringValue(trust, "trustBundleDigest") || !stringListContains(approval["authorizedReleaseKeyIds"], keyID) {
		return Receipt{}, refuse("RELEASE_APPROVAL_INVALID")
	}
	if !insideWindow(approval, when) {
		return Receipt{}, refuse("RELEASE_APPROVAL_EXPIRED")
	}
	if err := verifySignature(ctx, base, approvalKey.PublicKeyFile, "approval.sigstore.json", "approval.json"); err != nil {
		return Receipt{}, err
	}

	componentRecords, ok := objectList(manifest["components"])
	if !ok || len(componentRecords) == 0 {
		return Receipt{}, refuse("COMPONENT_SET_INVALID")
	}
	artifactSet := map[string]struct{}{}
	expectedFiles := baseFiles()
	for keyFile := range keyFiles {
		expectedFiles[keyFile] = struct{}{}
	}
	for _, record := range componentRecords {
		if !exactKeys(record, []string{"artifactDigest", "payloadDigest", "signatureBundleDigest"}) {
			return Receipt{}, refuse("COMPONENT_SET_INVALID")
		}
		artifact := stringValue(record, "artifactDigest")
		if !digestPattern.MatchString(artifact) {
			return Receipt{}, refuse("COMPONENT_SET_INVALID")
		}
		if _, duplicate := artifactSet[artifact]; duplicate {
			return Receipt{}, refuse("COMPONENT_SET_INVALID")
		}
		artifactSet[artifact] = struct{}{}
		hexadecimal := strings.TrimPrefix(artifact, "sha256:")
		payloadName := "components/" + hexadecimal + ".json"
		signatureName := "components/" + hexadecimal + ".sigstore.json"
		payload, payloadBytes, err := readObject(base, payloadName, []string{"artifactDigest", "bundleLockDigest", "kind", "license", "moduleId", "platform", "schemaVersion", "sbomDigest", "vulnerabilities"})
		if err != nil {
			return Receipt{}, err
		}
		signatureBytes, err := regularBytes(base, signatureName)
		if err != nil {
			return Receipt{}, err
		}
		if stringValue(payload, "schemaVersion") != "harness.planeon.ai/component-attestation/v1alpha1" || stringValue(payload, "artifactDigest") != artifact || stringValue(payload, "bundleLockDigest") != lockDigest || stringValue(record, "payloadDigest") != sha(payloadBytes) || stringValue(record, "signatureBundleDigest") != sha(signatureBytes) {
			return Receipt{}, refuse("COMPONENT_BINDING_INVALID")
		}
		if !componentPayloadMatches(lock, evidence, payload) {
			return Receipt{}, refuse("COMPONENT_SUBJECT_MISMATCH")
		}
		if err := verifySignature(ctx, base, releaseKey.PublicKeyFile, signatureName, payloadName); err != nil {
			return Receipt{}, err
		}
		expectedFiles[payloadName] = struct{}{}
		expectedFiles[signatureName] = struct{}{}
	}
	if err := validateOCI(base, lock, artifactSet, expectedFiles); err != nil {
		return Receipt{}, err
	}
	if err := validateClosure(base, expectedFiles); err != nil {
		return Receipt{}, err
	}
	platforms, ok := stringList(lock["platforms"])
	selectedModules, modulesOK := stringList(lock["selectedModules"])
	expectedPlatform := "linux/" + request.Architecture
	if !ok || len(platforms) != 1 || platforms[0] != expectedPlatform || !modulesOK || !equalStrings(selectedModules, request.SelectedModules) {
		return Receipt{}, refuse("PLATFORM_CLOSURE_INVALID")
	}
	componentModules := make([]string, 0, len(componentRecords))
	for _, record := range componentRecords {
		artifact := stringValue(record, "artifactDigest")
		payloadName := "components/" + strings.TrimPrefix(artifact, "sha256:") + ".json"
		payload, _, payloadErr := readObject(base, payloadName, []string{"artifactDigest", "bundleLockDigest", "kind", "license", "moduleId", "platform", "schemaVersion", "sbomDigest", "vulnerabilities"})
		if payloadErr != nil || stringValue(payload, "platform") != expectedPlatform {
			return Receipt{}, refuse("PLATFORM_CLOSURE_INVALID")
		}
		componentModules = append(componentModules, stringValue(payload, "moduleId"))
	}
	sort.Strings(componentModules)
	if !equalStrings(componentModules, request.SelectedModules) || !unique(componentModules) {
		return Receipt{}, refuse("MODULE_CLOSURE_INVALID")
	}
	verifierPayload := map[string]any{"cosignSha256": "sha256:" + CosignSHA256, "minimumTrustSequence": minimum, "schemaVersion": "harness.planeon.ai/bundle-verifier/v1alpha1"}
	return Receipt{
		SchemaVersion: "harness.planeon.ai/bundle-verification-receipt/v1alpha1", State: "VERIFIED",
		ReleaseDigest: stringValue(signed, "releaseDigest"), BundleLockDigest: lockDigest,
		EvidenceDigest: evidenceDigest, TrustBundleDigest: stringValue(trust, "trustBundleDigest"),
		RootManifestDigest: sha(manifestBytes), SigningKeyID: keyID, ProfileID: stringValue(lock, "profileId"),
		OrganizationID: stringValue(manifest, "organizationId"), Platform: platforms[0],
		VerificationTime: verificationTime, ComponentCount: len(componentRecords), VerifierDigest: canonicalDigest(verifierPayload),
		RequestDigest: preflightResult.RequestDigest, ObservationDigest: preflightResult.ObservationDigest,
		Conditions: append([]preflight.Condition(nil), preflightResult.Conditions...),
	}, nil
}

type trustKey struct {
	Roles         []string
	PublicKeyFile string
}

func validateTrust(base string, trust map[string]any, when time.Time) (map[string]trustKey, map[string]struct{}, error) {
	records, ok := objectList(trust["keys"])
	if !ok || len(records) == 0 {
		return nil, nil, refuse("TRUST_KEYS_INVALID")
	}
	keys := map[string]trustKey{}
	files := map[string]struct{}{}
	previousID := ""
	for _, record := range records {
		if !exactKeys(record, []string{"keyId", "notAfter", "notBefore", "publicKeyDigest", "publicKeyFile", "roles", "state"}) {
			return nil, nil, refuse("TRUST_KEYS_INVALID")
		}
		id, file := stringValue(record, "keyId"), stringValue(record, "publicKeyFile")
		roles, rolesOK := stringList(record["roles"])
		if !keyPattern.MatchString(id) || id <= previousID || file != "public-keys/"+id+".pub" || !rolesOK || len(roles) != 1 || !sort.StringsAreSorted(roles) || !unique(roles) || (!contains(roles, "BUNDLE_RELEASE") && !contains(roles, "RELEASE_APPROVAL")) || (stringValue(record, "state") != "ACTIVE" && stringValue(record, "state") != "RETIRING") || !insideWindow(record, when) {
			return nil, nil, refuse("TRUST_KEYS_INVALID")
		}
		previousID = id
		if _, exists := keys[id]; exists {
			return nil, nil, refuse("TRUST_KEYS_INVALID")
		}
		publicBytes, err := regularBytes(base, file)
		if err != nil || sha(publicBytes) != stringValue(record, "publicKeyDigest") {
			return nil, nil, refuse("TRUST_PUBLIC_KEY_INVALID")
		}
		keys[id], files[file] = trustKey{Roles: roles, PublicKeyFile: file}, struct{}{}
	}
	revocations, ok := objectList(trust["revocations"])
	if !ok {
		return nil, nil, refuse("TRUST_REVOCATIONS_INVALID")
	}
	seen := map[string]struct{}{}
	for _, record := range revocations {
		if !exactKeys(record, []string{"effectiveAt", "keyId", "reasonDigest"}) || !digestPattern.MatchString(stringValue(record, "reasonDigest")) {
			return nil, nil, refuse("TRUST_REVOCATIONS_INVALID")
		}
		id := stringValue(record, "keyId")
		if _, exists := keys[id]; !exists {
			return nil, nil, refuse("TRUST_REVOCATIONS_INVALID")
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, nil, refuse("TRUST_REVOCATIONS_INVALID")
		}
		seen[id] = struct{}{}
		effective, err := exactTime(stringValue(record, "effectiveAt"))
		if err != nil {
			return nil, nil, refuse("TRUST_REVOCATIONS_INVALID")
		}
		if !effective.After(when) {
			delete(keys, id)
		}
	}
	return keys, files, nil
}

func validateSupplyChain(evidence map[string]any) error {
	components, ok := objectList(evidence["components"])
	if !ok || len(components) == 0 {
		return refuse("SUPPLY_CHAIN_COMPONENTS_INVALID")
	}
	for _, component := range components {
		if !exactKeys(component, []string{"artifactDigest", "kind", "license", "moduleId", "platform", "sbomDigest", "vulnerabilities"}) {
			return refuse("SUPPLY_CHAIN_COMPONENTS_INVALID")
		}
		license, ok := component["license"].(map[string]any)
		if !ok || !exactKeys(license, []string{"decision", "expression"}) || stringValue(license, "decision") != "ACCEPTED" || stringValue(license, "expression") == "" {
			return refuse("LICENSE_NOT_ACCEPTED")
		}
		findings, ok := objectList(component["vulnerabilities"])
		if !ok {
			return refuse("VULNERABILITY_EVIDENCE_INVALID")
		}
		for _, finding := range findings {
			if !exactKeys(finding, []string{"disposition", "id", "severity"}) {
				return refuse("VULNERABILITY_EVIDENCE_INVALID")
			}
			severity := stringValue(finding, "severity")
			if stringValue(finding, "id") == "" || (severity != "LOW" && severity != "MEDIUM" && severity != "HIGH" && severity != "CRITICAL") || (stringValue(finding, "disposition") != "RESOLVED" && stringValue(finding, "disposition") != "ACCEPTED_RISK") {
				return refuse("VULNERABILITY_EVIDENCE_INVALID")
			}
			if (severity == "HIGH" || severity == "CRITICAL") && stringValue(finding, "disposition") != "RESOLVED" {
				return refuse("VULNERABILITY_UNRESOLVED")
			}
		}
	}
	models, ok := objectList(evidence["models"])
	if !ok {
		return refuse("MODEL_CUSTODY_INVALID")
	}
	for _, model := range models {
		if !exactKeys(model, []string{"decision", "modelId"}) || stringValue(model, "modelId") == "" || stringValue(model, "decision") != "ACCEPTED" {
			return refuse("MODEL_CUSTODY_NOT_ACCEPTED")
		}
	}
	return nil
}

func validateReleaseSubjects(lock, evidence map[string]any) error {
	locked, lockedOK := objectList(lock["components"])
	evidenced, evidencedOK := objectList(evidence["components"])
	if !lockedOK || !evidencedOK || len(locked) == 0 || len(locked) != len(evidenced) {
		return refuse("COMPONENT_SET_INVALID")
	}
	previous := ""
	for index, component := range locked {
		if !exactKeys(component, []string{"artifactDigest", "kind", "moduleId", "platform", "reference"}) {
			return refuse("COMPONENT_SET_INVALID")
		}
		artifact, module, reference := stringValue(component, "artifactDigest"), stringValue(component, "moduleId"), stringValue(component, "reference")
		if !digestPattern.MatchString(artifact) || module == "" || module <= previous || !referencePattern.MatchString(reference) || !strings.HasSuffix(reference, "@"+artifact) {
			return refuse("COMPONENT_SET_INVALID")
		}
		previous = module
		evidenceComponent := evidenced[index]
		if !exactKeys(evidenceComponent, []string{"artifactDigest", "kind", "license", "moduleId", "platform", "sbomDigest", "vulnerabilities"}) ||
			stringValue(evidenceComponent, "artifactDigest") != artifact || stringValue(evidenceComponent, "kind") != stringValue(component, "kind") ||
			stringValue(evidenceComponent, "moduleId") != module || stringValue(evidenceComponent, "platform") != stringValue(component, "platform") ||
			!digestPattern.MatchString(stringValue(evidenceComponent, "sbomDigest")) {
			return refuse("SUPPLY_CHAIN_SUBJECT_MISMATCH")
		}
	}
	return nil
}

func componentPayloadMatches(lock, evidence, payload map[string]any) bool {
	locked, _ := objectList(lock["components"])
	evidenced, _ := objectList(evidence["components"])
	for index, component := range locked {
		if stringValue(component, "artifactDigest") != stringValue(payload, "artifactDigest") {
			continue
		}
		evidenceComponent := evidenced[index]
		return stringValue(payload, "kind") == stringValue(component, "kind") &&
			stringValue(payload, "moduleId") == stringValue(component, "moduleId") &&
			stringValue(payload, "platform") == stringValue(component, "platform") &&
			stringValue(payload, "sbomDigest") == stringValue(evidenceComponent, "sbomDigest") &&
			canonicalDigest(payload["license"]) == canonicalDigest(evidenceComponent["license"]) &&
			canonicalDigest(payload["vulnerabilities"]) == canonicalDigest(evidenceComponent["vulnerabilities"])
	}
	return false
}

func validateOCI(base string, lock map[string]any, artifacts map[string]struct{}, expected map[string]struct{}) error {
	expected["oci/oci-layout"] = struct{}{}
	expected["oci/index.json"] = struct{}{}
	layout, layoutBytes, err := readObject(base, "oci/oci-layout", []string{"imageLayoutVersion"})
	if err != nil || stringValue(layout, "imageLayoutVersion") != "1.0.0" || sha(layoutBytes) != stringValue(lock, "ociLayoutDigest") {
		return refuse("OCI_LAYOUT_INVALID")
	}
	index, indexBytes, err := readObject(base, "oci/index.json", []string{"manifests", "mediaType", "schemaVersion"})
	if err != nil || stringValue(index, "mediaType") != "application/vnd.oci.image.index.v1+json" || sha(indexBytes) != stringValue(lock, "sourceIndexDigest") {
		return refuse("OCI_INDEX_INVALID")
	}
	schemaVersion, schemaOK := integerValue(index["schemaVersion"])
	if !schemaOK || schemaVersion != 2 {
		return refuse("OCI_INDEX_INVALID")
	}
	descriptors, descriptorsOK := objectList(index["manifests"])
	if !descriptorsOK {
		return refuse("OCI_INDEX_INVALID")
	}
	indexSet := map[string]int64{}
	for _, descriptor := range descriptors {
		if !exactKeys(descriptor, []string{"digest", "mediaType", "size"}) || stringValue(descriptor, "mediaType") != "application/vnd.oci.image.manifest.v1+json" {
			return refuse("OCI_INDEX_INVALID")
		}
		size, ok := integerValue(descriptor["size"])
		digest := stringValue(descriptor, "digest")
		if !ok || !digestPattern.MatchString(digest) {
			return refuse("OCI_INDEX_INVALID")
		}
		if _, duplicate := indexSet[digest]; duplicate {
			return refuse("OCI_INDEX_INVALID")
		}
		indexSet[digest] = size
	}
	blobs, ok := objectList(lock["blobs"])
	if !ok || len(blobs) == 0 {
		return refuse("OCI_BLOBS_INVALID")
	}
	blobSet := map[string]struct{}{}
	for _, blob := range blobs {
		if !exactKeys(blob, []string{"digest", "size"}) {
			return refuse("OCI_BLOBS_INVALID")
		}
		digest := stringValue(blob, "digest")
		size, sizeOK := integerValue(blob["size"])
		if !digestPattern.MatchString(digest) || !sizeOK || size < 0 {
			return refuse("OCI_BLOBS_INVALID")
		}
		if indexedSize, exists := indexSet[digest]; !exists || indexedSize != size {
			return refuse("OCI_INDEX_CLOSURE_INVALID")
		}
		name := "oci/blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
		data, err := regularBytes(base, name)
		if err != nil || int64(len(data)) != size || sha(data) != digest {
			return refuse("OCI_BLOB_DIGEST_MISMATCH")
		}
		expected[name], blobSet[digest] = struct{}{}, struct{}{}
	}
	if len(indexSet) != len(blobSet) {
		return refuse("OCI_INDEX_CLOSURE_INVALID")
	}
	for artifact := range artifacts {
		if _, exists := blobSet[artifact]; !exists {
			return refuse("COMPONENT_OCI_CLOSURE_INVALID")
		}
	}
	return nil
}

func baseFiles() map[string]struct{} {
	result := map[string]struct{}{}
	for _, name := range []string{"approval.json", "approval.sigstore.json", "bundle.lock.json", "release-manifest.json", "release-manifest.sigstore.json", "signed-release.json", "supply-chain.evidence.json", "trust-bundle.json"} {
		result[name] = struct{}{}
	}
	return result
}

func validateClosure(base string, expected map[string]struct{}) error {
	actual := map[string]struct{}{}
	casefold := map[string]string{}
	err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return refuse("BUNDLE_TREE_INVALID")
		}
		if path == base {
			return nil
		}
		relative, err := filepath.Rel(base, path)
		if err != nil {
			return refuse("BUNDLE_TREE_INVALID")
		}
		relative = filepath.ToSlash(relative)
		if strings.Contains(relative, "..") || entry.Type()&os.ModeSymlink != 0 {
			return refuse("BUNDLE_TREE_INVALID")
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return refuse("BUNDLE_TREE_INVALID")
		}
		info, err := entry.Info()
		if err != nil || hardLinked(info) {
			return refuse("BUNDLE_TREE_INVALID")
		}
		folded := strings.ToLower(relative)
		if prior, exists := casefold[folded]; exists && prior != relative {
			return refuse("BUNDLE_CASE_COLLISION")
		}
		casefold[folded], actual[relative] = relative, struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	if len(actual) != len(expected) {
		return refuse("BUNDLE_FILE_CLOSURE_INVALID")
	}
	for name := range expected {
		if _, exists := actual[name]; !exists {
			return refuse("BUNDLE_FILE_CLOSURE_INVALID")
		}
	}
	return nil
}

func exactDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", refuse("BUNDLE_ROOT_NOT_ABSOLUTE")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", refuse("BUNDLE_ROOT_INVALID")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(path) != resolved {
		return "", refuse("BUNDLE_ROOT_INVALID")
	}
	return resolved, nil
}

func regularBytes(base, relative string) ([]byte, error) {
	if relative == "" || filepath.IsAbs(relative) || strings.Contains(relative, "\\") || strings.Contains(relative, "..") {
		return nil, refuse("BUNDLE_PATH_INVALID")
	}
	path := filepath.Join(base, filepath.FromSlash(relative))
	if !strings.HasPrefix(path, base+string(filepath.Separator)) {
		return nil, refuse("BUNDLE_PATH_INVALID")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || hardLinked(info) {
		return nil, refuse("BUNDLE_FILE_INVALID")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, refuse("BUNDLE_FILE_INVALID")
	}
	return data, nil
}

func readObject(base, relative string, keys []string) (map[string]any, []byte, error) {
	data, err := regularBytes(base, relative)
	if err != nil {
		return nil, nil, err
	}
	var value map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil || value == nil || !exactKeys(value, keys) {
		return nil, nil, refuse("JSON_DOCUMENT_INVALID")
	}
	canonical, err := json.Marshal(value)
	if err != nil || string(canonical) != string(data) {
		return nil, nil, refuse("JSON_NOT_CANONICAL")
	}
	return value, data, nil
}

func verifySignature(ctx context.Context, base, publicKey, bundle, payload string) error {
	cosign, err := os.ReadFile(CosignPath)
	cosignDigest := sha256.Sum256(cosign)
	if err != nil || hex.EncodeToString(cosignDigest[:]) != CosignSHA256 {
		return refuse("COSIGN_BINARY_INVALID")
	}
	home, err := os.MkdirTemp("", "op002-cosign-")
	if err != nil {
		return refuse("COSIGN_TEMP_UNAVAILABLE")
	}
	defer os.RemoveAll(home)
	command := exec.CommandContext(ctx, CosignPath, "verify-blob", "--offline", "--insecure-ignore-tlog", "--key", filepath.Join(base, publicKey), "--bundle", filepath.Join(base, bundle), filepath.Join(base, payload))
	command.Env = []string{"HOME=" + home, "PATH=/opt/planeon/bin:/usr/bin:/bin"}
	command.Stdin = nil
	if output, err := command.CombinedOutput(); err != nil {
		_ = output
		return refuse("SIGNATURE_INVALID")
	}
	return nil
}

func exactTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Nanosecond() != 0 || parsed.Format(time.RFC3339) != value {
		return time.Time{}, refuse("VERIFICATION_TIME_INVALID")
	}
	return parsed, nil
}

func insideWindow(value map[string]any, when time.Time) bool {
	notBefore, first := exactTime(stringValue(value, "notBefore"))
	notAfter, second := exactTime(stringValue(value, "notAfter"))
	return first == nil && second == nil && !when.Before(notBefore) && when.Before(notAfter) && notBefore.Before(notAfter)
}

func hardLinked(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink != 1
}

func sha(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func canonicalDigest(value any) string {
	data, _ := json.Marshal(value)
	return sha(data)
}

func selfDigest(value map[string]any, field string) string {
	payload := make(map[string]any, len(value)-1)
	for key, item := range value {
		if key != field {
			payload[key] = item
		}
	}
	return canonicalDigest(payload)
}

func exactKeys(value map[string]any, expected []string) bool {
	if len(value) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, exists := value[key]; !exists {
			return false
		}
	}
	return true
}

func stringValue(value map[string]any, key string) string {
	result, _ := value[key].(string)
	return result
}

func integerValue(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	result, err := number.Int64()
	return result, err == nil
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

func objectList(value any) ([]map[string]any, bool) {
	raw, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := make([]map[string]any, len(raw))
	for index, item := range raw {
		result[index], ok = item.(map[string]any)
		if !ok {
			return nil, false
		}
	}
	return result, true
}

func stringListContains(value any, target string) bool {
	values, ok := stringList(value)
	return ok && sort.StringsAreSorted(values) && unique(values) && contains(values, target)
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func unique(values []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
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
	return fmt.Sprintf("INTERNAL_VERIFICATION_ERROR")
}
