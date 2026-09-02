package v1alpha1

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
)

var (
	stableIDPattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reasonCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$`)
	namespacePattern  = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
)

var allPhases = []InstallationPhase{
	PhaseAbsent, PhasePending, PhasePreflight, PhaseVerifying, PhaseApplying,
	PhaseHealthChecking, PhaseReady, PhaseBlocked, PhaseDegraded, PhaseFailed,
	PhaseUpgrading, PhaseRollingBack, PhaseUninstalling, PhaseRemoved,
	PhaseRetired, PhaseRevoked,
}

var allowedTransitions = map[InstallationPhase]map[InstallationPhase]struct{}{
	PhaseAbsent:         transitions(PhasePending),
	PhasePending:        transitions(PhasePreflight, PhaseBlocked, PhaseFailed),
	PhasePreflight:      transitions(PhaseVerifying, PhaseBlocked, PhaseFailed),
	PhaseVerifying:      transitions(PhaseApplying, PhaseBlocked, PhaseFailed),
	PhaseApplying:       transitions(PhaseHealthChecking, PhaseBlocked, PhaseFailed, PhaseRollingBack),
	PhaseHealthChecking: transitions(PhaseReady, PhaseDegraded, PhaseBlocked, PhaseFailed, PhaseRollingBack),
	PhaseReady:          transitions(PhaseDegraded, PhaseUpgrading, PhaseUninstalling, PhaseRetired, PhaseRevoked),
	PhaseBlocked:        transitions(PhasePending, PhaseRollingBack, PhaseUninstalling, PhaseRevoked),
	PhaseDegraded:       transitions(PhaseReady, PhaseBlocked, PhaseFailed, PhaseUpgrading, PhaseRollingBack, PhaseUninstalling, PhaseRevoked),
	PhaseFailed:         transitions(PhasePending, PhaseRollingBack, PhaseUninstalling, PhaseRevoked),
	PhaseUpgrading:      transitions(PhaseVerifying, PhaseHealthChecking, PhaseReady, PhaseDegraded, PhaseFailed, PhaseRollingBack, PhaseRevoked),
	PhaseRollingBack:    transitions(PhaseVerifying, PhaseHealthChecking, PhaseReady, PhaseDegraded, PhaseFailed, PhaseRevoked),
	PhaseUninstalling:   transitions(PhaseRemoved, PhaseFailed, PhaseRevoked),
	PhaseRemoved:        transitions(PhasePending, PhaseRetired, PhaseRevoked),
	PhaseRetired:        transitions(PhaseRevoked),
	PhaseRevoked:        transitions(),
}

var conditionTypes = map[string]struct{}{
	ConditionDependenciesResolved: {}, ConditionArtifactsVerified: {},
	ConditionConfigured: {}, ConditionReady: {}, ConditionHealthy: {},
	ConditionPolicyCompliant: {}, ConditionEvidenceCurrent: {},
}

func transitions(phases ...InstallationPhase) map[InstallationPhase]struct{} {
	result := make(map[InstallationPhase]struct{}, len(phases))
	for _, phase := range phases {
		result[phase] = struct{}{}
	}
	return result
}

func AllInstallationPhases() []InstallationPhase {
	return append([]InstallationPhase(nil), allPhases...)
}

func IsAllowedTransition(from, to InstallationPhase) bool {
	_, ok := allowedTransitions[from][to]
	return ok
}

func ValidateTransition(from, to InstallationPhase) error {
	if !IsKnownPhase(from) || !IsKnownPhase(to) {
		return errors.New("unknown installation phase")
	}
	if !IsAllowedTransition(from, to) {
		return fmt.Errorf("transition %s -> %s is not allowed", from, to)
	}
	return nil
}

func IsKnownPhase(phase InstallationPhase) bool {
	_, ok := allowedTransitions[phase]
	return ok
}

func ValidateSpec(spec HarnessInstallationSpec) error {
	for name, value := range map[string]string{
		"organizationId": spec.OrganizationID,
		"harnessId":      spec.HarnessID,
		"trustRef.name":  spec.TrustRef.Name,
	} {
		if !stableIDPattern.MatchString(value) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	for name, value := range map[string]string{
		"profileDigest": spec.ProfileDigest,
		"bundleDigest":  spec.BundleDigest,
		"releaseDigest": spec.ReleaseDigest,
	} {
		if !digestPattern.MatchString(value) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	if !namespacePattern.MatchString(spec.TargetNamespace) || len(spec.TargetNamespace) > 63 || spec.TargetNamespace == "default" {
		return errors.New("targetNamespace is invalid")
	}
	if spec.DesiredGeneration < 1 {
		return errors.New("desiredGeneration must be positive")
	}
	return nil
}

func ValidateStatus(status HarnessInstallationStatus) error {
	if !IsKnownPhase(status.Phase) {
		return errors.New("status phase is invalid")
	}
	if status.ObservedGeneration < 0 {
		return errors.New("observedGeneration cannot be negative")
	}
	if !reasonCodePattern.MatchString(status.ReasonCode) {
		return errors.New("reasonCode is invalid")
	}
	if status.LastTransitionAt == nil || status.LastTransitionAt.Time.Nanosecond() != 0 {
		return errors.New("lastTransitionAt must have whole-second precision")
	}
	for _, digest := range []*string{status.CurrentReleaseDigest, status.LastGoodReleaseDigest} {
		if digest != nil && !digestPattern.MatchString(*digest) {
			return errors.New("status release digest is invalid")
		}
	}
	seenEvidence := map[string]struct{}{}
	for _, ref := range status.EvidenceRefs {
		if !stableIDPattern.MatchString(ref.Kind) || !stableIDPattern.MatchString(ref.ID) || !digestPattern.MatchString(ref.Digest) {
			return errors.New("evidence reference is invalid")
		}
		key := ref.Kind + "\x00" + ref.ID + "\x00" + ref.Digest
		if _, exists := seenEvidence[key]; exists {
			return errors.New("duplicate evidence reference")
		}
		seenEvidence[key] = struct{}{}
	}
	seenConditions := map[string]struct{}{}
	for _, condition := range status.Conditions {
		if _, ok := conditionTypes[condition.Type]; !ok {
			return fmt.Errorf("condition type %s is invalid", condition.Type)
		}
		if _, exists := seenConditions[condition.Type]; exists {
			return fmt.Errorf("condition type %s is duplicated", condition.Type)
		}
		seenConditions[condition.Type] = struct{}{}
	}
	return nil
}

type LifecycleProjection struct {
	APIVersion string                      `json:"apiVersion"`
	Kind       string                      `json:"kind"`
	Metadata   LifecycleProjectionMetadata `json:"metadata"`
	Spec       LifecycleProjectionSpec     `json:"spec"`
}

type LifecycleProjectionMetadata struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type LifecycleBinding struct {
	OrganizationID string `json:"organizationId"`
	ProfileDigest  string `json:"profileDigest"`
	BundleDigest   string `json:"bundleDigest"`
	ReleaseDigest  string `json:"releaseDigest"`
}

type LifecycleProjectionSpec struct {
	Binding               LifecycleBinding    `json:"binding"`
	HarnessID             string              `json:"harnessId"`
	State                 InstallationPhase   `json:"state"`
	DesiredGeneration     int64               `json:"desiredGeneration"`
	ObservedGeneration    int64               `json:"observedGeneration"`
	CurrentReleaseDigest  *string             `json:"currentReleaseDigest"`
	LastGoodReleaseDigest *string             `json:"lastGoodReleaseDigest"`
	ReasonCode            string              `json:"reasonCode"`
	LastTransitionAt      string              `json:"lastTransitionAt"`
	EvidenceRefs          []EvidenceReference `json:"evidenceRefs"`
}

func (installation *HarnessInstallation) ToLifecycleProjection() (LifecycleProjection, error) {
	if installation == nil {
		return LifecycleProjection{}, errors.New("installation is nil")
	}
	if !stableIDPattern.MatchString(installation.Name) {
		return LifecycleProjection{}, errors.New("metadata.name is not a stable lifecycle id")
	}
	if err := ValidateSpec(installation.Spec); err != nil {
		return LifecycleProjection{}, err
	}
	if err := ValidateStatus(installation.Status); err != nil {
		return LifecycleProjection{}, err
	}
	evidence := append([]EvidenceReference(nil), installation.Status.EvidenceRefs...)
	sort.Slice(evidence, func(i, j int) bool {
		if evidence[i].Kind != evidence[j].Kind {
			return evidence[i].Kind < evidence[j].Kind
		}
		if evidence[i].ID != evidence[j].ID {
			return evidence[i].ID < evidence[j].ID
		}
		return evidence[i].Digest < evidence[j].Digest
	})
	return LifecycleProjection{
		APIVersion: "harness.planeon.ai/v1alpha1",
		Kind:       "HarnessInstallation",
		Metadata: LifecycleProjectionMetadata{
			ID: installation.Name, Version: "0.1.0",
		},
		Spec: LifecycleProjectionSpec{
			Binding: LifecycleBinding{
				OrganizationID: installation.Spec.OrganizationID,
				ProfileDigest:  installation.Spec.ProfileDigest,
				BundleDigest:   installation.Spec.BundleDigest,
				ReleaseDigest:  installation.Spec.ReleaseDigest,
			},
			HarnessID:             installation.Spec.HarnessID,
			State:                 installation.Status.Phase,
			DesiredGeneration:     installation.Spec.DesiredGeneration,
			ObservedGeneration:    installation.Status.ObservedGeneration,
			CurrentReleaseDigest:  installation.Status.CurrentReleaseDigest,
			LastGoodReleaseDigest: installation.Status.LastGoodReleaseDigest,
			ReasonCode:            installation.Status.ReasonCode,
			LastTransitionAt:      installation.Status.LastTransitionAt.UTC().Format(time.RFC3339),
			EvidenceRefs:          evidence,
		},
	}, nil
}
