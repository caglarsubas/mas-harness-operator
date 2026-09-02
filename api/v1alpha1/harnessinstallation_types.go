package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// InstallationPhase is the exact CON-005 lifecycle vocabulary.
// +kubebuilder:validation:Enum=ABSENT;PENDING;PREFLIGHT;VERIFYING;APPLYING;HEALTH_CHECKING;READY;BLOCKED;DEGRADED;FAILED;UPGRADING;ROLLING_BACK;UNINSTALLING;REMOVED;RETIRED;REVOKED
type InstallationPhase string

const (
	PhaseAbsent         InstallationPhase = "ABSENT"
	PhasePending        InstallationPhase = "PENDING"
	PhasePreflight      InstallationPhase = "PREFLIGHT"
	PhaseVerifying      InstallationPhase = "VERIFYING"
	PhaseApplying       InstallationPhase = "APPLYING"
	PhaseHealthChecking InstallationPhase = "HEALTH_CHECKING"
	PhaseReady          InstallationPhase = "READY"
	PhaseBlocked        InstallationPhase = "BLOCKED"
	PhaseDegraded       InstallationPhase = "DEGRADED"
	PhaseFailed         InstallationPhase = "FAILED"
	PhaseUpgrading      InstallationPhase = "UPGRADING"
	PhaseRollingBack    InstallationPhase = "ROLLING_BACK"
	PhaseUninstalling   InstallationPhase = "UNINSTALLING"
	PhaseRemoved        InstallationPhase = "REMOVED"
	PhaseRetired        InstallationPhase = "RETIRED"
	PhaseRevoked        InstallationPhase = "REVOKED"
)

const (
	ConditionDependenciesResolved = "DependenciesResolved"
	ConditionArtifactsVerified    = "ArtifactsVerified"
	ConditionConfigured           = "Configured"
	ConditionReady                = "Ready"
	ConditionHealthy              = "Healthy"
	ConditionPolicyCompliant      = "PolicyCompliant"
	ConditionEvidenceCurrent      = "EvidenceCurrent"
)

// HarnessInstallationSpec contains tenant-approved desired state only.
// +kubebuilder:validation:XValidation:rule="self.organizationId == oldSelf.organizationId",message="organizationId is immutable"
// +kubebuilder:validation:XValidation:rule="self.harnessId == oldSelf.harnessId",message="harnessId is immutable"
// +kubebuilder:validation:XValidation:rule="self.profileDigest == oldSelf.profileDigest",message="profileDigest is immutable"
// +kubebuilder:validation:XValidation:rule="self.bundleDigest == oldSelf.bundleDigest",message="bundleDigest is immutable"
// +kubebuilder:validation:XValidation:rule="self.releaseDigest == oldSelf.releaseDigest",message="releaseDigest is immutable"
// +kubebuilder:validation:XValidation:rule="self.targetNamespace == oldSelf.targetNamespace",message="targetNamespace is immutable"
// +kubebuilder:validation:XValidation:rule="self.trustRef == oldSelf.trustRef",message="trustRef is immutable"
// +kubebuilder:validation:XValidation:rule="self.desiredGeneration >= oldSelf.desiredGeneration",message="desiredGeneration cannot decrease"
type HarnessInstallationSpec struct {
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$`
	OrganizationID string `json:"organizationId"`
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$`
	HarnessID string `json:"harnessId"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	ProfileDigest string `json:"profileDigest"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	BundleDigest string `json:"bundleDigest"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	ReleaseDigest string `json:"releaseDigest"`
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:XValidation:rule="self != 'default'",message="default namespace is forbidden"
	TargetNamespace string `json:"targetNamespace"`
	// +kubebuilder:validation:Minimum=1
	DesiredGeneration int64          `json:"desiredGeneration"`
	TrustRef          TrustReference `json:"trustRef"`
}

type TrustReference struct {
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$`
	Name string `json:"name"`
}

type EvidenceReference struct {
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$`
	Kind string `json:"kind"`
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$`
	ID string `json:"id"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	Digest string `json:"digest"`
}

// +kubebuilder:validation:XValidation:rule="self.conditions.all(c, c.type in ['DependenciesResolved','ArtifactsVerified','Configured','Ready','Healthy','PolicyCompliant','EvidenceCurrent'])",message="condition type is not part of the closed vocabulary"
type HarnessInstallationStatus struct {
	Phase InstallationPhase `json:"phase,omitempty"`
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	CurrentReleaseDigest *string `json:"currentReleaseDigest,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	LastGoodReleaseDigest *string `json:"lastGoodReleaseDigest,omitempty"`
	// +kubebuilder:validation:Pattern=`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$`
	ReasonCode       string       `json:"reasonCode,omitempty"`
	LastTransitionAt *metav1.Time `json:"lastTransitionAt,omitempty"`
	// +listType=set
	EvidenceRefs []EvidenceReference `json:"evidenceRefs,omitempty"`
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=hinst
// +kubebuilder:validation:XValidation:rule="!has(self.status) || !has(self.status.observedGeneration) || self.status.observedGeneration <= self.spec.desiredGeneration",message="observedGeneration cannot exceed desiredGeneration"
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Observed",type=integer,JSONPath=`.status.observedGeneration`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type HarnessInstallation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HarnessInstallationSpec   `json:"spec"`
	Status HarnessInstallationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type HarnessInstallationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HarnessInstallation `json:"items"`
}

func init() {
	SchemeBuilder.Register(&HarnessInstallation{}, &HarnessInstallationList{})
}
