package envtest

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	harnessv1alpha1 "github.com/caglarsubas/mas-harness-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const digestC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const digestD = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

func validInstallation() *harnessv1alpha1.HarnessInstallation {
	now := metav1.NewTime(time.Date(2026, 8, 31, 5, 0, 0, 0, time.UTC))
	current, previous := digestC, digestC
	return &harnessv1alpha1.HarnessInstallation{
		TypeMeta:   metav1.TypeMeta{APIVersion: "harness.planeon.ai/v1alpha1", Kind: "HarnessInstallation"},
		ObjectMeta: metav1.ObjectMeta{Name: "installation.runtime-infrastructure", Namespace: "planeon-system"},
		Spec: harnessv1alpha1.HarnessInstallationSpec{
			OrganizationID: "org.acme", HarnessID: "runtime.infrastructure",
			ProfileDigest: digestA, BundleDigest: digestB, ReleaseDigest: digestC,
			TargetNamespace: "planeon-system", DesiredGeneration: 3,
			TrustRef: harnessv1alpha1.TrustReference{Name: "trust.release"},
		},
		Status: harnessv1alpha1.HarnessInstallationStatus{
			Phase: harnessv1alpha1.PhaseReady, ObservedGeneration: 3,
			CurrentReleaseDigest: &current, LastGoodReleaseDigest: &previous,
			ReasonCode: "HEALTH_CHECK_PASSED", LastTransitionAt: &now,
			EvidenceRefs: []harnessv1alpha1.EvidenceReference{{Kind: "resource.evidence", ID: "evidence.runtime-001", Digest: digestD}},
			Conditions:   []metav1.Condition{{Type: harnessv1alpha1.ConditionReady, Status: metav1.ConditionTrue, Reason: "HEALTH_CHECK_PASSED", LastTransitionTime: now}},
		},
	}
}

func TestLifecycleProjectionMatchesCON005Shape(t *testing.T) {
	projection, err := validInstallation().ToLifecycleProjection()
	if err != nil {
		t.Fatal(err)
	}
	actual, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"apiVersion":"harness.planeon.ai/v1alpha1","kind":"HarnessInstallation","metadata":{"id":"installation.runtime-infrastructure","version":"0.1.0"},"spec":{"binding":{"organizationId":"org.acme","profileDigest":"` + digestA + `","bundleDigest":"` + digestB + `","releaseDigest":"` + digestC + `"},"harnessId":"runtime.infrastructure","state":"READY","desiredGeneration":3,"observedGeneration":3,"currentReleaseDigest":"` + digestC + `","lastGoodReleaseDigest":"` + digestC + `","reasonCode":"HEALTH_CHECK_PASSED","lastTransitionAt":"2026-08-31T05:00:00Z","evidenceRefs":[{"kind":"resource.evidence","id":"evidence.runtime-001","digest":"` + digestD + `"}]}}`
	if string(actual) != expected {
		t.Fatalf("projection mismatch\nwant: %s\n got: %s", expected, actual)
	}
}

func TestAllSixteenStatesAndExactTransitionTable(t *testing.T) {
	phases := harnessv1alpha1.AllInstallationPhases()
	if len(phases) != 16 {
		t.Fatalf("expected 16 phases, got %d", len(phases))
	}
	expected := map[harnessv1alpha1.InstallationPhase][]harnessv1alpha1.InstallationPhase{
		harnessv1alpha1.PhaseAbsent:         {harnessv1alpha1.PhasePending},
		harnessv1alpha1.PhasePending:        {harnessv1alpha1.PhasePreflight, harnessv1alpha1.PhaseBlocked, harnessv1alpha1.PhaseFailed},
		harnessv1alpha1.PhasePreflight:      {harnessv1alpha1.PhaseVerifying, harnessv1alpha1.PhaseBlocked, harnessv1alpha1.PhaseFailed},
		harnessv1alpha1.PhaseVerifying:      {harnessv1alpha1.PhaseApplying, harnessv1alpha1.PhaseBlocked, harnessv1alpha1.PhaseFailed},
		harnessv1alpha1.PhaseApplying:       {harnessv1alpha1.PhaseHealthChecking, harnessv1alpha1.PhaseBlocked, harnessv1alpha1.PhaseFailed, harnessv1alpha1.PhaseRollingBack},
		harnessv1alpha1.PhaseHealthChecking: {harnessv1alpha1.PhaseReady, harnessv1alpha1.PhaseDegraded, harnessv1alpha1.PhaseBlocked, harnessv1alpha1.PhaseFailed, harnessv1alpha1.PhaseRollingBack},
		harnessv1alpha1.PhaseReady:          {harnessv1alpha1.PhaseDegraded, harnessv1alpha1.PhaseUpgrading, harnessv1alpha1.PhaseUninstalling, harnessv1alpha1.PhaseRetired, harnessv1alpha1.PhaseRevoked},
		harnessv1alpha1.PhaseBlocked:        {harnessv1alpha1.PhasePending, harnessv1alpha1.PhaseRollingBack, harnessv1alpha1.PhaseUninstalling, harnessv1alpha1.PhaseRevoked},
		harnessv1alpha1.PhaseDegraded:       {harnessv1alpha1.PhaseReady, harnessv1alpha1.PhaseBlocked, harnessv1alpha1.PhaseFailed, harnessv1alpha1.PhaseUpgrading, harnessv1alpha1.PhaseRollingBack, harnessv1alpha1.PhaseUninstalling, harnessv1alpha1.PhaseRevoked},
		harnessv1alpha1.PhaseFailed:         {harnessv1alpha1.PhasePending, harnessv1alpha1.PhaseRollingBack, harnessv1alpha1.PhaseUninstalling, harnessv1alpha1.PhaseRevoked},
		harnessv1alpha1.PhaseUpgrading:      {harnessv1alpha1.PhaseVerifying, harnessv1alpha1.PhaseHealthChecking, harnessv1alpha1.PhaseReady, harnessv1alpha1.PhaseDegraded, harnessv1alpha1.PhaseFailed, harnessv1alpha1.PhaseRollingBack, harnessv1alpha1.PhaseRevoked},
		harnessv1alpha1.PhaseRollingBack:    {harnessv1alpha1.PhaseVerifying, harnessv1alpha1.PhaseHealthChecking, harnessv1alpha1.PhaseReady, harnessv1alpha1.PhaseDegraded, harnessv1alpha1.PhaseFailed, harnessv1alpha1.PhaseRevoked},
		harnessv1alpha1.PhaseUninstalling:   {harnessv1alpha1.PhaseRemoved, harnessv1alpha1.PhaseFailed, harnessv1alpha1.PhaseRevoked},
		harnessv1alpha1.PhaseRemoved:        {harnessv1alpha1.PhasePending, harnessv1alpha1.PhaseRetired, harnessv1alpha1.PhaseRevoked},
		harnessv1alpha1.PhaseRetired:        {harnessv1alpha1.PhaseRevoked},
		harnessv1alpha1.PhaseRevoked:        {},
	}
	for _, from := range phases {
		allowed := map[harnessv1alpha1.InstallationPhase]bool{}
		for _, to := range expected[from] {
			allowed[to] = true
		}
		for _, to := range phases {
			if got := harnessv1alpha1.IsAllowedTransition(from, to); got != allowed[to] {
				t.Fatalf("transition mismatch %s -> %s: got %v", from, to, got)
			}
			if err := harnessv1alpha1.ValidateTransition(from, to); (err == nil) != allowed[to] {
				t.Fatalf("transition validation mismatch %s -> %s: %v", from, to, err)
			}
		}
	}
	if harnessv1alpha1.IsKnownPhase("UNKNOWN") {
		t.Fatal("unknown phase was accepted")
	}
}

func TestValidationRejectsInvalidBindingsAndStatus(t *testing.T) {
	base := validInstallation()
	vectors := []func(*harnessv1alpha1.HarnessInstallation){
		func(value *harnessv1alpha1.HarnessInstallation) { value.Spec.OrganizationID = "tenant" },
		func(value *harnessv1alpha1.HarnessInstallation) { value.Spec.ProfileDigest = "sha256:ABC" },
		func(value *harnessv1alpha1.HarnessInstallation) { value.Spec.TargetNamespace = "default" },
		func(value *harnessv1alpha1.HarnessInstallation) { value.Spec.DesiredGeneration = 0 },
		func(value *harnessv1alpha1.HarnessInstallation) { value.Status.Phase = "UNKNOWN" },
		func(value *harnessv1alpha1.HarnessInstallation) { value.Status.ObservedGeneration = -1 },
		func(value *harnessv1alpha1.HarnessInstallation) { value.Status.ReasonCode = "bad-reason" },
		func(value *harnessv1alpha1.HarnessInstallation) { value.Status.Conditions[0].Type = "Unknown" },
		func(value *harnessv1alpha1.HarnessInstallation) {
			value.Status.Conditions = append(value.Status.Conditions, value.Status.Conditions[0])
		},
	}
	for index, mutate := range vectors {
		candidate := base.DeepCopy()
		mutate(candidate)
		if _, err := candidate.ToLifecycleProjection(); err == nil {
			t.Fatalf("invalid vector %d was accepted", index)
		}
	}
}

func TestProjectionSortsEvidenceWithoutMutatingStatus(t *testing.T) {
	installation := validInstallation()
	installation.Status.EvidenceRefs = []harnessv1alpha1.EvidenceReference{
		{Kind: "resource.zeta", ID: "evidence.two", Digest: digestD},
		{Kind: "resource.alpha", ID: "evidence.one", Digest: digestA},
	}
	original := append([]harnessv1alpha1.EvidenceReference(nil), installation.Status.EvidenceRefs...)
	projection, err := installation.ToLifecycleProjection()
	if err != nil {
		t.Fatal(err)
	}
	if projection.Spec.EvidenceRefs[0].Kind != "resource.alpha" {
		t.Fatal("projection evidence is not deterministic")
	}
	if !reflect.DeepEqual(original, installation.Status.EvidenceRefs) {
		t.Fatal("projection mutated source status")
	}
}
