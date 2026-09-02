package foundation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/caglarsubas/mas-harness-operator/internal/apply"
	"github.com/caglarsubas/mas-harness-operator/internal/evidence"
	"github.com/caglarsubas/mas-harness-operator/internal/inventory"
)

const (
	BeforeApply             = "BEFORE_APPLY"
	AfterApplyBeforeReceipt = "AFTER_APPLY_BEFORE_RECEIPT"
	AfterReceipt            = "AFTER_RECEIPT"
	BeforeStatus            = "BEFORE_STATUS"
	AfterStatus             = "AFTER_STATUS"
)

type Condition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	ReasonCode         string `json:"reasonCode"`
	ObservedGeneration int64  `json:"observedGeneration"`
}

type Outcome struct {
	SchemaVersion        string          `json:"schemaVersion"`
	Phase                string          `json:"phase"`
	ObservedGeneration   int64           `json:"observedGeneration"`
	CurrentReleaseDigest string          `json:"currentReleaseDigest"`
	InventoryDigest      string          `json:"inventoryDigest"`
	EvidenceDigest       string          `json:"evidenceDigest"`
	Conditions           []Condition     `json:"conditions"`
	Evidence             evidence.Record `json:"evidence"`
}

type StatusSink interface {
	Publish(context.Context, Outcome) error
}

type CrashHook interface {
	At(string) error
}

type Input struct {
	Plan           Plan
	PlanDigest     string
	WatchNamespace string
	StartedAt      string
	CompletedAt    string
}

type Engine struct {
	Applier apply.Port
	Store   inventory.Store
	Status  StatusSink
	Crash   CrashHook
}

func (engine Engine) Reconcile(ctx context.Context, input Input) (Outcome, error) {
	if engine.Applier == nil || engine.Store == nil || engine.Status == nil {
		return Outcome{}, Refusal{Code: "FOUNDATION_BACKEND_UNAVAILABLE"}
	}
	if err := ValidatePlan(input.Plan); err != nil {
		return Outcome{}, err
	}
	if Digest(input.Plan) != input.PlanDigest {
		return Outcome{}, Refusal{Code: "PLAN_DIGEST_MISMATCH"}
	}
	if input.WatchNamespace == "" || input.WatchNamespace != input.Plan.TargetNamespace {
		return Outcome{}, Refusal{Code: "WATCH_NAMESPACE_MISMATCH"}
	}
	if err := validateTimes(input.StartedAt, input.CompletedAt); err != nil {
		return Outcome{}, err
	}
	binding := inventory.Binding{
		OrganizationID: input.Plan.OrganizationID, InstallationID: input.Plan.InstallationID,
		Generation: input.Plan.Generation, TargetNamespace: input.Plan.TargetNamespace,
		ProfileDigest: input.Plan.ProfileDigest, BundleDigest: input.Plan.BundleDigest,
		ReleaseDigest: input.Plan.ReleaseDigest, PlanDigest: input.PlanDigest,
		VerificationReceiptDigest: input.Plan.VerificationReceiptDigest,
	}
	key := inventory.Key(binding)
	current, revision, exists, err := engine.Store.Load(ctx, key)
	if err != nil {
		return Outcome{}, Refusal{Code: inventory.Reason(err)}
	}
	if !exists {
		current = inventory.GenerationInventory{SchemaVersion: inventory.SchemaVersion, Binding: binding, State: "APPLYING", Records: []inventory.ResourceRecord{}}
		revision, err = engine.Store.CompareAndSwap(ctx, key, 0, current)
		if err != nil {
			return Outcome{}, Refusal{Code: inventory.Reason(err)}
		}
	} else if err := validateResume(current, binding, input.Plan); err != nil {
		return Outcome{}, err
	}
	if current.State == "COMPLETE" {
		return buildOutcome(input, current)
	}

	resources := flatten(input.Plan)
	for index := len(current.Records); index < len(resources); index++ {
		planned := resources[index]
		if current.State != "WAVE_APPLYING" || current.NextIdentity != planned.Resource.Identity.Key() {
			current.State = "WAVE_APPLYING"
			current.NextWave, current.NextResource, current.NextIdentity = planned.WaveIndex, planned.ResourceIndex, planned.Resource.Identity.Key()
			revision, err = engine.Store.CompareAndSwap(ctx, key, revision, current)
			if err != nil {
				return Outcome{}, Refusal{Code: inventory.Reason(err)}
			}
		}
		if err := engine.crash(BeforeApply); err != nil {
			return Outcome{}, err
		}
		request := apply.Request{Identity: planned.Resource.Identity, Manifest: append([]byte(nil), planned.Resource.Manifest...), ManifestDigest: planned.Resource.ManifestDigest, FieldManager: apply.FieldManager, Force: false, DryRun: false}
		receipt, err := engine.Applier.Apply(ctx, request)
		if err != nil {
			return Outcome{}, Refusal{Code: apply.Reason(err)}
		}
		if err := apply.ValidateReceipt(request, receipt); err != nil {
			return Outcome{}, Refusal{Code: apply.Reason(err)}
		}
		if err := engine.crash(AfterApplyBeforeReceipt); err != nil {
			return Outcome{}, err
		}
		current.Records = append(current.Records, inventory.ResourceRecord{
			WaveID: planned.WaveID, Identity: receipt.Identity, DesiredManifestDigest: request.ManifestDigest,
			ObservedManifestDigest: receipt.ObservedManifestDigest, UID: receipt.UID,
			ResourceVersion: receipt.ResourceVersion, AppliedAt: receipt.AppliedAt, State: "APPLIED",
		})
		current.State = "APPLYING"
		current.NextIdentity = ""
		if index+1 < len(resources) {
			current.NextWave, current.NextResource = resources[index+1].WaveIndex, resources[index+1].ResourceIndex
		} else {
			current.State = "STATUS_PENDING"
			current.NextWave, current.NextResource = len(input.Plan.Waves), 0
		}
		revision, err = engine.Store.CompareAndSwap(ctx, key, revision, current)
		if err != nil {
			return Outcome{}, Refusal{Code: inventory.Reason(err)}
		}
		if err := engine.crash(AfterReceipt); err != nil {
			return Outcome{}, err
		}
	}
	if current.State != "STATUS_PENDING" {
		current.State, current.NextWave, current.NextResource, current.NextIdentity = "STATUS_PENDING", len(input.Plan.Waves), 0, ""
		revision, err = engine.Store.CompareAndSwap(ctx, key, revision, current)
		if err != nil {
			return Outcome{}, Refusal{Code: inventory.Reason(err)}
		}
	}
	if err := engine.crash(BeforeStatus); err != nil {
		return Outcome{}, err
	}
	outcome, err := buildOutcome(input, current)
	if err != nil {
		return Outcome{}, err
	}
	if err := engine.Status.Publish(ctx, outcome); err != nil {
		return Outcome{}, Refusal{Code: "STATUS_BACKEND_UNAVAILABLE"}
	}
	if err := engine.crash(AfterStatus); err != nil {
		return Outcome{}, err
	}
	current.State = "COMPLETE"
	if _, err := engine.Store.CompareAndSwap(ctx, key, revision, current); err != nil {
		return Outcome{}, Refusal{Code: inventory.Reason(err)}
	}
	return outcome, nil
}

type plannedResource struct {
	WaveID        string
	WaveIndex     int
	ResourceIndex int
	Resource      Resource
}

func flatten(plan Plan) []plannedResource {
	result := []plannedResource{}
	for waveIndex, wave := range plan.Waves {
		for resourceIndex, resource := range wave.Resources {
			result = append(result, plannedResource{WaveID: wave.ID, WaveIndex: waveIndex, ResourceIndex: resourceIndex, Resource: resource})
		}
	}
	return result
}

func validateResume(current inventory.GenerationInventory, binding inventory.Binding, plan Plan) error {
	if err := inventory.Validate(current, binding); err != nil {
		return Refusal{Code: inventory.Reason(err)}
	}
	resources := flatten(plan)
	if len(current.Records) > len(resources) {
		return Refusal{Code: "INVENTORY_CURSOR_INVALID"}
	}
	for index, record := range current.Records {
		planned := resources[index]
		if record.WaveID != planned.WaveID || record.Identity != planned.Resource.Identity || record.DesiredManifestDigest != planned.Resource.ManifestDigest || record.ObservedManifestDigest != planned.Resource.ManifestDigest {
			return Refusal{Code: "INVENTORY_BINDING_DRIFT"}
		}
	}
	completed := len(current.Records)
	switch current.State {
	case "WAVE_APPLYING":
		if completed >= len(resources) || current.NextWave != resources[completed].WaveIndex || current.NextResource != resources[completed].ResourceIndex || current.NextIdentity != resources[completed].Resource.Identity.Key() {
			return Refusal{Code: "INVENTORY_CURSOR_INVALID"}
		}
	case "APPLYING":
		if current.NextIdentity != "" || (completed < len(resources) && (current.NextWave != resources[completed].WaveIndex || current.NextResource != resources[completed].ResourceIndex)) {
			return Refusal{Code: "INVENTORY_CURSOR_INVALID"}
		}
	case "STATUS_PENDING", "COMPLETE":
		if completed != len(resources) || current.NextWave != len(plan.Waves) || current.NextResource != 0 || current.NextIdentity != "" {
			return Refusal{Code: "INVENTORY_CURSOR_INVALID"}
		}
	}
	return nil
}

func buildOutcome(input Input, current inventory.GenerationInventory) (Outcome, error) {
	inventoryDigest := inventory.ProjectionDigest(current)
	record, err := evidence.Build(evidence.Input{
		OrganizationID: input.Plan.OrganizationID, InstallationID: input.Plan.InstallationID,
		Generation: input.Plan.Generation, ProfileDigest: input.Plan.ProfileDigest, BundleDigest: input.Plan.BundleDigest,
		ReleaseDigest: input.Plan.ReleaseDigest, PlanDigest: input.PlanDigest, ReceiptDigest: input.Plan.VerificationReceiptDigest,
		InventoryDigest: inventoryDigest, WaveCount: len(input.Plan.Waves), ResourceCount: len(current.Records),
		Result: "FOUNDATION_APPLIED", ReasonCode: "FOUNDATION_APPLIED_AWAITING_HEALTH", StartedAt: input.StartedAt, CompletedAt: input.CompletedAt,
	})
	if err != nil {
		return Outcome{}, Refusal{Code: err.Error()}
	}
	conditions := []Condition{
		{Type: "ArtifactsVerified", Status: "True", ReasonCode: "SIGNED_RELEASE_VERIFIED", ObservedGeneration: input.Plan.Generation},
		{Type: "Configured", Status: "True", ReasonCode: "FOUNDATION_CONFIGURED", ObservedGeneration: input.Plan.Generation},
		{Type: "DependenciesResolved", Status: "True", ReasonCode: "FOUNDATION_DEPENDENCIES_RESOLVED", ObservedGeneration: input.Plan.Generation},
		{Type: "EvidenceCurrent", Status: "True", ReasonCode: "FOUNDATION_EVIDENCE_CURRENT", ObservedGeneration: input.Plan.Generation},
		{Type: "Healthy", Status: "Unknown", ReasonCode: "FOUNDATION_APPLIED_AWAITING_HEALTH", ObservedGeneration: input.Plan.Generation},
		{Type: "PolicyCompliant", Status: "True", ReasonCode: "FOUNDATION_POLICY_COMPLIANT", ObservedGeneration: input.Plan.Generation},
		{Type: "Ready", Status: "Unknown", ReasonCode: "FOUNDATION_APPLIED_AWAITING_HEALTH", ObservedGeneration: input.Plan.Generation},
	}
	return Outcome{SchemaVersion: "harness.planeon.ai/foundation-outcome/v1alpha1", Phase: "HEALTH_CHECKING", ObservedGeneration: input.Plan.Generation, CurrentReleaseDigest: input.Plan.ReleaseDigest, InventoryDigest: inventoryDigest, EvidenceDigest: record.EvidenceDigest, Conditions: conditions, Evidence: record}, nil
}

func validateTimes(startedAt, completedAt string) error {
	started, first := time.Parse(time.RFC3339, startedAt)
	completed, second := time.Parse(time.RFC3339, completedAt)
	if first != nil || second != nil || started.Location() != time.UTC || completed.Location() != time.UTC || started.Nanosecond() != 0 || completed.Nanosecond() != 0 || started.Format(time.RFC3339) != startedAt || completed.Format(time.RFC3339) != completedAt || completed.Before(started) {
		return Refusal{Code: "FOUNDATION_TIME_INVALID"}
	}
	return nil
}

func (engine Engine) crash(point string) error {
	if engine.Crash == nil {
		return nil
	}
	if err := engine.Crash.At(point); err != nil {
		return Refusal{Code: "CRASH_INJECTED_" + point}
	}
	return nil
}

func ReasonCode(err error) string {
	var refusal Refusal
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return fmt.Sprintf("FOUNDATION_INTERNAL_ERROR")
}
