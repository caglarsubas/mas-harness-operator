package foundation_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/caglarsubas/mas-harness-operator/internal/apply"
	"github.com/caglarsubas/mas-harness-operator/internal/controller/foundation"
	"github.com/caglarsubas/mas-harness-operator/internal/inventory"
)

const (
	startedAt   = "2026-09-03T00:00:00Z"
	completedAt = "2026-09-03T00:00:10Z"
)

func fixture(t *testing.T) (foundation.Plan, string) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "fixtures", "foundation", "valid-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, digest, err := foundation.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return plan, digest
}

func clonePlan(t *testing.T, plan foundation.Plan) foundation.Plan {
	t.Helper()
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var result foundation.Plan
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

type memoryStore struct {
	values       map[string]inventory.GenerationInventory
	revisions    map[string]uint64
	writes       int
	conflictNext bool
}

func newStore() *memoryStore {
	return &memoryStore{values: map[string]inventory.GenerationInventory{}, revisions: map[string]uint64{}}
}

func copyInventory(value inventory.GenerationInventory) inventory.GenerationInventory {
	data, _ := json.Marshal(value)
	var result inventory.GenerationInventory
	_ = json.Unmarshal(data, &result)
	return result
}

func (store *memoryStore) Load(_ context.Context, key string) (inventory.GenerationInventory, uint64, bool, error) {
	value, ok := store.values[key]
	return copyInventory(value), store.revisions[key], ok, nil
}

func (store *memoryStore) CompareAndSwap(_ context.Context, key string, expected uint64, value inventory.GenerationInventory) (uint64, error) {
	if store.conflictNext {
		store.conflictNext = false
		return 0, inventory.Refuse("INVENTORY_CONFLICT")
	}
	if store.revisions[key] != expected {
		return 0, inventory.Refuse("INVENTORY_CONFLICT")
	}
	store.revisions[key]++
	store.values[key] = copyInventory(value)
	store.writes++
	return store.revisions[key], nil
}

type fakeApplier struct {
	logical  map[string]apply.Receipt
	calls    int
	drift    bool
	failure  error
	requests []apply.Request
}

func newApplier() *fakeApplier { return &fakeApplier{logical: map[string]apply.Receipt{}} }

func (applier *fakeApplier) Apply(_ context.Context, request apply.Request) (apply.Receipt, error) {
	applier.calls++
	applier.requests = append(applier.requests, request)
	if applier.failure != nil {
		return apply.Receipt{}, applier.failure
	}
	if existing, ok := applier.logical[request.Identity.Key()]; ok {
		return existing, nil
	}
	receipt := apply.Receipt{Identity: request.Identity, UID: fmt.Sprintf("uid:%02d", len(applier.logical)+1), ResourceVersion: fmt.Sprintf("%d", len(applier.logical)+1), ObservedManifestDigest: request.ManifestDigest, AppliedAt: "2026-09-03T00:00:05Z"}
	if applier.drift {
		receipt.ObservedManifestDigest = "sha256:" + string(make([]byte, 64))
	}
	applier.logical[request.Identity.Key()] = receipt
	return receipt, nil
}

type statusSink struct {
	calls   int
	latest  foundation.Outcome
	failure error
}

func (sink *statusSink) Publish(_ context.Context, outcome foundation.Outcome) error {
	sink.calls++
	sink.latest = outcome
	return sink.failure
}

type oneCrash struct {
	point            string
	occurrence, seen int
	fired            bool
}

func (hook *oneCrash) At(point string) error {
	if point == hook.point {
		hook.seen++
		if !hook.fired && hook.seen == hook.occurrence {
			hook.fired = true
			return errors.New("simulated crash")
		}
	}
	return nil
}

func input(plan foundation.Plan, digest string) foundation.Input {
	return foundation.Input{Plan: plan, PlanDigest: digest, WatchNamespace: plan.TargetNamespace, StartedAt: startedAt, CompletedAt: completedAt}
}

func TestValidFoundationConvergesAndCompletionIsReadOnly(t *testing.T) {
	plan, digest := fixture(t)
	store, applier, statuses := newStore(), newApplier(), &statusSink{}
	engine := foundation.Engine{Applier: applier, Store: store, Status: statuses}
	first, err := engine.Reconcile(context.Background(), input(plan, digest))
	if err != nil {
		t.Fatal(err)
	}
	writes, applyCalls, statusCalls := store.writes, applier.calls, statuses.calls
	second, err := engine.Reconcile(context.Background(), input(plan, digest))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("completed outcome is not deterministic")
	}
	if len(applier.logical) != 6 || applier.calls != 6 || store.writes != writes || applier.calls != applyCalls || statuses.calls != statusCalls {
		t.Fatalf("idempotency failed logical=%d apply=%d writes=%d status=%d", len(applier.logical), applier.calls, store.writes, statuses.calls)
	}
	if first.Phase != "HEALTH_CHECKING" || first.ObservedGeneration != 1 || len(first.Conditions) != 7 || first.Evidence.ResourceCount != 6 || first.Evidence.WaveCount != 1 {
		t.Fatalf("outcome invalid: %+v", first)
	}
	wantConditions := []string{"ArtifactsVerified", "Configured", "DependenciesResolved", "EvidenceCurrent", "Healthy", "PolicyCompliant", "Ready"}
	for index, condition := range first.Conditions {
		if condition.Type != wantConditions[index] || condition.ObservedGeneration != 1 {
			t.Fatalf("condition[%d]=%+v", index, condition)
		}
		if (condition.Type == "Ready" || condition.Type == "Healthy") && condition.Status != "Unknown" {
			t.Fatal("health was falsely claimed")
		}
	}
	for _, request := range applier.requests {
		if request.FieldManager != apply.FieldManager || request.Force || request.DryRun || request.Identity.Namespace != plan.TargetNamespace {
			t.Fatalf("unsafe apply: %+v", request)
		}
	}
}

func TestCrashAtEveryBoundaryConvergesAfterRestart(t *testing.T) {
	plan, digest := fixture(t)
	vectors := []struct {
		point string
		max   int
	}{{foundation.BeforeApply, 6}, {foundation.AfterApplyBeforeReceipt, 6}, {foundation.AfterReceipt, 6}, {foundation.BeforeStatus, 1}, {foundation.AfterStatus, 1}}
	for _, vector := range vectors {
		for occurrence := 1; occurrence <= vector.max; occurrence++ {
			name := fmt.Sprintf("%s-%d", vector.point, occurrence)
			t.Run(name, func(t *testing.T) {
				store, applier, statuses := newStore(), newApplier(), &statusSink{}
				crash := &oneCrash{point: vector.point, occurrence: occurrence}
				firstEngine := foundation.Engine{Applier: applier, Store: store, Status: statuses, Crash: crash}
				if _, err := firstEngine.Reconcile(context.Background(), input(plan, digest)); foundation.ReasonCode(err) != "CRASH_INJECTED_"+vector.point {
					t.Fatalf("crash reason=%s", foundation.ReasonCode(err))
				}
				restarted := foundation.Engine{Applier: applier, Store: store, Status: statuses}
				outcome, err := restarted.Reconcile(context.Background(), input(plan, digest))
				if err != nil {
					t.Fatal(err)
				}
				if len(applier.logical) != 6 || outcome.Evidence.ResourceCount != 6 {
					t.Fatalf("did not converge logical=%d outcome=%+v", len(applier.logical), outcome)
				}
				writes, calls, publishes := store.writes, applier.calls, statuses.calls
				if _, err := restarted.Reconcile(context.Background(), input(plan, digest)); err != nil {
					t.Fatal(err)
				}
				if store.writes != writes || applier.calls != calls || statuses.calls != publishes {
					t.Fatal("completed restart performed writes")
				}
			})
		}
	}
}

func TestScopeBackendDriftAndCASFailuresAreBounded(t *testing.T) {
	plan, digest := fixture(t)
	t.Run("scope", func(t *testing.T) {
		store, applier, statuses := newStore(), newApplier(), &statusSink{}
		candidate := input(plan, digest)
		candidate.WatchNamespace = "other"
		_, err := (foundation.Engine{Applier: applier, Store: store, Status: statuses}).Reconcile(context.Background(), candidate)
		if foundation.ReasonCode(err) != "WATCH_NAMESPACE_MISMATCH" || store.writes != 0 || applier.calls != 0 {
			t.Fatalf("reason=%s", foundation.ReasonCode(err))
		}
	})
	t.Run("apply-conflict", func(t *testing.T) {
		store, applier, statuses := newStore(), newApplier(), &statusSink{}
		applier.failure = apply.Refuse("APPLY_CONFLICT")
		_, err := (foundation.Engine{Applier: applier, Store: store, Status: statuses}).Reconcile(context.Background(), input(plan, digest))
		if foundation.ReasonCode(err) != "APPLY_CONFLICT" || len(applier.logical) != 0 {
			t.Fatalf("reason=%s", foundation.ReasonCode(err))
		}
	})
	t.Run("apply-drift", func(t *testing.T) {
		store, applier, statuses := newStore(), newApplier(), &statusSink{}
		applier.drift = true
		_, err := (foundation.Engine{Applier: applier, Store: store, Status: statuses}).Reconcile(context.Background(), input(plan, digest))
		if foundation.ReasonCode(err) != "APPLY_RESPONSE_DRIFT" {
			t.Fatalf("reason=%s", foundation.ReasonCode(err))
		}
	})
	t.Run("cas", func(t *testing.T) {
		store, applier, statuses := newStore(), newApplier(), &statusSink{}
		store.conflictNext = true
		_, err := (foundation.Engine{Applier: applier, Store: store, Status: statuses}).Reconcile(context.Background(), input(plan, digest))
		if foundation.ReasonCode(err) != "INVENTORY_CONFLICT" || applier.calls != 0 {
			t.Fatalf("reason=%s", foundation.ReasonCode(err))
		}
	})
}

func TestInventoryBindingDriftBlocksResume(t *testing.T) {
	plan, digest := fixture(t)
	store, applier, statuses := newStore(), newApplier(), &statusSink{}
	binding := inventory.Binding{OrganizationID: plan.OrganizationID, InstallationID: plan.InstallationID, Generation: plan.Generation, TargetNamespace: plan.TargetNamespace, ProfileDigest: plan.ProfileDigest, BundleDigest: plan.BundleDigest, ReleaseDigest: plan.ReleaseDigest, PlanDigest: digest, VerificationReceiptDigest: plan.VerificationReceiptDigest}
	drift := binding
	drift.BundleDigest = "sha256:" + string(make([]byte, 64))
	key := inventory.Key(binding)
	store.values[key] = inventory.GenerationInventory{SchemaVersion: inventory.SchemaVersion, Binding: drift, State: "APPLYING", Records: []inventory.ResourceRecord{}}
	store.revisions[key] = 1
	_, err := (foundation.Engine{Applier: applier, Store: store, Status: statuses}).Reconcile(context.Background(), input(plan, digest))
	if foundation.ReasonCode(err) != "INVENTORY_BINDING_DRIFT" || applier.calls != 0 || store.writes != 0 {
		t.Fatalf("reason=%s", foundation.ReasonCode(err))
	}
}
