package envtest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	harnessv1alpha1 "github.com/caglarsubas/mas-harness-operator/api/v1alpha1"
	harnesscontroller "github.com/caglarsubas/mas-harness-operator/internal/controller"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

func TestReconcilerIsReadOnlyAndRestartSafe(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := harnessv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	installation := validInstallation()
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(installation).Build()
	reconciler := &harnesscontroller.HarnessInstallationReconciler{Client: client, Scheme: scheme}
	key := types.NamespacedName{Name: installation.Name, Namespace: installation.Namespace}
	before := &harnessv1alpha1.HarnessInstallation{}
	if err := client.Get(context.Background(), key, before); err != nil {
		t.Fatal(err)
	}
	for run := 0; run < 2; run++ {
		result, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
		if err != nil || !result.IsZero() {
			t.Fatalf("reconcile run %d: result=%v err=%v", run, result, err)
		}
	}
	after := &harnessv1alpha1.HarnessInstallation{}
	if err := client.Get(context.Background(), key, after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("OP-001 reconciler mutated the installation")
	}
	missing := ctrl.Request{NamespacedName: types.NamespacedName{Name: "installation.missing", Namespace: installation.Namespace}}
	if result, err := reconciler.Reconcile(context.Background(), missing); err != nil || !result.IsZero() {
		t.Fatalf("missing object should converge without mutation: %v %v", result, err)
	}
}

func TestReconcilerRejectsInvalidSpecWithoutMutation(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := harnessv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	installation := validInstallation()
	installation.Spec.TargetNamespace = "default"
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(installation).Build()
	reconciler := &harnesscontroller.HarnessInstallationReconciler{Client: client, Scheme: scheme}
	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: installation.Name, Namespace: installation.Namespace}})
	if err == nil {
		t.Fatal("invalid spec was accepted")
	}
}

func TestClosedRuntimeOptions(t *testing.T) {
	parsed, err := harnesscontroller.ParseArguments([]string{"--watch-namespace=planeon-system", "--health-probe-bind-address=0.0.0.0:8081", "--leader-elect=true"})
	if err != nil {
		t.Fatal(err)
	}
	options := harnesscontroller.ManagerOptions(parsed)
	if len(options.Cache.DefaultNamespaces) != 1 {
		t.Fatal("manager is not single-namespace scoped")
	}
	if _, ok := options.Cache.DefaultNamespaces["planeon-system"]; !ok {
		t.Fatal("manager watches the wrong namespace")
	}
	if options.Metrics.BindAddress != "0" || options.HealthProbeBindAddress != "0.0.0.0:8081" {
		t.Fatalf("unexpected listener options: %+v", options)
	}
	if !options.LeaderElection || options.LeaderElectionID != harnesscontroller.LeaderElectionID || options.LeaderElectionNamespace != "planeon-system" || options.LeaderElectionResourceLock != "leases" {
		t.Fatal("leader election is not closed")
	}
	invalid := [][]string{
		{},
		{"--watch-namespace=default", "--health-probe-bind-address=0.0.0.0:8081"},
		{"--watch-namespace=planeon-system", "--health-probe-bind-address=example.com:8081"},
		{"--watch-namespace=planeon-system", "--health-probe-bind-address=127.0.0.1:0"},
		{"--watch-namespace=planeon-system", "--health-probe-bind-address=127.0.0.1:8081", "extra"},
		{"--watch-namespace=planeon-system", "--health-probe-bind-address=127.0.0.1:8081", "--unknown=true"},
	}
	for index, arguments := range invalid {
		if _, err := harnesscontroller.ParseArguments(arguments); err == nil {
			t.Fatalf("invalid option vector %d was accepted", index)
		}
	}
}

func TestHealthHandlerUsesNoSocket(t *testing.T) {
	handler := &healthz.Handler{Checks: map[string]healthz.Checker{"ping": healthz.Ping}}
	request := httptest.NewRequest(http.MethodGet, "http://local/", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "ok" {
		t.Fatalf("unexpected health response: %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestSchemeRegistration(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := harnessv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	object, err := scheme.New(harnessv1alpha1.GroupVersion.WithKind("HarnessInstallation"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := object.(*harnessv1alpha1.HarnessInstallation); !ok {
		t.Fatalf("unexpected registered type: %T", object)
	}
}
