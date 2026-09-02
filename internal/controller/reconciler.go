package controller

import (
	"context"
	"fmt"

	harnessv1alpha1 "github.com/caglarsubas/mas-harness-operator/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// +kubebuilder:rbac:groups=harness.planeon.ai,resources=harnessinstallations,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=harness.planeon.ai,resources=harnessinstallations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=harness.planeon.ai,resources=harnessinstallations/finalizers,verbs=get;update;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;update;patch

type HarnessInstallationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *HarnessInstallationReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	installation := &harnessv1alpha1.HarnessInstallation{}
	if err := r.Get(ctx, request.NamespacedName, installation); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("read HarnessInstallation: %w", err)
	}
	if err := harnessv1alpha1.ValidateSpec(installation.Spec); err != nil {
		return ctrl.Result{}, fmt.Errorf("validate HarnessInstallation: %w", err)
	}
	// OP-001 intentionally performs no mutation. OP-002 owns verification and
	// OP-003 owns foundation application and lifecycle status updates.
	return ctrl.Result{}, nil
}

func (r *HarnessInstallationReconciler) SetupWithManager(manager ctrl.Manager) error {
	if err := manager.GetFieldIndexer().IndexField(
		context.Background(),
		&harnessv1alpha1.HarnessInstallation{},
		OrganizationIndex,
		func(object client.Object) []string {
			installation, ok := object.(*harnessv1alpha1.HarnessInstallation)
			if !ok || installation.Spec.OrganizationID == "" {
				return nil
			}
			return []string{installation.Spec.OrganizationID}
		},
	); err != nil {
		return fmt.Errorf("register organization index: %w", err)
	}
	return ctrl.NewControllerManagedBy(manager).
		For(&harnessv1alpha1.HarnessInstallation{}).
		Complete(r)
}
