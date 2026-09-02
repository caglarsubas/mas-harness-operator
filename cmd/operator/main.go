package main

import (
	"fmt"
	"os"

	harnessv1alpha1 "github.com/caglarsubas/mas-harness-operator/api/v1alpha1"
	harnesscontroller "github.com/caglarsubas/mas-harness-operator/internal/controller"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "operator refused:", err)
		os.Exit(2)
	}
}

func run(arguments []string) error {
	options, err := harnesscontroller.ParseArguments(arguments)
	if err != nil {
		return err
	}
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return fmt.Errorf("register Kubernetes scheme: %w", err)
	}
	if err := harnessv1alpha1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("register HarnessInstallation scheme: %w", err)
	}
	config, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("load Kubernetes REST configuration: %w", err)
	}
	manager, err := ctrl.NewManager(config, harnesscontroller.ManagerOptions(options))
	if err != nil {
		return fmt.Errorf("construct manager: %w", err)
	}
	if err := (&harnesscontroller.HarnessInstallationReconciler{
		Client: manager.GetClient(), Scheme: manager.GetScheme(),
	}).SetupWithManager(manager); err != nil {
		return err
	}
	if err := manager.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("register health check: %w", err)
	}
	if err := manager.AddReadyzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("register readiness check: %w", err)
	}
	return manager.Start(ctrl.SetupSignalHandler())
}
