package controller

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

const (
	LeaderElectionID  = "harness-operator.harness.planeon.ai"
	OrganizationIndex = "spec.organizationId"
)

type RuntimeOptions struct {
	WatchNamespace         string
	HealthProbeBindAddress string
	LeaderElect            bool
}

func ParseArguments(arguments []string) (RuntimeOptions, error) {
	set := flag.NewFlagSet("harness-operator", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	options := RuntimeOptions{}
	set.StringVar(&options.WatchNamespace, "watch-namespace", "", "single namespace to watch")
	set.StringVar(&options.HealthProbeBindAddress, "health-probe-bind-address", "", "explicit local health listener")
	set.BoolVar(&options.LeaderElect, "leader-elect", true, "enable Lease leader election")
	if err := set.Parse(arguments); err != nil {
		return RuntimeOptions{}, err
	}
	if set.NArg() != 0 {
		return RuntimeOptions{}, errors.New("positional arguments are forbidden")
	}
	if err := ValidateRuntimeOptions(options); err != nil {
		return RuntimeOptions{}, err
	}
	return options, nil
}

func ValidateRuntimeOptions(options RuntimeOptions) error {
	if options.WatchNamespace == "" || options.WatchNamespace == "default" {
		return errors.New("a non-default watch namespace is required")
	}
	host, port, err := net.SplitHostPort(options.HealthProbeBindAddress)
	if err != nil {
		return fmt.Errorf("health probe bind address is invalid: %w", err)
	}
	if host != "127.0.0.1" && host != "0.0.0.0" && host != "::1" && host != "::" {
		return errors.New("health probe must bind a local literal address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("health probe port is invalid")
	}
	return nil
}

func ManagerOptions(options RuntimeOptions) manager.Options {
	return manager.Options{
		Cache: cache.Options{DefaultNamespaces: map[string]cache.Config{
			options.WatchNamespace: {},
		}},
		Metrics:                    metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress:     options.HealthProbeBindAddress,
		LeaderElection:             options.LeaderElect,
		LeaderElectionID:           LeaderElectionID,
		LeaderElectionNamespace:    options.WatchNamespace,
		LeaderElectionResourceLock: "leases",
	}
}
