// Command manager runs the Tenarium Kubernetes operator.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
	"github.com/AimTune/tenarium/operator/internal/controller"
)

func main() {
	var (
		metricsAddr, probeAddr string
		leaderElect            bool
		watchNamespaces        string
		def                    controller.DefaultConnection
		apiKeySecret           string
		resync, maxBackoff     time.Duration
		concurrency, retries   int
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Address of the metrics endpoint; \"0\" disables it.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address of the health probe endpoint.")
	flag.BoolVar(&leaderElect, "leader-elect", false, "Enable leader election so only one replica is active.")
	flag.StringVar(&watchNamespaces, "watch-namespaces", "", "Comma-separated namespaces to watch; empty watches all.")
	flag.StringVar(&def.URL, "tenarium-url", os.Getenv("TENARIUM_URL"),
		"Default Tenarium server URL for resources without spec.connectionRef (env TENARIUM_URL).")
	flag.StringVar(&apiKeySecret, "tenarium-api-key-secret", os.Getenv("TENARIUM_API_KEY_SECRET"),
		"Secret holding the default API key, as namespace/name (env TENARIUM_API_KEY_SECRET). "+
			"Without it the env variable TENARIUM_API_KEY is used.")
	flag.StringVar(&def.SecretKey, "tenarium-api-key-secret-key", "api-key", "Key of the API key in --tenarium-api-key-secret.")
	flag.DurationVar(&resync, "resync-period", controller.DefaultResyncPeriod, "How often synced objects are checked for drift.")
	flag.DurationVar(&maxBackoff, "max-backoff", 5*time.Minute, "Maximum retry delay after API errors.")
	flag.IntVar(&concurrency, "max-concurrent-reconciles", 2, "Concurrent reconciles per controller.")
	flag.IntVar(&retries, "api-retries", 2, "Retries of failed, safe-to-repeat API requests within one reconcile.")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("setup")

	if apiKeySecret != "" {
		ns, name, ok := strings.Cut(apiKeySecret, "/")
		if !ok || ns == "" || name == "" {
			log.Error(fmt.Errorf("want namespace/name, got %q", apiKeySecret), "invalid --tenarium-api-key-secret")
			os.Exit(1)
		}
		def.SecretNamespace, def.SecretName = ns, name
	} else {
		def.APIKey = os.Getenv("TENARIUM_API_KEY")
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(tenariumv1.AddToScheme(scheme))

	mgrOpts := ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         leaderElect,
		LeaderElectionID:       "tenarium-operator.tenarium.io",
	}
	if watchNamespaces != "" {
		mgrOpts.Cache.DefaultNamespaces = map[string]cache.Config{}
		for _, ns := range strings.Split(watchNamespaces, ",") {
			if ns = strings.TrimSpace(ns); ns != "" {
				mgrOpts.Cache.DefaultNamespaces[ns] = cache.Config{}
			}
		}
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), mgrOpts)
	if err != nil {
		log.Error(err, "create manager")
		os.Exit(1)
	}

	conns := &controller.Connections{Reader: mgr.GetAPIReader(), Default: def, Retries: retries}
	rec := mgr.GetEventRecorder("tenarium-operator")
	if err := (&controller.TenantReconciler{
		Client: mgr.GetClient(), Connections: conns, Recorder: rec,
		ResyncPeriod: resync, MaxBackoff: maxBackoff, MaxConcurrentReconciles: concurrency,
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "set up controller", "controller", "Tenant")
		os.Exit(1)
	}
	if err := (&controller.PlanReconciler{
		Client: mgr.GetClient(), Connections: conns, Recorder: rec,
		ResyncPeriod: resync, MaxBackoff: maxBackoff, MaxConcurrentReconciles: concurrency,
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "set up controller", "controller", "Plan")
		os.Exit(1)
	}
	if err := (&controller.RolloutReconciler{
		Client: mgr.GetClient(), Connections: conns, Recorder: rec,
		ResyncPeriod: resync, MaxBackoff: maxBackoff, MaxConcurrentReconciles: concurrency,
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "set up controller", "controller", "Rollout")
		os.Exit(1)
	}
	if err := (&controller.TenantTemplateReconciler{
		Client: mgr.GetClient(), Connections: conns, Recorder: rec,
		ResyncPeriod: resync, MaxBackoff: maxBackoff, MaxConcurrentReconciles: concurrency,
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "set up controller", "controller", "TenantTemplate")
		os.Exit(1)
	}
	if err := (&controller.ConnectionReconciler{
		Client: mgr.GetClient(), Connections: conns, Recorder: rec,
		ResyncPeriod: resync, MaxBackoff: maxBackoff,
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "set up controller", "controller", "TenariumConnection")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Error(err, "add health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Error(err, "add ready check")
		os.Exit(1)
	}

	log.Info("starting manager", "defaultURL", def.URL)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "run manager")
		os.Exit(1)
	}
}
