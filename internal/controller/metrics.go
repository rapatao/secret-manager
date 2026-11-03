package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	syncFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "secretmanager_sync_failures_total",
		Help: "SecretSync reconciles that ended with Ready False, by reason.",
	}, []string{"reason"})
	deploymentRestarts = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "secretmanager_deployment_restarts_total",
		Help: "Deployments restarted because a synced Secret changed.",
	})
)

func init() {
	metrics.Registry.MustRegister(syncFailures, deploymentRestarts)
}
