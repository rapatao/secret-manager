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
	workloadRestarts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "secretmanager_workload_restarts_total",
		Help: "Deployments, StatefulSets and DaemonSets restarted because a synced Secret changed, by kind.",
	}, []string{"kind"})
)

func init() {
	metrics.Registry.MustRegister(syncFailures, workloadRestarts)
}
