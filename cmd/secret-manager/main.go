// Command secret-manager runs the secret-manager server or its client CLI.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/rapatao/secret-manager/api/v1alpha1"
	"github.com/rapatao/secret-manager/internal/cli"
	"github.com/rapatao/secret-manager/internal/controller"
	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/server"
	"github.com/rapatao/secret-manager/internal/storage"
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
)

var version = "dev"

const usage = `Usage: secret-manager <command> [flags]

Server:
  server [--addr :8080] [--namespace NS] [--storage kubernetes]
                                               run controller, API and Web UI
                                               (admin token from ` + cli.EnvToken + `)
  version                                      print the version

`

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "server":
			if err := runServer(args[1:]); err != nil {
				slog.Error("server stopped", "error", err)
				os.Exit(1)
			}
			return
		case "version":
			fmt.Println(version)
			return
		case "help", "-h", "--help":
			fmt.Print(usage, cli.Usage)
			return
		}
	}
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage, cli.Usage)
		os.Exit(2)
	}
	os.Exit(cli.Default().Run(context.Background(), args))
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	addr := fs.String("addr", ":8080", "listen address of the API and Web UI")
	metricsAddr := fs.String("metrics-addr", ":8081", "listen address of the Prometheus metrics, 0 to disable")
	namespace := fs.String("namespace", os.Getenv("POD_NAMESPACE"), "namespace holding the stored secrets (kubernetes storage)")
	storageName := fs.String("storage", "kubernetes", "storage backend: kubernetes")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	ctrl.SetLogger(logr.FromSlogHandler(logger.Handler()))

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return err
	}

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("kubernetes config: %w", err)
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: *metricsAddr},
		Client: client.Options{Cache: &client.CacheOptions{
			// Read Secrets and Deployments directly: no cluster-wide cache of
			// every Secret, and storage reads always see the latest write.
			DisableFor: []client.Object{&corev1.Secret{}, &appsv1.Deployment{}},
		}},
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	var backend storage.Backend
	switch *storageName {
	case "kubernetes":
		if *namespace == "" {
			return errors.New("--namespace or POD_NAMESPACE is required for kubernetes storage")
		}
		backend = k8sstorage.New(mgr.GetClient(), *namespace)
	default:
		return fmt.Errorf("unknown storage %q", *storageName)
	}

	changes := controller.NewChanges()
	svc := secrets.New(backend, changes.Notify)

	reconciler := &controller.SecretSyncReconciler{
		Client:   mgr.GetClient(),
		Secrets:  svc,
		Changes:  changes,
		Recorder: mgr.GetEventRecorder("secret-manager"),
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup controller: %w", err)
	}

	handler, err := server.New(svc, os.Getenv(cli.EnvToken))
	if err != nil {
		return err
	}
	httpServer := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	err = mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		errc := make(chan error, 1)
		go func() { errc <- httpServer.ListenAndServe() }()
		slog.Info("http server listening", "addr", *addr)
		select {
		case err := <-errc:
			return err
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return httpServer.Shutdown(shutdownCtx)
		}
	}))
	if err != nil {
		return err
	}

	slog.Info("starting secret-manager", "version", version, "storage", *storageName, "namespace", *namespace)
	return mgr.Start(ctrl.SetupSignalHandler())
}
