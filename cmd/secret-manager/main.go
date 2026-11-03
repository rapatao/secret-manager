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
	"github.com/prometheus/client_golang/prometheus/promhttp"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/rapatao/secret-manager/api/v1alpha1"
	"github.com/rapatao/secret-manager/internal/cli"
	"github.com/rapatao/secret-manager/internal/controller"
	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/server"
	"github.com/rapatao/secret-manager/internal/storage"
	"github.com/rapatao/secret-manager/internal/storage/encrypted"
	filestorage "github.com/rapatao/secret-manager/internal/storage/file"
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
	"github.com/rapatao/secret-manager/internal/tokens"
)

var version = "dev"

const envEncryptionKey = "SECRET_MANAGER_ENCRYPTION_KEY"

const usage = `Usage: secret-manager <command> [flags]

Server:
  server [--addr :8080] [--metrics-addr :8081] [--storage kubernetes|file]
         [--namespace NS] [--file secret-manager.json] [--controller=true]
         [--history-limit 10] [--last-used-flush 30m] [--log-level info]
         [--backup-dir DIR [--backup-interval 24h] [--backup-keep 7]
          [--backup-history]]
                                               run controller, API and Web UI
                                               (Web UI admin token from ` + cli.EnvToken + `,
                                               optional encryption key from
                                               ` + envEncryptionKey + `)

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
		case "help", "-h", "--help":
			fmt.Print(usage, cli.Usage)
			return
		}
	}
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage, cli.Usage)
		os.Exit(2)
	}
	c := cli.Default()
	c.Version = version
	os.Exit(c.Run(context.Background(), args))
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	addr := fs.String("addr", ":8080", "listen address of the API and Web UI")
	metricsAddr := fs.String("metrics-addr", ":8081", "listen address of the Prometheus metrics, 0 to disable")
	namespace := fs.String("namespace", os.Getenv("POD_NAMESPACE"), "namespace holding the stored secrets (kubernetes storage)")
	storageName := fs.String("storage", "kubernetes", "storage backend: kubernetes or file")
	filePath := fs.String("file", "secret-manager.json", "file holding the stored secrets (file storage)")
	runController := fs.Bool("controller", true, "run the SecretSync controller")
	historyLimit := fs.Int("history-limit", 10, "versions kept per path, current included, 0 to disable history")
	lastUsedFlush := fs.Duration("last-used-flush", 30*time.Minute, "time between saves of the last use of every integration")
	var sched server.BackupSchedule
	fs.StringVar(&sched.Dir, "backup-dir", "", "directory receiving scheduled backups, empty to disable them")
	fs.DurationVar(&sched.Interval, "backup-interval", 24*time.Hour, "time between scheduled backups")
	fs.IntVar(&sched.Keep, "backup-keep", 7, "scheduled backup files kept in --backup-dir")
	fs.BoolVar(&sched.History, "backup-history", false, "include the versions of every path in scheduled backups")
	var logLevel slog.Level
	fs.TextVar(&logLevel, "log-level", slog.LevelInfo, "log level: debug, info, warn or error")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *historyLimit < 0 {
		return errors.New("--history-limit must not be negative")
	}
	if *lastUsedFlush <= 0 {
		return errors.New("--last-used-flush must be positive")
	}
	if sched.Dir != "" {
		if sched.Interval <= 0 || sched.Keep < 1 {
			return errors.New("--backup-interval must be positive and --backup-keep at least 1")
		}
		if info, err := os.Stat(sched.Dir); err != nil || !info.IsDir() {
			return fmt.Errorf("--backup-dir %s is not a directory", sched.Dir)
		}
	}
	if *storageName == "kubernetes" && *namespace == "" {
		return errors.New("--namespace or POD_NAMESPACE is required for kubernetes storage")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)
	ctrl.SetLogger(logr.FromSlogHandler(logger.Handler()))

	var mgr manager.Manager
	if *runController || *storageName == "kubernetes" {
		var err error
		if mgr, err = newManager(*metricsAddr); err != nil {
			return err
		}
	}

	var backend storage.Backend
	switch *storageName {
	case "kubernetes":
		backend = k8sstorage.New(mgr.GetClient(), *namespace)
	case "file":
		var err error
		if backend, err = filestorage.New(*filePath); err != nil {
			return fmt.Errorf("file storage: %w", err)
		}
	default:
		return fmt.Errorf("unknown storage %q", *storageName)
	}
	var key []byte
	if v := os.Getenv(envEncryptionKey); v != "" {
		var err error
		if key, err = encrypted.ParseKey(v); err != nil {
			return fmt.Errorf("%s: %w", envEncryptionKey, err)
		}
	}
	enc, err := encrypted.New(backend, key)
	if err != nil {
		return err
	}
	backend = enc
	migrated, err := enc.EncryptPlaintext(context.Background())
	if err != nil {
		return fmt.Errorf("encrypt stored plaintext: %w", err)
	}
	if len(migrated) > 0 {
		slog.Info("encrypted plaintext paths", "paths", migrated)
	}

	var changes controller.Changes
	var onChange func(string)
	if *runController {
		changes = controller.NewChanges()
		onChange = changes.Notify
	}
	svc := secrets.New(backend, onChange)
	svc.KeepVersions = *historyLimit

	if *runController {
		reconciler := &controller.SecretSyncReconciler{
			Client:   mgr.GetClient(),
			Secrets:  svc,
			Changes:  changes,
			Recorder: mgr.GetEventRecorder("secret-manager"),
		}
		if err := reconciler.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("setup controller: %w", err)
		}
	}

	integrations := tokens.New(backend)
	handler, err := server.New(svc, integrations, os.Getenv(cli.EnvToken))
	if err != nil {
		return err
	}
	handler.Version = version
	httpServer := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}

	slog.Info("starting secret-manager", "version", version, "storage", *storageName, "controller", *runController,
		"encryption", key != nil, "backup_dir", sched.Dir)
	ctx, cancel := context.WithCancel(ctrl.SetupSignalHandler())
	if sched.Dir != "" {
		go handler.RunBackups(ctx, sched)
	}
	flushed := make(chan struct{})
	go func() {
		integrations.RunFlush(ctx, *lastUsedFlush)
		close(flushed)
	}()
	defer func() {
		cancel()
		<-flushed
	}()
	if mgr != nil {
		if err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error { return serve(ctx, httpServer) })); err != nil {
			return err
		}
		return mgr.Start(ctx)
	}

	errc := make(chan error, 2)
	go func() { errc <- serve(ctx, httpServer) }()
	if *metricsAddr != "0" {
		metricsServer := &http.Server{
			Addr:              *metricsAddr,
			Handler:           promhttp.HandlerFor(ctrlmetrics.Registry, promhttp.HandlerOpts{}),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() { errc <- serve(ctx, metricsServer) }()
	}
	return <-errc
}

func newManager(metricsAddr string) (manager.Manager, error) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("kubernetes config (run with --storage=file --controller=false to start without a cluster): %w", err)
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: metricsAddr},
		Client: client.Options{Cache: &client.CacheOptions{
			// Read Secrets and workloads directly: no cluster-wide cache of
			// every Secret, and storage reads always see the latest write.
			DisableFor: []client.Object{&corev1.Secret{}, &appsv1.Deployment{}, &appsv1.StatefulSet{}, &appsv1.DaemonSet{}},
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("create manager: %w", err)
	}
	return mgr, nil
}

func serve(ctx context.Context, srv *http.Server) error {
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	slog.Info("http server listening", "addr", srv.Addr)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
