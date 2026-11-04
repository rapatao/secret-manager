package kubernetes

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/rapatao/secret-manager/internal/storage"
	"github.com/rapatao/secret-manager/internal/storage/storagetest"
)

func TestConformance(t *testing.T) {
	storagetest.Run(t, func() storage.Backend {
		return New(fake.NewClientBuilder().Build(), "secret-manager")
	})
}

func TestSecretName(t *testing.T) {
	cases := map[string]string{
		"/":                "sm",
		"/kubernetes":      "sm.kubernetes",
		"/kubernetes/argo": "sm.kubernetes.argo",
	}
	for path, want := range cases {
		if got := SecretName(path); got != want {
			t.Errorf("SecretName(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestIgnoresUnmanagedSecret(t *testing.T) {
	foreign := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "sm.app"}}
	b := New(fake.NewClientBuilder().WithObjects(foreign).Build(), "ns")
	ctx := context.Background()

	if _, err := b.Get(ctx, "/app"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Get on unmanaged secret: want ErrNotFound, got %v", err)
	}
	if err := b.Put(ctx, "/app", map[string]string{"A": "1"}); err == nil {
		t.Fatal("Put over unmanaged secret: want error")
	}
}

func TestLabelVersions(t *testing.T) {
	old := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace:   "ns",
		Name:        VersionName("/app", 1),
		Labels:      map[string]string{HistoryLabel: "true"},
		Annotations: map[string]string{PathAnnotation: "/app", VersionAnnotation: "1", TimeAnnotation: "2026-01-02T03:04:05Z"},
	}}
	b := New(fake.NewClientBuilder().WithObjects(old).Build(), "ns")
	ctx := context.Background()
	if vs, _ := b.Versions(ctx, "/app"); len(vs) != 0 {
		t.Fatalf("unlabeled version found: %v", vs)
	}
	if n, err := b.LabelVersions(ctx); err != nil || n != 1 {
		t.Fatalf("LabelVersions = %d, %v", n, err)
	}
	if vs, err := b.Versions(ctx, "/app"); err != nil || len(vs) != 1 || vs[0].Number != 1 {
		t.Fatalf("Versions after labeling = %v, %v", vs, err)
	}
	if n, _ := b.LabelVersions(ctx); n != 0 {
		t.Fatalf("second LabelVersions labeled %d", n)
	}
}
