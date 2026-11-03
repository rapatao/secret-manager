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
