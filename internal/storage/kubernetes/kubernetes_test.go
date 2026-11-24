package kubernetes

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

func TestReservedName(t *testing.T) {
	for _, n := range []string{"sm", "sm-tokens", "sm-audit", "sm-sync-policy", "sm.a", "sm.a.b", "smh.3", "smh.a.b.3"} {
		if !ReservedName(n) {
			t.Errorf("ReservedName(%q) = false", n)
		}
	}
	for _, n := range []string{"sm-foo", "sm-app", "smx", "smh", "app", "sm-tokens-2"} {
		if ReservedName(n) {
			t.Errorf("ReservedName(%q) = true", n)
		}
	}
}

func TestJSONSecretsMustBeManaged(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name, label string
		get         func(*Backend) error
		put         func(*Backend) error
	}{
		{tokensName, TokensLabel,
			func(b *Backend) error { _, err := b.Tokens(ctx); return err },
			func(b *Backend) error { return b.PutTokens(ctx, nil) }},
		{policyName, SyncPolicyLabel,
			func(b *Backend) error { _, err := b.SyncPolicy(ctx); return err },
			func(b *Backend) error { return b.PutSyncPolicy(ctx, storage.SyncPolicy{}) }},
		{auditName, AuditLabel,
			func(b *Backend) error { _, err := b.AuditEvents(ctx); return err },
			func(b *Backend) error { return b.PutAuditEvents(ctx, nil) }},
	}
	for _, c := range cases {
		for variant, labels := range map[string]map[string]string{
			"no label":   nil,
			"with owner": {c.label: "true", SyncOwnerLabel: "x"},
		} {
			s := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: c.name, Labels: labels},
				Data:       map[string][]byte{"tokens": []byte("[]"), "policy": []byte("{}"), "events": []byte("[]")},
			}
			b := New(fake.NewClientBuilder().WithObjects(s).Build(), "ns")
			if err := c.get(b); err == nil || !strings.Contains(err.Error(), "ns/"+c.name) {
				t.Errorf("%s %s: get error %v", c.name, variant, err)
			}
			if err := c.put(b); err == nil {
				t.Errorf("%s %s: put succeeded", c.name, variant)
			}
		}
	}
}

func TestIgnoresSecretsOwnedBySync(t *testing.T) {
	ctx := context.Background()
	path := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: SecretName("/app"),
		Labels:      map[string]string{StoreLabel: "true", SyncOwnerLabel: "x"},
		Annotations: map[string]string{PathAnnotation: "/app"},
	}}
	hist := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: VersionName("/app", 1),
		Labels:      map[string]string{HistoryLabel: "true", PathHashLabel: PathHash("/app"), SyncOwnerLabel: "x"},
		Annotations: map[string]string{PathAnnotation: "/app", VersionAnnotation: "1"},
	}}
	b := New(fake.NewClientBuilder().WithObjects(path, hist).Build(), "ns")

	if _, err := b.Get(ctx, "/app"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("Get: %v", err)
	}
	if paths, err := b.List(ctx, "/"); err != nil || len(paths) != 0 {
		t.Fatalf("List: %v, %v", paths, err)
	}
	if err := b.Put(ctx, "/app", map[string]string{"A": "1"}); err == nil {
		t.Fatal("Put overwrote an owned Secret")
	}
	if err := b.Delete(ctx, "/app"); err != nil {
		t.Fatal(err)
	}
	var s corev1.Secret
	if err := b.c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "sm.app"}, &s); err != nil {
		t.Fatalf("Delete removed an owned Secret: %v", err)
	}
	if vs, err := b.Versions(ctx, "/app"); err != nil || len(vs) != 0 {
		t.Fatalf("Versions: %v, %v", vs, err)
	}
	if ps, err := b.VersionedPaths(ctx); err != nil || len(ps) != 0 {
		t.Fatalf("VersionedPaths: %v, %v", ps, err)
	}
}

func TestOwnedHistorySecretIsNotTouched(t *testing.T) {
	ctx := context.Background()
	owned := func() *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns", Name: VersionName("/app", 1),
				Labels:      map[string]string{HistoryLabel: "true", SyncOwnerLabel: "x"},
				Annotations: map[string]string{PathAnnotation: "/app", VersionAnnotation: "1"},
			},
			Data: map[string][]byte{"K": []byte("forged")},
		}
	}
	unchanged := func(t *testing.T, b *Backend) {
		t.Helper()
		var s corev1.Secret
		if err := b.c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: VersionName("/app", 1)}, &s); err != nil || string(s.Data["K"]) != "forged" {
			t.Fatalf("Secret changed: %v, %v", s.Data, err)
		}
	}

	b := New(fake.NewClientBuilder().WithObjects(owned()).Build(), "ns")
	if err := b.AddVersion(ctx, "/app", time.Now(), map[string]string{"A": "1"}, 5); err == nil {
		t.Fatal("AddVersion wrote over an owned Secret")
	}
	unchanged(t, b)

	b = New(fake.NewClientBuilder().WithObjects(owned()).Build(), "ns")
	err := b.ReplaceVersions(ctx, "/app", []storage.Version{{Number: 1, Time: time.Now(), Data: map[string]string{"A": "1"}}})
	if err == nil {
		t.Fatal("ReplaceVersions wrote over an owned Secret")
	}
	unchanged(t, b)
}

func TestIgnoresSecretsWithWrongName(t *testing.T) {
	ctx := context.Background()
	path := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: "anything",
		Labels:      map[string]string{StoreLabel: "true"},
		Annotations: map[string]string{PathAnnotation: "/app"},
	}}
	version := func(name, hash string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns", Name: name,
			Labels:      map[string]string{HistoryLabel: "true", PathHashLabel: hash},
			Annotations: map[string]string{PathAnnotation: "/app", VersionAnnotation: "7", TimeAnnotation: "2026-01-02T03:04:05Z"},
		}}
	}
	other := version("anything-else", PathHash("/app"))
	unhashed := version("also-wrong", "")
	good := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: VersionName("/app", 1),
		Labels:      map[string]string{HistoryLabel: "true", PathHashLabel: PathHash("/app")},
		Annotations: map[string]string{PathAnnotation: "/app", VersionAnnotation: "1", TimeAnnotation: "2026-01-02T03:04:05Z"},
	}}
	b := New(fake.NewClientBuilder().WithObjects(path, other, unhashed, good).Build(), "ns")

	if paths, err := b.List(ctx, "/"); err != nil || len(paths) != 0 {
		t.Fatalf("List: %v, %v", paths, err)
	}
	if vs, err := b.Versions(ctx, "/app"); err != nil || len(vs) != 1 || vs[0].Number != 1 {
		t.Fatalf("Versions: %v, %v", vs, err)
	}
	if ps, err := b.VersionedPaths(ctx); err != nil || len(ps) != 1 {
		t.Fatalf("VersionedPaths: %v, %v", ps, err)
	}
	if n, err := b.LabelVersions(ctx); err != nil || n != 0 {
		t.Fatalf("LabelVersions labeled %d, %v", n, err)
	}
	if err := b.AddVersion(ctx, "/app", time.Now(), map[string]string{"A": "1"}, 1); err != nil {
		t.Fatal(err)
	}
	vs, err := b.Versions(ctx, "/app")
	if err != nil || len(vs) != 1 || vs[0].Number != 2 {
		t.Fatalf("AddVersion numbered from a misnamed Secret: %v, %v", vs, err)
	}
	for _, name := range []string{"anything-else", "also-wrong"} {
		var s corev1.Secret
		if err := b.c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: name}, &s); err != nil {
			t.Fatalf("prune removed %s: %v", name, err)
		}
	}
}

func TestLabelVersionsSkipsOwned(t *testing.T) {
	ctx := context.Background()
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: VersionName("/app", 1),
		Labels:      map[string]string{HistoryLabel: "true", SyncOwnerLabel: "x"},
		Annotations: map[string]string{PathAnnotation: "/app", VersionAnnotation: "1"},
	}}
	b := New(fake.NewClientBuilder().WithObjects(s).Build(), "ns")
	if n, err := b.LabelVersions(ctx); err != nil || n != 0 {
		t.Fatalf("LabelVersions labeled %d, %v", n, err)
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
