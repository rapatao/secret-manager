// Package kubernetes stores secrets as Kubernetes Secrets, one per path.
package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/rapatao/secret-manager/internal/storage"
)

const (
	// StoreLabel marks Secrets owned by this backend.
	StoreLabel = "secretmanager.rapatao.com/store"
	// PathAnnotation holds the original path of a stored Secret.
	PathAnnotation = "secretmanager.rapatao.com/path"

	namePrefix = "sm"
)

// Backend implements storage.Backend on top of Secrets in a single namespace.
type Backend struct {
	c  client.Client
	ns string
}

var _ storage.Backend = (*Backend)(nil)

// New returns a Backend storing Secrets in namespace ns. The client should not
// be cache-backed, so reads observe the latest writes.
func New(c client.Client, ns string) *Backend {
	return &Backend{c: c, ns: ns}
}

// SecretName maps a path to its Secret name: "/" -> "sm", "/a/b" -> "sm.a.b".
// It relies on path segments never containing ".".
func SecretName(path string) string {
	return namePrefix + strings.ReplaceAll(strings.TrimSuffix(path, "/"), "/", ".")
}

// Get implements storage.Backend.
func (b *Backend) Get(ctx context.Context, path string) (map[string]string, error) {
	var s corev1.Secret
	err := b.c.Get(ctx, client.ObjectKey{Namespace: b.ns, Name: SecretName(path)}, &s)
	if apierrors.IsNotFound(err) || (err == nil && s.Labels[StoreLabel] != "true") {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get secret for %s: %w", path, err)
	}
	data := make(map[string]string, len(s.Data))
	for k, v := range s.Data {
		data[k] = string(v)
	}
	return data, nil
}

// Put implements storage.Backend.
func (b *Backend) Put(ctx context.Context, path string, data map[string]string) error {
	raw := make(map[string][]byte, len(data))
	for k, v := range data {
		raw[k] = []byte(v)
	}

	var s corev1.Secret
	err := b.c.Get(ctx, client.ObjectKey{Namespace: b.ns, Name: SecretName(path)}, &s)
	switch {
	case apierrors.IsNotFound(err):
		s = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:        SecretName(path),
				Namespace:   b.ns,
				Labels:      map[string]string{StoreLabel: "true"},
				Annotations: map[string]string{PathAnnotation: path},
			},
			Type: corev1.SecretTypeOpaque,
			Data: raw,
		}
		if err := b.c.Create(ctx, &s); err != nil {
			return fmt.Errorf("create secret for %s: %w", path, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("get secret for %s: %w", path, err)
	case s.Labels[StoreLabel] != "true":
		return fmt.Errorf("secret %s/%s exists and is not managed by secret-manager", b.ns, s.Name)
	}

	s.Data = raw
	if err := b.c.Update(ctx, &s); err != nil {
		return fmt.Errorf("update secret for %s: %w", path, err)
	}
	return nil
}

// Delete implements storage.Backend.
func (b *Backend) Delete(ctx context.Context, path string) error {
	if _, err := b.Get(ctx, path); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return err
	}
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: b.ns, Name: SecretName(path)}}
	if err := client.IgnoreNotFound(b.c.Delete(ctx, s)); err != nil {
		return fmt.Errorf("delete secret for %s: %w", path, err)
	}
	return nil
}

// List implements storage.Backend.
func (b *Backend) List(ctx context.Context, prefix string) ([]string, error) {
	var list corev1.SecretList
	if err := b.c.List(ctx, &list, client.InNamespace(b.ns), client.MatchingLabels{StoreLabel: "true"}); err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}
	var paths []string
	for _, s := range list.Items {
		if p := s.Annotations[PathAnnotation]; storage.Under(p, prefix) {
			paths = append(paths, p)
		}
	}
	slices.Sort(paths)
	return paths, nil
}
