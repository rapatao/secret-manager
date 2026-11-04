// Package kubernetes stores secrets as Kubernetes Secrets, one per path and
// one per version.
package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

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
	// HistoryLabel marks Secrets holding a version of a path.
	HistoryLabel = "secretmanager.rapatao.com/history"
	// VersionAnnotation holds the version number of a history Secret.
	VersionAnnotation = "secretmanager.rapatao.com/version"
	// TimeAnnotation holds the RFC 3339 time a version was written.
	TimeAnnotation = "secretmanager.rapatao.com/time"

	// TokensLabel marks the Secret holding the access tokens.
	TokensLabel = "secretmanager.rapatao.com/tokens"

	namePrefix    = "sm"
	historyPrefix = "smh"
	// AuditLabel marks the Secret holding the audit events.
	AuditLabel = "secretmanager.rapatao.com/audit"
	// PathHashLabel identifies the path of a history Secret by the first 32
	// hex digits of its SHA-256, as label values cannot hold every path.
	PathHashLabel = "secretmanager.rapatao.com/path-hash"

	// tokensName and auditName cannot collide with a path Secret: those are
	// "sm" or start with "sm.".
	tokensName = "sm-tokens"
	auditName  = "sm-audit"
	tokensKey  = "tokens"
	auditKey   = "events"
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
	return namePrefix + dotted(path)
}

// VersionName maps a path and version to its history Secret name:
// ("/a/b", 3) -> "smh.a.b.3".
func VersionName(path string, n int) string {
	return historyPrefix + dotted(path) + "." + strconv.Itoa(n)
}

func dotted(path string) string {
	return strings.ReplaceAll(strings.TrimSuffix(path, "/"), "/", ".")
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

// AddVersion implements storage.Backend.
func (b *Backend) AddVersion(ctx context.Context, path string, at time.Time, data map[string]string, keep int) error {
	versions, err := b.Versions(ctx, path)
	if err != nil {
		return err
	}
	n := 1
	if len(versions) > 0 {
		n = versions[0].Number + 1
	}
	if err := b.c.Create(ctx, b.versionSecret(path, storage.Version{Number: n, Time: at, Data: data})); err != nil {
		return fmt.Errorf("create version %d of %s: %w", n, path, err)
	}
	for _, v := range versions[min(keep-1, len(versions)):] {
		old := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: b.ns, Name: VersionName(path, v.Number)}}
		if err := client.IgnoreNotFound(b.c.Delete(ctx, old)); err != nil {
			return fmt.Errorf("prune version %d of %s: %w", v.Number, path, err)
		}
	}
	return nil
}

func (b *Backend) versionSecret(path string, v storage.Version) *corev1.Secret {
	raw := make(map[string][]byte, len(v.Data))
	for k, val := range v.Data {
		raw[k] = []byte(val)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      VersionName(path, v.Number),
			Namespace: b.ns,
			Labels:    map[string]string{HistoryLabel: "true", PathHashLabel: PathHash(path)},
			Annotations: map[string]string{
				PathAnnotation:    path,
				VersionAnnotation: strconv.Itoa(v.Number),
				TimeAnnotation:    v.Time.UTC().Format(time.RFC3339),
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: raw,
	}
}

// ReplaceVersions implements storage.Backend.
func (b *Backend) ReplaceVersions(ctx context.Context, path string, versions []storage.Version) error {
	existing, err := b.Versions(ctx, path)
	if err != nil {
		return err
	}
	stored := map[int]bool{}
	for _, v := range existing {
		stored[v.Number] = true
	}
	for _, v := range versions {
		want := b.versionSecret(path, v)
		if !stored[v.Number] {
			if err := b.c.Create(ctx, want); err != nil {
				return fmt.Errorf("create version %d of %s: %w", v.Number, path, err)
			}
			continue
		}
		delete(stored, v.Number)
		var s corev1.Secret
		if err := b.c.Get(ctx, client.ObjectKeyFromObject(want), &s); err != nil {
			return fmt.Errorf("get version %d of %s: %w", v.Number, path, err)
		}
		s.Labels, s.Annotations, s.Data = want.Labels, want.Annotations, want.Data
		if err := b.c.Update(ctx, &s); err != nil {
			return fmt.Errorf("update version %d of %s: %w", v.Number, path, err)
		}
	}
	for n := range stored {
		old := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: b.ns, Name: VersionName(path, n)}}
		if err := client.IgnoreNotFound(b.c.Delete(ctx, old)); err != nil {
			return fmt.Errorf("delete version %d of %s: %w", n, path, err)
		}
	}
	return nil
}

// PathHash returns the PathHashLabel value of path.
func PathHash(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:16])
}

// LabelVersions adds PathHashLabel to the history Secrets written before it
// existed, so Versions finds them, and returns how many it labeled.
func (b *Backend) LabelVersions(ctx context.Context) (int, error) {
	var list corev1.SecretList
	if err := b.c.List(ctx, &list, client.InNamespace(b.ns), client.MatchingLabels{HistoryLabel: "true"}); err != nil {
		return 0, fmt.Errorf("list versions: %w", err)
	}
	labeled := 0
	for _, s := range list.Items {
		path := s.Annotations[PathAnnotation]
		if path == "" || s.Labels[PathHashLabel] == PathHash(path) {
			continue
		}
		s.Labels[PathHashLabel] = PathHash(path)
		if err := b.c.Update(ctx, &s); err != nil {
			return labeled, fmt.Errorf("label version secret %s: %w", s.Name, err)
		}
		labeled++
	}
	return labeled, nil
}

// VersionedPaths implements storage.Backend.
func (b *Backend) VersionedPaths(ctx context.Context) ([]string, error) {
	var list corev1.SecretList
	if err := b.c.List(ctx, &list, client.InNamespace(b.ns), client.MatchingLabels{HistoryLabel: "true"}); err != nil {
		return nil, fmt.Errorf("list versions: %w", err)
	}
	var paths []string
	for _, s := range list.Items {
		if p := s.Annotations[PathAnnotation]; p != "" && !slices.Contains(paths, p) {
			paths = append(paths, p)
		}
	}
	slices.Sort(paths)
	return paths, nil
}

// Versions implements storage.Backend.
func (b *Backend) Versions(ctx context.Context, path string) ([]storage.Version, error) {
	var list corev1.SecretList
	labels := client.MatchingLabels{HistoryLabel: "true", PathHashLabel: PathHash(path)}
	if err := b.c.List(ctx, &list, client.InNamespace(b.ns), labels); err != nil {
		return nil, fmt.Errorf("list versions: %w", err)
	}
	var versions []storage.Version
	for _, s := range list.Items {
		if s.Annotations[PathAnnotation] != path {
			continue
		}
		n, err := strconv.Atoi(s.Annotations[VersionAnnotation])
		if err != nil {
			return nil, fmt.Errorf("secret %s: bad version annotation: %w", s.Name, err)
		}
		at, _ := time.Parse(time.RFC3339, s.Annotations[TimeAnnotation])
		data := make(map[string]string, len(s.Data))
		for k, v := range s.Data {
			data[k] = string(v)
		}
		versions = append(versions, storage.Version{Number: n, Time: at, Data: data})
	}
	slices.SortFunc(versions, func(a, b storage.Version) int { return b.Number - a.Number })
	return versions, nil
}

// Tokens implements storage.Backend.
func (b *Backend) Tokens(ctx context.Context) ([]storage.Token, error) {
	var tokens []storage.Token
	err := b.getJSON(ctx, tokensName, tokensKey, &tokens)
	return tokens, err
}

// PutTokens implements storage.Backend.
func (b *Backend) PutTokens(ctx context.Context, tokens []storage.Token) error {
	return b.putJSON(ctx, tokensName, TokensLabel, tokensKey, tokens)
}

// AuditEvents implements storage.Backend.
func (b *Backend) AuditEvents(ctx context.Context) ([]storage.AuditEvent, error) {
	var events []storage.AuditEvent
	err := b.getJSON(ctx, auditName, auditKey, &events)
	return events, err
}

// PutAuditEvents implements storage.Backend.
func (b *Backend) PutAuditEvents(ctx context.Context, events []storage.AuditEvent) error {
	return b.putJSON(ctx, auditName, AuditLabel, auditKey, events)
}

// getJSON decodes the JSON document stored under key in the Secret name into
// v, and leaves v unchanged when the Secret does not exist.
func (b *Backend) getJSON(ctx context.Context, name, key string, v any) error {
	var s corev1.Secret
	err := b.c.Get(ctx, client.ObjectKey{Namespace: b.ns, Name: name}, &s)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get secret %s: %w", name, err)
	}
	if err := json.Unmarshal(s.Data[key], v); err != nil {
		return fmt.Errorf("secret %s: parse: %w", name, err)
	}
	return nil
}

// putJSON stores v as JSON under key in the Secret name, labeled label,
// creating it when missing.
func (b *Backend) putJSON(ctx context.Context, name, label, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var s corev1.Secret
	err = b.c.Get(ctx, client.ObjectKey{Namespace: b.ns, Name: name}, &s)
	if apierrors.IsNotFound(err) {
		s = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: b.ns, Labels: map[string]string{label: "true"}},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{key: raw},
		}
		if err := b.c.Create(ctx, &s); err != nil {
			return fmt.Errorf("create secret %s: %w", name, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("get secret %s: %w", name, err)
	}
	s.Data = map[string][]byte{key: raw}
	if err := b.c.Update(ctx, &s); err != nil {
		return fmt.Errorf("update secret %s: %w", name, err)
	}
	return nil
}
