// Package syncpolicy manages the optional policy limiting what SecretSyncs may
// read and write.
package syncpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/storage"
)

// ErrDenied is returned by Check for a SecretSync the policy does not allow.
var ErrDenied = errors.New("denied by sync policy")

// SourceRef is a source path of a SecretSync.
type SourceRef struct {
	Path      string
	Recursive bool
}

// Store is safe for concurrent use. It loads the policy from the backend once
// and keeps it in memory, so the server must run as a single replica.
type Store struct {
	backend storage.Backend

	mu       sync.Mutex
	loaded   bool
	policy   storage.SyncPolicy
	onChange func()
}

// New returns a Store persisting the policy in backend. onChange, when not nil,
// is called after every successful Put.
func New(backend storage.Backend, onChange func()) *Store {
	return &Store{backend: backend, onChange: onChange}
}

func (s *Store) load(ctx context.Context) error {
	if s.loaded {
		return nil
	}
	p, err := s.backend.SyncPolicy(ctx)
	if err != nil {
		return err
	}
	s.policy, s.loaded = p, true
	return nil
}

// Get returns a copy of the policy. A load error is returned, never read as a
// policy without restrictions.
func (s *Store) Get(ctx context.Context) (storage.SyncPolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(ctx); err != nil {
		return storage.SyncPolicy{}, err
	}
	return s.policy.Clone(), nil
}

// ErrConflict is returned by Put when the stored policy is not the one the
// caller based its change on.
var ErrConflict = errors.New("the sync policy changed since it was read")

// Same reports whether a and b are the same policy. A policy without
// namespaces equals one with an empty namespace map, and the zero policy is
// the policy of a store that holds none.
func Same(a, b storage.SyncPolicy) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// Put validates p and stores it when the stored policy is old, checked under
// the store's lock, then calls onChange. It returns the stored, normalized
// policy, or ErrConflict when the stored policy differs from old. The check
// covers this process only, so the server must run as a single replica.
func (s *Store) Put(ctx context.Context, old, p storage.SyncPolicy) (storage.SyncPolicy, error) {
	p, err := Validate(p)
	if err != nil {
		return storage.SyncPolicy{}, err
	}
	s.mu.Lock()
	if err := s.load(ctx); err != nil {
		s.mu.Unlock()
		return storage.SyncPolicy{}, err
	}
	if !Same(s.policy, old) {
		s.mu.Unlock()
		return storage.SyncPolicy{}, ErrConflict
	}
	if err := s.backend.PutSyncPolicy(ctx, p); err != nil {
		s.mu.Unlock()
		return storage.SyncPolicy{}, err
	}
	s.policy, s.loaded = p, true
	onChange := s.onChange
	out := p.Clone()
	s.mu.Unlock()
	if onChange != nil {
		onChange()
	}
	return out, nil
}

// Validate returns p normalized: names must be DNS-1123 labels, paths are
// normalized, and every list is de-duplicated and sorted. p is not modified.
func Validate(p storage.SyncPolicy) (storage.SyncPolicy, error) {
	out := storage.SyncPolicy{Enabled: p.Enabled}
	if len(p.Namespaces) == 0 {
		return out, nil
	}
	out.Namespaces = make(map[string]storage.SyncRule, len(p.Namespaces))
	for ns, rule := range p.Namespaces {
		if err := validLabel("namespace", ns); err != nil {
			return storage.SyncPolicy{}, err
		}
		paths := make([]string, 0, len(rule.Paths))
		for _, path := range rule.Paths {
			n, err := secrets.NormalizePath(path)
			if err != nil {
				return storage.SyncPolicy{}, fmt.Errorf("namespace %s: %w", ns, err)
			}
			paths = append(paths, n)
		}
		var targets []string
		for _, t := range rule.TargetNamespaces {
			if err := validLabel("target namespace", t); err != nil {
				return storage.SyncPolicy{}, fmt.Errorf("namespace %s: %w", ns, err)
			}
			targets = append(targets, t)
		}
		out.Namespaces[ns] = storage.SyncRule{Paths: sortedUnique(paths), TargetNamespaces: sortedUnique(targets)}
	}
	return out, nil
}

func validLabel(what, v string) error {
	if errs := validation.IsDNS1123Label(v); len(errs) > 0 {
		return fmt.Errorf("%w: %s %q is not a valid namespace name: %s", secrets.ErrInvalid, what, v, errs[0])
	}
	return nil
}

func sortedUnique(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}

// Check reports whether a SecretSync in namespace ns reading sources and
// writing to targetNamespaces is allowed by p. The error wraps ErrDenied and
// names the violation. A disabled policy allows everything.
func Check(p storage.SyncPolicy, ns string, sources []SourceRef, targetNamespaces []string) error {
	if !p.Enabled {
		return nil
	}
	rule, ok := p.Namespaces[ns]
	if !ok {
		return fmt.Errorf("%w: namespace %s is not allowed to sync", ErrDenied, ns)
	}
	for _, src := range sources {
		path, err := secrets.NormalizePath(src.Path)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrDenied, err.Error())
		}
		if !slices.ContainsFunc(rule.Paths, func(allowed string) bool { return storage.Under(path, allowed) }) {
			kind := "path"
			if src.Recursive {
				kind = "recursive path"
			}
			return fmt.Errorf("%w: namespace %s may not read %s %s", ErrDenied, ns, kind, path)
		}
	}
	for _, t := range targetNamespaces {
		if t != ns && !slices.Contains(rule.TargetNamespaces, t) {
			return fmt.Errorf("%w: namespace %s may not write to namespace %s", ErrDenied, ns, t)
		}
	}
	return nil
}
