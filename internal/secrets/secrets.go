// Package secrets implements validation, recursive resolution and change
// notification on top of any storage.Backend.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"strings"
	"sync"

	"github.com/rapatao/secret-manager/internal/storage"
)

var (
	// ErrInvalid wraps validation failures of paths and keys.
	ErrInvalid = errors.New("invalid input")
	// ErrNotFound is returned when a path does not exist.
	ErrNotFound = storage.ErrNotFound

	pathRe = regexp.MustCompile(`^/([a-z0-9-]+(/[a-z0-9-]+)*)?$`)
	keyRe  = regexp.MustCompile(`^[-._a-zA-Z0-9]+$`)
)

// Service is safe for concurrent use.
type Service struct {
	backend  storage.Backend
	onChange func(path string)

	// ponytail: in-process mutex around read-modify-write, single server
	// replica; move to backend-level optimistic locking (resourceVersion /
	// SQL transactions) if HA is needed.
	mu sync.Mutex
}

// New returns a Service. onChange, when not nil, is called with the path after
// every successful write and must not block.
func New(backend storage.Backend, onChange func(path string)) *Service {
	if onChange == nil {
		onChange = func(string) {}
	}
	return &Service{backend: backend, onChange: onChange}
}

// NormalizePath validates path and strips a trailing slash.
func NormalizePath(path string) (string, error) {
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	if !pathRe.MatchString(path) {
		return "", fmt.Errorf("%w: path %q must look like /segment/segment using [a-z0-9-]", ErrInvalid, path)
	}
	return path, nil
}

// ValidateKey reports whether key can be used as a secret key.
func ValidateKey(key string) error {
	if !keyRe.MatchString(key) {
		return fmt.Errorf("%w: key %q must match [-._a-zA-Z0-9]+", ErrInvalid, key)
	}
	return nil
}

// Get returns the data at path. With recursive, data from every nested path is
// merged in path order, so on duplicate keys the deeper path wins. A missing
// path is ErrNotFound only when nothing was found at all.
func (s *Service) Get(ctx context.Context, path string, recursive bool) (map[string]string, error) {
	path, err := NormalizePath(path)
	if err != nil {
		return nil, err
	}
	if !recursive {
		return s.backend.Get(ctx, path)
	}

	paths, err := s.backend.List(ctx, path)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, ErrNotFound
	}
	merged := map[string]string{}
	for _, p := range paths {
		data, err := s.backend.Get(ctx, p)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		maps.Copy(merged, data)
	}
	return merged, nil
}

// ListPaths returns every stored path, sorted.
func (s *Service) ListPaths(ctx context.Context) ([]string, error) {
	return s.backend.List(ctx, "/")
}

// SetKeys merges values into path, creating the path when missing.
func (s *Service) SetKeys(ctx context.Context, path string, values map[string]string) error {
	path, err := NormalizePath(path)
	if err != nil {
		return err
	}
	for k := range values {
		if err := ValidateKey(k); err != nil {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.backend.Get(ctx, path)
	if errors.Is(err, ErrNotFound) {
		data = map[string]string{}
	} else if err != nil {
		return err
	}
	maps.Copy(data, values)
	if err := s.backend.Put(ctx, path, data); err != nil {
		return err
	}
	s.onChange(path)
	return nil
}

// DeleteKey removes key from path. A missing key is not an error.
func (s *Service) DeleteKey(ctx context.Context, path, key string) error {
	path, err := NormalizePath(path)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.backend.Get(ctx, path)
	if err != nil {
		return err
	}
	if _, ok := data[key]; !ok {
		return nil
	}
	delete(data, key)
	if err := s.backend.Put(ctx, path, data); err != nil {
		return err
	}
	s.onChange(path)
	return nil
}

// DeletePath removes path and its data. Nested paths are kept.
func (s *Service) DeletePath(ctx context.Context, path string) error {
	path, err := NormalizePath(path)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.backend.Delete(ctx, path); err != nil {
		return err
	}
	s.onChange(path)
	return nil
}
