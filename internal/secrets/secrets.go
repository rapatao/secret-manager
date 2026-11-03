// Package secrets implements validation, recursive resolution, change
// notification and version history on top of any storage.Backend.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

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

// Version is a snapshot of the data stored at a path.
type Version = storage.Version

// Service is safe for concurrent use.
type Service struct {
	// History is the number of versions kept per path, current included.
	// Zero disables history. Set it before the Service is used.
	KeepVersions int

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
// merged in alphabetical path order, so on duplicate keys a nested path wins
// over its parents. A missing path is ErrNotFound only when nothing was found
// at all.
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
	return s.UpdateKeys(ctx, path, values, nil)
}

// UpdateKeys merges values into path and removes the keys in remove in one
// write, recorded as one version. It creates the path when missing. Removing a
// missing key is not an error.
func (s *Service) UpdateKeys(ctx context.Context, path string, values map[string]string, remove []string) error {
	path, err := NormalizePath(path)
	if err != nil {
		return err
	}
	for k := range values {
		if err := ValidateKey(k); err != nil {
			return err
		}
	}
	for _, k := range remove {
		if _, ok := values[k]; ok {
			return fmt.Errorf("%w: key %q is both set and deleted", ErrInvalid, k)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.backend.Get(ctx, path)
	changed := errors.Is(err, ErrNotFound)
	if changed {
		data = map[string]string{}
	} else if err != nil {
		return err
	}
	for k, v := range values {
		if old, ok := data[k]; !ok || old != v {
			changed = true
		}
	}
	maps.Copy(data, values)
	for _, k := range remove {
		if _, ok := data[k]; ok {
			delete(data, k)
			changed = true
		}
	}
	if err := s.backend.Put(ctx, path, data); err != nil {
		return err
	}
	s.onChange(path)
	if !changed {
		return nil
	}
	return s.record(ctx, path, data)
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
	return s.record(ctx, path, data)
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

// DeletedPaths returns, sorted, every path that no longer exists but still
// has stored versions.
func (s *Service) DeletedPaths(ctx context.Context) ([]string, error) {
	versioned, err := s.backend.VersionedPaths(ctx)
	if err != nil {
		return nil, err
	}
	current, err := s.backend.List(ctx, "/")
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(versioned, func(p string) bool {
		_, found := slices.BinarySearch(current, p)
		return found
	}), nil
}

// History returns the versions of path, newest first. Versions of a deleted
// path are kept.
func (s *Service) History(ctx context.Context, path string) ([]Version, error) {
	path, err := NormalizePath(path)
	if err != nil {
		return nil, err
	}
	return s.backend.Versions(ctx, path)
}

// Version returns version n of path.
func (s *Service) Version(ctx context.Context, path string, n int) (Version, error) {
	versions, err := s.History(ctx, path)
	if err != nil {
		return Version{}, err
	}
	for _, v := range versions {
		if v.Number == n {
			return v, nil
		}
	}
	return Version{}, fmt.Errorf("%w: version %d of %s", ErrNotFound, n, path)
}

// Rollback replaces the data at path with version n, recreating a deleted
// path. The restored data is recorded as a new version.
func (s *Service) Rollback(ctx context.Context, path string, n int) error {
	path, err := NormalizePath(path)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	v, err := s.Version(ctx, path, n)
	if err != nil {
		return err
	}
	if current, err := s.backend.Get(ctx, path); err == nil && maps.Equal(current, v.Data) {
		return fmt.Errorf("%w: version %d is the current data", ErrInvalid, n)
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err := s.backend.Put(ctx, path, v.Data); err != nil {
		return err
	}
	s.onChange(path)
	return s.record(ctx, path, v.Data)
}

// PathBackup is the data of one path and, optionally, its versions, newest
// first.
type PathBackup struct {
	Path     string
	Data     map[string]string
	Versions []Version
}

// Backup returns the data of every stored path, sorted by path, with its
// versions when withHistory. Versions of deleted paths are not included.
func (s *Service) Backup(ctx context.Context, withHistory bool) ([]PathBackup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	paths, err := s.backend.List(ctx, "/")
	if err != nil {
		return nil, err
	}
	out := make([]PathBackup, 0, len(paths))
	for _, p := range paths {
		data, err := s.backend.Get(ctx, p)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		b := PathBackup{Path: p, Data: data}
		if withHistory {
			if b.Versions, err = s.backend.Versions(ctx, p); err != nil {
				return nil, err
			}
		}
		out = append(out, b)
	}
	return out, nil
}

// Restore replaces the data of every path in backup. Paths not in backup are
// kept. Versions are restored, oldest first and renumbered from 1, only for
// paths without stored versions and only when history is enabled. Every
// path and key is validated before anything is written.
func (s *Service) Restore(ctx context.Context, backup []PathBackup) error {
	for i, b := range backup {
		path, err := NormalizePath(b.Path)
		if err != nil {
			return err
		}
		backup[i].Path = path
		for k := range b.Data {
			if err := ValidateKey(k); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		}
		for _, v := range b.Versions {
			for k := range v.Data {
				if err := ValidateKey(k); err != nil {
					return fmt.Errorf("%s version %d: %w", path, v.Number, err)
				}
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, b := range backup {
		if err := s.restore(ctx, b); err != nil {
			return fmt.Errorf("restore %s: %w", b.Path, err)
		}
	}
	return nil
}

func (s *Service) restore(ctx context.Context, b PathBackup) error {
	data := b.Data
	if data == nil {
		data = map[string]string{}
	}
	newest, err := s.restoreVersions(ctx, b)
	if err != nil {
		return err
	}
	current, err := s.backend.Get(ctx, b.Path)
	if err == nil && maps.Equal(current, data) {
		return nil
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err := s.backend.Put(ctx, b.Path, data); err != nil {
		return err
	}
	s.onChange(b.Path)
	if newest != nil && maps.Equal(newest, data) {
		return nil
	}
	return s.record(ctx, b.Path, data)
}

// restoreVersions adds the versions of b when path has none yet and returns
// the data of the newest one added.
func (s *Service) restoreVersions(ctx context.Context, b PathBackup) (map[string]string, error) {
	if s.KeepVersions <= 0 || len(b.Versions) == 0 {
		return nil, nil
	}
	existing, err := s.backend.Versions(ctx, b.Path)
	if err != nil || len(existing) > 0 {
		return nil, err
	}
	versions := b.Versions[:min(len(b.Versions), s.KeepVersions)]
	for _, v := range slices.Backward(versions) {
		if err := s.backend.AddVersion(ctx, b.Path, v.Time, v.Data, s.KeepVersions); err != nil {
			return nil, err
		}
	}
	return versions[0].Data, nil
}

// record stores data as the newest version of path when history is enabled.
// It runs after the write, so a failure leaves the write in place.
func (s *Service) record(ctx context.Context, path string, data map[string]string) error {
	if s.KeepVersions <= 0 {
		return nil
	}
	if err := s.backend.AddVersion(ctx, path, time.Now(), data, s.KeepVersions); err != nil {
		return fmt.Errorf("write succeeded but recording its version failed: %w", err)
	}
	return nil
}
