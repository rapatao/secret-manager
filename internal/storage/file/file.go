// Package file stores secrets and their versions in a single JSON file.
package file

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/rapatao/secret-manager/internal/storage"
)

// Backend implements storage.Backend on top of a JSON file. The whole store is
// held in memory and the file is rewritten on every change.
type Backend struct {
	path string

	mu    sync.Mutex
	state state
}

type state struct {
	Paths    map[string]map[string]string `json:"paths"`
	Versions map[string][]storage.Version `json:"versions"`
	Tokens   []storage.Token              `json:"tokens,omitempty"`
	Audit    []storage.AuditEvent         `json:"audit,omitempty"`
}

var _ storage.Backend = (*Backend)(nil)

// New returns a Backend persisting to path, loading it when it exists. The
// file is created with mode 0600 on the first write.
func New(path string) (*Backend, error) {
	b := &Backend{path: path}
	if err := b.load(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *Backend) load() error {
	s := state{}
	raw, err := os.ReadFile(b.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	default:
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("parse %s: %w", b.path, err)
		}
	}
	if s.Paths == nil {
		s.Paths = map[string]map[string]string{}
	}
	if s.Versions == nil {
		s.Versions = map[string][]storage.Version{}
	}
	b.state = s
	return nil
}

// commit writes the in-memory state to disk. On failure it reloads the file,
// so memory never holds changes that were not persisted.
func (b *Backend) commit() error {
	err := b.save()
	if err != nil {
		if lerr := b.load(); lerr != nil {
			err = errors.Join(err, lerr)
		}
	}
	return err
}

func (b *Backend) save() error {
	raw, err := json.Marshal(b.state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(b.path), filepath.Base(b.path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(raw)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), b.path)
}

// Get implements storage.Backend.
func (b *Backend) Get(_ context.Context, path string) (map[string]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.state.Paths[path]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return maps.Clone(d), nil
}

// Put implements storage.Backend.
func (b *Backend) Put(_ context.Context, path string, data map[string]string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	d := maps.Clone(data)
	if d == nil {
		d = map[string]string{}
	}
	b.state.Paths[path] = d
	return b.commit()
}

// Delete implements storage.Backend.
func (b *Backend) Delete(_ context.Context, path string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.state.Paths[path]; !ok {
		return nil
	}
	delete(b.state.Paths, path)
	return b.commit()
}

// List implements storage.Backend.
func (b *Backend) List(_ context.Context, prefix string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for p := range b.state.Paths {
		if storage.Under(p, prefix) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out, nil
}

// AddVersion implements storage.Backend.
func (b *Backend) AddVersion(_ context.Context, path string, at time.Time, data map[string]string, keep int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	vs := b.state.Versions[path]
	n := 1
	if len(vs) > 0 {
		n = vs[0].Number + 1
	}
	vs = append([]storage.Version{{Number: n, Time: at, Data: maps.Clone(data)}}, vs...)
	b.state.Versions[path] = vs[:min(keep, len(vs))]
	return b.commit()
}

// VersionedPaths implements storage.Backend.
func (b *Backend) VersionedPaths(_ context.Context) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for p, vs := range b.state.Versions {
		if len(vs) > 0 {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out, nil
}

// ReplaceVersions implements storage.Backend.
func (b *Backend) ReplaceVersions(_ context.Context, path string, versions []storage.Version) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(versions) == 0 {
		delete(b.state.Versions, path)
		return b.commit()
	}
	vs := make([]storage.Version, len(versions))
	for i, v := range versions {
		v.Data = maps.Clone(v.Data)
		vs[i] = v
	}
	b.state.Versions[path] = vs
	return b.commit()
}

// Versions implements storage.Backend.
func (b *Backend) Versions(_ context.Context, path string) ([]storage.Version, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	vs := make([]storage.Version, len(b.state.Versions[path]))
	for i, v := range b.state.Versions[path] {
		v.Data = maps.Clone(v.Data)
		vs[i] = v
	}
	return vs, nil
}

// Tokens implements storage.Backend.
func (b *Backend) Tokens(_ context.Context) ([]storage.Token, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.state.Tokens), nil
}

// PutTokens implements storage.Backend.
func (b *Backend) PutTokens(_ context.Context, tokens []storage.Token) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state.Tokens = slices.Clone(tokens)
	return b.commit()
}

// AuditEvents implements storage.Backend.
func (b *Backend) AuditEvents(_ context.Context) ([]storage.AuditEvent, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.state.Audit), nil
}

// PutAuditEvents implements storage.Backend.
func (b *Backend) PutAuditEvents(_ context.Context, events []storage.AuditEvent) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state.Audit = slices.Clone(events)
	return b.commit()
}
