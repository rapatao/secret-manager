package secrets

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rapatao/secret-manager/internal/storage"
	"github.com/rapatao/secret-manager/internal/storage/storagetest"
)

type memBackend struct {
	mu       sync.Mutex
	data     map[string]map[string]string
	versions map[string][]storage.Version
	tokens   []storage.Token
	audit    []storage.AuditEvent
	failPut  bool
}

func newMem() *memBackend {
	return &memBackend{data: map[string]map[string]string{}, versions: map[string][]storage.Version{}}
}

func (m *memBackend) AddVersion(_ context.Context, path string, at time.Time, data map[string]string, keep int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	vs := m.versions[path]
	n := 1
	if len(vs) > 0 {
		n = vs[0].Number + 1
	}
	vs = append([]storage.Version{{Number: n, Time: at, Data: maps.Clone(data)}}, vs...)
	m.versions[path] = vs[:min(keep, len(vs))]
	return nil
}

func (m *memBackend) Versions(_ context.Context, path string) ([]storage.Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.versions[path]), nil
}

func (m *memBackend) ReplaceVersions(_ context.Context, path string, versions []storage.Version) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(versions) == 0 {
		delete(m.versions, path)
		return nil
	}
	m.versions[path] = slices.Clone(versions)
	return nil
}

func (m *memBackend) VersionedPaths(_ context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Sorted(maps.Keys(m.versions)), nil
}

func (m *memBackend) Tokens(_ context.Context) ([]storage.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.tokens), nil
}

func (m *memBackend) PutTokens(_ context.Context, tokens []storage.Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens = slices.Clone(tokens)
	return nil
}

func (m *memBackend) AuditEvents(_ context.Context) ([]storage.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.audit), nil
}

func (m *memBackend) PutAuditEvents(_ context.Context, events []storage.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audit = slices.Clone(events)
	return nil
}

func (m *memBackend) Get(_ context.Context, path string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.data[path]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return maps.Clone(d), nil
}

func (m *memBackend) Put(_ context.Context, path string, data map[string]string) error {
	if m.failPut {
		return errors.New("put failed")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[path] = maps.Clone(data)
	return nil
}

func (m *memBackend) Delete(_ context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, path)
	return nil
}

func (m *memBackend) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for p := range m.data {
		if storage.Under(p, prefix) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out, nil
}

func TestMemBackendConformance(t *testing.T) {
	storagetest.Run(t, func() storage.Backend { return newMem() })
}
