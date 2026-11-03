package secrets

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"testing"

	"github.com/rapatao/secret-manager/internal/storage"
	"github.com/rapatao/secret-manager/internal/storage/storagetest"
)

type memBackend struct {
	mu      sync.Mutex
	data    map[string]map[string]string
	failPut bool
}

func newMem() *memBackend { return &memBackend{data: map[string]map[string]string{}} }

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
