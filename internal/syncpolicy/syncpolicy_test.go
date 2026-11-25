package syncpolicy

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/storage"
	"github.com/rapatao/secret-manager/internal/storage/file"
)

type failingBackend struct {
	storage.Backend
	loadErr error
	putErr  error
}

func (f failingBackend) SyncPolicy(context.Context) (storage.SyncPolicy, error) {
	return storage.SyncPolicy{}, f.loadErr
}

func (f failingBackend) PutSyncPolicy(context.Context, storage.SyncPolicy) error { return f.putErr }

func newFile(t *testing.T) *file.Backend {
	t.Helper()
	b, err := file.New(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStoreLoadErrorIsReturned(t *testing.T) {
	boom := errors.New("boom")
	s := New(failingBackend{loadErr: boom}, nil)
	got, err := s.Get(context.Background())
	if !errors.Is(err, boom) || got.Enabled {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if _, err := s.Get(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("second Get = %v, want the load error again", err)
	}
}

func TestStorePut(t *testing.T) {
	ctx := context.Background()
	backend := newFile(t)
	calls := 0
	s := New(backend, func() { calls++ })

	if p, err := s.Get(ctx); err != nil || p.Enabled {
		t.Fatalf("Get on empty store = %+v, %v", p, err)
	}
	in := storage.SyncPolicy{Enabled: true, Namespaces: map[string]storage.SyncRule{
		"team-a": {Paths: []string{"/b/", "/a", "/a"}, TargetNamespaces: []string{"z", "y", "y"}},
	}}
	out, err := s.Put(ctx, storage.SyncPolicy{}, in)
	if err != nil {
		t.Fatal(err)
	}
	want := storage.SyncRule{Paths: []string{"/a", "/b"}, TargetNamespaces: []string{"y", "z"}}
	if got := out.Namespaces["team-a"]; !slices.Equal(got.Paths, want.Paths) || !slices.Equal(got.TargetNamespaces, want.TargetNamespaces) || calls != 1 {
		t.Fatalf("Put = %+v, calls %d", out, calls)
	}
	if !slices.Equal(in.Namespaces["team-a"].Paths, []string{"/b/", "/a", "/a"}) {
		t.Fatalf("input modified: %+v", in)
	}

	stored, _ := backend.SyncPolicy(ctx)
	if !stored.Enabled || !slices.Equal(stored.Namespaces["team-a"].Paths, want.Paths) {
		t.Fatalf("backend holds %+v", stored)
	}

	got, _ := s.Get(ctx)
	got.Namespaces["team-a"].Paths[0] = "/changed"
	got.Namespaces["other"] = storage.SyncRule{}
	again, _ := s.Get(ctx)
	if again.Namespaces["team-a"].Paths[0] != "/a" || len(again.Namespaces) != 1 {
		t.Fatalf("Get shares memory with the store: %+v", again)
	}

	out.Namespaces["team-a"].Paths[0] = "/changed"
	if again, _ = s.Get(ctx); again.Namespaces["team-a"].Paths[0] != "/a" {
		t.Fatalf("Put result shares memory with the store: %+v", again)
	}
}

func TestStorePutFailureKeepsPolicy(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")
	calls := 0
	s := New(failingBackend{putErr: boom}, func() { calls++ })
	s.loaded = true
	if _, err := s.Put(ctx, storage.SyncPolicy{}, storage.SyncPolicy{Enabled: true}); !errors.Is(err, boom) {
		t.Fatalf("Put = %v", err)
	}
	if p, _ := s.Get(ctx); p.Enabled || calls != 0 {
		t.Fatalf("policy changed after failed Put: %+v, calls %d", p, calls)
	}
}

func TestStorePutConflict(t *testing.T) {
	ctx := context.Background()
	calls := 0
	s := New(newFile(t), func() { calls++ })

	first := storage.SyncPolicy{Enabled: true, Namespaces: map[string]storage.SyncRule{"a": {Paths: []string{"/a"}}}}
	if _, err := s.Put(ctx, storage.SyncPolicy{Namespaces: map[string]storage.SyncRule{}}, first); err != nil {
		t.Fatalf("an empty map is the zero policy: %v", err)
	}
	if _, err := s.Put(ctx, storage.SyncPolicy{}, storage.SyncPolicy{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale base: %v", err)
	}
	if p, _ := s.Get(ctx); !p.Enabled || calls != 1 {
		t.Fatalf("stale Put changed the policy: %+v, calls %d", p, calls)
	}
	cur, _ := s.Get(ctx)
	if _, err := s.Put(ctx, cur, storage.SyncPolicy{}); err != nil {
		t.Fatalf("current base: %v", err)
	}
}

func TestStorePutConcurrent(t *testing.T) {
	ctx := context.Background()
	s := New(newFile(t), nil)
	var wg sync.WaitGroup
	var won atomic.Int32
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := storage.SyncPolicy{Enabled: true, Namespaces: map[string]storage.SyncRule{"ns" + strconv.Itoa(i): {Paths: []string{"/a"}}}}
			if _, err := s.Put(ctx, storage.SyncPolicy{}, p); err == nil {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("%d saves based on the same policy succeeded", won.Load())
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		in   storage.SyncPolicy
		ok   bool
	}{
		{"empty", storage.SyncPolicy{}, true},
		{"empty rule", storage.SyncPolicy{Namespaces: map[string]storage.SyncRule{"a": {}}}, true},
		{"bad namespace", storage.SyncPolicy{Namespaces: map[string]storage.SyncRule{"Team_A": {}}}, false},
		{"dotted namespace", storage.SyncPolicy{Namespaces: map[string]storage.SyncRule{"a.b": {}}}, false},
		{"empty namespace", storage.SyncPolicy{Namespaces: map[string]storage.SyncRule{"": {}}}, false},
		{"bad path", storage.SyncPolicy{Namespaces: map[string]storage.SyncRule{"a": {Paths: []string{"app"}}}}, false},
		{"bad target", storage.SyncPolicy{Namespaces: map[string]storage.SyncRule{"a": {TargetNamespaces: []string{"B"}}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Validate(tt.in)
			if (err == nil) != tt.ok || (err != nil && !errors.Is(err, secrets.ErrInvalid)) {
				t.Fatalf("Validate = %v, want ok=%v with ErrInvalid", err, tt.ok)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	policy := storage.SyncPolicy{Enabled: true, Namespaces: map[string]storage.SyncRule{
		"team-a": {Paths: []string{"/apps/a", "/shared"}, TargetNamespaces: []string{"team-b"}},
		"empty":  {},
	}}
	src := func(path string) []SourceRef { return []SourceRef{{Path: path}} }
	tests := []struct {
		name    string
		policy  storage.SyncPolicy
		ns      string
		sources []SourceRef
		targets []string
		want    string
	}{
		{"disabled allows everything", storage.SyncPolicy{Namespaces: policy.Namespaces}, "any", src("/x"), []string{"y"}, ""},
		{"zero policy allows everything", storage.SyncPolicy{}, "any", src("/x"), []string{"y"}, ""},
		{"namespace not listed", policy, "other", src("/apps/a"), nil, "namespace other is not allowed"},
		{"path equal to allowed", policy, "team-a", src("/apps/a"), []string{"team-a"}, ""},
		{"path below allowed", policy, "team-a", src("/apps/a/db"), nil, ""},
		{"trailing slash", policy, "team-a", src("/apps/a/"), nil, ""},
		{"path outside", policy, "team-a", src("/apps/b"), nil, "may not read path /apps/b"},
		{"sibling with shared prefix", policy, "team-a", src("/apps/ab"), nil, "may not read path /apps/ab"},
		{"parent of allowed", policy, "team-a", src("/apps"), nil, "may not read path /apps"},
		{"root", policy, "team-a", src("/"), nil, "may not read path /"},
		{"recursive below allowed", policy, "team-a", []SourceRef{{Path: "/shared/x", Recursive: true}}, nil, ""},
		{"recursive parent of allowed", policy, "team-a", []SourceRef{{Path: "/apps", Recursive: true}}, nil, "may not read recursive path /apps"},
		{"second source outside", policy, "team-a", []SourceRef{{Path: "/shared"}, {Path: "/other"}}, nil, "may not read path /other"},
		{"invalid source path", policy, "team-a", src("not-a-path"), nil, "must look like"},
		{"own namespace target", policy, "team-a", src("/shared"), []string{"team-a"}, ""},
		{"listed target", policy, "team-a", src("/shared"), []string{"team-a", "team-b"}, ""},
		{"unlisted target", policy, "team-a", src("/shared"), []string{"team-c"}, "may not write to namespace team-c"},
		{"empty paths allow no path", policy, "empty", src("/a"), nil, "may not read path /a"},
		{"empty paths allow own target", policy, "empty", nil, []string{"empty"}, ""},
		{"empty paths deny other target", policy, "empty", nil, []string{"team-a"}, "may not write to namespace team-a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check(tt.policy, tt.ns, tt.sources, tt.targets)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Check = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Check = %v, want ErrDenied containing %q", err, tt.want)
			}
			if errors.Is(err, secrets.ErrInvalid) {
				t.Fatalf("Check = %v, a denial must not also be an invalid input", err)
			}
		})
	}
}
