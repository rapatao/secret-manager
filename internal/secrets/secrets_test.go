package secrets

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"
)

func TestNormalizePath(t *testing.T) {
	valid := map[string]string{"/": "/", "/a": "/a", "/a/": "/a", "/a-1/b2": "/a-1/b2"}
	for in, want := range valid {
		got, err := NormalizePath(in)
		if err != nil || got != want {
			t.Errorf("NormalizePath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "a", "/a//b", "/a//", "/A", "/a.b", "/a_b", "/../x"} {
		if _, err := NormalizePath(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("NormalizePath(%q): want ErrInvalid, got %v", in, err)
		}
	}
}

func TestValidateKey(t *testing.T) {
	for _, k := range []string{"A", "db.password", "API_KEY-2"} {
		if err := ValidateKey(k); err != nil {
			t.Errorf("ValidateKey(%q): %v", k, err)
		}
	}
	for _, k := range []string{"", "a b", "a=b", "a/b"} {
		if err := ValidateKey(k); !errors.Is(err, ErrInvalid) {
			t.Errorf("ValidateKey(%q): want ErrInvalid, got %v", k, err)
		}
	}
}

func TestSetKeysMergesAndNotifies(t *testing.T) {
	ctx := context.Background()
	var changed []string
	s := New(newMem(), func(p string) { changed = append(changed, p) })

	if err := s.SetKeys(ctx, "/app/", map[string]string{"A": "1", "B": "2"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetKeys(ctx, "/app", map[string]string{"B": "3"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "/app", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"A": "1", "B": "3"}; !maps.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if want := []string{"/app", "/app"}; !slices.Equal(changed, want) {
		t.Fatalf("changes %v, want %v", changed, want)
	}
}

func TestSetKeysRejectsInvalidKey(t *testing.T) {
	s := New(newMem(), nil)
	err := s.SetKeys(context.Background(), "/app", map[string]string{"bad key": "x"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

func TestNoNotificationOnFailedWrite(t *testing.T) {
	m := newMem()
	m.failPut = true
	notified := false
	s := New(m, func(string) { notified = true })
	if err := s.SetKeys(context.Background(), "/app", map[string]string{"A": "1"}); err == nil {
		t.Fatal("want error")
	}
	if notified {
		t.Fatal("notified after failed write")
	}
}

func TestRecursiveGetDeeperWins(t *testing.T) {
	ctx := context.Background()
	s := New(newMem(), nil)
	mustSet(t, s, "/app", map[string]string{"A": "root", "B": "root"})
	mustSet(t, s, "/app/db", map[string]string{"B": "db", "C": "db"})
	mustSet(t, s, "/apple", map[string]string{"X": "other"})

	got, err := s.Get(ctx, "/app", true)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"A": "root", "B": "db", "C": "db"}; !maps.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	got, err = s.Get(ctx, "/app/db", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"B": "db", "C": "db"}; !maps.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestRecursiveGetMissing(t *testing.T) {
	_, err := New(newMem(), nil).Get(context.Background(), "/none", true)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestDeleteKeyAndPath(t *testing.T) {
	ctx := context.Background()
	s := New(newMem(), nil)
	mustSet(t, s, "/app", map[string]string{"A": "1", "B": "2"})

	if err := s.DeleteKey(ctx, "/app", "A"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteKey(ctx, "/app", "missing"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, "/app", false)
	if want := map[string]string{"B": "2"}; !maps.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if err := s.DeleteKey(ctx, "/none", "A"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteKey on missing path: want ErrNotFound, got %v", err)
	}

	if err := s.DeletePath(ctx, "/app"); err != nil {
		t.Fatal(err)
	}
	paths, _ := s.ListPaths(ctx)
	if len(paths) != 0 {
		t.Fatalf("paths after delete: %v", paths)
	}
}

func mustSet(t *testing.T, s *Service, path string, v map[string]string) {
	t.Helper()
	if err := s.SetKeys(context.Background(), path, v); err != nil {
		t.Fatal(err)
	}
}

func TestHistoryAndRollback(t *testing.T) {
	ctx := context.Background()
	var changed []string
	s := New(newMem(), func(p string) { changed = append(changed, p) })
	s.KeepVersions = 3

	mustSet := func(values map[string]string) {
		t.Helper()
		if err := s.SetKeys(ctx, "/app", values); err != nil {
			t.Fatal(err)
		}
	}
	mustSet(map[string]string{"A": "1"})
	mustSet(map[string]string{"A": "1"})
	mustSet(map[string]string{"A": "2", "B": "x"})
	if err := s.DeleteKey(ctx, "/app", "B"); err != nil {
		t.Fatal(err)
	}

	versions, err := s.History(ctx, "/app")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 3 || versions[0].Number != 3 {
		t.Fatalf("unchanged write must not add a version: %+v", versions)
	}

	if err := s.DeletePath(ctx, "/app"); err != nil {
		t.Fatal(err)
	}
	changed = nil
	if err := s.Rollback(ctx, "/app", 1); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "/app", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"A": "1"}; !maps.Equal(got, want) {
		t.Fatalf("after rollback got %v, want %v", got, want)
	}
	if !slices.Equal(changed, []string{"/app"}) {
		t.Fatalf("rollback changes %v", changed)
	}
	versions, _ = s.History(ctx, "/app")
	if versions[0].Number != 4 || len(versions) != 3 {
		t.Fatalf("rollback must add a pruned version: %+v", versions)
	}

	if err := s.Rollback(ctx, "/app", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rollback to pruned version: want ErrNotFound, got %v", err)
	}
}

func TestHistoryDisabled(t *testing.T) {
	ctx := context.Background()
	s := New(newMem(), nil)
	if err := s.SetKeys(ctx, "/app", map[string]string{"A": "1"}); err != nil {
		t.Fatal(err)
	}
	if versions, err := s.History(ctx, "/app"); err != nil || len(versions) != 0 {
		t.Fatalf("History = %v, %v; want none", versions, err)
	}
}
