package secrets

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/rapatao/secret-manager/internal/storage/encrypted"
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

func TestUpdateKeysSetsAndRemovesInOneVersion(t *testing.T) {
	ctx := context.Background()
	s := New(newMem(), nil)
	s.KeepVersions = 5
	if err := s.SetKeys(ctx, "/app", map[string]string{"A": "1", "B": "2"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateKeys(ctx, "/app", map[string]string{"A": "9", "C": "3"}, []string{"B", "MISSING"}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, "/app", false)
	if want := map[string]string{"A": "9", "C": "3"}; !maps.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if versions, _ := s.History(ctx, "/app"); len(versions) != 2 {
		t.Fatalf("want 2 versions, got %+v", versions)
	}
	if err := s.UpdateKeys(ctx, "/app", map[string]string{"A": "1"}, []string{"A"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("set and delete same key: want ErrInvalid, got %v", err)
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

	if err := s.Rollback(ctx, "/app", 4); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rollback to current data: want ErrInvalid, got %v", err)
	}
	if err := s.Rollback(ctx, "/app", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rollback to pruned version: want ErrNotFound, got %v", err)
	}
}

func TestDeleteVersions(t *testing.T) {
	ctx := context.Background()
	s := New(newMem(), nil)
	s.KeepVersions = 10
	for _, v := range []string{"1", "leaked", "3"} {
		if err := s.SetKeys(ctx, "/app", map[string]string{"A": v}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteVersions(ctx, "/app", 2, 9); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete with a missing version: want ErrNotFound, got %v", err)
	}
	if err := s.DeleteVersions(ctx, "/app"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("delete without versions: want ErrInvalid, got %v", err)
	}
	if err := s.DeleteVersions(ctx, "/app", 2); err != nil {
		t.Fatal(err)
	}
	versions, _ := s.History(ctx, "/app")
	if len(versions) != 2 || versions[0].Number != 3 || versions[1].Number != 1 {
		t.Fatalf("versions after delete: %+v", versions)
	}
	if got, _ := s.Get(ctx, "/app", false); got["A"] != "3" {
		t.Fatalf("data changed by version delete: %v", got)
	}
	if err := s.DeleteVersions(ctx, "/app", 1, 3); err != nil {
		t.Fatal(err)
	}
	if paths, _ := s.backend.VersionedPaths(ctx); len(paths) != 0 {
		t.Fatalf("versioned paths after deleting all: %v", paths)
	}
}

func TestCopyAndMovePath(t *testing.T) {
	ctx := context.Background()
	var changed []string
	s := New(newMem(), func(p string) { changed = append(changed, p) })
	s.KeepVersions = 10
	for _, v := range []string{"1", "2"} {
		if err := s.SetKeys(ctx, "/a", map[string]string{"K": v}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetKeys(ctx, "/taken", nil); err != nil {
		t.Fatal(err)
	}
	for _, to := range []string{"/a", "/taken", "/BAD"} {
		if err := s.CopyPath(ctx, "/a", to, false); !errors.Is(err, ErrInvalid) {
			t.Errorf("copy to %s: want ErrInvalid, got %v", to, err)
		}
	}
	if err := s.CopyPath(ctx, "/missing", "/x", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("copy missing path: %v", err)
	}

	changed = nil
	if err := s.CopyPath(ctx, "/a", "/b", false); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(ctx, "/b", false); got["K"] != "2" {
		t.Fatalf("copied data %v", got)
	}
	if vs, _ := s.History(ctx, "/b"); len(vs) != 2 || vs[0].Number != 2 {
		t.Fatalf("copied versions %+v", vs)
	}
	if _, err := s.Get(ctx, "/a", false); err != nil {
		t.Fatalf("copy removed the source: %v", err)
	}

	if err := s.CopyPath(ctx, "/a", "/c", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "/a", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("moved source still exists: %v", err)
	}
	if vs, _ := s.History(ctx, "/a"); len(vs) != 0 {
		t.Fatalf("moved source kept versions %+v", vs)
	}
	if vs, _ := s.History(ctx, "/c"); len(vs) != 2 {
		t.Fatalf("moved versions %+v", vs)
	}
	if !slices.Equal(changed, []string{"/b", "/c", "/a"}) {
		t.Fatalf("changes %v", changed)
	}
	if err := s.DeletePath(ctx, "/b"); err != nil {
		t.Fatal(err)
	}
	if err := s.CopyPath(ctx, "/c", "/b", false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("copy onto a deleted path with versions: %v", err)
	}
}

func TestCopyPathEncrypted(t *testing.T) {
	ctx := context.Background()
	b, err := encrypted.New(newMem(), bytes.Repeat([]byte{7}, encrypted.KeySize), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := New(b, nil)
	s.KeepVersions = 10
	if err := s.SetKeys(ctx, "/a", map[string]string{"K": "v"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CopyPath(ctx, "/a", "/b", false); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(ctx, "/b", false); err != nil || got["K"] != "v" {
		t.Fatalf("copied encrypted data = %v, %v", got, err)
	}
	if vs, err := s.History(ctx, "/b"); err != nil || len(vs) != 1 || vs[0].Data["K"] != "v" {
		t.Fatalf("copied encrypted versions = %v, %v", vs, err)
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

func TestBackupRestore(t *testing.T) {
	ctx := context.Background()
	src := New(newMem(), nil)
	src.KeepVersions = 10
	if err := src.SetKeys(ctx, "/app", map[string]string{"A": "1"}); err != nil {
		t.Fatal(err)
	}
	if err := src.SetKeys(ctx, "/app", map[string]string{"A": "2"}); err != nil {
		t.Fatal(err)
	}
	if err := src.SetKeys(ctx, "/tools", map[string]string{"T": "x"}); err != nil {
		t.Fatal(err)
	}

	plain, err := src.Backup(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 2 || plain[0].Path != "/app" || plain[0].Data["A"] != "2" || plain[0].Versions != nil {
		t.Fatalf("backup without history: %+v", plain)
	}
	full, err := src.Backup(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(full[0].Versions) != 2 {
		t.Fatalf("backup with history: %+v", full)
	}

	var changed []string
	dst := New(newMem(), func(p string) { changed = append(changed, p) })
	dst.KeepVersions = 10
	if err := dst.SetKeys(ctx, "/app", map[string]string{"A": "old", "B": "gone"}); err != nil {
		t.Fatal(err)
	}
	if err := dst.SetKeys(ctx, "/keep", map[string]string{"K": "1"}); err != nil {
		t.Fatal(err)
	}
	changed = nil
	if err := dst.Restore(ctx, full); err != nil {
		t.Fatal(err)
	}

	got, _ := dst.Get(ctx, "/app", false)
	if want := map[string]string{"A": "2"}; !maps.Equal(got, want) {
		t.Fatalf("/app = %v, want %v", got, want)
	}
	if _, err := dst.Get(ctx, "/keep", false); err != nil {
		t.Fatalf("path missing from backup was removed: %v", err)
	}
	if want := []string{"/app", "/tools"}; !slices.Equal(changed, want) {
		t.Fatalf("changes %v, want %v", changed, want)
	}

	appHistory, _ := dst.History(ctx, "/app")
	if len(appHistory) != 2 || appHistory[0].Data["A"] != "2" {
		t.Fatalf("/app had versions, restore must only record the new data: %+v", appHistory)
	}
	toolsHistory, _ := dst.History(ctx, "/tools")
	if len(toolsHistory) != 1 || !toolsHistory[0].Time.Equal(full[1].Versions[0].Time) {
		t.Fatalf("/tools versions not restored with their time: %+v", toolsHistory)
	}

	changed = nil
	if err := dst.Restore(ctx, full); err != nil || len(changed) != 0 {
		t.Fatalf("second restore: %v, changes %v", err, changed)
	}
}

func TestRestoreValidatesBeforeWriting(t *testing.T) {
	ctx := context.Background()
	s := New(newMem(), nil)
	err := s.Restore(ctx, []PathBackup{
		{Path: "/ok", Data: map[string]string{"A": "1"}},
		{Path: "/bad", Data: map[string]string{"a b": "1"}},
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
	if paths, _ := s.ListPaths(ctx); len(paths) != 0 {
		t.Fatalf("wrote %v before failing", paths)
	}
}

func TestDiff(t *testing.T) {
	got := Diff(map[string]string{"A": "1", "B": "2", "D": "4"}, map[string]string{"A": "1", "B": "3", "C": "x"})
	want := []Change{{"~", "B"}, {"+", "C"}, {"-", "D"}}
	if !slices.Equal(got, want) {
		t.Fatalf("Diff = %v, want %v", got, want)
	}
	if got := Diff(nil, nil); got != nil {
		t.Fatalf("Diff(nil, nil) = %v", got)
	}
}
