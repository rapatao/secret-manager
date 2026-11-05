package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rapatao/secret-manager/internal/storage"
	"github.com/rapatao/secret-manager/internal/storage/storagetest"
)

func TestConformance(t *testing.T) {
	storagetest.Run(t, func() storage.Backend {
		b, err := New(filepath.Join(t.TempDir(), "store.json"))
		if err != nil {
			t.Fatal(err)
		}
		return b
	})
}

func TestPersists(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.json")
	b, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Put(ctx, "/app", map[string]string{"A": "1"}); err != nil {
		t.Fatal(err)
	}
	if err := b.AddVersion(ctx, "/app", time.Now(), map[string]string{"A": "1"}, 5); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("file mode %v, want 0600", mode)
	}

	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.Get(ctx, "/app"); err != nil || got["A"] != "1" {
		t.Fatalf("Get after reopen = %v, %v", got, err)
	}
	if vs, err := reopened.Versions(ctx, "/app"); err != nil || len(vs) != 1 {
		t.Fatalf("Versions after reopen = %v, %v", vs, err)
	}
}

func TestFailedWriteKeepsDiskState(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	b, err := New(filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Put(ctx, "/app", map[string]string{"A": "1"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := b.Put(ctx, "/app", map[string]string{"A": "2"}); err == nil {
		t.Skip("directory still writable, running as root?")
	}
	if got, _ := b.Get(ctx, "/app"); got["A"] != "1" {
		t.Fatalf("after failed write Get = %v, want persisted value", got)
	}
}

func TestWriteKeepsSymlink(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	target := filepath.Join(dir, "store.json##class.work")
	link := filepath.Join(dir, "store.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(target), link); err != nil {
		t.Fatal(err)
	}
	b, err := New(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Put(ctx, "/app", map[string]string{"A": "1"}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link replaced: %v, %v", info, err)
	}
	reopened, err := New(target)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.Get(ctx, "/app"); err != nil || got["A"] != "1" {
		t.Fatalf("Get from target = %v, %v", got, err)
	}
}
