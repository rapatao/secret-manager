package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func names(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestWriteNewAndOverwrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.json")
	for _, want := range []string{"one", "two"} {
		if err := Write(p, []byte(want)); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(p)
		if err != nil || string(got) != want {
			t.Fatalf("got %q, %v; want %q", got, err, want)
		}
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(p)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
		}
	}
	if n := names(t, dir); len(n) != 1 {
		t.Fatalf("leftover files: %v", n)
	}
}

func TestWriteKeepsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	link := filepath.Join(dir, "link.json")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := Write(link, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link replaced: %v, %v", fi, err)
	}
	if got, _ := os.ReadFile(target); string(got) != "new" {
		t.Fatalf("target = %q", got)
	}
}

func TestWriteCleansUpOnRenameFailure(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "d")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p, "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(p, []byte("data")); err == nil {
		t.Fatal("expected error renaming over a non-empty directory")
	}
	if n := names(t, dir); len(n) != 1 || n[0] != "d" {
		t.Fatalf("leftover files: %v", n)
	}
}

func TestTempNameAvoidsBackupGlob(t *testing.T) {
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, tempPattern("backup-20240101T000000Z.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if m, _ := filepath.Match("backup-*.json", filepath.Base(f.Name())); m {
		t.Fatalf("temp name %s matches the prune glob", f.Name())
	}
}
