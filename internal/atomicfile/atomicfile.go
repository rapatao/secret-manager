// Package atomicfile replaces files atomically.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Write replaces path with data, mode 0600. The data is synced to a temporary
// file next to path, renamed over it, and the directory is synced. When path is
// a symlink, the file it points to is replaced and the link is kept.
func Write(path string, data []byte) error {
	if p, err := filepath.EvalSymlinks(path); err == nil {
		path = p
	}
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, tempPattern(base))
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// syncDir is best-effort: the file is already in place, and not every
// filesystem or OS supports syncing a directory.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

func tempPattern(base string) string {
	return "." + base + ".tmp-*"
}
