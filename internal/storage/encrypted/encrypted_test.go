package encrypted

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rapatao/secret-manager/internal/storage"
	"github.com/rapatao/secret-manager/internal/storage/file"
	"github.com/rapatao/secret-manager/internal/storage/storagetest"
)

var key = bytes.Repeat([]byte{7}, KeySize)

func newFile(t *testing.T) *file.Backend {
	t.Helper()
	f, err := file.New(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func wrap(t *testing.T, inner storage.Backend, key []byte) *Backend {
	t.Helper()
	b, err := New(inner, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestConformance(t *testing.T) {
	storagetest.Run(t, func() storage.Backend { return wrap(t, newFile(t), key) })
}

func TestConformanceWithoutKey(t *testing.T) {
	storagetest.Run(t, func() storage.Backend { return wrap(t, newFile(t), nil) })
}

func TestStoresCiphertext(t *testing.T) {
	ctx := context.Background()
	inner := newFile(t)
	b := wrap(t, inner, key)
	if err := b.Put(ctx, "/app", map[string]string{"A": "s3cret", "B": "s3cret"}); err != nil {
		t.Fatal(err)
	}
	if err := b.AddVersion(ctx, "/app", time.Now(), map[string]string{"A": "s3cret"}, 5); err != nil {
		t.Fatal(err)
	}
	raw, _ := inner.Get(ctx, "/app")
	if !strings.HasPrefix(raw["A"], prefix) || strings.Contains(raw["A"], "s3cret") || raw["A"] == raw["B"] {
		t.Fatalf("stored values %v", raw)
	}
	versions, _ := inner.Versions(ctx, "/app")
	if !strings.HasPrefix(versions[0].Data["A"], prefix) {
		t.Fatalf("stored version %v", versions[0].Data)
	}

	if _, err := wrap(t, inner, nil).Get(ctx, "/app"); !errors.Is(err, ErrNoKey) {
		t.Fatalf("read without key: %v", err)
	}
	if _, err := wrap(t, inner, bytes.Repeat([]byte{8}, KeySize)).Get(ctx, "/app"); err == nil {
		t.Fatal("read with wrong key succeeded")
	}

	if err := inner.Put(ctx, "/app", map[string]string{"A": raw["B"], "B": raw["A"]}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(ctx, "/app"); err == nil {
		t.Fatal("values swapped between keys decrypted")
	}
}

func TestMigratePlaintext(t *testing.T) {
	ctx := context.Background()
	inner := newFile(t)
	plain := wrap(t, inner, nil)
	for _, p := range []string{"/a", "/b"} {
		if err := plain.Put(ctx, p, map[string]string{"K": p}); err != nil {
			t.Fatal(err)
		}
	}
	if err := plain.AddVersion(ctx, "/a", time.Now(), map[string]string{"K": "old"}, 5); err != nil {
		t.Fatal(err)
	}
	b := wrap(t, inner, key)
	if got, _ := b.Get(ctx, "/a"); got["K"] != "/a" {
		t.Fatalf("plaintext read = %v", got)
	}
	if err := b.Put(ctx, "/b", map[string]string{"K": "/b"}); err != nil {
		t.Fatal(err)
	}

	done, unreadable, err := b.Migrate(ctx)
	if err != nil || !slices.Equal(done, []string{"/a", "/a version 1"}) || len(unreadable) != 0 {
		t.Fatalf("Migrate = %v, %v, %v", done, unreadable, err)
	}
	raw, _ := inner.Get(ctx, "/a")
	versions, _ := inner.Versions(ctx, "/a")
	if !strings.HasPrefix(raw["K"], prefix) || !strings.HasPrefix(versions[0].Data["K"], prefix) {
		t.Fatalf("still plaintext: %v, %v", raw, versions[0].Data)
	}
	if got, _ := b.Get(ctx, "/a"); got["K"] != "/a" {
		t.Fatalf("after encryption = %v", got)
	}
	if done, _, _ := b.Migrate(ctx); len(done) != 0 {
		t.Fatalf("second Migrate rewrote %v", done)
	}
}

func TestMigratePreviousKey(t *testing.T) {
	ctx := context.Background()
	inner := newFile(t)
	old := wrap(t, inner, key)
	if err := old.Put(ctx, "/a", map[string]string{"K": "v"}); err != nil {
		t.Fatal(err)
	}
	if err := old.AddVersion(ctx, "/a", time.Now(), map[string]string{"K": "v"}, 5); err != nil {
		t.Fatal(err)
	}
	other := wrap(t, inner, bytes.Repeat([]byte{9}, KeySize))
	if err := other.Put(ctx, "/lost", map[string]string{"K": "v"}); err != nil {
		t.Fatal(err)
	}

	newKey := bytes.Repeat([]byte{8}, KeySize)
	b, err := New(inner, newKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.Get(ctx, "/a"); err != nil || got["K"] != "v" {
		t.Fatalf("read with previous key = %v, %v", got, err)
	}
	done, unreadable, err := b.Migrate(ctx)
	if err != nil || !slices.Equal(done, []string{"/a", "/a version 1"}) || !slices.Equal(unreadable, []string{"/lost"}) {
		t.Fatalf("Migrate = %v, %v, %v", done, unreadable, err)
	}
	rotated := wrap(t, inner, newKey)
	if got, err := rotated.Get(ctx, "/a"); err != nil || got["K"] != "v" {
		t.Fatalf("read with new key only = %v, %v", got, err)
	}
	if vs, err := rotated.Versions(ctx, "/a"); err != nil || vs[0].Data["K"] != "v" {
		t.Fatalf("versions with new key only = %v, %v", vs, err)
	}

	if _, err := New(inner, nil, key); err == nil {
		t.Fatal("previous key without key accepted")
	}
}

func TestBackupEnvelope(t *testing.T) {
	doc := []byte(`{"format":1,"paths":[]}`)
	sealed, err := SealBackup(key, doc)
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncryptedBackup(sealed) || IsEncryptedBackup(doc) || bytes.Contains(sealed, []byte("paths")) {
		t.Fatalf("envelope %s", sealed)
	}
	got, err := OpenBackup(key, sealed)
	if err != nil || !bytes.Equal(got, doc) {
		t.Fatalf("OpenBackup = %s, %v", got, err)
	}
	if _, err := OpenBackup(bytes.Repeat([]byte{8}, KeySize), sealed); !errors.Is(err, ErrBackupKey) {
		t.Fatalf("OpenBackup with wrong key: %v", err)
	}
}

func TestParseKey(t *testing.T) {
	if _, err := ParseKey("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "not base64!", "c2hvcnQ="} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("ParseKey(%q) accepted", bad)
		}
	}
}
