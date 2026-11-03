package tokens

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/storage/file"
)

func TestStore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	backend, err := file.New(filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(backend)

	tok, secret, err := s.Create(ctx, "ci", "/app/", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, Prefix) || tok.Path != "/app" || !tok.ReadOnly || strings.Contains(tok.Hash, secret) {
		t.Fatalf("Create = %+v, %q", tok, secret)
	}
	for _, bad := range [][2]string{{"ci", "/app"}, {"Bad Name", "/app"}, {"ok", "app"}} {
		if _, _, err := s.Create(ctx, bad[0], bad[1], false); !errors.Is(err, secrets.ErrInvalid) {
			t.Errorf("Create(%q, %q) = %v, want ErrInvalid", bad[0], bad[1], err)
		}
	}

	reloaded, _ := file.New(filepath.Join(dir, "store.json"))
	if got, ok, err := New(reloaded).Lookup(ctx, secret); err != nil || !ok || got.Name != "ci" {
		t.Fatalf("Lookup after reload = %+v, %v, %v", got, ok, err)
	}
	for _, wrong := range []string{"", secret + "x", strings.TrimPrefix(secret, Prefix)} {
		if _, ok, _ := s.Lookup(ctx, wrong); ok {
			t.Errorf("Lookup(%q) matched", wrong)
		}
	}

	if err := s.Revoke(ctx, "ci"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Lookup(ctx, secret); ok {
		t.Fatal("revoked token still valid")
	}
	if err := s.Revoke(ctx, "ci"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("revoke missing: %v", err)
	}
}
