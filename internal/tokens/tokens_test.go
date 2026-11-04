package tokens

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	tok, secret, err := s.Create(ctx, "ci", "/app/", true, time.Time{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, Prefix) || tok.Path != "/app" || !tok.ReadOnly || strings.Contains(tok.Hash, secret) {
		t.Fatalf("Create = %+v, %q", tok, secret)
	}
	for _, bad := range [][2]string{{"ci", "/app"}, {"Bad Name", "/app"}, {"ok", "app"}} {
		if _, _, err := s.Create(ctx, bad[0], bad[1], false, time.Time{}, nil, nil); !errors.Is(err, secrets.ErrInvalid) {
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

	if _, _, err := s.Create(ctx, "past", "/", false, time.Now().Add(-time.Hour), nil, nil); !errors.Is(err, secrets.ErrInvalid) {
		t.Errorf("Create with past expiry = %v, want ErrInvalid", err)
	}

	if _, ok, err := s.Lookup(ctx, secret); !ok || err != nil {
		t.Fatalf("Lookup = %v, %v", ok, err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	reloaded, _ = file.New(filepath.Join(dir, "store.json"))
	list, err := New(reloaded).List(ctx)
	if err != nil || len(list) != 1 || list[0].LastUsed.IsZero() {
		t.Fatalf("last use after Flush = %+v, %v", list, err)
	}

	in := time.Now().Add(time.Hour)
	if got, err := s.Update(ctx, "ci", "/other/", false, in, nil, nil); err != nil || got.Path != "/other" || got.ReadOnly || !got.Expires.Equal(in.UTC().Truncate(time.Second)) {
		t.Fatalf("Update = %+v, %v", got, err)
	}
	if got, ok, _ := s.Lookup(ctx, secret); !ok || got.Path != "/other" {
		t.Fatalf("Lookup after Update = %+v, %v", got, ok)
	}
	if _, err := s.Update(ctx, "ci", "/", false, time.Now().Add(-time.Hour), nil, nil); !errors.Is(err, secrets.ErrInvalid) {
		t.Errorf("Update with past expiry = %v, want ErrInvalid", err)
	}
	if _, err := s.Update(ctx, "missing", "/", false, time.Time{}, nil, nil); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("Update missing = %v, want ErrNotFound", err)
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

func TestExpired(t *testing.T) {
	ctx := context.Background()
	backend, err := file.New(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(-time.Minute)
	if err := backend.PutTokens(ctx, []Token{{Name: "old", Hash: hash(Prefix + "x"), Path: "/", Expires: expires}}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := New(backend).Lookup(ctx, Prefix+"x"); ok || !errors.Is(err, ErrExpired) {
		t.Fatalf("Lookup expired = %v, %v, want ErrExpired", ok, err)
	}
}
