package local

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rapatao/secret-manager/internal/client"
)

func TestVault(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "dir", "vault.json")
	server := Scheme + path

	if _, err := Create(path, "short"); err == nil {
		t.Fatal("Create accepted a short passphrase")
	}
	key, err := Create(path, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(path, "correct horse"); err == nil {
		t.Fatal("Create replaced an existing vault")
	}
	if _, err := Unlock(path, "wrong horse"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Unlock with a wrong passphrase: %v", err)
	}
	unlocked, err := Unlock(path, "correct horse")
	if err != nil || string(unlocked) != string(key) {
		t.Fatalf("Unlock = %x, %v; want %x", unlocked, err, key)
	}
	if _, err := Open(ctx, path, make([]byte, len(key))); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("Open with a wrong key: %v", err)
	}

	open := func() *client.Client {
		v, err := Open(ctx, path, key)
		if err != nil {
			t.Fatal(err)
		}
		return client.New(server, v.Token).WithTransport(v)
	}
	vaults := make([]*client.Client, 20)
	for i := range vaults {
		vaults[i] = open()
	}
	var wg sync.WaitGroup
	for i, c := range vaults {
		wg.Go(func() {
			if err := c.Set(ctx, "/app", map[string]string{fmt.Sprintf("K%d", i): "v"}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()

	a := open()
	got, err := a.Get(ctx, "/app", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 20 {
		t.Fatalf("got %d keys after concurrent writes from separate vaults, want 20: %v", len(got), got)
	}
	history, err := a.History(ctx, "/app")
	if err != nil || len(history) != HistoryLimit {
		t.Fatalf("History = %d versions, %v; want %d", len(history), err, HistoryLimit)
	}
}

func TestNormalize(t *testing.T) {
	abs, _ := filepath.Abs("vault.json")
	for in, want := range map[string]string{
		"file://vault.json":   Scheme + abs,
		"file:///a/../b.json": "file:///b.json",
		"https://example.com": "https://example.com",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}
