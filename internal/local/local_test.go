package local

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rapatao/secret-manager/internal/client"
	"github.com/rapatao/secret-manager/internal/storage"
)

func TestMemoryBackendDoesNotShareMemory(t *testing.T) {
	ctx := context.Background()
	m := &memory{}

	policy := storage.SyncPolicy{Enabled: true, Namespaces: map[string]storage.SyncRule{"a": {Paths: []string{"/x"}}}}
	if err := m.PutSyncPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	policy.Namespaces["a"].Paths[0] = "/changed"
	policy.Namespaces["b"] = storage.SyncRule{}
	got, _ := m.SyncPolicy(ctx)
	got.Namespaces["a"].Paths[0] = "/changed-too"
	if again, _ := m.SyncPolicy(ctx); again.Namespaces["a"].Paths[0] != "/x" || len(again.Namespaces) != 1 {
		t.Fatalf("policy shared with a caller: %+v", again)
	}

	d := time.Hour
	tokens := []storage.Token{{Name: "t", CacheMaxAge: &d, AllowedFrom: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}}
	if err := m.PutTokens(ctx, tokens); err != nil {
		t.Fatal(err)
	}
	tokens[0].Name = "changed"
	tokens[0].AllowedFrom[0] = netip.MustParsePrefix("0.0.0.0/0")
	*tokens[0].CacheMaxAge = time.Minute
	got2, _ := m.Tokens(ctx)
	got2[0].AllowedFrom[0] = netip.MustParsePrefix("0.0.0.0/0")
	*got2[0].CacheMaxAge = time.Second
	again, _ := m.Tokens(ctx)
	if again[0].Name != "t" || again[0].AllowedFrom[0].String() != "10.0.0.0/8" || *again[0].CacheMaxAge != time.Hour {
		t.Fatalf("tokens shared with a caller: %+v", again)
	}

	events := []storage.AuditEvent{{Op: "x", Keys: []string{"k"}}}
	if err := m.PutAuditEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	events[0].Keys[0] = "changed"
	got3, _ := m.AuditEvents(ctx)
	got3[0].Keys[0] = "changed-too"
	if again, _ := m.AuditEvents(ctx); again[0].Keys[0] != "k" {
		t.Fatalf("audit events shared with a caller: %+v", again)
	}
}

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
