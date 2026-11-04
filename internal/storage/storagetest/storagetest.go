// Package storagetest provides a conformance suite for storage.Backend
// implementations.
package storagetest

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/rapatao/secret-manager/internal/storage"
)

// Run executes the conformance suite. newBackend must return an empty backend
// on every call.
func Run(t *testing.T, newBackend func() storage.Backend) {
	ctx := context.Background()

	t.Run("get missing path", func(t *testing.T) {
		_, err := newBackend().Get(ctx, "/missing")
		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("put then get", func(t *testing.T) {
		b := newBackend()
		want := map[string]string{"A": "1", "B": "two"}
		mustPut(t, b, "/app", want)
		got, err := b.Get(ctx, "/app")
		if err != nil {
			t.Fatal(err)
		}
		if !maps.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("put replaces data", func(t *testing.T) {
		b := newBackend()
		mustPut(t, b, "/app", map[string]string{"A": "1", "B": "2"})
		mustPut(t, b, "/app", map[string]string{"C": "3"})
		got, err := b.Get(ctx, "/app")
		if err != nil {
			t.Fatal(err)
		}
		if want := map[string]string{"C": "3"}; !maps.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("put empty data", func(t *testing.T) {
		b := newBackend()
		mustPut(t, b, "/empty", map[string]string{})
		got, err := b.Get(ctx, "/empty")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("want empty, got %v", got)
		}
	})

	t.Run("root path", func(t *testing.T) {
		b := newBackend()
		mustPut(t, b, "/", map[string]string{"A": "1"})
		if _, err := b.Get(ctx, "/"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("delete", func(t *testing.T) {
		b := newBackend()
		mustPut(t, b, "/app", map[string]string{"A": "1"})
		if err := b.Delete(ctx, "/app"); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Get(ctx, "/app"); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("want ErrNotFound after delete, got %v", err)
		}
		if err := b.Delete(ctx, "/app"); err != nil {
			t.Fatalf("deleting missing path: %v", err)
		}
	})

	t.Run("list by prefix", func(t *testing.T) {
		b := newBackend()
		for _, p := range []string{"/b", "/a/x", "/a", "/ab", "/a/x/y", "/"} {
			mustPut(t, b, p, map[string]string{"K": p})
		}
		cases := map[string][]string{
			"/":    {"/", "/a", "/a/x", "/a/x/y", "/ab", "/b"},
			"/a":   {"/a", "/a/x", "/a/x/y"},
			"/a/x": {"/a/x", "/a/x/y"},
			"/c":   nil,
		}
		for prefix, want := range cases {
			got, err := b.List(ctx, prefix)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, want) {
				t.Errorf("List(%q) = %v, want %v", prefix, got, want)
			}
		}
	})

	t.Run("versions", func(t *testing.T) {
		b := newBackend()
		at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		for i := range 4 {
			if err := b.AddVersion(ctx, "/a", at.Add(time.Duration(i)*time.Minute), map[string]string{"K": string(rune('0' + i))}, 3); err != nil {
				t.Fatal(err)
			}
		}
		if err := b.AddVersion(ctx, "/a/b", at, map[string]string{"X": "1"}, 3); err != nil {
			t.Fatal(err)
		}
		got, err := b.Versions(ctx, "/a")
		if err != nil {
			t.Fatal(err)
		}
		var numbers []int
		for _, v := range got {
			numbers = append(numbers, v.Number)
		}
		if want := []int{4, 3, 2}; !slices.Equal(numbers, want) {
			t.Fatalf("versions %v, want %v", numbers, want)
		}
		if !got[0].Time.Equal(at.Add(3*time.Minute)) || got[0].Data["K"] != "3" {
			t.Fatalf("newest version = %+v", got[0])
		}
		if paths, _ := b.List(ctx, "/"); len(paths) != 0 {
			t.Fatalf("versions listed as paths: %v", paths)
		}
	})

	t.Run("versions outlive delete", func(t *testing.T) {
		b := newBackend()
		mustPut(t, b, "/app", map[string]string{"A": "1"})
		if err := b.AddVersion(ctx, "/app", time.Now(), map[string]string{"A": "1"}, 10); err != nil {
			t.Fatal(err)
		}
		if err := b.Delete(ctx, "/app"); err != nil {
			t.Fatal(err)
		}
		got, err := b.Versions(ctx, "/app")
		if err != nil || len(got) != 1 {
			t.Fatalf("Versions = %v, %v; want one version", got, err)
		}
		if missing, err := b.Versions(ctx, "/missing"); err != nil || len(missing) != 0 {
			t.Fatalf("Versions(missing) = %v, %v", missing, err)
		}
	})

	t.Run("versioned paths", func(t *testing.T) {
		b := newBackend()
		mustPut(t, b, "/plain", map[string]string{"A": "1"})
		for _, p := range []string{"/b", "/a", "/a"} {
			if err := b.AddVersion(ctx, p, time.Now(), map[string]string{"A": "1"}, 10); err != nil {
				t.Fatal(err)
			}
		}
		got, err := b.VersionedPaths(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"/a", "/b"}; !slices.Equal(got, want) {
			t.Fatalf("VersionedPaths = %v, want %v", got, want)
		}
	})

	t.Run("replace versions", func(t *testing.T) {
		b := newBackend()
		at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		for i := range 3 {
			if err := b.AddVersion(ctx, "/a", at.Add(time.Duration(i)*time.Minute), map[string]string{"K": string(rune('1' + i))}, 10); err != nil {
				t.Fatal(err)
			}
		}
		if err := b.AddVersion(ctx, "/b", at, map[string]string{"X": "1"}, 10); err != nil {
			t.Fatal(err)
		}
		want := []storage.Version{
			{Number: 3, Time: at.Add(2 * time.Minute), Data: map[string]string{"K": "new"}},
			{Number: 1, Time: at, Data: map[string]string{"K": "1"}},
		}
		if err := b.ReplaceVersions(ctx, "/a", want); err != nil {
			t.Fatal(err)
		}
		got, err := b.Versions(ctx, "/a")
		if err != nil || len(got) != 2 {
			t.Fatalf("Versions = %v, %v; want 2", got, err)
		}
		for i := range want {
			if got[i].Number != want[i].Number || !got[i].Time.Equal(want[i].Time) || !maps.Equal(got[i].Data, want[i].Data) {
				t.Fatalf("version %d = %+v, want %+v", i, got[i], want[i])
			}
		}
		if err := b.AddVersion(ctx, "/a", at.Add(time.Hour), map[string]string{"K": "4"}, 10); err != nil {
			t.Fatal(err)
		}
		if got, _ := b.Versions(ctx, "/a"); got[0].Number != 4 {
			t.Fatalf("next version after replace = %d, want 4", got[0].Number)
		}
		if err := b.ReplaceVersions(ctx, "/a", nil); err != nil {
			t.Fatal(err)
		}
		if got, err := b.Versions(ctx, "/a"); err != nil || len(got) != 0 {
			t.Fatalf("Versions after removing all = %v, %v", got, err)
		}
		if paths, _ := b.VersionedPaths(ctx); !slices.Equal(paths, []string{"/b"}) {
			t.Fatalf("VersionedPaths = %v, want [/b]", paths)
		}
	})

	t.Run("tokens", func(t *testing.T) {
		b := newBackend()
		if got, err := b.Tokens(ctx); err != nil || len(got) != 0 {
			t.Fatalf("Tokens on empty backend = %v, %v", got, err)
		}
		want := []storage.Token{
			{Name: "ci", Hash: "aa", Path: "/app", ReadOnly: true, Created: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
			{Name: "dev", Hash: "bb", Path: "/"},
		}
		for range 2 {
			if err := b.PutTokens(ctx, want); err != nil {
				t.Fatal(err)
			}
		}
		got, err := b.Tokens(ctx)
		if err != nil || len(got) != 2 || got[0].Name != "ci" || !got[0].ReadOnly || !got[0].Created.Equal(want[0].Created) || got[1].Hash != "bb" {
			t.Fatalf("Tokens = %+v, %v", got, err)
		}
		if paths, _ := b.List(ctx, "/"); len(paths) != 0 {
			t.Fatalf("tokens listed as paths: %v", paths)
		}
		if err := b.PutTokens(ctx, nil); err != nil {
			t.Fatal(err)
		}
		if got, _ := b.Tokens(ctx); len(got) != 0 {
			t.Fatalf("Tokens after clearing = %v", got)
		}
	})
}

func mustPut(t *testing.T, b storage.Backend, path string, data map[string]string) {
	t.Helper()
	if err := b.Put(context.Background(), path, data); err != nil {
		t.Fatalf("Put(%q): %v", path, err)
	}
}
