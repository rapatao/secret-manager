// Package storagetest provides a conformance suite for storage.Backend
// implementations.
package storagetest

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"

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
}

func mustPut(t *testing.T, b storage.Backend, path string, data map[string]string) {
	t.Helper()
	if err := b.Put(context.Background(), path, data); err != nil {
		t.Fatalf("Put(%q): %v", path, err)
	}
}
