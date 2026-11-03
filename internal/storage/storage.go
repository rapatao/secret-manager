// Package storage defines the contract implemented by secret storage backends.
package storage

import (
	"context"
	"errors"
	"strings"
)

// ErrNotFound is returned by Backend.Get when the path does not exist.
var ErrNotFound = errors.New("path not found")

// Backend persists key-value data addressed by path. Paths are already
// validated by the caller and always start with "/".
type Backend interface {
	// Get returns the data stored at path or ErrNotFound.
	Get(ctx context.Context, path string) (map[string]string, error)
	// Put replaces all data stored at path, creating it when missing.
	Put(ctx context.Context, path string, data map[string]string) error
	// Delete removes path. Deleting a missing path is not an error.
	Delete(ctx context.Context, path string) error
	// List returns, sorted, every stored path equal to prefix or below it.
	List(ctx context.Context, prefix string) ([]string, error)
}

// Under reports whether path equals prefix or is nested below it.
func Under(path, prefix string) bool {
	if path == "" {
		return false
	}
	if prefix == "/" || path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}
