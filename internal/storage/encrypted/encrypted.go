// Package encrypted wraps a storage.Backend and encrypts every stored value
// with AES-256-GCM.
package encrypted

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rapatao/secret-manager/internal/storage"
)

// prefix marks an encrypted value. Values without it are plaintext written
// before encryption was enabled.
const prefix = "enc:v1:"

// KeySize is the length of the key in bytes.
const KeySize = 32

// ErrNoKey is returned when an encrypted value is read without a key.
var ErrNoKey = errors.New("stored value is encrypted but no encryption key is set")

// Backend encrypts values on write and decrypts them on read. Paths, key names
// and version metadata stay readable. Each value is bound to its path and key,
// so a ciphertext copied to another key fails to decrypt.
type Backend struct {
	inner storage.Backend
	aead  cipher.AEAD
}

var _ storage.Backend = (*Backend)(nil)

// New wraps inner. With a nil key values are written as plaintext and reading
// an encrypted value fails with ErrNoKey.
func New(inner storage.Backend, key []byte) (*Backend, error) {
	b := &Backend{inner: inner}
	if key == nil {
		return b, nil
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("encryption key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if b.aead, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}
	return b, nil
}

// ParseKey decodes a base64 key, as printed by `openssl rand -base64 32`.
func ParseKey(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("encryption key is not base64: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("encryption key must decode to %d bytes, got %d", KeySize, len(key))
	}
	return key, nil
}

func aad(path, key string) []byte {
	return []byte(path + "\x00" + key)
}

func (b *Backend) seal(path string, data map[string]string) map[string]string {
	if b.aead == nil || data == nil {
		return data
	}
	out := make(map[string]string, len(data))
	for k, v := range data {
		nonce := make([]byte, b.aead.NonceSize())
		_, _ = rand.Read(nonce)
		out[k] = prefix + base64.RawStdEncoding.EncodeToString(b.aead.Seal(nonce, nonce, []byte(v), aad(path, k)))
	}
	return out
}

func (b *Backend) open(path string, data map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(data))
	for k, v := range data {
		enc, ok := strings.CutPrefix(v, prefix)
		if !ok {
			out[k] = v
			continue
		}
		if b.aead == nil {
			return nil, fmt.Errorf("%s key %s: %w", path, k, ErrNoKey)
		}
		raw, err := base64.RawStdEncoding.DecodeString(enc)
		if err != nil || len(raw) < b.aead.NonceSize() {
			return nil, fmt.Errorf("%s key %s: malformed encrypted value", path, k)
		}
		n := b.aead.NonceSize()
		plain, err := b.aead.Open(nil, raw[:n], raw[n:], aad(path, k))
		if err != nil {
			return nil, fmt.Errorf("%s key %s: decrypt failed, wrong encryption key?", path, k)
		}
		out[k] = string(plain)
	}
	return out, nil
}

func plaintext(data map[string]string) bool {
	for _, v := range data {
		if !strings.HasPrefix(v, prefix) {
			return true
		}
	}
	return false
}

// EncryptPlaintext rewrites every stored path holding a plaintext value
// with its values encrypted, and returns the rewritten paths. Versions are
// not rewritten. It does nothing without a key.
func (b *Backend) EncryptPlaintext(ctx context.Context) ([]string, error) {
	if b.aead == nil {
		return nil, nil
	}
	paths, err := b.inner.List(ctx, "/")
	if err != nil {
		return nil, err
	}
	var done []string
	for _, p := range paths {
		raw, err := b.inner.Get(ctx, p)
		if errors.Is(err, storage.ErrNotFound) {
			continue
		}
		if err != nil {
			return done, err
		}
		if !plaintext(raw) {
			continue
		}
		data, err := b.open(p, raw)
		if err != nil {
			return done, err
		}
		if err := b.Put(ctx, p, data); err != nil {
			return done, err
		}
		done = append(done, p)
	}
	return done, nil
}

// Get implements storage.Backend.
func (b *Backend) Get(ctx context.Context, path string) (map[string]string, error) {
	data, err := b.inner.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	return b.open(path, data)
}

// Put implements storage.Backend.
func (b *Backend) Put(ctx context.Context, path string, data map[string]string) error {
	return b.inner.Put(ctx, path, b.seal(path, data))
}

// Delete implements storage.Backend.
func (b *Backend) Delete(ctx context.Context, path string) error {
	return b.inner.Delete(ctx, path)
}

// List implements storage.Backend.
func (b *Backend) List(ctx context.Context, prefix string) ([]string, error) {
	return b.inner.List(ctx, prefix)
}

// AddVersion implements storage.Backend.
func (b *Backend) AddVersion(ctx context.Context, path string, at time.Time, data map[string]string, keep int) error {
	return b.inner.AddVersion(ctx, path, at, b.seal(path, data), keep)
}

// Versions implements storage.Backend.
func (b *Backend) Versions(ctx context.Context, path string) ([]storage.Version, error) {
	versions, err := b.inner.Versions(ctx, path)
	if err != nil {
		return nil, err
	}
	for i, v := range versions {
		if versions[i].Data, err = b.open(path, v.Data); err != nil {
			return nil, fmt.Errorf("version %d: %w", v.Number, err)
		}
	}
	return versions, nil
}

// VersionedPaths implements storage.Backend.
func (b *Backend) VersionedPaths(ctx context.Context) ([]string, error) {
	return b.inner.VersionedPaths(ctx)
}
