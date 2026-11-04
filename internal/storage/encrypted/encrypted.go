// Package encrypted wraps a storage.Backend and encrypts every stored value
// with AES-256-GCM, and encrypts backup documents.
package encrypted

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
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
	// previous decrypts values written before the key was changed.
	previous cipher.AEAD
}

var _ storage.Backend = (*Backend)(nil)

// New wraps inner. With a nil key values are written as plaintext and reading
// an encrypted value fails with ErrNoKey. A non-nil previous key, which needs
// a key, also decrypts values; Migrate rewrites them with key.
func New(inner storage.Backend, key, previous []byte) (*Backend, error) {
	b := &Backend{inner: inner}
	if key == nil {
		if previous != nil {
			return nil, errors.New("a previous encryption key needs an encryption key")
		}
		return b, nil
	}
	var err error
	if b.aead, err = newAEAD(key); err != nil {
		return nil, err
	}
	if previous != nil {
		if b.previous, err = newAEAD(previous); err != nil {
			return nil, fmt.Errorf("previous %w", err)
		}
	}
	return b, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("encryption key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
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

func seal(aead cipher.AEAD, plain, additional []byte) []byte {
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	return aead.Seal(nonce, nonce, plain, additional)
}

func unseal(aead cipher.AEAD, raw, additional []byte) ([]byte, error) {
	n := aead.NonceSize()
	if len(raw) < n {
		return nil, errors.New("ciphertext too short")
	}
	return aead.Open(nil, raw[:n], raw[n:], additional)
}

func (b *Backend) seal(path string, data map[string]string) map[string]string {
	if b.aead == nil || data == nil {
		return data
	}
	out := make(map[string]string, len(data))
	for k, v := range data {
		out[k] = prefix + base64.RawStdEncoding.EncodeToString(seal(b.aead, []byte(v), aad(path, k)))
	}
	return out
}

// open decrypts data. stale reports a value that is plaintext while a key is
// set, or that was decrypted with the previous key.
func (b *Backend) open(path string, data map[string]string) (out map[string]string, stale bool, err error) {
	out = make(map[string]string, len(data))
	for k, v := range data {
		enc, ok := strings.CutPrefix(v, prefix)
		if !ok {
			out[k] = v
			stale = stale || b.aead != nil
			continue
		}
		if b.aead == nil {
			return nil, false, fmt.Errorf("%s key %s: %w", path, k, ErrNoKey)
		}
		raw, err := base64.RawStdEncoding.DecodeString(enc)
		if err != nil || len(raw) < b.aead.NonceSize() {
			return nil, false, fmt.Errorf("%s key %s: malformed encrypted value", path, k)
		}
		plain, err := unseal(b.aead, raw, aad(path, k))
		if err != nil && b.previous != nil {
			if plain, err = unseal(b.previous, raw, aad(path, k)); err == nil {
				stale = true
			}
		}
		if err != nil {
			return nil, false, fmt.Errorf("%s key %s: decrypt failed, wrong encryption key?", path, k)
		}
		out[k] = string(plain)
	}
	return out, stale, nil
}

// Migrate rewrites, with the current key, every stored path and version
// holding a plaintext value or a value encrypted with the previous key. It
// returns the rewritten paths and versions, and those it skipped because a
// value cannot be decrypted with either key. It does nothing without a key.
func (b *Backend) Migrate(ctx context.Context) (rewritten, unreadable []string, err error) {
	if b.aead == nil {
		return nil, nil, nil
	}
	paths, err := b.inner.List(ctx, "/")
	if err != nil {
		return nil, nil, err
	}
	for _, p := range paths {
		raw, err := b.inner.Get(ctx, p)
		if errors.Is(err, storage.ErrNotFound) {
			continue
		}
		if err != nil {
			return rewritten, unreadable, err
		}
		data, stale, err := b.open(p, raw)
		if err != nil {
			unreadable = append(unreadable, p)
			continue
		}
		if !stale {
			continue
		}
		if err := b.Put(ctx, p, data); err != nil {
			return rewritten, unreadable, err
		}
		rewritten = append(rewritten, p)
	}

	versioned, err := b.inner.VersionedPaths(ctx)
	if err != nil {
		return rewritten, unreadable, err
	}
	for _, p := range versioned {
		versions, err := b.inner.Versions(ctx, p)
		if err != nil {
			return rewritten, unreadable, err
		}
		var changed []string
		for i, v := range versions {
			name := p + " version " + strconv.Itoa(v.Number)
			data, stale, err := b.open(p, v.Data)
			if err != nil {
				unreadable = append(unreadable, name)
				continue
			}
			if stale {
				versions[i].Data = b.seal(p, data)
				changed = append(changed, name)
			}
		}
		if len(changed) == 0 {
			continue
		}
		if err := b.inner.ReplaceVersions(ctx, p, versions); err != nil {
			return rewritten, unreadable, err
		}
		rewritten = append(rewritten, changed...)
	}
	return rewritten, unreadable, nil
}

// Get implements storage.Backend.
func (b *Backend) Get(ctx context.Context, path string) (map[string]string, error) {
	data, err := b.inner.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	data, _, err = b.open(path, data)
	return data, err
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
		if versions[i].Data, _, err = b.open(path, v.Data); err != nil {
			return nil, fmt.Errorf("version %d: %w", v.Number, err)
		}
	}
	return versions, nil
}

// ReplaceVersions implements storage.Backend.
func (b *Backend) ReplaceVersions(ctx context.Context, path string, versions []storage.Version) error {
	sealed := make([]storage.Version, len(versions))
	for i, v := range versions {
		v.Data = b.seal(path, v.Data)
		sealed[i] = v
	}
	return b.inner.ReplaceVersions(ctx, path, sealed)
}

// VersionedPaths implements storage.Backend.
func (b *Backend) VersionedPaths(ctx context.Context) ([]string, error) {
	return b.inner.VersionedPaths(ctx)
}

// Tokens implements storage.Backend. Tokens are stored as hashes, so they are
// not encrypted.
func (b *Backend) Tokens(ctx context.Context) ([]storage.Token, error) {
	return b.inner.Tokens(ctx)
}

// PutTokens implements storage.Backend.
func (b *Backend) PutTokens(ctx context.Context, tokens []storage.Token) error {
	return b.inner.PutTokens(ctx, tokens)
}

// AuditEvents implements storage.Backend. Audit events hold no values, so
// they are not encrypted.
func (b *Backend) AuditEvents(ctx context.Context) ([]storage.AuditEvent, error) {
	return b.inner.AuditEvents(ctx)
}

// PutAuditEvents implements storage.Backend.
func (b *Backend) PutAuditEvents(ctx context.Context, events []storage.AuditEvent) error {
	return b.inner.PutAuditEvents(ctx, events)
}
