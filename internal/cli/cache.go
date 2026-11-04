package cli

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/rapatao/secret-manager/internal/client"
)

// EnvCacheMaxAge is how long cached secrets may be used while the server is
// unreachable, as a Go duration. 0 disables the cache. It only lowers the max
// age the server allows.
const EnvCacheMaxAge = "SECRET_MANAGER_CACHE_MAX_AGE"

const (
	defaultCacheMaxAge = 7 * 24 * time.Hour
	cacheKeyAccount    = "offline-cache-key"
)

// cache keeps the last secrets read from each server, path and recursive
// flag, encrypted with AES-256-GCM. The key lives only in the OS keychain;
// without a usable keychain nothing is cached.
type cache struct {
	dir    string
	maxAge time.Duration
}

type cacheEntry struct {
	Time time.Time         `json:"time"`
	Data map[string]string `json:"data"`
	// MaxAge is the max age in force when the entry was saved. Entries saved
	// before servers sent one have none.
	MaxAge time.Duration `json:"maxAge,omitzero"`
	// Partial marks an entry holding only the keys read one by one, which
	// does not stand in for the whole path.
	Partial bool `json:"partial,omitzero"`
}

func (c *CLI) cache() (cache, error) {
	maxAge := defaultCacheMaxAge
	if v := c.Getenv(EnvCacheMaxAge); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			return cache{}, fmt.Errorf("%w: %s=%q must be a duration like 24h, or 0", errUsage, EnvCacheMaxAge, v)
		}
		maxAge = d
	}
	if c.ConfigDir == "" {
		maxAge = 0
	}
	return cache{dir: filepath.Join(c.ConfigDir, "cache"), maxAge: maxAge}, nil
}

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (ch cache) serverDir(server string) string {
	return filepath.Join(ch.dir, hashHex(server))
}

// entry returns the file of an entry and the additional data bound to its
// ciphertext, so a file copied to another entry fails to decrypt.
func (ch cache) entry(server, path string, recursive bool) (file, id string) {
	id = fmt.Sprintf("%s\n%s\n%t", server, path, recursive)
	return filepath.Join(ch.serverDir(server), hashHex(id)), id
}

func cacheAEAD(create bool) (cipher.AEAD, error) {
	encoded, err := keyring.Get(keyringService, cacheKeyAccount)
	if errors.Is(err, keyring.ErrNotFound) && create {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		encoded = base64.StdEncoding.EncodeToString(key)
		err = keyring.Set(keyringService, cacheKeyAccount, encoded)
	}
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// save stores e for up to serverMaxAge, or the client max age when it is
// lower or the server sent none. A max age of 0 removes the entry. A missing
// keychain is not an error: nothing is cached.
func (ch cache) save(server, path string, recursive bool, e cacheEntry, serverMaxAge *time.Duration) error {
	if ch.maxAge == 0 {
		return nil
	}
	maxAge := ch.maxAge
	if serverMaxAge != nil {
		maxAge = min(maxAge, *serverMaxAge)
	}
	file, id := ch.entry(server, path, recursive)
	if maxAge <= 0 {
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	aead, err := cacheAEAD(true)
	if err != nil {
		return nil //nolint:nilerr // no usable keychain disables the cache
	}
	e.MaxAge = maxAge
	plain, err := json.Marshal(e)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	return writeAtomic(filepath.Dir(file), filepath.Base(file), aead.Seal(nonce, nonce, plain, []byte(id)))
}

// load returns the entry when it exists and is not older than its own max
// age and the client max age. Expired entries are removed.
func (ch cache) load(server, path string, recursive bool) (cacheEntry, bool) {
	if ch.maxAge == 0 {
		return cacheEntry{}, false
	}
	file, id := ch.entry(server, path, recursive)
	sealed, err := os.ReadFile(file)
	if err != nil {
		return cacheEntry{}, false
	}
	aead, err := cacheAEAD(false)
	if err != nil || len(sealed) < aead.NonceSize() {
		return cacheEntry{}, false
	}
	n := aead.NonceSize()
	plain, err := aead.Open(nil, sealed[:n], sealed[n:], []byte(id))
	var e cacheEntry
	if err != nil || json.Unmarshal(plain, &e) != nil {
		return cacheEntry{}, false
	}
	maxAge := ch.maxAge
	if e.MaxAge > 0 {
		maxAge = min(maxAge, e.MaxAge)
	}
	if time.Since(e.Time) > maxAge {
		_ = os.Remove(file)
		return cacheEntry{}, false
	}
	return e, true
}

// clear removes every entry of server.
func (ch cache) clear(server string) error {
	return os.RemoveAll(ch.serverDir(server))
}

// unreachable reports whether err means the server could not answer, as
// opposed to answering with an error such as 401 or 404.
func unreachable(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var apiErr *client.Error
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		}
		return false
	}
	return true
}

// getSecrets reads the secrets of f.path, or only key when it is not empty,
// from the server and caches them. A key is merged into the cached path,
// which keeps its read time so older values expire on schedule. When the
// server is unreachable it falls back to the cache with a warning.
func (c *CLI) getSecrets(ctx context.Context, f *flags, api *client.Client, key string) (map[string]string, error) {
	ch, err := c.cache()
	if err != nil {
		return nil, err
	}
	data, serverMaxAge, err := api.Read(ctx, f.path, key, f.recursive)
	if err == nil {
		entry := cacheEntry{Time: time.Now(), Data: data, Partial: key != ""}
		if key != "" {
			if e, ok := ch.load(f.server, f.path, f.recursive); ok && e.Data != nil {
				e.Data[key] = data[key]
				entry = e
			}
		}
		if err := ch.save(f.server, f.path, f.recursive, entry, serverMaxAge); err != nil {
			fmt.Fprintln(c.Stderr, "warning: offline cache not updated:", err)
		}
		return data, nil
	}
	if !unreachable(ctx, err) {
		return nil, err
	}
	e, ok := ch.load(f.server, f.path, f.recursive)
	if _, has := e.Data[key]; !ok || (key == "" && e.Partial) || (key != "" && !has) {
		return nil, err
	}
	fmt.Fprintf(c.Stderr, "warning: %s unreachable (%v); using secrets cached at %s\n",
		f.server, err, e.Time.Format(time.RFC3339))
	return e.Data, nil
}
