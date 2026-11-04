// Package local runs the secret-manager server in-process against a vault: a
// file storage JSON file encrypted with a key derived from a passphrase.
package local

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/server"
	"github.com/rapatao/secret-manager/internal/storage"
	"github.com/rapatao/secret-manager/internal/storage/encrypted"
	"github.com/rapatao/secret-manager/internal/storage/file"
	"github.com/rapatao/secret-manager/internal/tokens"
)

// Scheme prefixes the server URL naming a vault, as in file:///home/me/vault.json.
const Scheme = "file://"

// MinPassphraseLength is the shortest passphrase accepted for a new vault.
const MinPassphraseLength = 8

// HistoryLimit is the number of versions kept per path, current included.
const HistoryLimit = 10

const (
	metaKDF     = "kdf"
	metaSalt    = "kdf.salt"
	metaTime    = "kdf.time"
	metaMemory  = "kdf.memory"
	metaThreads = "kdf.threads"
	metaCheck   = "key.check"
	kdfName     = "argon2id"
)

// ErrWrongPassphrase is returned when a key does not open the vault.
var ErrWrongPassphrase = errors.New("wrong passphrase for the vault")

// Path returns the vault file named by server, and whether server names one.
func Path(server string) (string, bool) {
	return strings.CutPrefix(server, Scheme)
}

// Normalize returns server with an absolute, cleaned vault path when it names
// a vault, and server unchanged otherwise.
func Normalize(server string) string {
	p, ok := Path(server)
	if !ok || p == "" {
		return server
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	return Scheme + p
}

// Exists reports whether a file is present at path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Create makes a new vault at path protected by passphrase and returns its key.
func Create(path, passphrase string) ([]byte, error) {
	if len(passphrase) < MinPassphraseLength {
		return nil, fmt.Errorf("passphrase must have at least %d characters", MinPassphraseLength)
	}
	if Exists(path) {
		return nil, fmt.Errorf("%s already exists", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	unlock, err := lock(path, true)
	if err != nil {
		return nil, err
	}
	defer unlock()
	fb, err := file.New(path)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	p := defaultParams
	key := p.derive(passphrase, salt)
	err = fb.SetMeta(map[string]string{
		metaKDF:     kdfName,
		metaSalt:    base64.StdEncoding.EncodeToString(salt),
		metaTime:    strconv.FormatUint(uint64(p.time), 10),
		metaMemory:  strconv.FormatUint(uint64(p.memory), 10),
		metaThreads: strconv.FormatUint(uint64(p.threads), 10),
		metaCheck:   check(key),
	})
	return key, err
}

// Unlock derives the key of the vault at path from passphrase.
func Unlock(path, passphrase string) ([]byte, error) {
	unlock, err := lock(path, false)
	if err != nil {
		return nil, err
	}
	defer unlock()
	fb, err := openFile(path)
	if err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(fb.Meta(metaSalt))
	if err != nil {
		return nil, fmt.Errorf("%s: invalid %s: %w", path, metaSalt, err)
	}
	var p params
	for name, dst := range map[string]*uint32{metaTime: &p.time, metaMemory: &p.memory} {
		v, err := strconv.ParseUint(fb.Meta(name), 10, 32)
		if err != nil || v == 0 {
			return nil, fmt.Errorf("%s: invalid %s %q", path, name, fb.Meta(name))
		}
		*dst = uint32(v)
	}
	threads, err := strconv.ParseUint(fb.Meta(metaThreads), 10, 8)
	if err != nil || threads == 0 {
		return nil, fmt.Errorf("%s: invalid %s %q", path, metaThreads, fb.Meta(metaThreads))
	}
	p.threads = uint8(threads)
	key := p.derive(passphrase, salt)
	if !hmac.Equal([]byte(check(key)), []byte(fb.Meta(metaCheck))) {
		return nil, ErrWrongPassphrase
	}
	return key, nil
}

// params are the Argon2id cost parameters of a vault; memory is in KiB.
type params struct {
	time    uint32
	memory  uint32
	threads uint8
}

// defaultParams is the second recommended option of RFC 9106.
var defaultParams = params{time: 3, memory: 64 * 1024, threads: 4}

func (p params) derive(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, p.time, p.memory, p.threads, encrypted.KeySize)
}

func check(key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("secret-manager vault key check"))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

func openFile(path string) (*file.Backend, error) {
	if !Exists(path) {
		return nil, fmt.Errorf("vault %s does not exist; run servers login --server %s%s to create it", path, Scheme, path)
	}
	fb, err := file.New(path)
	if err != nil {
		return nil, err
	}
	if fb.Meta(metaKDF) != kdfName {
		return nil, fmt.Errorf("%s is not a secret-manager vault", path)
	}
	return fb, nil
}

// Vault serves the API and Web UI of one vault. Every request takes the vault
// lock and reloads the file, so several processes can share a vault.
type Vault struct {
	*server.Server
	path string
	file *file.Backend
	// Token is an integration token with read-write access to every path.
	Token string
}

// Open opens the vault at path with key.
func Open(ctx context.Context, path string, key []byte) (*Vault, error) {
	unlock, err := lock(path, false)
	if err != nil {
		return nil, err
	}
	defer unlock()
	fb, err := openFile(path)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal([]byte(check(key)), []byte(fb.Meta(metaCheck))) {
		return nil, ErrWrongPassphrase
	}
	enc, err := encrypted.New(&memory{Backend: fb}, key, nil)
	if err != nil {
		return nil, err
	}
	svc := secrets.New(enc, nil)
	svc.KeepVersions = HistoryLimit
	tks := tokens.New(enc)
	srv, err := server.New(svc, tks, rand.Text()+rand.Text())
	if err != nil {
		return nil, err
	}
	srv.SetLogger(slog.New(slog.DiscardHandler))
	srv.CacheMaxAge = 0
	srv.Settings = server.Settings{Storage: "file", Encryption: true}
	_, token, err := tks.Create(ctx, "local", "/", false, time.Time{}, nil, nil)
	if err != nil {
		return nil, err
	}
	return &Vault{Server: srv, path: path, file: fb, Token: token}, nil
}

// ServeHTTP serves r holding the vault lock, shared for reads.
func (v *Vault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	unlock, err := lock(v.path, r.Method != http.MethodGet && r.Method != http.MethodHead)
	if err == nil {
		defer unlock()
		err = v.file.Reload()
	}
	if err != nil {
		http.Error(w, "open vault: "+err.Error(), http.StatusInternalServerError)
		return
	}
	v.Server.ServeHTTP(w, r)
}

// RoundTrip implements http.RoundTripper by serving req in-process. req is
// addressed to the vault URL, so its path starts with the vault path.
func (v *Vault) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.URL = &url.URL{Path: strings.TrimPrefix(req.URL.Path, v.path), RawQuery: req.URL.RawQuery}
	r.RemoteAddr = "127.0.0.1:0"
	r.RequestURI = r.URL.RequestURI()
	rec := httptest.NewRecorder()
	v.ServeHTTP(rec, r)
	return rec.Result(), nil
}

// memory keeps integration tokens and audit events in memory, so the vault
// file holds only secrets and their versions.
type memory struct {
	storage.Backend
	tokens []storage.Token
	audit  []storage.AuditEvent
}

func (m *memory) Tokens(context.Context) ([]storage.Token, error) { return m.tokens, nil }

func (m *memory) PutTokens(_ context.Context, t []storage.Token) error {
	m.tokens = t
	return nil
}

func (m *memory) AuditEvents(context.Context) ([]storage.AuditEvent, error) { return m.audit, nil }

func (m *memory) PutAuditEvents(_ context.Context, e []storage.AuditEvent) error {
	m.audit = e
	return nil
}
