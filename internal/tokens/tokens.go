// Package tokens manages access tokens limited to a path prefix.
package tokens

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/storage"
)

// Prefix starts every token, so a scoped token is easy to tell from the admin
// token and to find in leaked text.
const Prefix = "smt_"

var nameRe = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

// ErrExpired is returned by Lookup for a token past its expiry.
var ErrExpired = errors.New("token expired")

// Token describes an access token. The token itself is only returned by
// Create.
type Token = storage.Token

// Store is safe for concurrent use. It loads the tokens from the backend
// once and keeps them in memory, so the server must run as a single replica.
// Lookup records the last use in memory only; Flush persists it.
type Store struct {
	backend storage.Backend

	mu     sync.Mutex
	loaded bool
	tokens []Token
	dirty  bool
}

// New returns a Store persisting tokens in backend.
func New(backend storage.Backend) *Store {
	return &Store{backend: backend}
}

func (s *Store) load(ctx context.Context) error {
	if s.loaded {
		return nil
	}
	tokens, err := s.backend.Tokens(ctx)
	if err != nil {
		return err
	}
	s.tokens, s.loaded = tokens, true
	return nil
}

func hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// List returns every token, sorted by name.
func (s *Store) List(ctx context.Context) ([]Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	out := slices.Clone(s.tokens)
	slices.SortFunc(out, func(a, b Token) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Create stores a new token named name for the paths under path, expiring at
// expires unless it is zero, and returns it with its secret value, which is
// not stored.
func (s *Store) Create(ctx context.Context, name, path string, readOnly bool, expires time.Time) (Token, string, error) {
	if !nameRe.MatchString(name) {
		return Token{}, "", fmt.Errorf("%w: token name %q must match [a-z0-9-]{1,63}", secrets.ErrInvalid, name)
	}
	path, err := secrets.NormalizePath(path)
	if err != nil {
		return Token{}, "", err
	}
	now := time.Now().UTC().Truncate(time.Second)
	if !expires.IsZero() && !expires.After(now) {
		return Token{}, "", fmt.Errorf("%w: expiry must be in the future", secrets.ErrInvalid)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(ctx); err != nil {
		return Token{}, "", err
	}
	if slices.ContainsFunc(s.tokens, func(t Token) bool { return t.Name == name }) {
		return Token{}, "", fmt.Errorf("%w: token %s already exists", secrets.ErrInvalid, name)
	}
	secret := Prefix + rand.Text()
	t := Token{Name: name, Hash: hash(secret), Path: path, ReadOnly: readOnly, Created: now}
	if !expires.IsZero() {
		t.Expires = expires.UTC().Truncate(time.Second)
	}
	tokens := append(slices.Clone(s.tokens), t)
	if err := s.backend.PutTokens(ctx, tokens); err != nil {
		return Token{}, "", err
	}
	s.tokens, s.dirty = tokens, false
	return t, secret, nil
}

// Update changes the path, access and expiry of the token named name. Its
// secret value stays the same. expires must be in the future, zero or the
// current expiry.
func (s *Store) Update(ctx context.Context, name, path string, readOnly bool, expires time.Time) (Token, error) {
	path, err := secrets.NormalizePath(path)
	if err != nil {
		return Token{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(ctx); err != nil {
		return Token{}, err
	}
	i := slices.IndexFunc(s.tokens, func(t Token) bool { return t.Name == name })
	if i < 0 {
		return Token{}, fmt.Errorf("%w: token %s", secrets.ErrNotFound, name)
	}
	if !expires.IsZero() {
		expires = expires.UTC().Truncate(time.Second)
		if !expires.Equal(s.tokens[i].Expires) && !expires.After(time.Now()) {
			return Token{}, fmt.Errorf("%w: expiry must be in the future", secrets.ErrInvalid)
		}
	}
	tokens := slices.Clone(s.tokens)
	tokens[i].Path, tokens[i].ReadOnly, tokens[i].Expires = path, readOnly, expires
	if err := s.backend.PutTokens(ctx, tokens); err != nil {
		return Token{}, err
	}
	s.tokens, s.dirty = tokens, false
	return tokens[i], nil
}

// Revoke deletes the token named name.
func (s *Store) Revoke(ctx context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(ctx); err != nil {
		return err
	}
	tokens := slices.DeleteFunc(slices.Clone(s.tokens), func(t Token) bool { return t.Name == name })
	if len(tokens) == len(s.tokens) {
		return fmt.Errorf("%w: token %s", secrets.ErrNotFound, name)
	}
	if err := s.backend.PutTokens(ctx, tokens); err != nil {
		return err
	}
	s.tokens, s.dirty = tokens, false
	return nil
}

// Lookup returns the token whose secret value is secret and records its use.
// An expired token is returned with ErrExpired.
func (s *Store) Lookup(ctx context.Context, secret string) (Token, bool, error) {
	if !strings.HasPrefix(secret, Prefix) {
		return Token{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(ctx); err != nil {
		return Token{}, false, err
	}
	h := hash(secret)
	now := time.Now().UTC().Truncate(time.Second)
	for i, t := range s.tokens {
		if t.Hash != h {
			continue
		}
		if !t.Expires.IsZero() && !now.Before(t.Expires) {
			return t, false, fmt.Errorf("%w: %s", ErrExpired, t.Name)
		}
		if !t.LastUsed.Equal(now) {
			s.tokens[i].LastUsed, s.dirty = now, true
		}
		return s.tokens[i], true, nil
	}
	return Token{}, false, nil
}

// Flush persists the last use of every token when it changed since the
// last write.
func (s *Store) Flush(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	if err := s.backend.PutTokens(ctx, s.tokens); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

// RunFlush calls Flush every interval until ctx is done, then once more.
// Failures are logged and retried on the next run.
func (s *Store) RunFlush(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.Flush(flushCtx); err != nil {
				slog.Warn("persist token last use", "error", err)
			}
			return
		case <-t.C:
			if err := s.Flush(ctx); err != nil {
				slog.Warn("persist token last use", "error", err)
			}
		}
	}
}
