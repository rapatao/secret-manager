// Package tokens manages access tokens limited to a path prefix.
package tokens

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

// Token describes an access token. The token itself is only returned by
// Create.
type Token = storage.Token

// Store is safe for concurrent use. It loads the tokens from the backend
// once and keeps them in memory, so the server must run as a single replica.
type Store struct {
	backend storage.Backend

	mu     sync.Mutex
	loaded bool
	tokens []Token
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

// Create stores a new token named name for the paths under path and returns
// it with its secret value, which is not stored.
func (s *Store) Create(ctx context.Context, name, path string, readOnly bool) (Token, string, error) {
	if !nameRe.MatchString(name) {
		return Token{}, "", fmt.Errorf("%w: token name %q must match [a-z0-9-]{1,63}", secrets.ErrInvalid, name)
	}
	path, err := secrets.NormalizePath(path)
	if err != nil {
		return Token{}, "", err
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
	t := Token{Name: name, Hash: hash(secret), Path: path, ReadOnly: readOnly, Created: time.Now().UTC().Truncate(time.Second)}
	tokens := append(slices.Clone(s.tokens), t)
	if err := s.backend.PutTokens(ctx, tokens); err != nil {
		return Token{}, "", err
	}
	s.tokens = tokens
	return t, secret, nil
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
	s.tokens = tokens
	return nil
}

// Lookup returns the token whose secret value is secret.
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
	for _, t := range s.tokens {
		if t.Hash == h {
			return t, true, nil
		}
	}
	return Token{}, false, nil
}
