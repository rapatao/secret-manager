// Package storage defines the contract implemented by secret storage backends.
package storage

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"
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

	// AddVersion stores data as the next version of path, numbered one above
	// the newest stored version, then deletes all but the newest keep
	// versions by rank, so numbers may have gaps. keep below 1 is an error and
	// nothing is written.
	AddVersion(ctx context.Context, path string, at time.Time, data map[string]string, keep int) error
	// Versions returns the stored versions of path, newest first. Versions
	// outlive Delete.
	Versions(ctx context.Context, path string) ([]Version, error)
	// VersionedPaths returns, sorted, every path with at least one stored
	// version, deleted paths included.
	VersionedPaths(ctx context.Context) ([]string, error)
	// ReplaceVersions replaces every stored version of path with versions,
	// newest first, keeping their numbers and times. An empty versions
	// removes every version of path.
	ReplaceVersions(ctx context.Context, path string, versions []Version) error

	// Tokens returns every stored access token, or none.
	Tokens(ctx context.Context) ([]Token, error)
	// PutTokens replaces every stored access token.
	PutTokens(ctx context.Context, tokens []Token) error

	// SyncPolicy returns the stored SecretSync policy, or the zero policy
	// when none was stored.
	SyncPolicy(ctx context.Context) (SyncPolicy, error)
	// PutSyncPolicy replaces the stored SecretSync policy.
	PutSyncPolicy(ctx context.Context, policy SyncPolicy) error

	// AuditEvents returns the stored audit events, oldest first, or none.
	AuditEvents(ctx context.Context) ([]AuditEvent, error)
	// PutAuditEvents replaces every stored audit event.
	PutAuditEvents(ctx context.Context, events []AuditEvent) error
}

// AuditEvent is one audit log entry: a change, a login or a failed
// authentication. It holds key names, never values. Token is the integration
// that made the request; Name is the integration an integration operation
// acted on.
type AuditEvent struct {
	Time      time.Time `json:"time"`
	Source    string    `json:"source"`
	Op        string    `json:"op"`
	Remote    string    `json:"remote,omitempty"`
	Client    string    `json:"client,omitempty"`
	Forwarded string    `json:"forwardedFor,omitempty"`
	Token     string    `json:"token,omitempty"`
	Path      string    `json:"path,omitempty"`
	Name      string    `json:"name,omitempty"`
	Error     string    `json:"error,omitempty"`
	Keys      []string  `json:"keys,omitempty"`
}

// Token is an access token limited to the paths under Path. Hash is the hex
// SHA-256 of the token; the token itself is never stored. A zero Expires
// never expires. A nil CacheMaxAge uses the server default for how long
// clients may use cached secrets while the server is unreachable. A token
// with AllowedFrom is only accepted from client addresses in those ranges.
type Token struct {
	Name     string    `json:"name"`
	Hash     string    `json:"hash"`
	Path     string    `json:"path"`
	ReadOnly bool      `json:"readOnly"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires,omitzero"`
	LastUsed time.Time `json:"lastUsed,omitzero"`

	CacheMaxAge *time.Duration `json:"cacheMaxAge,omitempty"`
	AllowedFrom []netip.Prefix `json:"allowedFrom,omitempty"`
}

// SyncPolicy limits what SecretSyncs may read and write. A disabled policy
// restricts nothing. When enabled, only the SecretSync namespaces in Namespaces
// are allowed, each limited by its rule.
type SyncPolicy struct {
	Enabled    bool                `json:"enabled"`
	Namespaces map[string]SyncRule `json:"namespaces,omitempty"`
}

// SyncRule limits the SecretSyncs of one namespace to the secret paths under
// Paths and, besides their own namespace, to the target namespaces listed.
type SyncRule struct {
	Paths            []string `json:"paths"`
	TargetNamespaces []string `json:"targetNamespaces,omitempty"`
}

// Clone returns a copy sharing no memory with p.
func (p SyncPolicy) Clone() SyncPolicy {
	if p.Namespaces == nil {
		return p
	}
	ns := make(map[string]SyncRule, len(p.Namespaces))
	for k, r := range p.Namespaces {
		ns[k] = SyncRule{Paths: slices.Clone(r.Paths), TargetNamespaces: slices.Clone(r.TargetNamespaces)}
	}
	p.Namespaces = ns
	return p
}

// Version is a snapshot of the data stored at a path. Unreadable marks a
// version whose Data could not be decrypted, and is nil. It is never stored.
type Version struct {
	Number     int
	Time       time.Time
	Data       map[string]string
	Unreadable bool `json:"-"`
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
