// Package server exposes secrets.Service through a REST API and a Web UI.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/storage"
	"github.com/rapatao/secret-manager/internal/tokens"
)

// MinTokenLength is the shortest admin token accepted by New.
const MinTokenLength = 32

const maxBodyBytes = 1 << 20

// ponytail: restore decodes the whole backup in memory; stream it if stores
// outgrow this limit.
const maxRestoreBytes = 64 << 20

// BackupFormat is the version of the backup document. Restore rejects other
// formats.
const BackupFormat = 1

// Capabilities lists the API features this server supports, reported by
// GET /api/v1/info. Clients check them before using a feature added after
// the first release. A shipped capability never changes meaning and is never
// removed; changed behavior gets a new name.
var Capabilities = []string{"backup", "history", "paths", "secrets", "tokens"}

// Server serves the API under /api/v1 and the Web UI under /.
type Server struct {
	// Version is reported by GET /api/v1/info.
	Version string

	secrets  *secrets.Service
	tokens   *tokens.Store
	token    []byte
	sessions *sessions
	mux      *http.ServeMux
	log      *slog.Logger
}

// New returns a Server authenticating with the admin token and with the
// scoped tokens in tks.
func New(svc *secrets.Service, tks *tokens.Store, token string) (*Server, error) {
	if len(token) < MinTokenLength {
		return nil, errors.New("admin token must have at least 32 characters")
	}
	s := &Server{
		secrets:  svc,
		tokens:   tks,
		token:    []byte(token),
		sessions: newSessions([]byte(token), 12*time.Hour),
		mux:      http.NewServeMux(),
		log:      slog.Default(),
	}
	s.routes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	s.mux.HandleFunc("GET /readyz", s.readyz)

	s.mux.Handle("GET /api/v1/info", s.bearer(anyToken, s.apiInfo))
	s.mux.Handle("GET /api/v1/paths", s.bearer(anyToken, s.apiListPaths))
	s.mux.Handle("DELETE /api/v1/paths", s.bearer(writePath, s.apiDeletePath))
	s.mux.Handle("GET /api/v1/secrets", s.bearer(readPath, s.apiGet))
	s.mux.Handle("PUT /api/v1/secrets", s.bearer(writePath, s.apiSet))
	s.mux.Handle("DELETE /api/v1/secrets/{key}", s.bearer(writePath, s.apiDeleteKey))
	s.mux.Handle("GET /api/v1/backup", s.bearer(adminOnly, s.apiBackup))
	s.mux.Handle("POST /api/v1/restore", s.bearer(adminOnly, s.apiRestore))
	s.mux.Handle("GET /api/v1/history", s.bearer(readPath, s.apiHistory))
	s.mux.Handle("GET /api/v1/history/{version}", s.bearer(readPath, s.apiVersion))
	s.mux.Handle("POST /api/v1/history/{version}/rollback", s.bearer(writePath, s.apiRollback))
	s.mux.Handle("GET /api/v1/tokens", s.bearer(adminOnly, s.apiListTokens))
	s.mux.Handle("POST /api/v1/tokens", s.bearer(adminOnly, s.apiCreateToken))
	s.mux.Handle("DELETE /api/v1/tokens/{name}", s.bearer(adminOnly, s.apiRevokeToken))

	s.mux.Handle("GET /ui.js", s.ui(s.uiScript))
	s.mux.Handle("GET /login", s.ui(s.uiLoginForm))
	s.mux.Handle("POST /login", s.ui(s.uiLogin))
	s.mux.Handle("POST /logout", s.ui(s.session(s.uiLogout)))
	s.mux.Handle("GET /{$}", s.ui(s.session(s.uiIndex)))
	s.mux.Handle("GET /path", s.ui(s.session(s.uiPath)))
	s.mux.Handle("POST /path", s.ui(s.session(s.uiCreatePath)))
	s.mux.Handle("POST /path/delete", s.ui(s.session(s.uiDeletePath)))
	s.mux.Handle("POST /key", s.ui(s.session(s.uiSetKey)))
	s.mux.Handle("POST /path/rollback", s.ui(s.session(s.uiRollback)))
}

// readyz reports whether the storage backend can be read.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	// ponytail: lists every path; add a Backend.Ping if stores grow to thousands of paths.
	if _, err := s.secrets.ListPaths(ctx); err != nil {
		s.log.Error("readiness check failed", "error", err)
		http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) validToken(got string) bool {
	return subtle.ConstantTimeCompare([]byte(got), s.token) == 1
}

// need is the access a route requires from a scoped token. The admin token
// passes every check.
type need int

const (
	anyToken need = iota
	readPath
	writePath
	adminOnly
)

type tokenKey struct{}

// scopedToken returns the scoped token that authenticated r, if any.
func scopedToken(r *http.Request) (tokens.Token, bool) {
	t, ok := r.Context().Value(tokenKey{}).(tokens.Token)
	return t, ok
}

func (s *Server) bearer(n need, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if ok && s.validToken(got) {
			next(w, r)
			return
		}
		var t tokens.Token
		if ok {
			var err error
			if t, ok, err = s.tokens.Lookup(r.Context(), got); err != nil {
				s.serviceError(w, r, err)
				return
			}
		}
		if !ok {
			s.audit(r, "api", "auth", "", nil, errInvalidToken)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), tokenKey{}, t))
		if err := allowed(t, n, r.URL.Query().Get("path")); err != nil {
			s.audit(r, "api", "auth", r.URL.Query().Get("path"), nil, err)
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		next(w, r)
	})
}

func allowed(t tokens.Token, n need, path string) error {
	switch n {
	case anyToken:
		return nil
	case adminOnly:
		return fmt.Errorf("token %s cannot do this; it needs the admin token", t.Name)
	case writePath:
		if t.ReadOnly {
			return fmt.Errorf("token %s is read-only", t.Name)
		}
	}
	if p, err := secrets.NormalizePath(path); err != nil || !storage.Under(p, t.Path) {
		return fmt.Errorf("token %s is limited to %s", t.Name, t.Path)
	}
	return nil
}

func (s *Server) apiInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"version": s.Version, "capabilities": Capabilities})
}

func (s *Server) apiListPaths(w http.ResponseWriter, r *http.Request) {
	paths, err := s.secrets.ListPaths(r.Context())
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	if t, ok := scopedToken(r); ok {
		paths = slices.DeleteFunc(paths, func(p string) bool { return !storage.Under(p, t.Path) })
	}
	if paths == nil {
		paths = []string{}
	}
	writeJSON(w, http.StatusOK, map[string][]string{"paths": paths})
}

func (s *Server) apiGet(w http.ResponseWriter, r *http.Request) {
	data, err := s.secrets.Get(r.Context(), r.URL.Query().Get("path"), r.URL.Query().Get("recursive") == "true")
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]map[string]string{"data": data})
}

func (s *Server) apiSet(w http.ResponseWriter, r *http.Request) {
	var values map[string]string
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&values); err != nil {
		writeError(w, http.StatusBadRequest, "body must be a JSON object of string values")
		return
	}
	path := r.URL.Query().Get("path")
	err := s.secrets.SetKeys(r.Context(), path, values)
	s.audit(r, "api", "set", path, slices.Sorted(maps.Keys(values)), err)
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiDeleteKey(w http.ResponseWriter, r *http.Request) {
	path, key := r.URL.Query().Get("path"), r.PathValue("key")
	err := s.secrets.DeleteKey(r.Context(), path, key)
	s.audit(r, "api", "delete_key", path, []string{key}, err)
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiDeletePath(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	err := s.secrets.DeletePath(r.Context(), path)
	s.audit(r, "api", "delete_path", path, nil, err)
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type versionJSON struct {
	Version int               `json:"version"`
	Time    time.Time         `json:"time"`
	Keys    []string          `json:"keys,omitempty"`
	Data    map[string]string `json:"data,omitempty"`
}

type backupJSON struct {
	Format  int              `json:"format"`
	Version string           `json:"version,omitempty"`
	Time    time.Time        `json:"time"`
	Paths   []backupPathJSON `json:"paths"`
}

type backupPathJSON struct {
	Path     string            `json:"path"`
	Data     map[string]string `json:"data"`
	Versions []versionJSON     `json:"versions,omitempty"`
}

func (s *Server) apiBackup(w http.ResponseWriter, r *http.Request) {
	out, err := s.backup(r.Context(), r.URL.Query().Get("history") == "true")
	s.audit(r, "api", "backup", "", nil, err)
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) backup(ctx context.Context, withHistory bool) (backupJSON, error) {
	backup, err := s.secrets.Backup(ctx, withHistory)
	if err != nil {
		return backupJSON{}, err
	}
	out := backupJSON{Format: BackupFormat, Version: s.Version, Time: time.Now().UTC(), Paths: []backupPathJSON{}}
	for _, b := range backup {
		p := backupPathJSON{Path: b.Path, Data: b.Data}
		for _, v := range b.Versions {
			p.Versions = append(p.Versions, versionJSON{Version: v.Number, Time: v.Time, Data: v.Data})
		}
		out.Paths = append(out.Paths, p)
	}
	return out, nil
}

func (s *Server) apiRestore(w http.ResponseWriter, r *http.Request) {
	var in backupJSON
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRestoreBytes)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "body must be a backup document")
		return
	}
	if in.Format != BackupFormat {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported backup format %d, want %d", in.Format, BackupFormat))
		return
	}
	backup := make([]secrets.PathBackup, 0, len(in.Paths))
	for _, p := range in.Paths {
		b := secrets.PathBackup{Path: p.Path, Data: p.Data}
		for _, v := range p.Versions {
			b.Versions = append(b.Versions, secrets.Version{Number: v.Version, Time: v.Time, Data: v.Data})
		}
		backup = append(backup, b)
	}
	err := s.secrets.Restore(r.Context(), backup)
	s.audit(r, "api", "restore", "", nil, err)
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"paths": len(backup)})
}

func (s *Server) apiHistory(w http.ResponseWriter, r *http.Request) {
	versions, err := s.secrets.History(r.Context(), r.URL.Query().Get("path"))
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	out := []versionJSON{}
	for _, v := range versions {
		out = append(out, versionJSON{Version: v.Number, Time: v.Time, Keys: slices.Sorted(maps.Keys(v.Data))})
	}
	writeJSON(w, http.StatusOK, map[string][]versionJSON{"versions": out})
}

func (s *Server) apiVersion(w http.ResponseWriter, r *http.Request) {
	n, err := parseVersion(r.PathValue("version"))
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	v, err := s.secrets.Version(r.Context(), r.URL.Query().Get("path"), n)
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, versionJSON{Version: v.Number, Time: v.Time, Data: v.Data})
}

func (s *Server) apiRollback(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	err := s.rollback(r, path, r.PathValue("version"))
	s.audit(r, "api", "rollback", path, nil, err)
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rollback(r *http.Request, path, version string) error {
	n, err := parseVersion(version)
	if err != nil {
		return err
	}
	return s.secrets.Rollback(r.Context(), path, n)
}

func parseVersion(v string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%w: version %q must be a positive integer", secrets.ErrInvalid, v)
	}
	return n, nil
}

type tokenJSON struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	ReadOnly bool      `json:"readOnly"`
	Created  time.Time `json:"created"`
	Token    string    `json:"token,omitempty"`
}

func (s *Server) apiListTokens(w http.ResponseWriter, r *http.Request) {
	list, err := s.tokens.List(r.Context())
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	out := []tokenJSON{}
	for _, t := range list {
		out = append(out, tokenJSON{Name: t.Name, Path: t.Path, ReadOnly: t.ReadOnly, Created: t.Created})
	}
	writeJSON(w, http.StatusOK, map[string][]tokenJSON{"tokens": out})
}

func (s *Server) apiCreateToken(w http.ResponseWriter, r *http.Request) {
	var in tokenJSON
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, `body must be {"name": ..., "path": ..., "readOnly": ...}`)
		return
	}
	t, secret, err := s.tokens.Create(r.Context(), in.Name, in.Path, in.ReadOnly)
	s.audit(r, "api", "create_token", in.Path, nil, err, "name", in.Name)
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, tokenJSON{Name: t.Name, Path: t.Path, ReadOnly: t.ReadOnly, Created: t.Created, Token: secret})
}

func (s *Server) apiRevokeToken(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := s.tokens.Revoke(r.Context(), name)
	s.audit(r, "api", "revoke_token", "", nil, err, "name", name)
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

var errInvalidToken = errors.New("invalid token")

// audit logs a change or an authentication attempt. Key names are logged,
// values never are. X-Forwarded-For is client supplied and only informative.
func (s *Server) audit(r *http.Request, source, op, path string, keys []string, err error, extra ...any) {
	attrs := []any{"source", source, "op", op, "remote", r.RemoteAddr}
	if t, ok := scopedToken(r); ok {
		attrs = append(attrs, "token", t.Name)
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		attrs = append(attrs, "forwarded_for", fwd)
	}
	if path != "" {
		attrs = append(attrs, "path", path)
	}
	if len(keys) > 0 {
		attrs = append(attrs, "keys", keys)
	}
	attrs = append(attrs, extra...)
	if err != nil {
		s.log.Warn("audit", append(attrs, "error", err.Error())...)
		return
	}
	s.log.Info("audit", attrs...)
}

func (s *Server) serviceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, secrets.ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, secrets.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	default:
		s.logFailure(r, err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// logFailure logs an unexpected error with the request it failed.
func (s *Server) logFailure(r *http.Request, err error) {
	s.log.Error("secret operation failed", "method", r.Method, "url", r.URL.Path, "path", r.FormValue("path"), "error", err)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
