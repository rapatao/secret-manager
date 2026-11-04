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
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
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
var Capabilities = []string{"backup", "history", "history-delete", "integrations", "paths", "paths-copy", "secrets"}

// DefaultCacheMaxAge is the CacheMaxAge of a new Server.
const DefaultCacheMaxAge = 7 * 24 * time.Hour

// Settings describe how the server runs.
type Settings struct {
	Storage    string
	Encryption bool
	Controller bool
	Backups    BackupSchedule
}

// Server serves the API under /api/v1 and the Web UI under /.
type Server struct {
	// Version is reported by GET /api/v1/info.
	Version string
	// CacheMaxAge is how long clients may use the secrets they read while the
	// server is unreachable, unless the integration sets its own. 0 disables
	// their cache.
	CacheMaxAge time.Duration
	// Settings are shown on the Web UI summary.
	Settings Settings
	// TrustedProxies are the addresses whose X-Forwarded-For header names
	// the client, see clientAddr.
	TrustedProxies []netip.Prefix

	secrets    *secrets.Service
	tokens     *tokens.Store
	token      []byte
	sessions   *sessions
	grants     *grants
	auditLog   auditLog
	auditStore AuditStore
	logins     *loginLimiter
	// lastBackup is the latest scheduled backup run.
	lastBackup atomic.Pointer[backupRun]
	mux        *http.ServeMux
	log        *slog.Logger
}

// New returns a Server whose Web UI signs in with the admin token and whose
// API authenticates with the integration tokens in tks.
func New(svc *secrets.Service, tks *tokens.Store, token string) (*Server, error) {
	if len(token) < MinTokenLength {
		return nil, errors.New("admin token must have at least 32 characters")
	}
	s := &Server{
		CacheMaxAge: DefaultCacheMaxAge,
		secrets:     svc,
		tokens:      tks,
		token:       []byte(token),
		sessions:    newSessions([]byte(token), 12*time.Hour),
		grants:      newGrants(5 * time.Minute),
		logins:      newLoginLimiter(),
		mux:         http.NewServeMux(),
		log:         slog.Default(),
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
	s.mux.Handle("POST /api/v1/paths/copy", s.bearer(readPath, s.apiCopyPath(false)))
	s.mux.Handle("POST /api/v1/paths/move", s.bearer(writePath, s.apiCopyPath(true)))
	s.mux.Handle("GET /api/v1/secrets", s.bearer(readPath, s.apiGet))
	s.mux.Handle("PUT /api/v1/secrets", s.bearer(writePath, s.apiSet))
	s.mux.Handle("DELETE /api/v1/secrets/{key}", s.bearer(writePath, s.apiDeleteKey))
	s.mux.Handle("GET /api/v1/backup", s.bearer(readAll, s.apiBackup))
	s.mux.Handle("POST /api/v1/restore", s.bearer(writeAll, s.apiRestore))
	s.mux.Handle("GET /api/v1/history", s.bearer(readPath, s.apiHistory))
	s.mux.Handle("GET /api/v1/history/{version}", s.bearer(readPath, s.apiVersion))
	s.mux.Handle("DELETE /api/v1/history/{version}", s.bearer(writePath, s.apiDeleteVersion))
	s.mux.Handle("POST /api/v1/history/{version}/rollback", s.bearer(writePath, s.apiRollback))
	s.mux.HandleFunc("POST /api/v1/authorize/device", s.apiAuthorizeDevice)
	s.mux.HandleFunc("POST /api/v1/authorize/token", s.apiAuthorizeToken)

	s.mux.Handle("GET /ui.js", s.ui(s.uiScript))
	s.mux.Handle("GET /login", s.ui(s.uiLoginForm))
	s.mux.Handle("POST /login", s.ui(s.uiLogin))
	s.mux.Handle("POST /logout", s.ui(s.session(s.uiLogout)))
	s.mux.Handle("GET /{$}", s.ui(s.session(s.uiSummary)))
	s.mux.Handle("GET /secrets", s.ui(s.session(s.uiSecrets)))
	s.mux.Handle("POST /secrets", s.ui(s.session(s.uiCreatePath)))
	s.mux.Handle("GET /secrets/path", s.ui(s.session(s.uiPath)))
	s.mux.Handle("POST /secrets/keys", s.ui(s.session(s.uiSetKey)))
	s.mux.Handle("POST /secrets/delete", s.ui(s.session(s.uiDeletePath)))
	s.mux.Handle("POST /secrets/copy", s.ui(s.session(s.uiCopyPath)))
	s.mux.Handle("POST /secrets/rollback", s.ui(s.session(s.uiRollback)))
	s.mux.Handle("POST /secrets/versions/delete", s.ui(s.session(s.uiDeleteVersion)))
	s.mux.Handle("GET /audit", s.ui(s.session(s.uiAudit)))
	s.mux.Handle("GET /integrations", s.ui(s.session(s.uiIntegrations)))
	s.mux.Handle("POST /integrations", s.ui(s.session(s.uiCreateIntegration)))
	s.mux.Handle("POST /integrations/update", s.ui(s.session(s.uiUpdateIntegration)))
	s.mux.Handle("POST /integrations/revoke", s.ui(s.session(s.uiRevokeIntegration)))
	s.mux.Handle("GET /authorize", s.ui(s.session(s.uiAuthorizeForm)))
	s.mux.Handle("POST /authorize", s.ui(s.session(s.uiAuthorize)))
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

// need is the access a route requires from a token.
type need int

const (
	anyToken need = iota
	readPath
	writePath
	// readAll and writeAll need a token for the path /.
	readAll
	writeAll
)

type tokenKey struct{}

// scopedToken returns the token that authenticated r, if any.
func scopedToken(r *http.Request) (tokens.Token, bool) {
	t, ok := r.Context().Value(tokenKey{}).(tokens.Token)
	return t, ok
}

func (s *Server) bearer(n need, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		var t tokens.Token
		if ok {
			var err error
			t, ok, err = s.tokens.Lookup(r.Context(), got)
			if errors.Is(err, tokens.ErrExpired) {
				s.audit(r, "api", "auth", "", nil, err)
				writeError(w, http.StatusUnauthorized, err.Error())
				return
			}
			if err != nil {
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
	if n == anyToken {
		return nil
	}
	if (n == writePath || n == writeAll) && t.ReadOnly {
		return fmt.Errorf("token %s is read-only", t.Name)
	}
	if t.Path == "/" {
		return nil
	}
	if n == readAll || n == writeAll {
		path = "/"
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
	maxAge := s.CacheMaxAge
	if t, _ := scopedToken(r); t.CacheMaxAge != nil {
		maxAge = *t.CacheMaxAge
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data, "cacheMaxAge": int(maxAge.Seconds())})
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

// apiCopyPath copies, or with move moves, the path in ?path= to ?to=. The
// token must be allowed to write to.
func (s *Server) apiCopyPath(move bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path, to := r.URL.Query().Get("path"), r.URL.Query().Get("to")
		if t, ok := scopedToken(r); ok {
			if err := allowed(t, writePath, to); err != nil {
				s.audit(r, "api", "auth", to, nil, err)
				writeError(w, http.StatusForbidden, err.Error())
				return
			}
		}
		if err := s.copyPath(r, "api", path, to, move); err != nil {
			s.serviceError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// copyPath copies or moves path to to and audits it.
func (s *Server) copyPath(r *http.Request, source, path, to string, move bool) error {
	err := s.secrets.CopyPath(r.Context(), path, to, move)
	op := "copy_path"
	if move {
		op = "move_path"
	}
	s.audit(r, source, op, path, nil, err, "to", to)
	return err
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

func (s *Server) apiDeleteVersion(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	err := s.deleteVersion(r, path, r.PathValue("version"))
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteVersion deletes one version of path and audits it.
func (s *Server) deleteVersion(r *http.Request, path, version string) error {
	n, err := parseVersion(version)
	if err == nil {
		err = s.secrets.DeleteVersions(r.Context(), path, n)
	}
	source := "api"
	if _, ok := scopedToken(r); !ok {
		source = "ui"
	}
	s.audit(r, source, "delete_version", path, nil, err, "version", version)
	return err
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

var errInvalidToken = errors.New("invalid token")

// audit logs a change or an authentication attempt and keeps it for the Web
// UI. Key names are logged, values never are. X-Forwarded-For is logged as
// received; client is the address resolved through the trusted proxies. extra holds key-value pairs; "name" is the
// integration an integration operation acted on.
func (s *Server) audit(r *http.Request, source, op, path string, keys []string, err error, extra ...any) {
	e := auditEvent{Source: source, Op: op, Remote: r.RemoteAddr, Forwarded: strings.Join(r.Header.Values("X-Forwarded-For"), ", "), Path: path, Keys: keys}
	if remote, ok := parseHop(r.RemoteAddr); ok && len(s.TrustedProxies) > 0 {
		if client := s.clientAddr(r); client != remote.String() {
			e.Client = client
		}
	}
	if t, ok := scopedToken(r); ok {
		e.Token = t.Name
	}
	for i := 0; i+1 < len(extra); i += 2 {
		if extra[i] == "name" {
			e.Name, _ = extra[i+1].(string)
		}
	}
	if err != nil {
		e.Error = err.Error()
	}
	s.record(e, extra...)
}

// record logs e, with extra attributes, and keeps it for the Web UI.
func (s *Server) record(e auditEvent, extra ...any) {
	e.Time = time.Now()
	s.auditLog.add(e)
	attrs := []any{"source", e.Source, "op", e.Op}
	if e.Remote != "" {
		attrs = append(attrs, "remote", e.Remote)
	}
	if e.Client != "" {
		attrs = append(attrs, "client", e.Client)
	}
	if e.Token != "" {
		attrs = append(attrs, "token", e.Token)
	}
	if e.Forwarded != "" {
		attrs = append(attrs, "forwarded_for", e.Forwarded)
	}
	if e.Path != "" {
		attrs = append(attrs, "path", e.Path)
	}
	if len(e.Keys) > 0 {
		attrs = append(attrs, "keys", e.Keys)
	}
	attrs = append(attrs, extra...)
	if e.Error != "" {
		s.log.Warn("audit", append(attrs, "error", e.Error)...)
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
