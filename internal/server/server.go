// Package server exposes secrets.Service through a REST API and a Web UI.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rapatao/secret-manager/internal/secrets"
)

// MinTokenLength is the shortest admin token accepted by New.
const MinTokenLength = 32

const maxBodyBytes = 1 << 20

// Server serves the API under /api/v1 and the Web UI under /.
type Server struct {
	secrets  *secrets.Service
	token    []byte
	sessions *sessions
	mux      *http.ServeMux
	log      *slog.Logger
}

// New returns a Server authenticating with token.
func New(svc *secrets.Service, token string) (*Server, error) {
	if len(token) < MinTokenLength {
		return nil, errors.New("admin token must have at least 32 characters")
	}
	s := &Server{
		secrets:  svc,
		token:    []byte(token),
		sessions: newSessions(12 * time.Hour),
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

	s.mux.Handle("GET /api/v1/paths", s.bearer(s.apiListPaths))
	s.mux.Handle("DELETE /api/v1/paths", s.bearer(s.apiDeletePath))
	s.mux.Handle("GET /api/v1/secrets", s.bearer(s.apiGet))
	s.mux.Handle("PUT /api/v1/secrets", s.bearer(s.apiSet))
	s.mux.Handle("DELETE /api/v1/secrets/{key}", s.bearer(s.apiDeleteKey))

	s.mux.Handle("GET /login", s.ui(s.uiLoginForm))
	s.mux.Handle("POST /login", s.ui(s.uiLogin))
	s.mux.Handle("POST /logout", s.ui(s.session(s.uiLogout)))
	s.mux.Handle("GET /{$}", s.ui(s.session(s.uiIndex)))
	s.mux.Handle("GET /path", s.ui(s.session(s.uiPath)))
	s.mux.Handle("POST /path", s.ui(s.session(s.uiCreatePath)))
	s.mux.Handle("POST /path/delete", s.ui(s.session(s.uiDeletePath)))
	s.mux.Handle("POST /key", s.ui(s.session(s.uiSetKey)))
	s.mux.Handle("POST /key/delete", s.ui(s.session(s.uiDeleteKey)))
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

func (s *Server) bearer(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !s.validToken(token) {
			s.audit(r, "api", "auth", "", nil, errInvalidToken)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	})
}

func (s *Server) apiListPaths(w http.ResponseWriter, r *http.Request) {
	paths, err := s.secrets.ListPaths(r.Context())
	if err != nil {
		s.serviceError(w, r, err)
		return
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

var errInvalidToken = errors.New("invalid token")

// audit logs a change or an authentication attempt. Key names are logged,
// values never are. X-Forwarded-For is client supplied and only informative.
func (s *Server) audit(r *http.Request, source, op, path string, keys []string, err error) {
	attrs := []any{"source", source, "op", op, "remote", r.RemoteAddr}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		attrs = append(attrs, "forwarded_for", fwd)
	}
	if path != "" {
		attrs = append(attrs, "path", path)
	}
	if len(keys) > 0 {
		attrs = append(attrs, "keys", keys)
	}
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
