// Package server exposes secrets.Service through a REST API and a Web UI.
package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
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

func (s *Server) validToken(got string) bool {
	return subtle.ConstantTimeCompare([]byte(got), s.token) == 1
}

func (s *Server) bearer(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !s.validToken(token) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	})
}

func (s *Server) apiListPaths(w http.ResponseWriter, r *http.Request) {
	paths, err := s.secrets.ListPaths(r.Context())
	if err != nil {
		serviceError(w, err)
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
		serviceError(w, err)
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
	if err := s.secrets.SetKeys(r.Context(), r.URL.Query().Get("path"), values); err != nil {
		serviceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiDeleteKey(w http.ResponseWriter, r *http.Request) {
	if err := s.secrets.DeleteKey(r.Context(), r.URL.Query().Get("path"), r.PathValue("key")); err != nil {
		serviceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiDeletePath(w http.ResponseWriter, r *http.Request) {
	if err := s.secrets.DeletePath(r.Context(), r.URL.Query().Get("path")); err != nil {
		serviceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func serviceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, secrets.ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, secrets.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	default:
		slog.Error("secret operation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
