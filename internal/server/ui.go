package server

import (
	"crypto/rand"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/rapatao/secret-manager/internal/secrets"
)

const sessionCookie = "sm_session"

// crossOrigin rejects cross-site form posts using Sec-Fetch-Site, falling back
// to Origin for older browsers.
var crossOrigin = http.NewCrossOriginProtection()

//go:embed ui/*.html
var uiFS embed.FS

var pages = map[string]*template.Template{}

func init() {
	for _, name := range []string{"login", "index", "path"} {
		pages[name] = template.Must(template.ParseFS(uiFS, "ui/layout.html", "ui/"+name+".html"))
	}
}

type sessions struct {
	mu  sync.Mutex
	ttl time.Duration
	ids map[string]time.Time
}

func newSessions(ttl time.Duration) *sessions {
	return &sessions{ttl: ttl, ids: map[string]time.Time{}}
}

func (s *sessions) create() string {
	id := rand.Text()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, exp := range s.ids {
		if now.After(exp) {
			delete(s.ids, k)
		}
	}
	s.ids[id] = now.Add(s.ttl)
	return id
}

func (s *sessions) valid(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.ids[id]
	return ok && time.Now().Before(exp)
}

func (s *sessions) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ids, id)
}

// ui sets security headers and rejects cross-origin form posts.
func (s *Server) ui(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if err := crossOrigin.Check(r); err != nil {
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func (s *Server) session(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || !s.sessions.valid(c.Value) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) uiLoginForm(w http.ResponseWriter, _ *http.Request) {
	render(w, http.StatusOK, "login", nil)
}

func (s *Server) uiLogin(w http.ResponseWriter, r *http.Request) {
	if !s.validToken(r.PostFormValue("token")) {
		render(w, http.StatusUnauthorized, "login", map[string]string{"Error": "invalid token"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    s.sessions.create(),
		Path:     "/",
		MaxAge:   int(s.sessions.ttl.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) uiLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) uiIndex(w http.ResponseWriter, r *http.Request) {
	paths, err := s.secrets.ListPaths(r.Context())
	if err != nil {
		uiError(w, err)
		return
	}
	render(w, http.StatusOK, "index", map[string]any{"Paths": paths, "Error": r.URL.Query().Get("error")})
}

type entry struct{ Key, Value string }

func (s *Server) uiPath(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	data, err := s.secrets.Get(r.Context(), path, false)
	if err != nil {
		uiError(w, err)
		return
	}
	var entries []entry
	for _, k := range slices.Sorted(maps.Keys(data)) {
		entries = append(entries, entry{k, data[k]})
	}
	render(w, http.StatusOK, "path", map[string]any{"Path": path, "Entries": entries, "Error": r.URL.Query().Get("error")})
}

func (s *Server) uiCreatePath(w http.ResponseWriter, r *http.Request) {
	path := r.PostFormValue("path")
	if err := s.secrets.SetKeys(r.Context(), path, nil); err != nil {
		redirectWithError(w, r, "/?", err)
		return
	}
	normalized, _ := secrets.NormalizePath(path)
	http.Redirect(w, r, pathURL(normalized), http.StatusSeeOther)
}

func (s *Server) uiDeletePath(w http.ResponseWriter, r *http.Request) {
	if err := s.secrets.DeletePath(r.Context(), r.PostFormValue("path")); err != nil {
		redirectWithError(w, r, "/?", err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) uiSetKey(w http.ResponseWriter, r *http.Request) {
	path := r.PostFormValue("path")
	err := s.secrets.SetKeys(r.Context(), path, map[string]string{r.PostFormValue("key"): r.PostFormValue("value")})
	if err != nil {
		redirectWithError(w, r, pathURL(path)+"&", err)
		return
	}
	http.Redirect(w, r, pathURL(path), http.StatusSeeOther)
}

func (s *Server) uiDeleteKey(w http.ResponseWriter, r *http.Request) {
	path := r.PostFormValue("path")
	if err := s.secrets.DeleteKey(r.Context(), path, r.PostFormValue("key")); err != nil {
		redirectWithError(w, r, pathURL(path)+"&", err)
		return
	}
	http.Redirect(w, r, pathURL(path), http.StatusSeeOther)
}

func pathURL(path string) string {
	return "/path?path=" + url.QueryEscape(path)
}

func redirectWithError(w http.ResponseWriter, r *http.Request, prefix string, err error) {
	if !errors.Is(err, secrets.ErrInvalid) && !errors.Is(err, secrets.ErrNotFound) {
		uiError(w, err)
		return
	}
	http.Redirect(w, r, prefix+"error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
}

func uiError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, secrets.ErrInvalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, secrets.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	default:
		slog.Error("secret operation failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func render(w http.ResponseWriter, status int, page string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages[page].ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("render page", "page", page, "error", err)
	}
}
