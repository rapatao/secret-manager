package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"errors"
	"html/template"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rapatao/secret-manager/internal/secrets"
)

const sessionCookie = "sm_session"

// crossOrigin rejects cross-site form posts using Sec-Fetch-Site, falling back
// to Origin for older browsers.
var crossOrigin = http.NewCrossOriginProtection()

//go:embed ui/*.html ui/ui.js
var uiFS embed.FS

var pages = map[string]*template.Template{}

func init() {
	for _, name := range []string{"login", "index", "path"} {
		pages[name] = template.Must(template.ParseFS(uiFS, "ui/layout.html", "ui/"+name+".html"))
	}
}

// sessions issues cookies signed with a key derived from the admin token, so
// they survive restarts and are invalidated when the token changes. Logging
// out deletes the cookie; a copy of it stays valid until it expires.
type sessions struct {
	ttl time.Duration
	key []byte
}

func newSessions(token []byte, ttl time.Duration) *sessions {
	m := hmac.New(sha256.New, token)
	m.Write([]byte("secret-manager ui session"))
	return &sessions{ttl: ttl, key: m.Sum(nil)}
}

func (s *sessions) sign(payload string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *sessions) create() string {
	payload := strconv.FormatInt(time.Now().Add(s.ttl).Unix(), 10) + "." + rand.Text()
	return payload + "." + s.sign(payload)
}

func (s *sessions) valid(id string) bool {
	i := strings.LastIndexByte(id, '.')
	if i < 0 || !hmac.Equal([]byte(id[i+1:]), []byte(s.sign(id[:i]))) {
		return false
	}
	unix, _, _ := strings.Cut(id[:i], ".")
	sec, err := strconv.ParseInt(unix, 10, 64)
	return err == nil && time.Now().Before(time.Unix(sec, 0))
}

// ui sets security headers and rejects cross-origin form posts.
func (s *Server) ui(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
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

func (s *Server) uiScript(w http.ResponseWriter, r *http.Request) {
	http.ServeFileFS(w, r, uiFS, "ui/ui.js")
}

func (s *Server) uiLoginForm(w http.ResponseWriter, _ *http.Request) {
	render(w, http.StatusOK, "login", nil)
}

func (s *Server) uiLogin(w http.ResponseWriter, r *http.Request) {
	if !s.validToken(r.PostFormValue("token")) {
		s.audit(r, "ui", "login", "", nil, errInvalidToken)
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
	s.audit(r, "ui", "login", "", nil, nil)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) uiLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) uiIndex(w http.ResponseWriter, r *http.Request) {
	paths, err := s.secrets.ListPaths(r.Context())
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	deleted, err := s.secrets.DeletedPaths(r.Context())
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	q := r.URL.Query().Get("q")
	unmatched := func(p string) bool { return !strings.Contains(p, q) }
	render(w, http.StatusOK, "index", map[string]any{
		"Paths":   slices.DeleteFunc(paths, unmatched),
		"Deleted": slices.DeleteFunc(deleted, unmatched),
		"Query":   q,
		"Error":   r.URL.Query().Get("error"),
	})
}

type entry struct{ Key, Value string }

func (s *Server) uiPath(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	versions, err := s.secrets.History(r.Context(), path)
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	data, err := s.secrets.Get(r.Context(), path, false)
	deleted := errors.Is(err, secrets.ErrNotFound) && len(versions) > 0
	if err != nil && !deleted {
		s.uiError(w, r, err)
		return
	}
	var entries []entry
	for _, k := range slices.Sorted(maps.Keys(data)) {
		entries = append(entries, entry{k, data[k]})
	}
	var history []uiVersion
	for _, v := range versions {
		h := uiVersion{Number: v.Number, Time: v.Time.Format(time.RFC3339)}
		for _, k := range slices.Sorted(maps.Keys(v.Data)) {
			h.Entries = append(h.Entries, entry{k, v.Data[k]})
		}
		history = append(history, h)
	}
	render(w, http.StatusOK, "path", map[string]any{"Path": path, "Deleted": deleted, "Entries": entries, "History": history, "Error": r.URL.Query().Get("error")})
}

type uiVersion struct {
	Number  int
	Time    string
	Entries []entry
}

func (s *Server) uiRollback(w http.ResponseWriter, r *http.Request) {
	path := r.PostFormValue("path")
	err := s.rollback(r, path, r.PostFormValue("version"))
	s.audit(r, "ui", "rollback", path, nil, err)
	if err != nil {
		s.redirectWithError(w, r, pathURL(path)+"&", err)
		return
	}
	http.Redirect(w, r, pathURL(path), http.StatusSeeOther)
}

func (s *Server) uiCreatePath(w http.ResponseWriter, r *http.Request) {
	path := r.PostFormValue("path")
	err := s.secrets.SetKeys(r.Context(), path, nil)
	s.audit(r, "ui", "create_path", path, nil, err)
	if err != nil {
		s.redirectWithError(w, r, "/?", err)
		return
	}
	normalized, _ := secrets.NormalizePath(path)
	http.Redirect(w, r, pathURL(normalized), http.StatusSeeOther)
}

func (s *Server) uiDeletePath(w http.ResponseWriter, r *http.Request) {
	path := r.PostFormValue("path")
	err := s.secrets.DeletePath(r.Context(), path)
	s.audit(r, "ui", "delete_path", path, nil, err)
	if err != nil {
		s.redirectWithError(w, r, "/?", err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) uiSetKey(w http.ResponseWriter, r *http.Request) {
	path := r.PostFormValue("path")
	key := r.PostFormValue("key")
	err := s.secrets.SetKeys(r.Context(), path, map[string]string{key: r.PostFormValue("value")})
	s.audit(r, "ui", "set", path, []string{key}, err)
	if err != nil {
		s.redirectWithError(w, r, pathURL(path)+"&", err)
		return
	}
	http.Redirect(w, r, pathURL(path), http.StatusSeeOther)
}

func (s *Server) uiDeleteKey(w http.ResponseWriter, r *http.Request) {
	path := r.PostFormValue("path")
	key := r.PostFormValue("key")
	err := s.secrets.DeleteKey(r.Context(), path, key)
	s.audit(r, "ui", "delete_key", path, []string{key}, err)
	if err != nil {
		s.redirectWithError(w, r, pathURL(path)+"&", err)
		return
	}
	http.Redirect(w, r, pathURL(path), http.StatusSeeOther)
}

func pathURL(path string) string {
	return "/path?path=" + url.QueryEscape(path)
}

func (s *Server) redirectWithError(w http.ResponseWriter, r *http.Request, prefix string, err error) {
	if !errors.Is(err, secrets.ErrInvalid) && !errors.Is(err, secrets.ErrNotFound) {
		s.uiError(w, r, err)
		return
	}
	http.Redirect(w, r, prefix+"error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
}

func (s *Server) uiError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, secrets.ErrInvalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, secrets.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	default:
		s.logFailure(r, err)
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
