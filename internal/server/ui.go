package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
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

var errUnconfirmed = fmt.Errorf("%w: confirm the action first", secrets.ErrInvalid)

// crossOrigin rejects cross-site form posts using Sec-Fetch-Site, falling back
// to Origin for older browsers.
var crossOrigin = http.NewCrossOriginProtection()

//go:embed ui/*.html ui/ui.js
var uiFS embed.FS

var pages = map[string]*template.Template{}

// timeLayout formats every time the Web UI shows, in UTC.
const timeLayout = "2006-01-02 15:04 UTC"

func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

var pageFuncs = template.FuncMap{
	"time": func(t time.Time) template.HTML {
		return template.HTML(`<time datetime="` + t.UTC().Format(time.RFC3339) + `">` + formatTime(t) + `</time>`) //nolint:gosec // only formatted digits
	},
}

func init() {
	for _, name := range []string{"login", "summary", "secrets", "path", "integrations", "authorize"} {
		pages[name] = template.Must(template.New(name).Funcs(pageFuncs).ParseFS(uiFS, "ui/layout.html", "ui/"+name+".html"))
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
		h.Set("Content-Security-Policy", "default-src 'none'; img-src data:; script-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
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
			login := "/login"
			if r.Method == http.MethodGet {
				login += "?" + url.Values{"next": {r.URL.RequestURI()}}.Encode()
			}
			http.Redirect(w, r, login, http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) uiScript(w http.ResponseWriter, r *http.Request) {
	http.ServeFileFS(w, r, uiFS, "ui/ui.js")
}

func (s *Server) uiLoginForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "login", map[string]any{"Next": r.URL.Query().Get("next")})
}

// localPath returns next when it is a path on this server, else "/".
func localPath(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	return next
}

func (s *Server) uiLogin(w http.ResponseWriter, r *http.Request) {
	if !s.validToken(r.PostFormValue("token")) {
		s.audit(r, "ui", "login", "", nil, errInvalidToken)
		s.render(w, http.StatusUnauthorized, "login", map[string]any{"Error": "invalid token", "Next": r.PostFormValue("next")})
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
	http.Redirect(w, r, localPath(r.PostFormValue("next")), http.StatusSeeOther)
}

func (s *Server) uiLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) uiSecrets(w http.ResponseWriter, r *http.Request) {
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
	s.render(w, http.StatusOK, "secrets", map[string]any{
		"Paths":   paths,
		"Deleted": deleted,
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
	for i, v := range versions {
		h := uiVersion{Number: v.Number, Time: v.Time, Current: !deleted && i == 0, Same: !deleted && maps.Equal(v.Data, data)}
		for _, c := range secrets.Diff(data, v.Data) {
			h.Restore = append(h.Restore, uiChange{c, data[c.Key], v.Data[c.Key]})
		}
		switch {
		case i+1 < len(versions):
			h.Changes = secrets.Diff(versions[i+1].Data, v.Data)
		case v.Number == 1:
			h.Changes = secrets.Diff(nil, v.Data)
		}
		history = append(history, h)
	}
	s.render(w, http.StatusOK, "path", map[string]any{"Path": path, "Deleted": deleted, "Entries": entries, "History": history, "Error": r.URL.Query().Get("error")})
}

type uiVersion struct {
	Number  int
	Time    time.Time
	Changes []secrets.Change
	Current bool
	Same    bool
	Restore []uiChange
}

type uiChange struct {
	secrets.Change
	Before, After string
}

func (s *Server) uiRollback(w http.ResponseWriter, r *http.Request) {
	path := r.PostFormValue("path")
	version := r.PostFormValue("version")
	if r.PostFormValue("confirm") != version {
		s.redirectWithError(w, r, pathURL(path)+"&", errUnconfirmed)
		return
	}
	err := s.rollback(r, path, version)
	s.audit(r, "ui", "rollback", path, nil, err)
	if err != nil {
		s.redirectWithError(w, r, pathURL(path)+"&", err)
		return
	}
	http.Redirect(w, r, pathURL(path), http.StatusSeeOther)
}

func (s *Server) uiCreatePath(w http.ResponseWriter, r *http.Request) {
	path := r.PostFormValue("path")
	if r.PostFormValue("confirm") != "yes" {
		s.redirectWithError(w, r, "/secrets?", errUnconfirmed)
		return
	}
	err := s.secrets.SetKeys(r.Context(), path, nil)
	s.audit(r, "ui", "create_path", path, nil, err)
	if err != nil {
		s.redirectWithError(w, r, "/secrets?", err)
		return
	}
	normalized, _ := secrets.NormalizePath(path)
	http.Redirect(w, r, pathURL(normalized), http.StatusSeeOther)
}

func (s *Server) uiDeletePath(w http.ResponseWriter, r *http.Request) {
	path := r.PostFormValue("path")
	if r.PostFormValue("confirm") != path {
		s.redirectWithError(w, r, pathURL(path)+"&", fmt.Errorf("%w: type the path to confirm the deletion", secrets.ErrInvalid))
		return
	}
	err := s.secrets.DeletePath(r.Context(), path)
	s.audit(r, "ui", "delete_path", path, nil, err)
	if err != nil {
		s.redirectWithError(w, r, "/secrets?", err)
		return
	}
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

func (s *Server) uiSetKey(w http.ResponseWriter, r *http.Request) {
	path := r.PostFormValue("path")
	if r.PostFormValue("confirm") != "yes" {
		s.redirectWithError(w, r, pathURL(path)+"&", errUnconfirmed)
		return
	}
	keys, values := r.PostForm["key"], r.PostForm["value"]
	newKeys, newValues := r.PostForm["new-key"], r.PostForm["new-value"]
	if len(keys) != len(values) || len(newKeys) != len(newValues) {
		s.redirectWithError(w, r, pathURL(path)+"&", fmt.Errorf("%w: every key needs a value", secrets.ErrInvalid))
		return
	}
	data := make(map[string]string, len(keys)+len(newKeys))
	for i, k := range keys {
		data[k] = values[i]
	}
	// ponytail: checked before the write, so a key created concurrently can
	// still be overwritten; move into secrets.UpdateKeys if that matters.
	current, err := s.secrets.Get(r.Context(), path, false)
	if err != nil && !errors.Is(err, secrets.ErrNotFound) {
		s.uiError(w, r, err)
		return
	}
	for i, k := range newKeys {
		if _, ok := current[k]; ok {
			s.redirectWithError(w, r, pathURL(path)+"&", fmt.Errorf("%w: key %q already exists", secrets.ErrInvalid, k))
			return
		}
		if _, ok := data[k]; ok {
			s.redirectWithError(w, r, pathURL(path)+"&", fmt.Errorf("%w: key %q is added twice", secrets.ErrInvalid, k))
			return
		}
		data[k] = newValues[i]
	}
	keys = append(keys, newKeys...)
	remove := r.PostForm["delete"]
	err = s.secrets.UpdateKeys(r.Context(), path, data, remove)
	if len(keys) > 0 || len(remove) == 0 {
		s.audit(r, "ui", "set", path, keys, err)
	}
	if len(remove) > 0 {
		s.audit(r, "ui", "delete_key", path, remove, err)
	}
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

func (s *Server) render(w http.ResponseWriter, status int, page string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Version"] = s.Version
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages[page].ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("render page", "page", page, "error", err)
	}
}
