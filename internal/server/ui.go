package server

import (
	"bytes"
	"cmp"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
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
	"sync"
	"time"

	"github.com/rapatao/secret-manager/internal/dotenv"
	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/storage/encrypted"
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
		day, clock, _ := strings.Cut(formatTime(t), " ")
		return template.HTML(`<time datetime="` + t.UTC().Format(time.RFC3339) + `"><span>` + day + `</span> <span>` + clock + `</span></time>`) //nolint:gosec // only formatted digits
	},
}

func init() {
	for _, name := range []string{"login", "summary", "secrets", "path", "integrations", "authorize", "audit"} {
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
		h.Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; img-src data:; script-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
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
	addr, now := s.clientAddr(r), time.Now()
	if wait := s.logins.wait(addr, now); wait > 0 {
		err := fmt.Errorf("too many failed sign-ins, try again in %s", wait.Round(time.Second))
		s.auditAt(s.Events.Logins, r, "ui", "login", "", nil, err)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Round(time.Second).Seconds())))
		s.render(w, http.StatusTooManyRequests, "login", map[string]any{"Error": err.Error(), "Next": r.PostFormValue("next")})
		return
	}
	if !s.validToken(r.PostFormValue("token")) {
		s.logins.fail(addr, now)
		s.auditAt(s.Events.Logins, r, "ui", "login", "", nil, errInvalidToken)
		s.render(w, http.StatusUnauthorized, "login", map[string]any{"Error": "invalid token", "Next": r.PostFormValue("next")})
		return
	}
	s.logins.succeed(addr)
	s.startSession(w)
	s.auditAt(s.Events.Logins, r, "ui", "login", "", nil, nil)
	http.Redirect(w, r, localPath(r.PostFormValue("next")), http.StatusSeeOther)
}

func (s *Server) startSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is off only with PlainHTTP, for the loopback local UI
		Name:     sessionCookie,
		Value:    s.sessions.create(),
		Path:     "/",
		MaxAge:   int(s.sessions.ttl.Seconds()),
		HttpOnly: true,
		Secure:   !s.PlainHTTP,
		SameSite: http.SameSiteStrictMode,
	})
}

// loginLinks holds the unused codes of LoginLink and their expiry.
type loginLinks struct {
	mu    sync.Mutex
	codes map[string]time.Time
}

// LoginLink returns a path that signs in to the Web UI without the admin
// token. It works once, within a minute.
func (s *Server) LoginLink() string {
	code := rand.Text()
	s.links.mu.Lock()
	defer s.links.mu.Unlock()
	if s.links.codes == nil {
		s.links.codes = map[string]time.Time{}
	}
	s.links.codes[code] = time.Now().Add(time.Minute)
	return "/login/link?" + url.Values{"code": {code}}.Encode()
}

func (s *Server) uiLoginLink(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	s.links.mu.Lock()
	expires, ok := s.links.codes[code]
	delete(s.links.codes, code)
	s.links.mu.Unlock()
	if !ok || time.Now().After(expires) {
		s.auditAt(s.Events.Logins, r, "ui", "login", "", nil, errors.New("invalid or expired login link"))
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.startSession(w)
	s.auditAt(s.Events.Logins, r, "ui", "login", "", nil, nil)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) uiLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, //nolint:gosec // G124: see startSession
		HttpOnly: true, Secure: !s.PlainHTTP, SameSite: http.SameSiteStrictMode})
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

// entry is a key of a path. Changed is the time of the newest version that
// set it, zero when the kept history does not reach that far.
type entry struct {
	Key, Value string
	Changed    time.Time
}

func (s *Server) uiPath(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	versions, err := s.secrets.History(r.Context(), path)
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	data, err := s.secrets.Get(r.Context(), path, false)
	deleted := errors.Is(err, secrets.ErrNotFound) && len(versions) > 0
	if deleted {
		s.auditRead(r, "ui", "read", path, versions[0].Data, nil)
	} else {
		s.auditRead(r, "ui", "read", path, data, err)
	}
	if err != nil && !deleted {
		s.uiError(w, r, err)
		return
	}
	var history []uiVersion
	changed := map[string]time.Time{}
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
		for _, c := range h.Changes {
			if _, seen := changed[c.Key]; !seen && c.Op != "-" {
				changed[c.Key] = v.Time
			}
		}
		history = append(history, h)
	}
	var entries []entry
	for _, k := range slices.Sorted(maps.Keys(data)) {
		entries = append(entries, entry{k, data[k], changed[k]})
	}
	cmp, err := compareVersions(r.URL.Query(), deleted, data, versions)
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	s.render(w, http.StatusOK, "path", map[string]any{
		"Path": path, "Deleted": deleted, "Entries": entries, "History": history,
		"Compare": cmp, "Error": r.URL.Query().Get("error"),
	})
}

// comparison is the difference between two snapshots of a path, From and To
// being "current" or a version number.
type comparison struct {
	From, To string
	Changes  []uiChange
}

// compareVersions compares the snapshots named by the from and to query
// parameters, nil when they are absent.
func compareVersions(q url.Values, deleted bool, current map[string]string, versions []secrets.Version) (*comparison, error) {
	if q.Get("from") == "" && q.Get("to") == "" {
		return nil, nil
	}
	snapshot := func(name string) (map[string]string, error) {
		if name == "current" && !deleted {
			return current, nil
		}
		n, err := strconv.Atoi(name)
		if err == nil {
			for _, v := range versions {
				if v.Number == n {
					return v.Data, nil
				}
			}
		}
		return nil, fmt.Errorf("%w: no version %q to compare", secrets.ErrInvalid, name)
	}
	c := &comparison{From: q.Get("from"), To: q.Get("to")}
	from, err := snapshot(c.From)
	if err != nil {
		return nil, err
	}
	to, err := snapshot(c.To)
	if err != nil {
		return nil, err
	}
	for _, ch := range secrets.Diff(from, to) {
		c.Changes = append(c.Changes, uiChange{ch, from[ch.Key], to[ch.Key]})
	}
	return c, nil
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

func (s *Server) uiDeleteVersion(w http.ResponseWriter, r *http.Request) {
	path := r.PostFormValue("path")
	version := r.PostFormValue("version")
	if r.PostFormValue("confirm") != version {
		s.redirectWithError(w, r, pathURL(path)+"&", errUnconfirmed)
		return
	}
	if err := s.deleteVersion(r, path, version); err != nil {
		s.redirectWithError(w, r, pathURL(path)+"&", err)
		return
	}
	versions, err := s.secrets.History(r.Context(), path)
	if err == nil && len(versions) == 0 {
		if _, err = s.secrets.Get(r.Context(), path, false); errors.Is(err, secrets.ErrNotFound) {
			http.Redirect(w, r, "/secrets", http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, pathURL(path), http.StatusSeeOther)
}

func (s *Server) uiCopyPath(w http.ResponseWriter, r *http.Request) {
	path, to := r.PostFormValue("path"), r.PostFormValue("to")
	op := r.PostFormValue("confirm")
	if op != "copy" && op != "move" {
		s.redirectWithError(w, r, pathURL(path)+"&", errUnconfirmed)
		return
	}
	if err := s.copyPath(r, "ui", path, to, op == "move"); err != nil {
		s.redirectWithError(w, r, pathURL(path)+"&", err)
		return
	}
	normalized, _ := secrets.NormalizePath(to)
	http.Redirect(w, r, pathURL(normalized), http.StatusSeeOther)
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

// uiExport downloads the keys of a path as a dotenv or JSON file.
func (s *Server) uiExport(w http.ResponseWriter, r *http.Request) {
	path, format := r.URL.Query().Get("path"), r.URL.Query().Get("format")
	if format != "dotenv" && format != "json" {
		s.uiError(w, r, fmt.Errorf("%w: unknown format %q", secrets.ErrInvalid, format))
		return
	}
	data, err := s.secrets.Get(r.Context(), path, false)
	s.auditRead(r, "ui", "export", path, data, err)
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	var out bytes.Buffer
	ext := ".env"
	if format == "json" {
		ext = ".json"
		enc := json.NewEncoder(&out)
		enc.SetIndent("", "  ")
		err = enc.Encode(data)
	} else {
		err = dotenv.Format(&out, data)
	}
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	normalized, _ := secrets.NormalizePath(path)
	name := cmp.Or(strings.ReplaceAll(strings.Trim(normalized, "/"), "/", "-"), "root")
	download(w, name+ext, out.Bytes())
}

// uiBackup downloads a backup of every path, encrypted with the server's
// backup key when it has one.
func (s *Server) uiBackup(w http.ResponseWriter, r *http.Request) {
	doc, err := s.backup(r.Context(), r.URL.Query().Get("history") == "true")
	var raw []byte
	if err == nil {
		raw, err = json.Marshal(doc)
	}
	if err == nil && s.Settings.Backups.Key != nil {
		raw, err = encrypted.SealBackup(s.Settings.Backups.Key, raw)
	}
	s.auditAt(s.Events.Backups, r, "ui", "backup", "", nil, err)
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	download(w, "backup-"+doc.Time.Format("20060102T150405Z")+".json", raw)
}

// download sends body as an attachment named name, which must need no quoting.
func download(w http.ResponseWriter, name string, body []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(body)
}

func pathURL(path string) string {
	return "/secrets/path?path=" + url.QueryEscape(path)
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
