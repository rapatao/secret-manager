package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/tokens"
)

// maxPendingLogins bounds the logins waiting for approval, since
// /api/v1/authorize/device needs no authentication.
const maxPendingLogins = 100

// expiryPresets are the expiries offered when creating an integration.
var expiryPresets = []struct{ Value, Label string }{
	{"7d", "7 days"}, {"30d", "30 days"}, {"90d", "90 days"}, {"1y", "1 year"}, {"never", "Never"}, {"custom", "Custom date"},
}

var presetDurations = map[string]time.Duration{
	"7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour, "90d": 90 * 24 * time.Hour, "1y": 365 * 24 * time.Hour,
}

// cachePresets are the offline cache max ages offered for an integration,
// after the server default.
var cachePresets = []struct {
	Value time.Duration
	Label string
}{
	{0, "Disabled"}, {time.Hour, "1 hour"}, {24 * time.Hour, "1 day"}, {7 * 24 * time.Hour, "7 days"}, {30 * 24 * time.Hour, "30 days"},
}

func cacheLabel(d time.Duration) string {
	for _, p := range cachePresets {
		if p.Value == d {
			return p.Label
		}
	}
	return shortDuration(d)
}

// cacheOptions lists the cache choices of the integration form: the server
// default first, as "default".
func (s *Server) cacheOptions() []struct{ Value, Label string } {
	out := []struct{ Value, Label string }{{"default", s.cacheLabelOf(nil)}}
	for _, p := range cachePresets {
		out = append(out, struct{ Value, Label string }{p.Value.String(), p.Label})
	}
	return out
}

// cacheLabelOf describes the cache max age of an integration as the form's
// summary shows it.
func (s *Server) cacheLabelOf(d *time.Duration) string {
	if d == nil {
		return "Server default (" + cacheLabel(s.CacheMaxAge) + ")"
	}
	return cacheLabel(*d)
}

func cacheValue(d *time.Duration) string {
	if d == nil {
		return "default"
	}
	return d.String()
}

var (
	errLoginPending = errors.New("authorization_pending")
	errLoginDenied  = errors.New("access_denied")
	errLoginInvalid = fmt.Errorf("%w: invalid or expired login code", secrets.ErrInvalid)
)

// grant is the access approved for a new integration token.
type grant struct {
	name, path string
	readOnly   bool
	expires    time.Time
	// keep leaves the expiry of an existing integration unchanged.
	keep bool
	// cacheMaxAge is nil for the server default.
	cacheMaxAge *time.Duration
}

// login is a CLI login waiting for approval in the Web UI, then for the CLI
// to collect its token. A loopback login is approved with an authorization
// code sent to the CLI's local redirect and bound to a PKCE challenge. A
// device login is approved by user code and polled for by device code.
type login struct {
	expires time.Time
	name    string

	challenge string
	code      string

	userCode   string
	deviceCode string
	approved   bool
	denied     bool

	grant grant
}

// grants keeps pending logins in memory: a restart cancels them.
type grants struct {
	ttl time.Duration

	mu     sync.Mutex
	logins []*login
}

func newGrants(ttl time.Duration) *grants {
	return &grants{ttl: ttl}
}

func (g *grants) add(l *login) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	g.logins = slices.DeleteFunc(g.logins, func(l *login) bool { return !now.Before(l.expires) })
	if len(g.logins) >= maxPendingLogins {
		return errors.New("too many pending logins, retry later")
	}
	l.expires = now.Add(g.ttl)
	g.logins = append(g.logins, l)
	return nil
}

// find returns the pending login matching match. With take, the login is
// removed, so its code works once.
func (g *grants) find(match func(*login) bool, take bool) (*login, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for i, l := range g.logins {
		if !now.Before(l.expires) || !match(l) {
			continue
		}
		if take {
			g.logins = slices.Delete(g.logins, i, i+1)
		}
		return l, true
	}
	return nil, false
}

func equal(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func newUserCode() string {
	c := rand.Text()[:8]
	return c[:4] + "-" + c[4:]
}

// loopbackRedirect returns redirect when it is an http URL on the loopback
// interface with a port, the only place a CLI login may receive its code.
func loopbackRedirect(redirect string) (*url.URL, error) {
	u, err := url.Parse(redirect)
	if err != nil || u.Scheme != "http" || u.Port() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		!slices.Contains([]string{"127.0.0.1", "::1", "localhost"}, u.Hostname()) {
		return nil, fmt.Errorf("%w: redirect_uri must be an http URL on 127.0.0.1 with a port", secrets.ErrInvalid)
	}
	return u, nil
}

// parseGrant reads the integration fields of a form: name, path, read-only,
// expiry and offline cache. Only an edit may keep the current expiry.
func parseGrant(r *http.Request, now time.Time, edit bool) (grant, error) {
	g := grant{name: r.PostFormValue("name"), path: r.PostFormValue("path"), readOnly: r.PostFormValue("read-only") == "on"}
	if g.path == "" {
		g.path = "/"
	}
	if v := r.PostFormValue("cache-max-age"); v != "" && v != "default" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			return grant{}, fmt.Errorf("%w: unknown offline cache %q", secrets.ErrInvalid, v)
		}
		g.cacheMaxAge = &d
	}
	switch preset := r.PostFormValue("expires"); preset {
	case "never":
	case "keep":
		if !edit {
			return grant{}, fmt.Errorf("%w: pick an expiry", secrets.ErrInvalid)
		}
		g.keep = true
	case "custom":
		day, err := time.Parse(time.DateOnly, r.PostFormValue("expires-date"))
		if err != nil {
			return grant{}, fmt.Errorf("%w: pick an expiry date", secrets.ErrInvalid)
		}
		g.expires = day.Add(24 * time.Hour)
	default:
		d, ok := presetDurations[preset]
		if !ok {
			return grant{}, fmt.Errorf("%w: unknown expiry %q", secrets.ErrInvalid, preset)
		}
		g.expires = now.Add(d)
	}
	return g, nil
}

func (s *Server) createToken(r *http.Request, source string, g grant) (tokens.Token, string, error) {
	t, secret, err := s.tokens.Create(r.Context(), g.name, g.path, g.readOnly, g.expires, g.cacheMaxAge)
	s.audit(r, source, "create_token", g.path, nil, err, "name", g.name)
	return t, secret, err
}

// nameTaken reports an error when an integration already uses name.
func (s *Server) nameTaken(r *http.Request, name string) error {
	list, err := s.tokens.List(r.Context())
	if err != nil {
		return err
	}
	if slices.ContainsFunc(list, func(t tokens.Token) bool { return t.Name == name }) {
		return fmt.Errorf("%w: integration %s already exists; pick another name or revoke it first", secrets.ErrInvalid, name)
	}
	return nil
}

func (s *Server) uiIntegrations(w http.ResponseWriter, r *http.Request) {
	s.renderIntegrations(w, r, http.StatusOK, nil)
}

func (s *Server) renderIntegrations(w http.ResponseWriter, r *http.Request, status int, created map[string]string) {
	list, err := s.tokens.List(r.Context())
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	now := time.Now()
	cacheOptions := s.cacheOptions()
	var rows []map[string]any
	for _, t := range list {
		current := "never"
		if !t.Expires.IsZero() {
			current = formatTime(t.Expires)
		}
		presets := append([]struct{ Value, Label string }{{"keep", "Keep current (" + current + ")"}}, expiryPresets...)
		rows = append(rows, map[string]any{
			"Token":        t,
			"Expired":      !t.Expires.IsZero() && !now.Before(t.Expires),
			"Presets":      presets,
			"CacheOptions": cacheOptions,
			"CacheLabel":   s.cacheLabelOf(t.CacheMaxAge),
			"Grant": map[string]any{"Name": t.Name, "Path": t.Path, "ReadOnly": t.ReadOnly, "Expires": "keep",
				"Cache": cacheValue(t.CacheMaxAge), "Edit": true},
		})
	}
	s.render(w, status, "integrations", map[string]any{
		"Integrations": rows,
		"Created":      created,
		"Presets":      expiryPresets,
		"CacheOptions": cacheOptions,
		"Grant":        map[string]any{"Path": "/", "Expires": "90d", "Cache": "default"},
		"Error":        r.URL.Query().Get("error"),
	})
}

func (s *Server) uiCreateIntegration(w http.ResponseWriter, r *http.Request) {
	if r.PostFormValue("confirm") != "yes" {
		s.redirectWithError(w, r, "/integrations?", errUnconfirmed)
		return
	}
	g, err := parseGrant(r, time.Now(), false)
	if err != nil {
		s.redirectWithError(w, r, "/integrations?", err)
		return
	}
	t, secret, err := s.createToken(r, "ui", g)
	if err != nil {
		s.redirectWithError(w, r, "/integrations?", err)
		return
	}
	s.renderIntegrations(w, r, http.StatusCreated, map[string]string{"Name": t.Name, "Token": secret})
}

func (s *Server) uiUpdateIntegration(w http.ResponseWriter, r *http.Request) {
	if r.PostFormValue("confirm") != "yes" {
		s.redirectWithError(w, r, "/integrations?", errUnconfirmed)
		return
	}
	g, err := parseGrant(r, time.Now(), true)
	if err == nil && g.keep {
		g.expires, err = s.currentExpiry(r, g.name)
	}
	if err == nil {
		_, err = s.tokens.Update(r.Context(), g.name, g.path, g.readOnly, g.expires, g.cacheMaxAge)
	}
	s.audit(r, "ui", "update_token", g.path, nil, err, "name", g.name)
	if err != nil {
		s.redirectWithError(w, r, "/integrations?", err)
		return
	}
	http.Redirect(w, r, "/integrations", http.StatusSeeOther)
}

func (s *Server) currentExpiry(r *http.Request, name string) (time.Time, error) {
	list, err := s.tokens.List(r.Context())
	if err != nil {
		return time.Time{}, err
	}
	i := slices.IndexFunc(list, func(t tokens.Token) bool { return t.Name == name })
	if i < 0 {
		return time.Time{}, fmt.Errorf("%w: integration %s", secrets.ErrNotFound, name)
	}
	return list[i].Expires, nil
}

func (s *Server) uiRevokeIntegration(w http.ResponseWriter, r *http.Request) {
	name := r.PostFormValue("name")
	if r.PostFormValue("confirm") != name {
		s.redirectWithError(w, r, "/integrations?", errUnconfirmed)
		return
	}
	err := s.tokens.Revoke(r.Context(), name)
	s.audit(r, "ui", "revoke_token", "", nil, err, "name", name)
	if err != nil {
		s.redirectWithError(w, r, "/integrations?", err)
		return
	}
	http.Redirect(w, r, "/integrations", http.StatusSeeOther)
}

// uiAuthorizeForm shows the approval page of a CLI login: a loopback login
// carries redirect_uri, state and code_challenge, a device login user_code.
func (s *Server) uiAuthorizeForm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data := map[string]any{
		"Presets":      expiryPresets,
		"CacheOptions": s.cacheOptions(),
		"Grant":        map[string]any{"Name": q.Get("name"), "Path": "/", "Expires": "90d", "Cache": "default"},
		"Error":        q.Get("error"),
	}
	if code := strings.ToUpper(q.Get("user_code")); code != "" {
		l, ok := s.grants.find(func(l *login) bool { return equal(l.userCode, code) && !l.approved && !l.denied }, false)
		if !ok {
			s.uiError(w, r, errLoginInvalid)
			return
		}
		data["UserCode"] = l.userCode
		data["Grant"].(map[string]any)["Name"] = l.name
		s.render(w, http.StatusOK, "authorize", data)
		return
	}
	u, err := loopbackRedirect(q.Get("redirect_uri"))
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	if q.Get("code_challenge") == "" || q.Get("state") == "" {
		s.uiError(w, r, fmt.Errorf("%w: code_challenge and state are required", secrets.ErrInvalid))
		return
	}
	data["Redirect"], data["State"], data["Challenge"] = u.String(), q.Get("state"), q.Get("code_challenge")
	w.Header().Set("Content-Security-Policy", strings.Replace(w.Header().Get("Content-Security-Policy"),
		"form-action 'self'", "form-action 'self' "+u.Scheme+"://"+u.Host, 1))
	s.render(w, http.StatusOK, "authorize", data)
}

func (s *Server) uiAuthorize(w http.ResponseWriter, r *http.Request) {
	userCode := strings.ToUpper(r.PostFormValue("user_code"))
	back := "/authorize?" + url.Values{"user_code": {userCode}}.Encode() + "&"
	if userCode == "" {
		back = "/authorize?" + url.Values{
			"redirect_uri":   {r.PostFormValue("redirect_uri")},
			"state":          {r.PostFormValue("state")},
			"code_challenge": {r.PostFormValue("code_challenge")},
			"name":           {r.PostFormValue("name")},
		}.Encode() + "&"
	}
	deny := r.PostFormValue("decision") == "deny"

	if userCode != "" {
		l, ok := s.grants.find(func(l *login) bool { return equal(l.userCode, userCode) && !l.approved && !l.denied }, false)
		if !ok {
			s.uiError(w, r, errLoginInvalid)
			return
		}
		g, err := s.approvedGrant(r, deny)
		if err != nil {
			s.redirectWithError(w, r, back, err)
			return
		}
		s.grants.mu.Lock()
		l.approved, l.denied, l.grant = !deny, deny, g
		s.grants.mu.Unlock()
		s.render(w, http.StatusOK, "authorize", map[string]any{"Done": true, "Denied": deny})
		return
	}

	u, err := loopbackRedirect(r.PostFormValue("redirect_uri"))
	if err != nil {
		s.uiError(w, r, err)
		return
	}
	state, challenge := r.PostFormValue("state"), r.PostFormValue("code_challenge")
	if state == "" || challenge == "" {
		s.uiError(w, r, fmt.Errorf("%w: code_challenge and state are required", secrets.ErrInvalid))
		return
	}
	q := url.Values{"state": {state}}
	if deny {
		s.audit(r, "ui", "authorize", "", nil, errLoginDenied)
		q.Set("error", errLoginDenied.Error())
	} else {
		g, err := s.approvedGrant(r, false)
		if err != nil {
			s.redirectWithError(w, r, back, err)
			return
		}
		l := &login{name: g.name, challenge: challenge, code: rand.Text(), approved: true, grant: g}
		if err := s.grants.add(l); err != nil {
			s.uiError(w, r, err)
			return
		}
		q.Set("code", l.code)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// approvedGrant validates the approval form. Denied logins need no fields.
func (s *Server) approvedGrant(r *http.Request, deny bool) (grant, error) {
	if deny {
		s.audit(r, "ui", "authorize", "", nil, errLoginDenied)
		return grant{}, nil
	}
	if r.PostFormValue("confirm") != "yes" {
		return grant{}, errUnconfirmed
	}
	g, err := parseGrant(r, time.Now(), false)
	if err == nil {
		err = s.nameTaken(r, g.name)
	}
	s.audit(r, "ui", "authorize", g.path, nil, err, "name", g.name)
	return g, err
}

type deviceJSON struct {
	DeviceCode string `json:"deviceCode"`
	UserCode   string `json:"userCode"`
	// VerificationURI is relative to the server URL.
	VerificationURI string `json:"verificationUri"`
	ExpiresIn       int    `json:"expiresIn"`
	Interval        int    `json:"interval"`
}

// apiAuthorizeDevice starts a device login. It needs no token: the login
// gives nothing until an admin approves its user code in the Web UI.
func (s *Server) apiAuthorizeDevice(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, `body must be {"name": ...}`)
		return
	}
	l := &login{name: in.Name, userCode: newUserCode(), deviceCode: rand.Text()}
	if err := s.grants.add(l); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, deviceJSON{
		DeviceCode:      l.deviceCode,
		UserCode:        l.userCode,
		VerificationURI: "/authorize?" + url.Values{"user_code": {l.userCode}}.Encode(),
		ExpiresIn:       int(s.grants.ttl.Seconds()),
		Interval:        2,
	})
}

type issuedJSON struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	ReadOnly bool      `json:"readOnly"`
	Expires  time.Time `json:"expires,omitzero"`
	Token    string    `json:"token"`
}

// apiAuthorizeToken hands the token of an approved login to the CLI, once:
// for {"code", "codeVerifier"} of a loopback login or {"deviceCode"} of a
// device login.
func (s *Server) apiAuthorizeToken(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code, CodeVerifier, DeviceCode string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, `body must be {"code": ..., "codeVerifier": ...} or {"deviceCode": ...}`)
		return
	}
	var l *login
	var ok bool
	switch {
	case in.Code != "":
		l, ok = s.grants.find(func(l *login) bool { return equal(l.code, in.Code) }, true)
		if ok && !equal(l.challenge, pkceChallenge(in.CodeVerifier)) {
			ok = false
		}
	case in.DeviceCode != "":
		l, ok = s.grants.find(func(l *login) bool { return equal(l.deviceCode, in.DeviceCode) && (l.approved || l.denied) }, true)
		if !ok {
			if _, waiting := s.grants.find(func(l *login) bool { return equal(l.deviceCode, in.DeviceCode) }, false); waiting {
				writeError(w, http.StatusBadRequest, errLoginPending.Error())
				return
			}
		}
	}
	if !ok {
		writeError(w, http.StatusBadRequest, errLoginInvalid.Error())
		return
	}
	if l.denied {
		writeError(w, http.StatusForbidden, errLoginDenied.Error())
		return
	}
	t, secret, err := s.createToken(r, "api", l.grant)
	if err != nil {
		s.serviceError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, issuedJSON{Name: t.Name, Path: t.Path, ReadOnly: t.ReadOnly, Expires: t.Expires, Token: secret})
}

// pkceChallenge is the S256 code challenge of verifier (RFC 7636).
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
