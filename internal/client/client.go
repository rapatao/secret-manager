// Package client is a Go client for the secret-manager REST API.
package client

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Client calls a secret-manager server. It is not safe for concurrent use.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
	info    *Info
}

// Error is a non-2xx API response.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.Status, e.Message)
}

// New returns a Client for the server at baseURL using token, which may be
// empty for the login calls.
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// WithTransport makes c send its requests through rt and returns c.
func (c *Client) WithTransport(rt http.RoundTripper) *Client {
	c.http.Transport = rt
	return c
}

// Info describes a server: its version and the API features it supports.
type Info struct {
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities"`
}

// Baseline lists the capabilities of servers released before
// /api/v1/info, which report no version.
var Baseline = []string{"history", "paths", "secrets"}

// Info returns the server version and capabilities, fetched once per Client.
// A server without /api/v1/info reports Baseline and an empty Version.
func (c *Client) Info(ctx context.Context) (Info, error) {
	if c.info != nil {
		return *c.info, nil
	}
	var out Info
	err := c.do(ctx, http.MethodGet, "/api/v1/info", nil, nil, &out)
	if apiErr := (*Error)(nil); errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
		out, err = Info{Capabilities: Baseline}, nil
	}
	if err != nil {
		return Info{}, err
	}
	c.info = &out
	return out, nil
}

// Require returns an error unless the server supports capability.
func (c *Client) Require(ctx context.Context, capability string) error {
	info, err := c.Info(ctx)
	if err != nil {
		return err
	}
	if slices.Contains(info.Capabilities, capability) {
		return nil
	}
	return fmt.Errorf("server %s at %s does not support %s; upgrade the server",
		cmp.Or(info.Version, "(unknown version)"), c.baseURL, capability)
}

// Paths lists every stored path.
func (c *Client) Paths(ctx context.Context) ([]string, error) {
	var out struct{ Paths []string }
	err := c.do(ctx, http.MethodGet, "/api/v1/paths", nil, nil, &out)
	return out.Paths, err
}

// Get returns the secrets at path, merging nested paths when recursive.
func (c *Client) Get(ctx context.Context, path string, recursive bool) (map[string]string, error) {
	data, _, err := c.Read(ctx, path, "", recursive)
	return data, err
}

// Read is Get that also returns how long the server allows the secrets to be
// used from a cache while it is unreachable, nil when the server does not say.
// A non-empty key asks the server for that key only. Servers without the
// secrets-key capability send the whole path, and Read drops the other keys.
func (c *Client) Read(ctx context.Context, path, key string, recursive bool) (map[string]string, *time.Duration, error) {
	q := url.Values{"path": {path}}
	if recursive {
		q.Set("recursive", "true")
	}
	endpoint := "/api/v1/secrets"
	if key != "" {
		endpoint += "/" + url.PathEscape(key)
	}
	var out struct {
		Data        map[string]string
		CacheMaxAge *int
	}
	err := c.do(ctx, http.MethodGet, endpoint, q, nil, &out)
	// Servers before secrets-key only route DELETE on /api/v1/secrets/{key}.
	if apiErr := (*Error)(nil); key != "" && errors.As(err, &apiErr) && apiErr.Status == http.StatusMethodNotAllowed {
		data, maxAge, err := c.Read(ctx, path, "", recursive)
		if err != nil {
			return nil, nil, err
		}
		v, ok := data[key]
		if !ok {
			return nil, nil, &Error{Status: http.StatusNotFound, Message: fmt.Sprintf("key %s not found in %s", key, path)}
		}
		return map[string]string{key: v}, maxAge, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if out.CacheMaxAge == nil {
		return out.Data, nil, nil
	}
	maxAge := time.Duration(*out.CacheMaxAge) * time.Second
	return out.Data, &maxAge, nil
}

// Set merges values into path.
func (c *Client) Set(ctx context.Context, path string, values map[string]string) error {
	return c.do(ctx, http.MethodPut, "/api/v1/secrets", url.Values{"path": {path}}, values, nil)
}

// DeleteKey removes key from path.
func (c *Client) DeleteKey(ctx context.Context, path, key string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/secrets/"+url.PathEscape(key), url.Values{"path": {path}}, nil, nil)
}

// DeletePath removes path.
func (c *Client) DeletePath(ctx context.Context, path string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/paths", url.Values{"path": {path}}, nil, nil)
}

// CopyPath copies path, with its versions, to the new path to; with move,
// path is deleted afterwards.
func (c *Client) CopyPath(ctx context.Context, path, to string, move bool) error {
	op := "/api/v1/paths/copy"
	if move {
		op = "/api/v1/paths/move"
	}
	return c.do(ctx, http.MethodPost, op, url.Values{"path": {path}, "to": {to}}, nil, nil)
}

// Version is a stored version of a path. History fills Keys, Version fills
// Data.
type Version struct {
	Version int               `json:"version"`
	Time    time.Time         `json:"time"`
	Keys    []string          `json:"keys"`
	Data    map[string]string `json:"data"`
}

// History lists the versions of path, newest first.
func (c *Client) History(ctx context.Context, path string) ([]Version, error) {
	var out struct{ Versions []Version }
	err := c.do(ctx, http.MethodGet, "/api/v1/history", url.Values{"path": {path}}, nil, &out)
	return out.Versions, err
}

// Version returns version n of path with its data.
func (c *Client) Version(ctx context.Context, path string, n int) (Version, error) {
	var out Version
	err := c.do(ctx, http.MethodGet, "/api/v1/history/"+strconv.Itoa(n), url.Values{"path": {path}}, nil, &out)
	return out, err
}

// DeleteVersion deletes version n of path.
func (c *Client) DeleteVersion(ctx context.Context, path string, n int) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/history/"+strconv.Itoa(n), url.Values{"path": {path}}, nil, nil)
}

// Rollback replaces the data at path with version n.
func (c *Client) Rollback(ctx context.Context, path string, n int) error {
	return c.do(ctx, http.MethodPost, "/api/v1/history/"+strconv.Itoa(n)+"/rollback", url.Values{"path": {path}}, nil, nil)
}

// Backup returns a backup document holding every path, with its versions
// when withHistory.
func (c *Client) Backup(ctx context.Context, withHistory bool) (json.RawMessage, error) {
	var q url.Values
	if withHistory {
		q = url.Values{"history": {"true"}}
	}
	var out json.RawMessage
	err := c.do(ctx, http.MethodGet, "/api/v1/backup", q, nil, &out)
	return out, err
}

// Restore writes a backup document made by Backup and returns the number of
// paths it held.
func (c *Client) Restore(ctx context.Context, backup json.RawMessage) (int, error) {
	var out struct{ Paths int }
	err := c.do(ctx, http.MethodPost, "/api/v1/restore", nil, backup, &out)
	return out.Paths, err
}

// Login is the integration token issued for an approved CLI login.
type Login struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	ReadOnly bool      `json:"readOnly"`
	Expires  time.Time `json:"expires"`
	Token    string    `json:"token"`
}

// Device is a device login waiting for approval of UserCode in the Web UI.
type Device struct {
	DeviceCode string `json:"deviceCode"`
	UserCode   string `json:"userCode"`
	// VerificationURI is the absolute URL of the approval page.
	VerificationURI string `json:"verificationUri"`
	ExpiresIn       int    `json:"expiresIn"`
	Interval        int    `json:"interval"`
}

// ErrPending is returned by PollDevice until the login is approved.
var ErrPending = errors.New("login not approved yet")

// ErrNoBrowserLogin is returned by the login calls when the server predates
// browser logins.
var ErrNoBrowserLogin = errors.New("server does not support browser login; upgrade it or log in with --token-stdin")

// URL returns the server URL.
func (c *Client) URL() string { return c.baseURL }

func loginError(err error) error {
	var apiErr *Error
	if errors.As(err, &apiErr) && (apiErr.Status == http.StatusNotFound || apiErr.Status == http.StatusMethodNotAllowed) {
		return ErrNoBrowserLogin
	}
	return err
}

// CheckBrowserLogin returns ErrNoBrowserLogin when the server cannot issue
// tokens through the browser.
func (c *Client) CheckBrowserLogin(ctx context.Context) error {
	err := c.do(ctx, http.MethodPost, "/api/v1/authorize/token", nil, struct{}{}, nil)
	if apiErr := (*Error)(nil); errors.As(err, &apiErr) && apiErr.Status == http.StatusBadRequest {
		return nil
	}
	return loginError(err)
}

// ExchangeCode returns the token of a loopback login approved with code,
// proving the login was started here with the PKCE verifier.
func (c *Client) ExchangeCode(ctx context.Context, code, verifier string) (Login, error) {
	var out Login
	err := c.do(ctx, http.MethodPost, "/api/v1/authorize/token", nil, map[string]string{"code": code, "codeVerifier": verifier}, &out)
	return out, loginError(err)
}

// StartDevice starts a device login suggesting name for the integration.
func (c *Client) StartDevice(ctx context.Context, name string) (Device, error) {
	var out Device
	if err := c.do(ctx, http.MethodPost, "/api/v1/authorize/device", nil, map[string]string{"name": name}, &out); err != nil {
		return Device{}, loginError(err)
	}
	out.VerificationURI = c.baseURL + out.VerificationURI
	return out, nil
}

// PollDevice returns the token of an approved device login, or ErrPending.
func (c *Client) PollDevice(ctx context.Context, d Device) (Login, error) {
	var out Login
	err := c.do(ctx, http.MethodPost, "/api/v1/authorize/token", nil, map[string]string{"deviceCode": d.DeviceCode}, &out)
	if apiErr := (*Error)(nil); errors.As(err, &apiErr) && apiErr.Message == "authorization_pending" {
		return Login{}, ErrPending
	}
	return out, loginError(err)
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	u := c.baseURL + path
	if query != nil {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode >= 300 {
		var e struct{ Error string }
		_ = json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&e)
		return &Error{Status: res.StatusCode, Message: e.Error}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(res.Body).Decode(out)
}
