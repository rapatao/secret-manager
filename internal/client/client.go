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

// New returns a Client for the server at baseURL using the admin token.
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
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
	q := url.Values{"path": {path}}
	if recursive {
		q.Set("recursive", "true")
	}
	var out struct{ Data map[string]string }
	err := c.do(ctx, http.MethodGet, "/api/v1/secrets", q, nil, &out)
	return out.Data, err
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

// Rollback replaces the data at path with version n.
func (c *Client) Rollback(ctx context.Context, path string, n int) error {
	return c.do(ctx, http.MethodPost, "/api/v1/history/"+strconv.Itoa(n)+"/rollback", url.Values{"path": {path}}, nil, nil)
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
	req.Header.Set("Authorization", "Bearer "+c.token)
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
