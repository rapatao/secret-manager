package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/rapatao/secret-manager/internal/secrets"
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
)

const token = "0123456789abcdef0123456789abcdef"

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	svc := secrets.New(k8sstorage.New(fake.NewClientBuilder().Build(), "sm"), nil)
	s, err := New(svc, token)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(s)
	t.Cleanup(ts.Close)
	return ts
}

func do(t *testing.T, ts *httptest.Server, method, path, auth, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func TestNewRejectsShortToken(t *testing.T) {
	if _, err := New(nil, "short"); err == nil {
		t.Fatal("want error")
	}
}

func TestAPIAuth(t *testing.T) {
	ts := newTestServer(t)
	for _, auth := range []string{"", "wrong-token"} {
		if code, _ := do(t, ts, "GET", "/api/v1/paths", auth, ""); code != http.StatusUnauthorized {
			t.Errorf("auth %q: status %d", auth, code)
		}
	}
	if code, _ := do(t, ts, "GET", "/healthz", "", ""); code != http.StatusOK {
		t.Errorf("healthz status %d", code)
	}
}

func TestAPIRoundTrip(t *testing.T) {
	ts := newTestServer(t)

	if code, body := do(t, ts, "PUT", "/api/v1/secrets?path=/app", token, `{"A":"1","B":"2"}`); code != http.StatusNoContent {
		t.Fatalf("set: %d %s", code, body)
	}
	if code, _ := do(t, ts, "PUT", "/api/v1/secrets?path=/app/db", token, `{"B":"db"}`); code != http.StatusNoContent {
		t.Fatalf("set nested: %d", code)
	}

	code, body := do(t, ts, "GET", "/api/v1/paths", token, "")
	if code != http.StatusOK || strings.TrimSpace(body) != `{"paths":["/app","/app/db"]}` {
		t.Fatalf("paths: %d %s", code, body)
	}

	var got struct{ Data map[string]string }
	_, body = do(t, ts, "GET", "/api/v1/secrets?path=/app&recursive=true", token, "")
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Data["A"] != "1" || got.Data["B"] != "db" {
		t.Fatalf("recursive get: %s", body)
	}

	if code, _ := do(t, ts, "DELETE", "/api/v1/secrets/A?path=/app", token, ""); code != http.StatusNoContent {
		t.Fatalf("delete key: %d", code)
	}
	_, body = do(t, ts, "GET", "/api/v1/secrets?path=/app", token, "")
	if strings.TrimSpace(body) != `{"data":{"B":"2"}}` {
		t.Fatalf("after delete key: %s", body)
	}

	if code, _ := do(t, ts, "DELETE", "/api/v1/paths?path=/app", token, ""); code != http.StatusNoContent {
		t.Fatalf("delete path: %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/v1/secrets?path=/app", token, ""); code != http.StatusNotFound {
		t.Fatalf("get deleted path: %d", code)
	}
}

func TestAPIErrors(t *testing.T) {
	ts := newTestServer(t)
	cases := []struct {
		method, path, body string
		want               int
	}{
		{"PUT", "/api/v1/secrets?path=/app", `not json`, http.StatusBadRequest},
		{"PUT", "/api/v1/secrets?path=/app", `{"A":1}`, http.StatusBadRequest},
		{"PUT", "/api/v1/secrets?path=bad", `{"A":"1"}`, http.StatusBadRequest},
		{"PUT", "/api/v1/secrets?path=/app", `{"bad key":"1"}`, http.StatusBadRequest},
		{"GET", "/api/v1/secrets?path=/missing", ``, http.StatusNotFound},
	}
	for _, tc := range cases {
		if code, body := do(t, ts, tc.method, tc.path, token, tc.body); code != tc.want {
			t.Errorf("%s %s %s: %d %s, want %d", tc.method, tc.path, tc.body, code, body, tc.want)
		}
	}
}

func uiClient(t *testing.T, ts *httptest.Server) *http.Client {
	t.Helper()
	c := ts.Client()
	jar, _ := cookiejar.New(nil)
	c.Jar = jar
	return c
}

func postForm(t *testing.T, c *http.Client, ts *httptest.Server, path string, form url.Values, origin string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func get(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	res, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func TestUIRequiresLogin(t *testing.T) {
	ts := newTestServer(t)
	c := uiClient(t, ts)
	code, body := get(t, c, ts.URL+"/")
	if code != http.StatusOK || !strings.Contains(body, `name="token"`) {
		t.Fatalf("want login page, got %d", code)
	}
	code, _ = postForm(t, c, ts, "/login", url.Values{"token": {"wrong"}}, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("bad login: %d", code)
	}
}

func TestUIFlow(t *testing.T) {
	ts := newTestServer(t)
	c := uiClient(t, ts)
	origin := ts.URL

	if code, _ := postForm(t, c, ts, "/login", url.Values{"token": {token}}, origin); code != http.StatusOK {
		t.Fatalf("login: %d", code)
	}
	if code, _ := postForm(t, c, ts, "/path", url.Values{"path": {"/app"}}, origin); code != http.StatusOK {
		t.Fatalf("create path: %d", code)
	}
	if code, _ := postForm(t, c, ts, "/key", url.Values{"path": {"/app"}, "key": {"PASS"}, "value": {"<s3cret>"}}, origin); code != http.StatusOK {
		t.Fatalf("set key: %d", code)
	}
	_, body := get(t, c, ts.URL+"/path?path=/app")
	if !strings.Contains(body, "PASS") || !strings.Contains(body, "&lt;s3cret&gt;") {
		t.Fatalf("path page missing escaped key/value:\n%s", body)
	}

	_, body = postForm(t, c, ts, "/key", url.Values{"path": {"/app"}, "key": {"bad key"}, "value": {"x"}}, origin)
	if !strings.Contains(body, `class="error"`) {
		t.Fatal("invalid key error not shown")
	}

	if code, _ := postForm(t, c, ts, "/key", url.Values{"path": {"/app"}, "key": {"X"}, "value": {"1"}}, "https://evil.example"); code != http.StatusForbidden {
		t.Fatalf("cross-origin post: %d", code)
	}

	if code, _ := postForm(t, c, ts, "/logout", nil, origin); code != http.StatusOK {
		t.Fatalf("logout: %d", code)
	}
	_, body = get(t, c, ts.URL+"/")
	if !strings.Contains(body, `name="token"`) {
		t.Fatal("session still valid after logout")
	}
}
