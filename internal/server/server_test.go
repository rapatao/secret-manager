package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/rapatao/secret-manager/internal/secrets"
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
)

const token = "0123456789abcdef0123456789abcdef"

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newTestServer(t *testing.T) *httptest.Server {
	ts, _ := newLoggedServer(t)
	return ts
}

func newLoggedServer(t *testing.T) (*httptest.Server, *syncBuffer) {
	t.Helper()
	svc := secrets.New(k8sstorage.New(fake.NewClientBuilder().Build(), "sm"), nil)
	svc.KeepVersions = 10
	s, err := New(svc, token)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	s.log = slog.New(slog.NewJSONHandler(logs, nil))
	ts := httptest.NewTLSServer(s)
	t.Cleanup(ts.Close)
	return ts, logs
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

func TestAPIHistory(t *testing.T) {
	ts := newTestServer(t)
	do(t, ts, "PUT", "/api/v1/secrets?path=/app", token, `{"A":"1"}`)
	do(t, ts, "PUT", "/api/v1/secrets?path=/app", token, `{"A":"2","B":"x"}`)
	do(t, ts, "DELETE", "/api/v1/paths?path=/app", token, "")

	var list struct {
		Versions []struct {
			Version int
			Keys    []string
			Data    map[string]string
		}
	}
	code, body := do(t, ts, "GET", "/api/v1/history?path=/app", token, "")
	if err := json.Unmarshal([]byte(body), &list); code != http.StatusOK || err != nil {
		t.Fatalf("history: %d %s", code, body)
	}
	if len(list.Versions) != 2 || list.Versions[0].Version != 2 || strings.Join(list.Versions[0].Keys, ",") != "A,B" || list.Versions[0].Data != nil {
		t.Fatalf("history must list keys without values: %s", body)
	}

	code, body = do(t, ts, "GET", "/api/v1/history/1?path=/app", token, "")
	if code != http.StatusOK || !strings.Contains(body, `"data":{"A":"1"}`) {
		t.Fatalf("version: %d %s", code, body)
	}

	if code, body := do(t, ts, "POST", "/api/v1/history/1/rollback?path=/app", token, ""); code != http.StatusNoContent {
		t.Fatalf("rollback: %d %s", code, body)
	}
	_, body = do(t, ts, "GET", "/api/v1/secrets?path=/app", token, "")
	if strings.TrimSpace(body) != `{"data":{"A":"1"}}` {
		t.Fatalf("after rollback: %s", body)
	}

	for path, want := range map[string]int{
		"/api/v1/history/9?path=/app":   http.StatusNotFound,
		"/api/v1/history/x?path=/app":   http.StatusBadRequest,
		"/api/v1/history/0?path=/app":   http.StatusBadRequest,
		"/api/v1/history?path=bad":      http.StatusBadRequest,
		"/api/v1/history/1?path=/other": http.StatusNotFound,
	} {
		if code, body := do(t, ts, "GET", path, token, ""); code != want {
			t.Errorf("GET %s: %d %s, want %d", path, code, body, want)
		}
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

func postForm(t *testing.T, c *http.Client, ts *httptest.Server, path string, form url.Values, origin string, headers ...string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
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
	postForm(t, c, ts, "/path", url.Values{"path": {"/other"}}, origin)
	_, body := get(t, c, ts.URL+"/?q=ap")
	if !strings.Contains(body, ">/app<") || strings.Contains(body, ">/other<") {
		t.Fatalf("search not filtering paths:\n%s", body)
	}
	if code, js := get(t, c, ts.URL+"/ui.js"); code != http.StatusOK || !strings.Contains(js, "clipboard") {
		t.Fatalf("ui.js: %d", code)
	}

	_, body = get(t, c, ts.URL+"/path?path=/app")
	if !strings.Contains(body, "PASS") || !strings.Contains(body, "&lt;s3cret&gt;") {
		t.Fatalf("path page missing escaped key/value:\n%s", body)
	}

	postForm(t, c, ts, "/key", url.Values{"path": {"/app"}, "key": {"PASS"}, "value": {"new"}}, origin)
	_, body = get(t, c, ts.URL+"/path?path=/app")
	if !strings.Contains(body, "<h2>History</h2>") || !strings.Contains(body, `name="version" value="2"`) {
		t.Fatalf("path page missing history:\n%s", body)
	}
	if code, _ := postForm(t, c, ts, "/path/rollback", url.Values{"path": {"/app"}, "version": {"2"}}, origin); code != http.StatusOK {
		t.Fatalf("rollback: %d", code)
	}
	_, body = get(t, c, ts.URL+"/path?path=/app")
	if !strings.Contains(body, `name="value" rows="3">&lt;s3cret&gt;</textarea>`) {
		t.Fatalf("rollback not applied:\n%s", body)
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

func TestUICrossOrigin(t *testing.T) {
	ts := newTestServer(t)
	c := uiClient(t, ts)
	login := url.Values{"token": {token}}

	// Browsers send Origin: null on same-origin posts under Referrer-Policy: no-referrer.
	if code, _ := postForm(t, c, ts, "/login", login, "null", "Sec-Fetch-Site", "same-origin"); code != http.StatusOK {
		t.Fatalf("same-origin post with Origin null: %d", code)
	}
	if code, _ := postForm(t, c, ts, "/login", login, "https://evil.example", "Sec-Fetch-Site", "cross-site"); code != http.StatusForbidden {
		t.Fatalf("cross-site post: %d", code)
	}
	if code, _ := postForm(t, c, ts, "/login", login, ""); code != http.StatusOK {
		t.Fatalf("post without browser headers: %d", code)
	}
}

func TestAuditLog(t *testing.T) {
	ts, logs := newLoggedServer(t)
	do(t, ts, "PUT", "/api/v1/secrets?path=/app", token, `{"PASS":"hunter2","USER":"bob"}`)
	do(t, ts, "DELETE", "/api/v1/secrets/USER?path=/app", token, "")
	do(t, ts, "DELETE", "/api/v1/paths?path=/BAD", token, "")
	do(t, ts, "GET", "/api/v1/paths", "wrong-token", "")
	c := uiClient(t, ts)
	postForm(t, c, ts, "/login", url.Values{"token": {"wrong"}}, ts.URL)

	type entry struct {
		Level, Msg, Source, Op, Path, Error string
		Keys                                []string
	}
	var got []entry
	for line := range strings.Lines(logs.String()) {
		var e entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if e.Msg == "audit" {
			e.Msg = ""
			e.Error, _, _ = strings.Cut(e.Error, ":")
			got = append(got, e)
		}
	}
	want := []entry{
		{Level: "INFO", Source: "api", Op: "set", Path: "/app", Keys: []string{"PASS", "USER"}},
		{Level: "INFO", Source: "api", Op: "delete_key", Path: "/app", Keys: []string{"USER"}},
		{Level: "WARN", Source: "api", Op: "delete_path", Path: "/BAD", Error: "invalid input"},
		{Level: "WARN", Source: "api", Op: "auth", Error: "invalid token"},
		{Level: "WARN", Source: "ui", Op: "login", Error: "invalid token"},
	}
	if g, w := fmtEntries(got), fmtEntries(want); g != w {
		t.Fatalf("audit entries\n got %s\nwant %s", g, w)
	}
	if strings.Contains(logs.String(), "hunter2") {
		t.Fatal("secret value logged")
	}
}

func fmtEntries[T any](v []T) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// brokenServer returns a Server whose storage fails every List and Get.
func brokenServer(t *testing.T) (*Server, *syncBuffer) {
	t.Helper()
	fail := errors.New("apiserver down")
	c := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error { return fail },
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return fail
		},
	}).Build()
	s, err := New(secrets.New(k8sstorage.New(c, "sm"), nil), token)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	s.log = slog.New(slog.NewJSONHandler(logs, nil))
	return s, logs
}

func serve(s http.Handler, req *http.Request) int {
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec.Code
}

func TestReadyz(t *testing.T) {
	ts := newTestServer(t)
	if code, _ := do(t, ts, "GET", "/readyz", "", ""); code != http.StatusOK {
		t.Fatalf("healthy readyz: %d", code)
	}
	s, _ := brokenServer(t)
	if code := serve(s, httptest.NewRequest(http.MethodGet, "/readyz", nil)); code != http.StatusServiceUnavailable {
		t.Fatalf("broken readyz: %d", code)
	}
}

func TestFailureLogHasRequestContext(t *testing.T) {
	s, logs := brokenServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets?path=/app", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if code := serve(s, req); code != http.StatusInternalServerError {
		t.Fatalf("code %d", code)
	}
	var e struct{ Msg, Method, URL, Path, Error string }
	if err := json.Unmarshal([]byte(logs.String()), &e); err != nil {
		t.Fatalf("log %q: %v", logs.String(), err)
	}
	if e.Msg != "secret operation failed" || e.Method != http.MethodGet || e.URL != "/api/v1/secrets" || e.Path != "/app" ||
		!strings.Contains(e.Error, "apiserver down") {
		t.Fatalf("log entry %+v", e)
	}
}

func TestAPIInfo(t *testing.T) {
	ts := newTestServer(t)
	if code, _ := do(t, ts, "GET", "/api/v1/info", "", ""); code != http.StatusUnauthorized {
		t.Fatalf("info without token: %d", code)
	}
	code, body := do(t, ts, "GET", "/api/v1/info", token, "")
	if code != http.StatusOK || strings.TrimSpace(body) != `{"capabilities":["backup","history","paths","secrets"],"version":""}` {
		t.Fatalf("info: %d %s", code, body)
	}
}

func TestAPIBackupRestore(t *testing.T) {
	src, logs := newLoggedServer(t)
	do(t, src, "PUT", "/api/v1/secrets?path=/app", token, `{"A":"1"}`)
	do(t, src, "PUT", "/api/v1/secrets?path=/app", token, `{"A":"2"}`)

	code, plain := do(t, src, "GET", "/api/v1/backup", token, "")
	if code != http.StatusOK || !strings.Contains(plain, `"format":1`) ||
		!strings.Contains(plain, `"paths":[{"path":"/app","data":{"A":"2"}}]`) {
		t.Fatalf("backup: %d %s", code, plain)
	}
	_, full := do(t, src, "GET", "/api/v1/backup?history=true", token, "")
	if strings.Count(full, `"version":`) != 2 {
		t.Fatalf("backup with history: %s", full)
	}
	if !strings.Contains(logs.String(), `"op":"backup"`) {
		t.Fatalf("backup not audited: %s", logs)
	}

	dst := newTestServer(t)
	if code, body := do(t, dst, "POST", "/api/v1/restore", token, full); code != http.StatusOK || strings.TrimSpace(body) != `{"paths":1}` {
		t.Fatalf("restore: %d %s", code, body)
	}
	if _, body := do(t, dst, "GET", "/api/v1/secrets?path=/app", token, ""); strings.TrimSpace(body) != `{"data":{"A":"2"}}` {
		t.Fatalf("restored data: %s", body)
	}
	if _, body := do(t, dst, "GET", "/api/v1/history?path=/app", token, ""); strings.Count(body, `"version":`) != 2 {
		t.Fatalf("restored history: %s", body)
	}

	for _, body := range []string{`nope`, `{"format":2,"paths":[]}`, `{"format":1,"paths":[{"path":"bad"}]}`} {
		if code, _ := do(t, dst, "POST", "/api/v1/restore", token, body); code != http.StatusBadRequest {
			t.Errorf("restore %s: status %d", body, code)
		}
	}
}

func TestSessionSurvivesRestart(t *testing.T) {
	id := newSessions([]byte(token), time.Hour).create()
	if !newSessions([]byte(token), time.Hour).valid(id) {
		t.Fatal("session rejected after restart with same token")
	}
	if newSessions([]byte(token+"x"), time.Hour).valid(id) {
		t.Fatal("session accepted after token change")
	}
	if newSessions([]byte(token), time.Hour).valid("9" + id) {
		t.Fatal("tampered session accepted")
	}
	expired := newSessions([]byte(token), -time.Hour)
	if expired.valid(expired.create()) {
		t.Fatal("expired session accepted")
	}
}
