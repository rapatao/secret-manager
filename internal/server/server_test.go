package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/storage"
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
	"github.com/rapatao/secret-manager/internal/tokens"
)

const token = "0123456789abcdef0123456789abcdef"

// apiToken is a read-write integration token for /, stored by newLoggedServer.
const apiToken = "smt_testfullaccess"

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

func newLoggedServer(t *testing.T, configure ...func(*Server)) (*httptest.Server, *syncBuffer) {
	t.Helper()
	backend := k8sstorage.New(fake.NewClientBuilder().Build(), "sm")
	svc := secrets.New(backend, nil)
	svc.KeepVersions = 10
	sum := sha256.Sum256([]byte(apiToken))
	if err := backend.PutTokens(context.Background(), []storage.Token{{Name: "full", Hash: hex.EncodeToString(sum[:]), Path: "/"}}); err != nil {
		t.Fatal(err)
	}
	s, err := New(svc, tokens.New(backend), token)
	if err != nil {
		t.Fatal(err)
	}
	s.Version = "v9.9.9-test"
	logs := &syncBuffer{}
	s.log = slog.New(slog.NewJSONHandler(logs, nil))
	for _, f := range configure {
		f(s)
	}
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
	if _, err := New(nil, nil, "short"); err == nil {
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

	if code, body := do(t, ts, "PUT", "/api/v1/secrets?path=/app", apiToken, `{"A":"1","B":"2"}`); code != http.StatusNoContent {
		t.Fatalf("set: %d %s", code, body)
	}
	if code, _ := do(t, ts, "PUT", "/api/v1/secrets?path=/app/db", apiToken, `{"B":"db"}`); code != http.StatusNoContent {
		t.Fatalf("set nested: %d", code)
	}

	code, body := do(t, ts, "GET", "/api/v1/paths", apiToken, "")
	if code != http.StatusOK || strings.TrimSpace(body) != `{"paths":["/app","/app/db"]}` {
		t.Fatalf("paths: %d %s", code, body)
	}

	var got struct{ Data map[string]string }
	_, body = do(t, ts, "GET", "/api/v1/secrets?path=/app&recursive=true", apiToken, "")
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Data["A"] != "1" || got.Data["B"] != "db" {
		t.Fatalf("recursive get: %s", body)
	}

	if code, _ := do(t, ts, "DELETE", "/api/v1/secrets/A?path=/app", apiToken, ""); code != http.StatusNoContent {
		t.Fatalf("delete key: %d", code)
	}
	_, body = do(t, ts, "GET", "/api/v1/secrets?path=/app", apiToken, "")
	if strings.TrimSpace(body) != `{"cacheMaxAge":604800,"data":{"B":"2"}}` {
		t.Fatalf("after delete key: %s", body)
	}

	if code, _ := do(t, ts, "DELETE", "/api/v1/paths?path=/app", apiToken, ""); code != http.StatusNoContent {
		t.Fatalf("delete path: %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/v1/secrets?path=/app", apiToken, ""); code != http.StatusNotFound {
		t.Fatalf("get deleted path: %d", code)
	}
}

func TestAPIHistory(t *testing.T) {
	ts := newTestServer(t)
	do(t, ts, "PUT", "/api/v1/secrets?path=/app", apiToken, `{"A":"1"}`)
	do(t, ts, "PUT", "/api/v1/secrets?path=/app", apiToken, `{"A":"2","B":"x"}`)
	do(t, ts, "DELETE", "/api/v1/paths?path=/app", apiToken, "")

	var list struct {
		Versions []struct {
			Version int
			Keys    []string
			Data    map[string]string
		}
	}
	code, body := do(t, ts, "GET", "/api/v1/history?path=/app", apiToken, "")
	if err := json.Unmarshal([]byte(body), &list); code != http.StatusOK || err != nil {
		t.Fatalf("history: %d %s", code, body)
	}
	if len(list.Versions) != 2 || list.Versions[0].Version != 2 || strings.Join(list.Versions[0].Keys, ",") != "A,B" || list.Versions[0].Data != nil {
		t.Fatalf("history must list keys without values: %s", body)
	}

	code, body = do(t, ts, "GET", "/api/v1/history/1?path=/app", apiToken, "")
	if code != http.StatusOK || !strings.Contains(body, `"data":{"A":"1"}`) {
		t.Fatalf("version: %d %s", code, body)
	}

	if code, body := do(t, ts, "POST", "/api/v1/history/1/rollback?path=/app", apiToken, ""); code != http.StatusNoContent {
		t.Fatalf("rollback: %d %s", code, body)
	}
	_, body = do(t, ts, "GET", "/api/v1/secrets?path=/app", apiToken, "")
	if strings.TrimSpace(body) != `{"cacheMaxAge":604800,"data":{"A":"1"}}` {
		t.Fatalf("after rollback: %s", body)
	}

	for path, want := range map[string]int{
		"/api/v1/history/9?path=/app":   http.StatusNotFound,
		"/api/v1/history/x?path=/app":   http.StatusBadRequest,
		"/api/v1/history/0?path=/app":   http.StatusBadRequest,
		"/api/v1/history?path=bad":      http.StatusBadRequest,
		"/api/v1/history/1?path=/other": http.StatusNotFound,
	} {
		if code, body := do(t, ts, "GET", path, apiToken, ""); code != want {
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
		if code, body := do(t, ts, tc.method, tc.path, apiToken, tc.body); code != tc.want {
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
	if _, body := get(t, c, ts.URL+"/login"); !strings.Contains(body, `<link rel="icon" href="data:image/svg+xml,`) {
		t.Fatalf("favicon missing:\n%s", body)
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
	if _, body := postForm(t, c, ts, "/secrets", url.Values{"path": {"/app"}}, origin); !strings.Contains(body, "confirm the action first") || strings.Contains(body, `data-path="/app"`) {
		t.Fatalf("path created without confirmation:\n%s", body)
	}
	if code, _ := postForm(t, c, ts, "/secrets", url.Values{"path": {"/app"}, "confirm": {"yes"}}, origin); code != http.StatusOK {
		t.Fatalf("create path: %d", code)
	}
	if code, _ := postForm(t, c, ts, "/secrets/keys", url.Values{"path": {"/app"}, "key": {"PASS"}, "value": {"<s3cret>"}, "confirm": {"yes"}}, origin); code != http.StatusOK {
		t.Fatalf("set key: %d", code)
	}
	postForm(t, c, ts, "/secrets", url.Values{"path": {"/other"}, "confirm": {"yes"}}, origin)
	_, body := get(t, c, ts.URL+"/secrets")
	if !strings.Contains(body, `Secret Manager</a><span class="muted mono">(v9.9.9-test)</span>`) || !strings.Contains(body, `href="/secrets">Secrets</a>`) || !strings.Contains(body, `href="/integrations">Integrations</a>`) {
		t.Fatalf("header missing server version:\n%s", body)
	}
	if !strings.Contains(body, `<tr data-path="/app">`) || !strings.Contains(body, `<tr data-path="/other">`) || strings.Contains(body, ">Search<") {
		t.Fatalf("paths not listed for filtering:\n%s", body)
	}
	if code, js := get(t, c, ts.URL+"/ui.js"); code != http.StatusOK || !strings.Contains(js, "clipboard") {
		t.Fatalf("ui.js: %d", code)
	}

	_, body = get(t, c, ts.URL+"/secrets/path?path=/app")
	if !strings.Contains(body, "PASS") || !strings.Contains(body, "&lt;s3cret&gt;") {
		t.Fatalf("path page missing escaped key/value:\n%s", body)
	}
	if !strings.Contains(body, `<span class="masked mono" aria-hidden="true">`) || !strings.Contains(body, `<td class="muted" data-label="Changed"><time datetime=`) {
		t.Fatalf("path page missing masked value or change time:\n%s", body)
	}

	postForm(t, c, ts, "/secrets/keys", url.Values{"path": {"/app"}, "key": {"PASS"}, "value": {"new"}, "confirm": {"yes"}}, origin)
	_, body = get(t, c, ts.URL+"/secrets/path?path=/app")
	if !strings.Contains(body, "<h2>History</h2>") || !strings.Contains(body, `name="version" value="2"`) ||
		!strings.Contains(body, `<span class="change mod">~PASS</span>`) || !strings.Contains(body, `<span class="change add">&#43;PASS</span>`) {
		t.Fatalf("path page missing history:\n%s", body)
	}
	if !strings.Contains(body, `<span class="badge">current</span>`) || strings.Contains(body, `<dialog id="restore-3">`) {
		t.Fatalf("current version offered for restore:\n%s", body)
	}
	if strings.Contains(body, "<th>Data</th>") || !strings.Contains(body, `<dialog id="diff-2">`) || strings.Contains(body, `<dialog id="diff-3">`) {
		t.Fatalf("history not offering a diff modal instead of the data column:\n%s", body)
	}
	_, diff, _ := strings.Cut(body, `<dialog id="diff-2">`)
	diff, _, _ = strings.Cut(diff, "</dialog>")
	if strings.Contains(diff, "<details") || !strings.Contains(diff, `<tr class="mod"><td class="mono">~</td><td><code>PASS</code></td><td><code>new</code></td>`) {
		t.Fatalf("history diff values hidden or uncolored:\n%s", diff)
	}
	if strings.Contains(body, "show values") {
		t.Fatalf("diff values hidden:\n%s", body)
	}
	if !strings.Contains(body, `<td class="mono">~</td><td><code>PASS</code></td><td><code>new</code></td><td><code>&lt;s3cret&gt;</code></td>`) {
		t.Fatalf("restore dialog missing diff:\n%s", body)
	}
	_, body = postForm(t, c, ts, "/secrets/rollback", url.Values{"path": {"/app"}, "version": {"2"}}, origin)
	if !strings.Contains(body, "confirm the action first") {
		t.Fatalf("rollback without confirmation:\n%s", body)
	}
	if code, _ := postForm(t, c, ts, "/secrets/rollback", url.Values{"path": {"/app"}, "version": {"2"}, "confirm": {"2"}}, origin); code != http.StatusOK {
		t.Fatalf("rollback: %d", code)
	}
	_, body = get(t, c, ts.URL+"/secrets/path?path=/app")
	if !strings.Contains(body, `form="edit-keys">&lt;s3cret&gt;</textarea>`) {
		t.Fatalf("rollback not applied:\n%s", body)
	}

	_, body = postForm(t, c, ts, "/secrets/keys", url.Values{"path": {"/app"}, "key": {"PASS"}, "value": {"x"}}, origin)
	if !strings.Contains(body, "confirm the action first") {
		t.Fatalf("save without confirmation:\n%s", body)
	}

	_, body = postForm(t, c, ts, "/secrets/keys", url.Values{"path": {"/app"}, "key": {"bad key"}, "value": {"x"}, "confirm": {"yes"}}, origin)
	if !strings.Contains(body, `class="error"`) {
		t.Fatal("invalid key error not shown")
	}

	if code, _ := postForm(t, c, ts, "/secrets/keys", url.Values{"path": {"/app"}, "key": {"X"}, "value": {"1"}, "confirm": {"yes"}}, "https://evil.example"); code != http.StatusForbidden {
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

func TestUISummary(t *testing.T) {
	ts := newTestServer(t)
	do(t, ts, "PUT", "/api/v1/secrets?path=/app", apiToken, `{"A":"1","B":"2"}`)
	do(t, ts, "PUT", "/api/v1/secrets?path=/app", apiToken, `{"C":"3"}`)
	do(t, ts, "PUT", "/api/v1/secrets?path=/gone", apiToken, `{"D":"4"}`)
	do(t, ts, "DELETE", "/api/v1/paths?path=/gone", apiToken, "")
	createToken(t, ts, url.Values{"name": {"soon"}, "path": {"/app"}, "expires": {"7d"}})

	c := uiClient(t, ts)
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL)
	code, body := get(t, c, ts.URL+"/")
	for _, want := range []string{
		`<span class="value">1</span><span class="muted">Paths</span>`,
		`<span class="value">3</span><span class="muted">Keys</span>`,
		`<span class="value">1</span><span class="muted">Deleted paths</span>`,
		`<span class="value">3</span><span class="muted">Stored versions</span>`,
		`<tr><td>Expiring within 7 days</td><td>1</td></tr>`,
		`<span class="change add">&#43;C</span>`,
		`<tr><td>History limit</td><td>10 versions per path</td></tr>`,
		`<tr><td>Offline cache default</td><td>7 days</td></tr>`,
		` UTC</span></time></td>`,
	} {
		if code != http.StatusOK || !strings.Contains(body, want) {
			t.Fatalf("summary: %d, missing %s\n%s", code, want, body)
		}
	}
	if strings.Contains(body, `data-path=`) {
		t.Fatalf("summary lists paths:\n%s", body)
	}
}

func TestShortDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{24 * time.Hour: "24h", 90 * time.Minute: "1h30m", 30 * time.Minute: "30m", 30 * time.Second: "30s", 0: "0s"} {
		if got := shortDuration(d); got != want {
			t.Errorf("shortDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestUIHistoryCurrentOnlyNewest(t *testing.T) {
	ts := newTestServer(t)
	c := uiClient(t, ts)
	origin := ts.URL
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, origin)
	postForm(t, c, ts, "/secrets", url.Values{"path": {"/dup"}, "confirm": {"yes"}}, origin)
	add := url.Values{"path": {"/dup"}, "new-key": {"KEY"}, "new-value": {"v"}, "confirm": {"yes"}}
	postForm(t, c, ts, "/secrets/keys", add, origin)
	postForm(t, c, ts, "/secrets/keys", url.Values{"path": {"/dup"}, "delete": {"KEY"}, "confirm": {"yes"}}, origin)
	postForm(t, c, ts, "/secrets/keys", add, origin)
	_, body := get(t, c, ts.URL+"/secrets/path?path=/dup")
	if strings.Count(body, `<span class="badge">current</span>`) != 1 || strings.Count(body, "same as current") != 1 ||
		!strings.Contains(body, `<dialog id="restore-3">`) || strings.Contains(body, `<dialog id="restore-2">`) {
		t.Fatalf("history current markers:\n%s", body)
	}
}

func TestUIDeletedPath(t *testing.T) {
	ts := newTestServer(t)
	c := uiClient(t, ts)
	origin := ts.URL
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, origin)
	postForm(t, c, ts, "/secrets/keys", url.Values{"path": {"/gone"}, "key": {"A", "B"}, "value": {"1", "2"}, "confirm": {"yes"}}, origin)
	postForm(t, c, ts, "/secrets", url.Values{"path": {"/kept"}, "confirm": {"yes"}}, origin)
	_, body := get(t, c, ts.URL+"/secrets/path?path=/gone")
	if !strings.Contains(body, "<code>A</code>") || !strings.Contains(body, "<code>B</code>") {
		t.Fatalf("multiple keys not set:\n%s", body)
	}
	if strings.Count(body, `form="edit-keys"`) != 6 || strings.Count(body, ">Save changes</button>") != 1 || !strings.Contains(body, `<dialog id="review-save">`) {
		t.Fatalf("key table not one edit form:\n%s", body)
	}
	_, body = postForm(t, c, ts, "/secrets/keys", url.Values{"path": {"/gone"}, "key": {"C", "D"}, "value": {"3"}, "confirm": {"yes"}}, origin)
	if !strings.Contains(body, "every key needs a value") {
		t.Fatalf("mismatched keys and values accepted:\n%s", body)
	}
	for _, tc := range []struct {
		keys []string
		want string
	}{
		{[]string{"A"}, `key &#34;A&#34; already exists`},
		{[]string{"N", "N"}, `key &#34;N&#34; is added twice`},
	} {
		_, body = postForm(t, c, ts, "/secrets/keys", url.Values{"path": {"/gone"}, "new-key": tc.keys, "new-value": make([]string, len(tc.keys)), "confirm": {"yes"}}, origin)
		if !strings.Contains(body, tc.want) || strings.Contains(body, `data-key="N"`) {
			t.Fatalf("new keys %v: want %s:\n%s", tc.keys, tc.want, body)
		}
	}
	edits := url.Values{"path": {"/gone"}, "key": {"A"}, "value": {"10"}, "new-key": {"E"}, "new-value": {"5"}, "delete": {"B"}}
	_, body = postForm(t, c, ts, "/secrets/keys", edits, origin)
	if !strings.Contains(body, "confirm the action first") || !strings.Contains(body, `data-key="B"`) {
		t.Fatalf("edits saved without confirmation:\n%s", body)
	}
	edits.Set("confirm", "yes")
	postForm(t, c, ts, "/secrets/keys", edits, origin)
	_, body = get(t, c, ts.URL+"/secrets/path?path=/gone")
	if strings.Contains(body, `data-key="B"`) || !strings.Contains(body, `data-key="E"`) ||
		!strings.Contains(body, `form="edit-keys">10</textarea>`) ||
		!strings.Contains(body, `<span class="badge">v2</span>`) || strings.Contains(body, `<span class="badge">v3</span>`) {
		t.Fatalf("add, change and delete not saved as one version:\n%s", body)
	}
	_, body = postForm(t, c, ts, "/secrets/delete", url.Values{"path": {"/gone"}, "confirm": {"/kept"}}, origin)
	if !strings.Contains(body, "type the path to confirm") || !strings.Contains(body, "<code>A</code>") {
		t.Fatalf("delete without confirmation:\n%s", body)
	}
	if code, _ := postForm(t, c, ts, "/secrets/delete", url.Values{"path": {"/gone"}, "confirm": {"/gone"}}, origin); code != http.StatusOK {
		t.Fatalf("delete path: %d", code)
	}

	_, body = get(t, c, ts.URL+"/secrets")
	if !strings.Contains(body, "Deleted paths") || !strings.Contains(body, ">/gone<") {
		t.Fatalf("deleted path not listed:\n%s", body)
	}

	code, body := get(t, c, ts.URL+"/secrets/path?path=/gone")
	if code != http.StatusOK || !strings.Contains(body, "This path was deleted") ||
		!strings.Contains(body, `name="version" value="1"`) || strings.Contains(body, "Add key") {
		t.Fatalf("deleted path page: %d\n%s", code, body)
	}
	postForm(t, c, ts, "/secrets/rollback", url.Values{"path": {"/gone"}, "version": {"1"}, "confirm": {"1"}}, origin)
	_, body = get(t, c, ts.URL+"/secrets")
	if strings.Contains(body, "Deleted paths") {
		t.Fatalf("restored path still listed as deleted:\n%s", body)
	}
	if code, _ := get(t, c, ts.URL+"/secrets/path?path=/never"); code != http.StatusNotFound {
		t.Fatalf("missing path: %d", code)
	}
}

func TestDeleteVersion(t *testing.T) {
	ts, logs := newLoggedServer(t)
	for _, v := range []string{"1", "leaked"} {
		do(t, ts, "PUT", "/api/v1/secrets?path=/app", apiToken, `{"A":"`+v+`"}`)
	}
	if code, _ := do(t, ts, "DELETE", "/api/v1/history/2?path=/app", apiToken, ""); code != http.StatusNoContent {
		t.Fatalf("delete version: %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/v1/history/2?path=/app", apiToken, ""); code != http.StatusNotFound {
		t.Fatalf("deleted version still readable: %d", code)
	}
	if code, _ := do(t, ts, "DELETE", "/api/v1/history/2?path=/app", apiToken, ""); code != http.StatusNotFound {
		t.Fatalf("delete missing version: %d", code)
	}
	if !strings.Contains(logs.String(), `"op":"delete_version","remote"`) {
		t.Fatalf("delete not audited:\n%s", logs)
	}

	c := uiClient(t, ts)
	origin := ts.URL
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, origin)
	do(t, ts, "DELETE", "/api/v1/paths?path=/app", apiToken, "")
	_, body := postForm(t, c, ts, "/secrets/versions/delete", url.Values{"path": {"/app"}, "version": {"1"}}, origin)
	if !strings.Contains(body, "confirm the action first") {
		t.Fatalf("version deleted without confirmation:\n%s", body)
	}
	_, body = postForm(t, c, ts, "/secrets/versions/delete", url.Values{"path": {"/app"}, "version": {"1"}, "confirm": {"1"}}, origin)
	if !strings.Contains(body, "<h1>Secrets</h1>") || strings.Contains(body, "Deleted paths") {
		t.Fatalf("deleting the last version of a deleted path:\n%s", body)
	}
}

func TestUIPageTitles(t *testing.T) {
	ts := newTestServer(t)
	c := uiClient(t, ts)
	if _, body := get(t, c, ts.URL+"/login"); !strings.Contains(body, "<title>Sign in - Secret Manager</title>") {
		t.Fatalf("login title:\n%s", body)
	}
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL)
	postForm(t, c, ts, "/secrets", url.Values{"path": {"/app"}, "confirm": {"yes"}}, ts.URL)
	for page, want := range map[string]string{
		"/":                       "Summary - Secret Manager",
		"/secrets":                "Secrets - Secret Manager",
		"/secrets/path?path=/app": "/app - Secret Manager",
		"/integrations":           "Integrations - Secret Manager",
		"/audit":                  "Audit log - Secret Manager",
	} {
		if _, body := get(t, c, ts.URL+page); !strings.Contains(body, "<title>"+want+"</title>") {
			t.Errorf("%s: want title %q", page, want)
		}
	}
}

func TestCopyAndMovePath(t *testing.T) {
	ts, logs := newLoggedServer(t)
	do(t, ts, "PUT", "/api/v1/secrets?path=/a", apiToken, `{"K":"1"}`)
	do(t, ts, "PUT", "/api/v1/secrets?path=/a", apiToken, `{"K":"2"}`)
	if code, _ := do(t, ts, "POST", "/api/v1/paths/copy?path=/a&to=/b", apiToken, ""); code != http.StatusNoContent {
		t.Fatalf("copy: %d", code)
	}
	if code, _ := do(t, ts, "POST", "/api/v1/paths/copy?path=/a&to=/b", apiToken, ""); code != http.StatusBadRequest {
		t.Fatalf("copy onto an existing path: %d", code)
	}
	if _, body := do(t, ts, "GET", "/api/v1/history?path=/b", apiToken, ""); strings.Count(body, `"version"`) != 2 {
		t.Fatalf("copied history: %s", body)
	}
	if !strings.Contains(logs.String(), `"op":"copy_path","remote"`) || !strings.Contains(logs.String(), `"to":"/b"`) {
		t.Fatalf("copy not audited:\n%s", logs)
	}

	c := uiClient(t, ts)
	origin := ts.URL
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, origin)
	_, body := postForm(t, c, ts, "/secrets/copy", url.Values{"path": {"/b"}, "to": {"/c"}}, origin)
	if !strings.Contains(body, "confirm the action first") {
		t.Fatalf("moved without confirmation:\n%s", body)
	}
	_, body = postForm(t, c, ts, "/secrets/copy", url.Values{"path": {"/b"}, "to": {"/c"}, "confirm": {"move"}}, origin)
	if !strings.Contains(body, `<h1 class="mono">/c</h1>`) {
		t.Fatalf("move did not open the new path:\n%s", body)
	}
	if code, _ := do(t, ts, "GET", "/api/v1/secrets?path=/b", apiToken, ""); code != http.StatusNotFound {
		t.Fatalf("moved source still readable: %d", code)
	}
}

func TestUICompareVersions(t *testing.T) {
	ts := newTestServer(t)
	for _, body := range []string{`{"A":"1","B":"x"}`, `{"A":"2"}`, `{"C":"3"}`} {
		do(t, ts, "PUT", "/api/v1/secrets?path=/app", apiToken, body)
	}
	c := uiClient(t, ts)
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL)

	_, body := get(t, c, ts.URL+"/secrets/path?path=/app")
	if !strings.Contains(body, `<option value="2" selected>v2</option>`) || !strings.Contains(body, `<option value="current" selected>current</option>`) || strings.Contains(body, `class="body compare-result"`) {
		t.Fatalf("compare form defaults:\n%s", body)
	}
	_, body = get(t, c, ts.URL+"/secrets/path?path=/app&from=1&to=3")
	if !strings.Contains(body, "v1 compared with v3") || !strings.Contains(body, `<tr class="add"><td class="mono">&#43;</td><td><code>C</code>`) ||
		!strings.Contains(body, `<td><code>1</code></td><td><code>2</code></td>`) || !strings.Contains(body, `<option value="1" selected>v1</option>`) {
		t.Fatalf("v1 compared with v3:\n%s", body)
	}
	_, body = get(t, c, ts.URL+"/secrets/path?path=/app&from=3&to=current")
	if !strings.Contains(body, "Both hold the same data") {
		t.Fatalf("same data:\n%s", body)
	}
	if code, _ := get(t, c, ts.URL+"/secrets/path?path=/app&from=9&to=current"); code != http.StatusBadRequest {
		t.Fatalf("missing version: %d", code)
	}
}

func TestUILoginRateLimit(t *testing.T) {
	ts := newTestServer(t)
	c := uiClient(t, ts)
	for range loginFreeFailures {
		if code, _ := postForm(t, c, ts, "/login", url.Values{"token": {"wrong"}}, ts.URL); code != http.StatusUnauthorized {
			t.Fatalf("failed sign-in: %d", code)
		}
	}
	postForm(t, c, ts, "/login", url.Values{"token": {"wrong"}}, ts.URL)
	code, body := postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL)
	if code != http.StatusTooManyRequests || !strings.Contains(body, "too many failed sign-ins") {
		t.Fatalf("sign-in while limited: %d\n%s", code, body)
	}
}

func TestUILoginRateLimitBehindProxy(t *testing.T) {
	backend := k8sstorage.New(fake.NewClientBuilder().Build(), "sm")
	s, err := New(secrets.New(backend, nil), tokens.New(backend), token)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	s.log = slog.New(slog.NewJSONHandler(logs, nil))
	if s.TrustedProxies, err = ParsePrefixes("127.0.0.1,::1"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(s)
	t.Cleanup(ts.Close)
	c := uiClient(t, ts)
	for range loginFreeFailures + 1 {
		postForm(t, c, ts, "/login", url.Values{"token": {"wrong"}}, ts.URL, "X-Forwarded-For", "6.6.6.6, 198.51.100.7")
	}
	if code, _ := postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL, "X-Forwarded-For", "198.51.100.7"); code != http.StatusTooManyRequests {
		t.Fatalf("limited client: %d", code)
	}
	if code, _ := postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL, "X-Forwarded-For", "6.6.6.6, 198.51.100.8"); code != http.StatusOK {
		t.Fatalf("other client behind the same proxy: %d", code)
	}
	if !strings.Contains(logs.String(), `"client":"198.51.100.7"`) {
		t.Fatalf("client not audited:\n%s", logs)
	}
}

func TestAuditPersisted(t *testing.T) {
	ctx := context.Background()
	backend := k8sstorage.New(fake.NewClientBuilder().Build(), "sm")
	newServer := func() *Server {
		s, err := New(secrets.New(backend, nil), tokens.New(backend), token)
		if err != nil {
			t.Fatal(err)
		}
		s.log = slog.New(slog.NewJSONHandler(io.Discard, nil))
		if err := s.LoadAudit(ctx, backend); err != nil {
			t.Fatal(err)
		}
		return s
	}
	first := newServer()
	for i := range auditKept + 3 {
		first.record(auditEvent{Source: "api", Op: "set", Path: "/p" + strconv.Itoa(i)})
	}
	if err := first.FlushAudit(ctx); err != nil {
		t.Fatal(err)
	}
	second := newServer()
	got := second.auditLog.recent()
	if len(got) != auditKept || got[0].Path != "/p"+strconv.Itoa(auditKept+2) || got[auditKept-1].Path != "/p3" {
		t.Fatalf("loaded %d events, newest %+v", len(got), got[0])
	}
	if second.auditLog.dirty {
		t.Fatal("loading marked the log dirty")
	}
}

func TestUIAudit(t *testing.T) {
	ts := newTestServer(t)
	do(t, ts, "PUT", "/api/v1/secrets?path=/app", apiToken, `{"A":"hunter2"}`)
	do(t, ts, "GET", "/api/v1/paths", "wrong-token", "")
	c := uiClient(t, ts)
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL)

	_, body := get(t, c, ts.URL+"/audit")
	if !strings.Contains(body, "<code>set</code>") || !strings.Contains(body, "invalid token") ||
		!strings.Contains(body, `<option value="full">full</option>`) || strings.Contains(body, "hunter2") {
		t.Fatalf("audit page:\n%s", body)
	}
	_, body = get(t, c, ts.URL+"/audit?integration=full")
	if !strings.Contains(body, "<code>set</code>") || strings.Contains(body, "invalid token") || strings.Contains(body, "<code>login</code>") {
		t.Fatalf("audit page filtered by integration:\n%s", body)
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
	do(t, ts, "PUT", "/api/v1/secrets?path=/app", apiToken, `{"PASS":"hunter2","USER":"bob"}`)
	do(t, ts, "DELETE", "/api/v1/secrets/USER?path=/app", apiToken, "")
	do(t, ts, "DELETE", "/api/v1/paths?path=/BAD", apiToken, "")
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
	s, err := New(secrets.New(k8sstorage.New(c, "sm"), nil), tokens.New(k8sstorage.New(c, "sm")), token)
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
	req.Header.Set("Authorization", "Bearer "+apiToken)
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
	code, body := do(t, ts, "GET", "/api/v1/info", apiToken, "")
	if code != http.StatusOK || strings.TrimSpace(body) != `{"capabilities":["backup","history","history-delete","integrations","paths","paths-copy","secrets"],"version":"v9.9.9-test"}` {
		t.Fatalf("info: %d %s", code, body)
	}
}

func TestAPIBackupRestore(t *testing.T) {
	src, logs := newLoggedServer(t)
	do(t, src, "PUT", "/api/v1/secrets?path=/app", apiToken, `{"A":"1"}`)
	do(t, src, "PUT", "/api/v1/secrets?path=/app", apiToken, `{"A":"2"}`)

	code, plain := do(t, src, "GET", "/api/v1/backup", apiToken, "")
	if code != http.StatusOK || !strings.Contains(plain, `"format":1`) ||
		!strings.Contains(plain, `"paths":[{"path":"/app","data":{"A":"2"}}]`) {
		t.Fatalf("backup: %d %s", code, plain)
	}
	_, full := do(t, src, "GET", "/api/v1/backup?history=true", apiToken, "")
	if strings.Count(full, `{"version":`) != 2 {
		t.Fatalf("backup with history: %s", full)
	}
	if !strings.Contains(logs.String(), `"op":"backup"`) {
		t.Fatalf("backup not audited: %s", logs)
	}

	dst := newTestServer(t)
	if code, body := do(t, dst, "POST", "/api/v1/restore", apiToken, full); code != http.StatusOK || strings.TrimSpace(body) != `{"paths":1}` {
		t.Fatalf("restore: %d %s", code, body)
	}
	if _, body := do(t, dst, "GET", "/api/v1/secrets?path=/app", apiToken, ""); strings.TrimSpace(body) != `{"cacheMaxAge":604800,"data":{"A":"2"}}` {
		t.Fatalf("restored data: %s", body)
	}
	if _, body := do(t, dst, "GET", "/api/v1/history?path=/app", apiToken, ""); strings.Count(body, `"version":`) != 2 {
		t.Fatalf("restored history: %s", body)
	}

	for _, body := range []string{`nope`, `{"format":2,"paths":[]}`, `{"format":1,"paths":[{"path":"bad"}]}`} {
		if code, _ := do(t, dst, "POST", "/api/v1/restore", apiToken, body); code != http.StatusBadRequest {
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

var newTokenRe = regexp.MustCompile(`id="new-token" class="mono" value="([^"]+)"`)

// createToken creates an integration in the Web UI and returns its token.
func createToken(t *testing.T, ts *httptest.Server, form url.Values) string {
	t.Helper()
	c := uiClient(t, ts)
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL)
	if form.Get("expires") == "" {
		form.Set("expires", "never")
	}
	form.Set("confirm", "yes")
	code, body := postForm(t, c, ts, "/integrations", form, ts.URL)
	m := newTokenRe.FindStringSubmatch(body)
	if code != http.StatusCreated || m == nil {
		t.Fatalf("create integration %v: %d\n%s", form, code, body)
	}
	return m[1]
}

func doFrom(t *testing.T, ts *httptest.Server, path, auth, forwarded string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+auth)
	req.Header.Set("X-Forwarded-For", forwarded)
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

func TestIntegrationAllowedFrom(t *testing.T) {
	ts, logs := newLoggedServer(t, func(s *Server) { s.TrustedProxies, _ = ParsePrefixes("127.0.0.1, ::1") })
	do(t, ts, "PUT", "/api/v1/secrets?path=/app", apiToken, `{"A":"1"}`)
	ci := createToken(t, ts, url.Values{"name": {"ci"}, "path": {"/app"}, "allowed-from": {"198.51.100.0/24, 203.0.113.9"}})
	if code := doFrom(t, ts, "/api/v1/secrets?path=/app", ci, "198.51.100.7"); code != http.StatusOK {
		t.Fatalf("allowed range: %d", code)
	}
	if code := doFrom(t, ts, "/api/v1/secrets?path=/app", ci, "203.0.113.9"); code != http.StatusOK {
		t.Fatalf("allowed address: %d", code)
	}
	if code := doFrom(t, ts, "/api/v1/secrets?path=/app", ci, "198.51.100.7, 192.0.2.1"); code != http.StatusForbidden {
		t.Fatalf("client entry on the left must not pass: %d", code)
	}
	if !strings.Contains(logs.String(), `"error":"token ci is not allowed from 192.0.2.1"`) {
		t.Fatalf("rejection not audited:\n%s", logs)
	}
	if code := doFrom(t, ts, "/api/v1/info", apiToken, "192.0.2.1"); code != http.StatusOK {
		t.Fatalf("token without allowlist: %d", code)
	}

	c := uiClient(t, ts)
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL)
	_, body := get(t, c, ts.URL+"/integrations")
	if !strings.Contains(body, `<code>198.51.100.0/24, 203.0.113.9</code>`) || !strings.Contains(body, `name="allowed-from" value="198.51.100.0/24, 203.0.113.9"`) {
		t.Fatalf("allowlist not shown:\n%s", body)
	}
	edit := url.Values{"name": {"ci"}, "path": {"/app"}, "expires": {"keep"}, "allowed-from": {""}, "confirm": {"yes"}}
	postForm(t, c, ts, "/integrations/update", edit, ts.URL)
	if code := doFrom(t, ts, "/api/v1/secrets?path=/app", ci, "192.0.2.1"); code != http.StatusOK {
		t.Fatalf("after clearing the allowlist: %d", code)
	}
	edit.Set("allowed-from", "not-an-address")
	_, body = postForm(t, c, ts, "/integrations/update", edit, ts.URL)
	if !strings.Contains(body, "allowed addresses") {
		t.Fatalf("invalid allowlist accepted:\n%s", body)
	}
}

func TestAuditReads(t *testing.T) {
	for _, on := range []bool{false, true} {
		ts, logs := newLoggedServer(t, func(s *Server) { s.AuditReads = on })
		do(t, ts, "PUT", "/api/v1/secrets?path=/app", apiToken, `{"PASS":"hunter2"}`)
		do(t, ts, "GET", "/api/v1/secrets?path=/app", apiToken, "")
		do(t, ts, "GET", "/api/v1/history/1?path=/app", apiToken, "")
		c := uiClient(t, ts)
		postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL)
		get(t, c, ts.URL+"/secrets/path?path=/app")

		out := logs.String()
		reads := strings.Count(out, `"op":"read"`) + strings.Count(out, `"op":"read_version"`)
		if want := map[bool]int{false: 0, true: 3}[on]; reads != want {
			t.Fatalf("audit reads %v: %d read events, want %d\n%s", on, reads, want, out)
		}
		if on && (!strings.Contains(out, `"source":"ui","op":"read"`) || !strings.Contains(out, `"keys":["PASS"],"version":1`)) {
			t.Fatalf("read events:\n%s", out)
		}
		if strings.Contains(out, "hunter2") {
			t.Fatal("secret value logged")
		}
	}
}

func TestScopedTokens(t *testing.T) {
	ts, logs := newLoggedServer(t)
	do(t, ts, "PUT", "/api/v1/secrets?path=/app", apiToken, `{"A":"1"}`)
	do(t, ts, "PUT", "/api/v1/secrets?path=/app/db", apiToken, `{"B":"2"}`)
	do(t, ts, "PUT", "/api/v1/secrets?path=/apple", apiToken, `{"C":"3"}`)
	do(t, ts, "PUT", "/api/v1/secrets?path=/other", apiToken, `{"D":"4"}`)

	ro := createToken(t, ts, url.Values{"name": {"ci"}, "path": {"/app"}, "read-only": {"on"}})
	rw := createToken(t, ts, url.Values{"name": {"dev"}, "path": {"/app/db"}})
	rootRO := createToken(t, ts, url.Values{"name": {"root-ro"}, "path": {"/"}, "read-only": {"on"}})

	cases := []struct {
		auth, method, path, body string
		want                     int
	}{
		{ro, "GET", "/api/v1/info", "", http.StatusOK},
		{ro, "GET", "/api/v1/secrets?path=/app", "", http.StatusOK},
		{ro, "GET", "/api/v1/secrets?path=/app&recursive=true", "", http.StatusOK},
		{ro, "GET", "/api/v1/secrets?path=/app/db", "", http.StatusOK},
		{ro, "GET", "/api/v1/history?path=/app", "", http.StatusOK},
		{ro, "GET", "/api/v1/secrets?path=/apple", "", http.StatusForbidden},
		{ro, "GET", "/api/v1/secrets?path=/other", "", http.StatusForbidden},
		{ro, "GET", "/api/v1/secrets?path=/", "", http.StatusForbidden},
		{ro, "GET", "/api/v1/secrets?path=bad", "", http.StatusForbidden},
		{ro, "PUT", "/api/v1/secrets?path=/app", `{"A":"x"}`, http.StatusForbidden},
		{ro, "DELETE", "/api/v1/paths?path=/app", "", http.StatusForbidden},
		{ro, "POST", "/api/v1/history/1/rollback?path=/app", "", http.StatusForbidden},
		{ro, "GET", "/api/v1/backup", "", http.StatusForbidden},
		{rw, "PUT", "/api/v1/secrets?path=/app/db", `{"B":"x"}`, http.StatusNoContent},
		{rw, "PUT", "/api/v1/secrets?path=/app/db/new", `{"E":"5"}`, http.StatusNoContent},
		{rw, "DELETE", "/api/v1/secrets/E?path=/app/db/new", "", http.StatusNoContent},
		{rw, "PUT", "/api/v1/secrets?path=/app", `{"A":"x"}`, http.StatusForbidden},
		{rw, "POST", "/api/v1/restore", `{"format":1,"paths":[]}`, http.StatusForbidden},
		{ro, "POST", "/api/v1/paths/copy?path=/app&to=/app/copy", "", http.StatusForbidden},
		{rw, "POST", "/api/v1/paths/copy?path=/app/db&to=/other/db", "", http.StatusForbidden},
		{rw, "POST", "/api/v1/paths/copy?path=/app&to=/app/db/copy", "", http.StatusForbidden},
		{rw, "POST", "/api/v1/paths/copy?path=/app/db&to=/app/db/copy", "", http.StatusNoContent},
		{rw, "POST", "/api/v1/paths/move?path=/app/db/copy&to=/app/db/moved", "", http.StatusNoContent},
		{rootRO, "GET", "/api/v1/backup", "", http.StatusOK},
		{rootRO, "POST", "/api/v1/restore", `{"format":1,"paths":[]}`, http.StatusForbidden},
		{token, "GET", "/api/v1/info", "", http.StatusUnauthorized},
		{"smt_unknown", "GET", "/api/v1/info", "", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		if code, body := do(t, ts, tc.method, tc.path, tc.auth, tc.body); code != tc.want {
			t.Errorf("%s %s with %.8s: %d %s, want %d", tc.method, tc.path, tc.auth, code, body, tc.want)
		}
	}

	if _, body := do(t, ts, "GET", "/api/v1/paths", ro, ""); strings.TrimSpace(body) != `{"paths":["/app","/app/db","/app/db/moved","/app/db/new"]}` {
		t.Fatalf("scoped paths: %s", body)
	}
	if !strings.Contains(logs.String(), `"op":"set","remote"`) || !strings.Contains(logs.String(), `"token":"dev"`) {
		t.Fatalf("scoped write not audited with token name: %s", logs)
	}

	c := uiClient(t, ts)
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL)
	_, body := get(t, c, ts.URL+"/integrations")
	if strings.Contains(body, ro) || !strings.Contains(body, "<code>ci</code>") || !strings.Contains(body, "read-only") {
		t.Fatalf("integration list:\n%s", body)
	}
	if _, body := postForm(t, c, ts, "/integrations", url.Values{"name": {"ci"}, "path": {"/x"}, "expires": {"never"}, "confirm": {"yes"}}, ts.URL); !strings.Contains(body, "already exists") {
		t.Fatalf("duplicate integration:\n%s", body)
	}
	edit := url.Values{"name": {"ci"}, "path": {"/other"}, "expires": {"keep"}}
	if _, body := postForm(t, c, ts, "/integrations/update", edit, ts.URL); !strings.Contains(body, "confirm the action first") {
		t.Fatalf("updated without confirmation:\n%s", body)
	}
	edit.Set("confirm", "yes")
	if code, body := postForm(t, c, ts, "/integrations/update", edit, ts.URL); code != http.StatusOK || strings.Contains(body, `class="error"`) {
		t.Fatalf("update: %d\n%s", code, body)
	}
	for _, tc := range []struct {
		path string
		want int
	}{{"/other", http.StatusOK}, {"/app", http.StatusForbidden}} {
		if code, _ := do(t, ts, "GET", "/api/v1/secrets?path="+tc.path, ro, ""); code != tc.want {
			t.Errorf("updated token on %s: %d, want %d", tc.path, code, tc.want)
		}
	}
	if code, _ := do(t, ts, "PUT", "/api/v1/secrets?path=/other", ro, `{"D":"5"}`); code != http.StatusNoContent {
		t.Errorf("updated token without read-only: %d", code)
	}
	if _, body := postForm(t, c, ts, "/integrations", url.Values{"name": {"k"}, "path": {"/"}, "expires": {"keep"}, "confirm": {"yes"}}, ts.URL); !strings.Contains(body, "pick an expiry") {
		t.Fatalf("create accepted keep:\n%s", body)
	}
	if _, body := postForm(t, c, ts, "/integrations/update", url.Values{"name": {"nope"}, "path": {"/"}, "expires": {"keep"}, "confirm": {"yes"}}, ts.URL); !strings.Contains(body, "not found") {
		t.Fatalf("update of missing integration:\n%s", body)
	}
	if _, body := postForm(t, c, ts, "/integrations/revoke", url.Values{"name": {"ci"}}, ts.URL); !strings.Contains(body, "confirm the action first") {
		t.Fatalf("revoked without confirmation:\n%s", body)
	}
	if code, _ := postForm(t, c, ts, "/integrations/revoke", url.Values{"name": {"ci"}, "confirm": {"ci"}}, ts.URL); code != http.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/v1/secrets?path=/app", ro, ""); code != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d", code)
	}
	if code, _ := postForm(t, uiClient(t, ts), ts, "/login", url.Values{"token": {rw}}, ts.URL); code != http.StatusUnauthorized {
		t.Fatalf("integration token logged into the UI: %d", code)
	}
}

func TestCacheMaxAge(t *testing.T) {
	ts := newTestServer(t)
	do(t, ts, "PUT", "/api/v1/secrets?path=/app", apiToken, `{"A":"1"}`)
	def := createToken(t, ts, url.Values{"name": {"def"}, "path": {"/app"}})
	off := createToken(t, ts, url.Values{"name": {"off"}, "path": {"/app"}, "cache-max-age": {"0s"}})
	hour := createToken(t, ts, url.Values{"name": {"hour"}, "path": {"/app"}, "cache-max-age": {"1h0m0s"}})
	for tok, want := range map[string]string{def: `"cacheMaxAge":604800`, off: `"cacheMaxAge":0`, hour: `"cacheMaxAge":3600`} {
		if _, body := do(t, ts, "GET", "/api/v1/secrets?path=/app", tok, ""); !strings.Contains(body, want) {
			t.Errorf("secrets with %.8s: %s, want %s", tok, body, want)
		}
	}

	c := uiClient(t, ts)
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL)
	_, body := get(t, c, ts.URL+"/integrations")
	if !strings.Contains(body, `data-cache="1 hour"`) || !strings.Contains(body, `data-cache="Server default (7 days)"`) {
		t.Fatalf("integration list:\n%s", body)
	}
	edit := url.Values{"name": {"hour"}, "path": {"/app"}, "expires": {"keep"}, "cache-max-age": {"default"}, "confirm": {"yes"}}
	postForm(t, c, ts, "/integrations/update", edit, ts.URL)
	if _, body := do(t, ts, "GET", "/api/v1/secrets?path=/app", hour, ""); !strings.Contains(body, `"cacheMaxAge":604800`) {
		t.Errorf("after reset to default: %s", body)
	}
	if _, body := postForm(t, c, ts, "/integrations", url.Values{"name": {"bad"}, "path": {"/"}, "expires": {"never"}, "cache-max-age": {"-1h"}, "confirm": {"yes"}}, ts.URL); !strings.Contains(body, "unknown offline cache") {
		t.Fatalf("negative cache accepted:\n%s", body)
	}
}

func TestIntegrationExpiry(t *testing.T) {
	ts := newTestServer(t)
	tomorrow := time.Now().UTC().Add(24 * time.Hour).Format(time.DateOnly)
	custom := createToken(t, ts, url.Values{"name": {"custom"}, "path": {"/"}, "expires": {"custom"}, "expires-date": {tomorrow}})
	if code, _ := do(t, ts, "GET", "/api/v1/paths", custom, ""); code != http.StatusOK {
		t.Fatalf("custom expiry token: %d", code)
	}
	c := uiClient(t, ts)
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL)
	for _, form := range []url.Values{
		{"name": {"a"}, "expires": {"custom"}, "expires-date": {"2001-01-01"}, "confirm": {"yes"}},
		{"name": {"b"}, "expires": {"custom"}, "confirm": {"yes"}},
		{"name": {"c"}, "expires": {"2w"}, "confirm": {"yes"}},
		{"name": {"d"}, "path": {"/"}, "expires": {"never"}},
	} {
		if code, body := postForm(t, c, ts, "/integrations", form, ts.URL); code != http.StatusOK || !strings.Contains(body, `class="error"`) {
			t.Errorf("create %v: %d, want an error", form, code)
		}
	}
}
