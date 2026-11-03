package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizeLoopback(t *testing.T) {
	ts := newTestServer(t)
	c := uiClient(t, ts)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	verifier := "a-verifier-of-at-least-43-characters-0123456789"
	q := url.Values{
		"redirect_uri":   {"http://127.0.0.1:4711/callback"},
		"state":          {"st"},
		"code_challenge": {pkceChallenge(verifier)},
		"name":           {"cli-laptop"},
	}

	res, err := c.Get(ts.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if loc := res.Header.Get("Location"); res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/login?next=%2Fauthorize%3F") {
		t.Fatalf("unauthenticated authorize: %d %s", res.StatusCode, loc)
	}
	res, err = c.PostForm(ts.URL+"/login", url.Values{"token": {token}, "next": {"/authorize?" + q.Encode()}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if loc := res.Header.Get("Location"); loc != "/authorize?"+q.Encode() {
		t.Fatalf("login next: %s", loc)
	}

	res, err = c.Get(ts.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if csp := res.Header.Get("Content-Security-Policy"); res.StatusCode != http.StatusOK || !strings.Contains(csp, "form-action 'self' http://127.0.0.1:4711;") {
		t.Fatalf("authorize page: %d %s", res.StatusCode, csp)
	}
	for _, bad := range []string{"https://127.0.0.1:1/cb", "http://evil.example:1/cb", "http://127.0.0.1/cb", "http://127.0.0.1:1/cb?x=1"} {
		bq := url.Values{"redirect_uri": {bad}, "state": {"s"}, "code_challenge": {"c"}}
		if code, _ := get(t, c, ts.URL+"/authorize?"+bq.Encode()); code != http.StatusBadRequest {
			t.Errorf("redirect_uri %s: %d", bad, code)
		}
	}

	approve := url.Values{"confirm": {"yes"}, "name": {"cli-laptop"}, "path": {"/app"}, "expires": {"30d"}}
	for k, v := range q {
		approve[k] = v
	}
	approve.Set("decision", "deny")
	if loc := mustPost(t, c, ts.URL+"/authorize", approve); !strings.HasPrefix(loc, "http://127.0.0.1:4711/callback?") || !strings.Contains(loc, "error=access_denied") {
		t.Fatalf("deny redirect: %s", loc)
	}
	approve.Del("decision")
	loc, _ := url.Parse(mustPost(t, c, ts.URL+"/authorize", approve))
	code := loc.Query().Get("code")
	if loc.Host != "127.0.0.1:4711" || loc.Query().Get("state") != "st" || code == "" {
		t.Fatalf("approve redirect: %s", loc)
	}

	if status, body := do(t, ts, "POST", "/api/v1/authorize/token", "", `{"code":"`+code+`","codeVerifier":"wrong"}`); status != http.StatusBadRequest {
		t.Fatalf("wrong verifier: %d %s", status, body)
	}
	if status, _ := do(t, ts, "POST", "/api/v1/authorize/token", "", `{"code":"`+code+`","codeVerifier":"`+verifier+`"}`); status != http.StatusBadRequest {
		t.Fatalf("code reused after a failed exchange: %d", status)
	}

	loc, _ = url.Parse(mustPost(t, c, ts.URL+"/authorize", approve))
	status, body := do(t, ts, "POST", "/api/v1/authorize/token", "", `{"code":"`+loc.Query().Get("code")+`","codeVerifier":"`+verifier+`"}`)
	var issued issuedJSON
	if err := json.Unmarshal([]byte(body), &issued); status != http.StatusOK || err != nil || issued.Path != "/app" || issued.Expires.IsZero() {
		t.Fatalf("exchange: %d %s", status, body)
	}
	if status, _ := do(t, ts, "GET", "/api/v1/paths", issued.Token, ""); status != http.StatusOK {
		t.Fatalf("issued token: %d", status)
	}
	if loc := mustPost(t, c, ts.URL+"/authorize", approve); !strings.Contains(loc, "already+exists") {
		t.Fatalf("duplicate name approved: %s", loc)
	}
}

func TestAuthorizeDevice(t *testing.T) {
	ts := newTestServer(t)
	c := uiClient(t, ts)
	postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL)

	start := func() deviceJSON {
		_, body := do(t, ts, "POST", "/api/v1/authorize/device", "", `{"name":"cli-box"}`)
		var d deviceJSON
		if err := json.Unmarshal([]byte(body), &d); err != nil || d.DeviceCode == "" || len(d.UserCode) != 9 {
			t.Fatalf("device start: %s", body)
		}
		return d
	}
	poll := func(d deviceJSON) (int, string) {
		return do(t, ts, "POST", "/api/v1/authorize/token", "", `{"deviceCode":"`+d.DeviceCode+`"}`)
	}

	d := start()
	if status, body := poll(d); status != http.StatusBadRequest || !strings.Contains(body, "authorization_pending") {
		t.Fatalf("pending poll: %d %s", status, body)
	}
	if status, body := get(t, c, ts.URL+d.VerificationURI); status != http.StatusOK || !strings.Contains(body, d.UserCode) || !strings.Contains(body, `value="cli-box"`) {
		t.Fatalf("approval page: %d\n%s", status, body)
	}
	if status, body := postForm(t, c, ts, "/authorize", url.Values{"user_code": {strings.ToLower(d.UserCode)}, "confirm": {"yes"}, "name": {"cli-box"}, "path": {"/"}, "read-only": {"on"}, "expires": {"never"}}, ts.URL); status != http.StatusOK || !strings.Contains(body, "Login approved") {
		t.Fatalf("approve: %d\n%s", status, body)
	}
	status, body := poll(d)
	var issued issuedJSON
	if err := json.Unmarshal([]byte(body), &issued); status != http.StatusOK || err != nil || !issued.ReadOnly || !issued.Expires.IsZero() {
		t.Fatalf("device token: %d %s", status, body)
	}
	if status, _ := poll(d); status != http.StatusBadRequest {
		t.Fatalf("device code reused: %d", status)
	}

	d = start()
	postForm(t, c, ts, "/authorize", url.Values{"user_code": {d.UserCode}, "decision": {"deny"}}, ts.URL)
	if status, body := poll(d); status != http.StatusForbidden || !strings.Contains(body, "access_denied") {
		t.Fatalf("denied poll: %d %s", status, body)
	}
	if status, _ := get(t, c, ts.URL+"/authorize?user_code=NOPE-NOPE"); status != http.StatusBadRequest {
		t.Fatalf("unknown user code: %d", status)
	}
}

// mustPost posts form and returns the redirect Location.
func mustPost(t *testing.T, c *http.Client, u string, form url.Values) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", strings.TrimSuffix(u, "/authorize"))
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.Header.Get("Location")
}
