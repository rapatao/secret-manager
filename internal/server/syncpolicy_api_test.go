package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/storage"
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
	"github.com/rapatao/secret-manager/internal/syncpolicy"
	"github.com/rapatao/secret-manager/internal/tokens"
)

const (
	readOnlyToken = "smt_testreadonly"
	pathToken     = "smt_testscoped"
)

type apiPolicyEnv struct {
	ts    *httptest.Server
	store *syncpolicy.Store
	calls *atomic.Int32
	logs  *syncBuffer
}

func newAPIPolicyEnv(t *testing.T, withStore bool, preview func(context.Context, storage.SyncPolicy) ([]string, error)) apiPolicyEnv {
	t.Helper()
	backend := k8sstorage.New(fake.NewClientBuilder().Build(), "sm")
	hash := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
	err := backend.PutTokens(context.Background(), []storage.Token{
		{Name: "full", Hash: hash(apiToken), Path: "/"},
		{Name: "ro", Hash: hash(readOnlyToken), Path: "/", ReadOnly: true},
		{Name: "scoped", Hash: hash(pathToken), Path: "/apps"},
	})
	if err != nil {
		t.Fatal(err)
	}
	env := apiPolicyEnv{calls: &atomic.Int32{}}
	env.store = syncpolicy.New(backend, func() { env.calls.Add(1) })
	ts, logs := newLoggedServerOn(t, backend, func(s *Server) {
		if withStore {
			s.SyncPolicy = env.store
			s.PolicyPreview = preview
		}
	})
	env.ts, env.logs = ts, logs
	return env
}

func newLoggedServerOn(t *testing.T, backend *k8sstorage.Backend, configure func(*Server)) (*httptest.Server, *syncBuffer) {
	t.Helper()
	svc := secrets.New(backend, nil)
	s, err := New(svc, tokens.New(backend), token)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	s.log = slog.New(slog.NewJSONHandler(logs, nil))
	configure(s)
	ts := httptest.NewTLSServer(s)
	t.Cleanup(ts.Close)
	return ts, logs
}

func policyBase(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/sync-policy", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	d := res.Header.Get(PolicyDigestHeader)
	if res.StatusCode != http.StatusOK || d == "" {
		t.Fatalf("GET: %d, digest %q", res.StatusCode, d)
	}
	return d
}

// put sends PUT /api/v1/sync-policy with the digest of the stored policy as
// base and the query parameters in extra, such as "confirm=<digest>".
func put(t *testing.T, ts *httptest.Server, extra, body string) (int, string) {
	t.Helper()
	q := "?base=" + policyBase(t, ts)
	if extra != "" {
		q += "&" + extra
	}
	return do(t, ts, "PUT", "/api/v1/sync-policy"+q, apiToken, body)
}

const policyDoc = `{"enabled":true,"namespaces":{"team-a":{"paths":["/apps"],"targetNamespaces":["team-b"]}}}`

func TestAPISyncPolicyAuth(t *testing.T) {
	env := newAPIPolicyEnv(t, true, nil)
	for method, wants := range map[string]map[string]int{
		"GET": {"": 401, "wrong": 401, pathToken: 403, readOnlyToken: 200, apiToken: 200},
		"PUT": {"": 401, pathToken: 403, readOnlyToken: 403, apiToken: 200},
	} {
		for auth, want := range wants {
			path := "/api/v1/sync-policy"
			if method == "PUT" {
				path += "?base=" + policyBase(t, env.ts)
			}
			if code, body := do(t, env.ts, method, path, auth, policyDoc); code != want {
				t.Errorf("%s with %q: %d %s, want %d", method, auth, code, body, want)
			}
		}
	}
}

func TestAPISyncPolicyRoundTrip(t *testing.T) {
	env := newAPIPolicyEnv(t, true, nil)
	if code, _ := put(t, env.ts, "", policyDoc); code != http.StatusOK {
		t.Fatalf("put %d", code)
	}
	code, body := do(t, env.ts, "GET", "/api/v1/sync-policy", apiToken, "")
	if code != http.StatusOK || strings.TrimSpace(body) != policyDoc {
		t.Fatalf("get %d %s", code, body)
	}
	if policyBase(t, env.ts) == baseDigest(storage.SyncPolicy{}) {
		t.Fatal("digest did not change with the policy")
	}
	if env.calls.Load() != 1 {
		t.Fatalf("onChange called %d times", env.calls.Load())
	}
}

func TestAPISyncPolicyInvalidSavesNothing(t *testing.T) {
	env := newAPIPolicyEnv(t, true, nil)
	for _, body := range []string{
		`{"enabled":true,"namespaces":{"Bad_NS":{"paths":["/x"]}}}`,
		`{"enabled":true,"namespaces":{"a":{"paths":["no-slash"]}}}`,
		`{"enabled":true,"unknown":1}`,
		`{"enabled":true} {"enabled":false}`,
		`not json`,
	} {
		if code, resp := put(t, env.ts, "", body); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", body, code, resp)
		}
	}
	if p, _ := env.store.Get(context.Background()); p.Enabled || len(p.Namespaces) != 0 || env.calls.Load() != 0 {
		t.Fatalf("saved: %+v", p)
	}
}

func TestAPISyncPolicyRejectsTrailingData(t *testing.T) {
	env := newAPIPolicyEnv(t, true, nil)
	for _, body := range []string{policyDoc + "}", policyDoc + "]", policyDoc + " x", `{"enabled":true,"confirm":"delete"}`} {
		if code, resp := put(t, env.ts, "", body); code != http.StatusBadRequest {
			t.Errorf("%q: %d %s", body, code, resp)
		}
	}
	if p, _ := env.store.Get(context.Background()); p.Enabled || env.calls.Load() != 0 {
		t.Fatalf("saved: %+v", p)
	}
	if code, resp := put(t, env.ts, "", policyDoc+"\n \n"); code != http.StatusOK {
		t.Fatalf("trailing whitespace: %d %s", code, resp)
	}
}

func TestAPISyncPolicyConfirmWithNothingDenied(t *testing.T) {
	env := newAPIPolicyEnv(t, true, func(context.Context, storage.SyncPolicy) ([]string, error) { return nil, nil })
	if code, body := put(t, env.ts, "confirm=delete", policyDoc); code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	if p, _ := env.store.Get(context.Background()); !p.Enabled {
		t.Fatal("not saved")
	}
}

func TestAPISyncPolicyRequiresBase(t *testing.T) {
	env := newAPIPolicyEnv(t, true, nil)
	code, body := do(t, env.ts, "PUT", "/api/v1/sync-policy", apiToken, policyDoc)
	if code != http.StatusBadRequest || !strings.Contains(body, "base is required") {
		t.Fatalf("%d %s", code, body)
	}
	if p, _ := env.store.Get(context.Background()); p.Enabled {
		t.Fatal("saved without a base")
	}
}

func TestAPISyncPolicyStaleBaseConflicts(t *testing.T) {
	env := newAPIPolicyEnv(t, true, nil)
	stale := policyBase(t, env.ts)
	cur, _ := env.store.Get(context.Background())
	if _, err := env.store.Put(context.Background(), cur, storage.SyncPolicy{Enabled: true, Namespaces: map[string]storage.SyncRule{"other": {Paths: []string{"/o"}}}}); err != nil {
		t.Fatal(err)
	}
	calls := env.calls.Load()

	code, body := do(t, env.ts, "PUT", "/api/v1/sync-policy?base="+stale, apiToken, policyDoc)
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil || code != http.StatusConflict || len(out) != 1 || out["error"] == nil {
		t.Fatalf("%d %s", code, body)
	}
	if p, _ := env.store.Get(context.Background()); p.Namespaces["other"].Paths == nil || p.Namespaces["team-a"].Paths != nil || env.calls.Load() != calls {
		t.Fatalf("the stale save changed the policy: %+v", p)
	}
	if logs := env.logs.String(); !strings.Contains(logs, `"op":"update_sync_policy"`) || !strings.Contains(logs, "changed since it was read") {
		t.Fatalf("conflict not audited:\n%s", logs)
	}
	if code, body = put(t, env.ts, "", policyDoc); code != http.StatusOK {
		t.Fatalf("fresh base: %d %s", code, body)
	}
}

func TestAPISyncPolicyChangeBetweenReadAndSaveConflicts(t *testing.T) {
	var env apiPolicyEnv
	changed := false
	env = newAPIPolicyEnv(t, true, func(ctx context.Context, _ storage.SyncPolicy) ([]string, error) {
		if !changed {
			changed = true
			cur, _ := env.store.Get(ctx)
			_, err := env.store.Put(ctx, cur, storage.SyncPolicy{Enabled: true, Namespaces: map[string]storage.SyncRule{"other": {Paths: []string{"/o"}}}})
			return nil, err
		}
		return nil, nil
	})
	code, body := put(t, env.ts, "", policyDoc)
	if code != http.StatusConflict || strings.Contains(body, "denied") {
		t.Fatalf("%d %s", code, body)
	}
	if p, _ := env.store.Get(context.Background()); p.Namespaces["team-a"].Paths != nil {
		t.Fatalf("overwrote the concurrent change: %+v", p)
	}
}

func TestAPISyncPolicyPutReturnsDigest(t *testing.T) {
	env := newAPIPolicyEnv(t, true, nil)
	req, _ := http.NewRequest(http.MethodPut, env.ts.URL+"/api/v1/sync-policy?base="+policyBase(t, env.ts), strings.NewReader(policyDoc))
	req.Header.Set("Authorization", "Bearer "+apiToken)
	res, err := env.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got := res.Header.Get(PolicyDigestHeader); got == "" || got != policyBase(t, env.ts) {
		t.Fatalf("digest %q, stored %q", got, policyBase(t, env.ts))
	}
}

func TestAPISyncPolicyBodyCap(t *testing.T) {
	env := newAPIPolicyEnv(t, true, nil)
	big := `{"enabled":false,"namespaces":{"a":{"paths":["/` + strings.Repeat("a", 2<<20) + `"]}}}`
	if code, _ := put(t, env.ts, "", big); code != http.StatusBadRequest {
		t.Fatalf("status %d", code)
	}
}

func TestAPISyncPolicyConfirmation(t *testing.T) {
	env := newAPIPolicyEnv(t, true, previewByPaths)
	code, body := put(t, env.ts, "", policyDoc)
	if code != http.StatusConflict {
		t.Fatalf("status %d %s", code, body)
	}
	var out struct {
		Denied []string
		Count  int
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.Count != 1 || !slices.Equal(out.Denied, []string{"team-a/app: denied: /apps"}) {
		t.Fatalf("body %s", body)
	}
	if p, _ := env.store.Get(context.Background()); p.Enabled || env.calls.Load() != 0 {
		t.Fatalf("saved without confirmation: %+v", p)
	}

	var preview struct{ Digest string }
	if err := json.Unmarshal([]byte(body), &preview); err != nil || preview.Digest == "" {
		t.Fatalf("no digest in %s", body)
	}

	for _, wrong := range []string{"delete", "0000", ""} {
		code, again := put(t, env.ts, "confirm="+wrong, policyDoc)
		if code != http.StatusConflict || !strings.Contains(again, preview.Digest) {
			t.Fatalf("confirm=%q: %d %s", wrong, code, again)
		}
	}
	if p, _ := env.store.Get(context.Background()); p.Enabled {
		t.Fatal("saved with a wrong confirmation")
	}

	if code, body = put(t, env.ts, "confirm="+preview.Digest, policyDoc); code != http.StatusOK {
		t.Fatalf("confirmed: %d %s", code, body)
	}
	if p, _ := env.store.Get(context.Background()); !p.Enabled || env.calls.Load() != 1 {
		t.Fatalf("not saved: %+v", p)
	}
	logs := env.logs.String()
	if !strings.Contains(logs, `"source":"api"`) || !strings.Contains(logs, `"op":"enable_sync_policy"`) || !strings.Contains(logs, "team-a") {
		t.Fatalf("not audited:\n%s", logs)
	}

	if code, _ = put(t, env.ts, "", policyDoc); code != http.StatusOK {
		t.Fatalf("policy already denied needs no confirmation: %d", code)
	}
}

func TestAPISyncPolicyPreviewOrderVaries(t *testing.T) {
	calls := 0
	preview := func(context.Context, storage.SyncPolicy) ([]string, error) {
		calls++
		out := []string{"a/x: denied", "a/y: denied", "a/x: denied"}
		if calls%2 == 0 {
			slices.Reverse(out)
		}
		return out, nil
	}
	env := newAPIPolicyEnv(t, true, preview)
	code, body := put(t, env.ts, "", policyDoc)
	if code != http.StatusConflict || !strings.Contains(body, `"count":2`) {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ = put(t, env.ts, "confirm="+previewDigest(t, body), policyDoc); code != http.StatusOK {
		t.Fatalf("confirmed: %d", code)
	}
}

func previewDigest(t *testing.T, body string) string {
	t.Helper()
	var out struct{ Digest string }
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.Digest == "" {
		t.Fatalf("no digest in %s", body)
	}
	return out.Digest
}

func TestAPISyncPolicyDigestFollowsThePreview(t *testing.T) {
	changeList := false
	env := newAPIPolicyEnv(t, true, func(_ context.Context, p storage.SyncPolicy) ([]string, error) {
		out, _ := previewByPaths(context.Background(), p)
		if changeList {
			out = append(out, "z/app: denied: extra")
		}
		return out, nil
	})
	_, first := put(t, env.ts, "", policyDoc)
	_, again := put(t, env.ts, "", policyDoc)
	_, otherPolicy := put(t, env.ts, "", strings.Replace(policyDoc, `"/apps"`, `"/apps","/more"`, 1))
	changeList = true
	_, otherList := put(t, env.ts, "", policyDoc)

	if previewDigest(t, first) != previewDigest(t, again) {
		t.Fatal("the digest of the same preview changed")
	}
	if previewDigest(t, first) == previewDigest(t, otherPolicy) {
		t.Fatal("the digest ignores the policy")
	}
	if previewDigest(t, first) == previewDigest(t, otherList) {
		t.Fatal("the digest ignores the denied list")
	}
	if code, body := put(t, env.ts, "confirm="+previewDigest(t, first), policyDoc); code != http.StatusConflict {
		t.Fatalf("a digest of another list was accepted: %d %s", code, body)
	}
}

func TestAPISyncPolicyPreviewErrorSavesNothing(t *testing.T) {
	env := newAPIPolicyEnv(t, true, func(context.Context, storage.SyncPolicy) ([]string, error) {
		return nil, errors.New("list failed")
	})
	for _, target := range []string{"", "confirm=delete"} {
		if code, _ := put(t, env.ts, target, policyDoc); code != http.StatusInternalServerError {
			t.Fatalf("%s: %d", target, code)
		}
	}
	if p, _ := env.store.Get(context.Background()); p.Enabled {
		t.Fatal("saved after a preview error")
	}
}

func TestAPISyncPolicyDisabledNeedsNoPreview(t *testing.T) {
	env := newAPIPolicyEnv(t, true, previewByPaths)
	_, body := put(t, env.ts, "", policyDoc)
	if code, _ := put(t, env.ts, "confirm="+previewDigest(t, body), policyDoc); code != http.StatusOK {
		t.Fatal(code)
	}
	if code, _ := put(t, env.ts, "", `{"enabled":false}`); code != http.StatusOK {
		t.Fatalf("disable: %d", code)
	}
	if !strings.Contains(env.logs.String(), `"op":"disable_sync_policy"`) {
		t.Fatalf("not audited:\n%s", env.logs.String())
	}
}

func TestAPISyncPolicyFailedPutIsAudited(t *testing.T) {
	backend := k8sstorage.New(fake.NewClientBuilder().Build(), "sm")
	failing := failingPut{backend}
	svc := secrets.New(backend, nil)
	s, err := New(svc, tokens.New(backend), token)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	s.log = slog.New(slog.NewJSONHandler(logs, nil))
	s.SyncPolicy = syncpolicy.New(failing, nil)
	sum := sha256.Sum256([]byte(apiToken))
	if err := backend.PutTokens(context.Background(), []storage.Token{{Name: "full", Hash: hex.EncodeToString(sum[:]), Path: "/"}}); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(s)
	t.Cleanup(ts.Close)
	if code, _ := put(t, ts, "", policyDoc); code != http.StatusInternalServerError {
		t.Fatalf("status %d", code)
	}
	if out := logs.String(); !strings.Contains(out, `"source":"api"`) || !strings.Contains(out, "storage down") {
		t.Fatalf("failed save not audited:\n%s", out)
	}
}

func TestAPISyncPolicyHiddenWithoutStore(t *testing.T) {
	env := newAPIPolicyEnv(t, false, nil)
	for _, method := range []string{"GET", "PUT"} {
		if code, _ := do(t, env.ts, method, "/api/v1/sync-policy", apiToken, policyDoc); code != http.StatusNotFound {
			t.Errorf("%s: %d", method, code)
		}
	}
	_, body := do(t, env.ts, "GET", "/api/v1/info", apiToken, "")
	if strings.Contains(body, "sync-policy") {
		t.Fatalf("capability advertised: %s", body)
	}
}

func TestAPISyncPolicyCapability(t *testing.T) {
	env := newAPIPolicyEnv(t, true, nil)
	_, body := do(t, env.ts, "GET", "/api/v1/info", apiToken, "")
	if !strings.Contains(body, `"sync-policy"`) {
		t.Fatalf("capability missing: %s", body)
	}
}
