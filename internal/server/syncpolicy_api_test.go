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

const policyDoc = `{"enabled":true,"namespaces":{"team-a":{"paths":["/apps"],"targetNamespaces":["team-b"]}}}`

func TestAPISyncPolicyAuth(t *testing.T) {
	env := newAPIPolicyEnv(t, true, nil)
	for method, wants := range map[string]map[string]int{
		"GET": {"": 401, "wrong": 401, pathToken: 403, readOnlyToken: 200, apiToken: 200},
		"PUT": {"": 401, pathToken: 403, readOnlyToken: 403, apiToken: 200},
	} {
		for auth, want := range wants {
			if code, body := do(t, env.ts, method, "/api/v1/sync-policy", auth, policyDoc); code != want {
				t.Errorf("%s with %q: %d %s, want %d", method, auth, code, body, want)
			}
		}
	}
}

func TestAPISyncPolicyRoundTrip(t *testing.T) {
	env := newAPIPolicyEnv(t, true, nil)
	if code, _ := do(t, env.ts, "PUT", "/api/v1/sync-policy", apiToken, policyDoc); code != http.StatusOK {
		t.Fatalf("put %d", code)
	}
	code, body := do(t, env.ts, "GET", "/api/v1/sync-policy", apiToken, "")
	if code != http.StatusOK || strings.TrimSpace(body) != policyDoc {
		t.Fatalf("get %d %s", code, body)
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
		if code, resp := do(t, env.ts, "PUT", "/api/v1/sync-policy", apiToken, body); code != http.StatusBadRequest {
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
		if code, resp := do(t, env.ts, "PUT", "/api/v1/sync-policy", apiToken, body); code != http.StatusBadRequest {
			t.Errorf("%q: %d %s", body, code, resp)
		}
	}
	if p, _ := env.store.Get(context.Background()); p.Enabled || env.calls.Load() != 0 {
		t.Fatalf("saved: %+v", p)
	}
	if code, resp := do(t, env.ts, "PUT", "/api/v1/sync-policy", apiToken, policyDoc+"\n \n"); code != http.StatusOK {
		t.Fatalf("trailing whitespace: %d %s", code, resp)
	}
}

func TestAPISyncPolicyConfirmWithNothingDenied(t *testing.T) {
	env := newAPIPolicyEnv(t, true, func(context.Context, storage.SyncPolicy) ([]string, error) { return nil, nil })
	if code, body := do(t, env.ts, "PUT", "/api/v1/sync-policy?confirm=delete", apiToken, policyDoc); code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	if p, _ := env.store.Get(context.Background()); !p.Enabled {
		t.Fatal("not saved")
	}
}

func TestAPISyncPolicyBodyCap(t *testing.T) {
	env := newAPIPolicyEnv(t, true, nil)
	big := `{"enabled":false,"namespaces":{"a":{"paths":["/` + strings.Repeat("a", 2<<20) + `"]}}}`
	if code, _ := do(t, env.ts, "PUT", "/api/v1/sync-policy", apiToken, big); code != http.StatusBadRequest {
		t.Fatalf("status %d", code)
	}
}

func TestAPISyncPolicyConfirmation(t *testing.T) {
	env := newAPIPolicyEnv(t, true, previewByPaths)
	code, body := do(t, env.ts, "PUT", "/api/v1/sync-policy", apiToken, policyDoc)
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

	if code, body = do(t, env.ts, "PUT", "/api/v1/sync-policy?confirm=delete", apiToken, policyDoc); code != http.StatusOK {
		t.Fatalf("confirmed: %d %s", code, body)
	}
	if p, _ := env.store.Get(context.Background()); !p.Enabled || env.calls.Load() != 1 {
		t.Fatalf("not saved: %+v", p)
	}
	logs := env.logs.String()
	if !strings.Contains(logs, `"source":"api"`) || !strings.Contains(logs, `"op":"enable_sync_policy"`) || !strings.Contains(logs, "team-a") {
		t.Fatalf("not audited:\n%s", logs)
	}

	if code, _ = do(t, env.ts, "PUT", "/api/v1/sync-policy", apiToken, policyDoc); code != http.StatusOK {
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
	code, body := do(t, env.ts, "PUT", "/api/v1/sync-policy", apiToken, policyDoc)
	if code != http.StatusConflict || !strings.Contains(body, `"count":2`) {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ = do(t, env.ts, "PUT", "/api/v1/sync-policy?confirm=delete", apiToken, policyDoc); code != http.StatusOK {
		t.Fatalf("confirmed: %d", code)
	}
}

func TestAPISyncPolicyPreviewErrorSavesNothing(t *testing.T) {
	env := newAPIPolicyEnv(t, true, func(context.Context, storage.SyncPolicy) ([]string, error) {
		return nil, errors.New("list failed")
	})
	for _, target := range []string{"/api/v1/sync-policy", "/api/v1/sync-policy?confirm=delete"} {
		if code, _ := do(t, env.ts, "PUT", target, apiToken, policyDoc); code != http.StatusInternalServerError {
			t.Fatalf("%s: %d", target, code)
		}
	}
	if p, _ := env.store.Get(context.Background()); p.Enabled {
		t.Fatal("saved after a preview error")
	}
}

func TestAPISyncPolicyDisabledNeedsNoPreview(t *testing.T) {
	env := newAPIPolicyEnv(t, true, previewByPaths)
	if code, _ := do(t, env.ts, "PUT", "/api/v1/sync-policy?confirm=delete", apiToken, policyDoc); code != http.StatusOK {
		t.Fatal(code)
	}
	if code, _ := do(t, env.ts, "PUT", "/api/v1/sync-policy", apiToken, `{"enabled":false}`); code != http.StatusOK {
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
	if code, _ := do(t, ts, "PUT", "/api/v1/sync-policy", apiToken, policyDoc); code != http.StatusInternalServerError {
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
