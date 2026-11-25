package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/rapatao/secret-manager/internal/secrets"
	"github.com/rapatao/secret-manager/internal/storage"
	k8sstorage "github.com/rapatao/secret-manager/internal/storage/kubernetes"
	"github.com/rapatao/secret-manager/internal/tokens"
)

const slowStore = 300 * time.Millisecond

type slowBackend struct{ storage.Backend }

func (s slowBackend) List(ctx context.Context, prefix string) ([]string, error) {
	time.Sleep(slowStore)
	return s.Backend.List(ctx, prefix)
}

func (s slowBackend) Put(ctx context.Context, path string, data map[string]string) error {
	time.Sleep(slowStore)
	return s.Backend.Put(ctx, path, data)
}

// newSlowServer serves a Server whose storage is slower than the 100ms write
// deadline that each API request and the backup download start with, as an
// http.Server with a WriteTimeout sets it.
func newSlowServer(t *testing.T) *httptest.Server {
	t.Helper()
	backend := k8sstorage.New(fake.NewClientBuilder().Build(), "sm")
	sum := sha256.Sum256([]byte(apiToken))
	if err := backend.PutTokens(context.Background(), []storage.Token{{Name: "full", Hash: hex.EncodeToString(sum[:]), Path: "/"}}); err != nil {
		t.Fatal(err)
	}
	s, err := New(secrets.New(slowBackend{backend}, nil), tokens.New(backend), token)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/backup" {
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		}
		s.ServeHTTP(w, r)
	}))
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func slowRequest(ts *httptest.Server, method, path, body string) (*http.Response, error) {
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiToken)
	return ts.Client().Do(req)
}

func TestWriteTimeoutCutsSlowHandlers(t *testing.T) {
	ts := newSlowServer(t)
	if res, err := slowRequest(ts, http.MethodGet, "/api/v1/paths", ""); err == nil {
		res.Body.Close()
		t.Fatalf("a handler slower than the write timeout completed: %d", res.StatusCode)
	}
}

func TestBackupExtendsTheWriteDeadline(t *testing.T) {
	ts := newSlowServer(t)
	res, err := slowRequest(ts, http.MethodGet, "/api/v1/backup", "")
	if err != nil {
		t.Fatalf("backup cut by the write timeout: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("backup status %d", res.StatusCode)
	}
}

func TestRestoreExtendsTheWriteDeadline(t *testing.T) {
	ts := newSlowServer(t)
	res, err := slowRequest(ts, http.MethodPost, "/api/v1/restore", `{"format":1,"paths":[{"path":"/a","data":{"K":"v"}}]}`)
	if err != nil {
		t.Fatalf("restore cut by the write timeout: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("restore status %d", res.StatusCode)
	}
}

func TestWebBackupExtendsTheWriteDeadline(t *testing.T) {
	ts := newSlowServer(t)
	c := uiClient(t, ts)
	if status, _ := postForm(t, c, ts, "/login", url.Values{"token": {token}}, ts.URL); status != http.StatusOK {
		t.Fatalf("sign-in: %d", status)
	}
	status, body := postForm(t, c, ts, "/backup", url.Values{"plain": {"true"}}, ts.URL)
	if status != http.StatusOK || !strings.Contains(body, `"format"`) {
		t.Fatalf("backup download: %d %.200s", status, body)
	}
}
