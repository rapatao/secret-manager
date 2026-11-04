package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInfoAndRequire(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"version":"1.4.0","capabilities":["paths","backup"]}`))
	}))
	defer ts.Close()

	c := New(ts.URL, "t")
	ctx := context.Background()
	if err := c.Require(ctx, "backup"); err != nil {
		t.Fatal(err)
	}
	err := c.Require(ctx, "teleport")
	if err == nil || !strings.Contains(err.Error(), "server 1.4.0 at "+ts.URL+" does not support teleport") {
		t.Fatalf("missing capability: %v", err)
	}
	if calls != 1 {
		t.Fatalf("info fetched %d times, want 1", calls)
	}
}

func TestInfoFromServerWithoutInfo(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	c := New(ts.URL, "t")
	info, err := c.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "" || strings.Join(info.Capabilities, ",") != "history,paths,secrets" {
		t.Fatalf("baseline: %+v", info)
	}
	if err := c.Require(context.Background(), "backup"); err == nil || !strings.Contains(err.Error(), "(unknown version)") {
		t.Fatalf("require on old server: %v", err)
	}
}

func TestReadKeyFromServerWithoutSecretsKey(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/secrets", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"A":"1","B":"2"},"cacheMaxAge":60}`))
	})
	mux.HandleFunc("DELETE /api/v1/secrets/{key}", func(http.ResponseWriter, *http.Request) {})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := New(ts.URL, "t")
	data, maxAge, err := c.Read(context.Background(), "/app", "A", false)
	if err != nil || len(data) != 1 || data["A"] != "1" || maxAge == nil || *maxAge != time.Minute {
		t.Fatalf("fallback read: %v %v %v", data, maxAge, err)
	}
	_, _, err = c.Read(context.Background(), "/app", "C", false)
	if apiErr := (*Error)(nil); !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound {
		t.Fatalf("fallback missing key: %v", err)
	}
}
