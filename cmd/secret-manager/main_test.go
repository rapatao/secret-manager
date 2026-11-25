package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetricsMuxServesOnlyMetrics(t *testing.T) {
	h := metricsMux()
	for path, want := range map[string]int{"/metrics": http.StatusOK, "/": http.StatusNotFound, "/other": http.StatusNotFound} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("GET %s: %d, want %d", path, rec.Code, want)
		}
	}
}
