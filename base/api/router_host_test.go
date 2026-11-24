package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newLocalTestRequest is httptest.NewRequest addressed to the local API
// instead of example.com, which the Host check refuses.
func newLocalTestRequest(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	r.Host = "127.0.0.1:817"
	return r
}

func TestIsAllowedAPIHost(t *testing.T) {
	t.Parallel()

	for host, want := range map[string]bool{
		"":                     true,
		"127.0.0.1:817":        true,
		"127.0.0.1":            true,
		"[::1]:817":            true,
		"localhost:817":        true,
		"LOCALHOST":            true,
		"192.168.1.10:817":     true,
		"rebind.example:817":   false,
		"example.com":          false,
		"localhost.evil.com":   false,
		"127.0.0.1.nip.io:817": false,
	} {
		if got := isAllowedAPIHost(host); got != want {
			t.Errorf("isAllowedAPIHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestForeignHostIsRefused(t *testing.T) {
	t.Parallel()

	handler := &mainHandler{mux: mainMux}

	r := httptest.NewRequest(http.MethodGet, apiV1Path+"ping", nil)
	r.Host = "rebind.example:817"
	r.Header.Set("Origin", "http://rebind.example:817")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("request with foreign Host: status %d, want 403", w.Code)
	}
}
