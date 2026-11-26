package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDetectMime(t *testing.T) {
	t.Parallel()

	cases := []struct {
		file string
		data string
		want string
	}{
		{"a.json", "type: x", mimeJSON},
		{"a.YML", "{}", mimeYAML},
		{"-", "  {\"type\":\"settings\"}", mimeJSON},
		{"-", "type: settings", mimeYAML},
		{"export", "\n{}", mimeJSON},
	}
	for _, c := range cases {
		if got := detectMime(c.file, []byte(c.data)); got != c.want {
			t.Errorf("detectMime(%q, %q) = %q, want %q", c.file, c.data, got, c.want)
		}
	}
}

func TestFormatMime(t *testing.T) {
	t.Parallel()

	m, err := formatMime("JSON")
	if err != nil || m != mimeJSON {
		t.Errorf("json: got %q, %v", m, err)
	}
	m, err = formatMime("yml")
	if err != nil || m != mimeYAML {
		t.Errorf("yml: got %q, %v", m, err)
	}
	_, err = formatMime("xml")
	if !errors.Is(err, errSyncInvalidFmt) {
		t.Errorf("xml: got %v", err)
	}
}

func TestSyncRequest(t *testing.T) { //nolint:paralleltest // Changes syncAPIAddress.
	var gotMethod, gotPath, gotQuery, gotType, gotAccept, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotQuery = r.Method, r.URL.Path, r.URL.RawQuery
		gotType, gotAccept = r.Header.Get("Content-Type"), r.Header.Get("Accept")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		if r.URL.Query().Get("to") == "fail" {
			http.Error(w, "the supplied export cannot be imported here", http.StatusPreconditionFailed)
			return
		}
		_, _ = w.Write([]byte(`{"restartRequired":false}`))
	}))
	defer srv.Close()

	old := syncAPIAddress
	syncAPIAddress = strings.TrimPrefix(srv.URL, "http://")
	defer func() { syncAPIAddress = old }()

	// Export: GET with Accept header and repeated keys.
	q := url.Values{"from": {"global"}, "key": {"a/b", "c/d"}}
	_, err := syncRequest(context.Background(), http.MethodGet, "sync/settings/export", q, mimeYAML, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodGet || gotPath != "/api/v1/sync/settings/export" ||
		gotQuery != "from=global&key=a%2Fb&key=c%2Fd" || gotAccept != mimeYAML {
		t.Errorf("export request: %s %s?%s accept=%q", gotMethod, gotPath, gotQuery, gotAccept)
	}

	// Import: POST with body and Content-Type.
	var res []byte
	q = url.Values{"to": {"global"}, "validate": {"true"}}
	res, err = syncRequest(context.Background(), http.MethodPost, "sync/settings/import", q, mimeJSON, []byte(`{"type":"settings"}`))
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotType != mimeJSON || gotBody != `{"type":"settings"}` {
		t.Errorf("import request: %s type=%q body=%q", gotMethod, gotType, gotBody)
	}
	if string(res) != `{"restartRequired":false}` {
		t.Errorf("import result: %q", res)
	}

	// API errors are returned with their message.
	q = url.Values{"to": {"fail"}}
	_, err = syncRequest(context.Background(), http.MethodPost, "sync/settings/import", q, mimeJSON, []byte(`{}`))
	if !errors.Is(err, errSyncAPI) || !strings.Contains(err.Error(), "cannot be imported here") {
		t.Errorf("expected api error, got %v", err)
	}
}

func TestEmptySettingsExport(t *testing.T) {
	t.Parallel()

	if got := string(emptySettingsExport("json")); got != `{"type":"settings","config":{}}` {
		t.Errorf("json: %q", got)
	}
	if got := string(emptySettingsExport("yaml")); got != "type: settings\nconfig: {}\n" {
		t.Errorf("yaml: %q", got)
	}
}
