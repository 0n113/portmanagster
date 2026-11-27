package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSyncAPI serves the sync endpoints used by backup create and restore.
type fakeSyncAPI struct {
	mu        sync.Mutex
	imports   []string // "path?query" of each import
	rejectID  string   // profile export content that fails validation
	failExpID string   // profile ID whose export fails
}

func (f *fakeSyncAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/sync/settings/export":
		_, _ = io.WriteString(w, "type: settings\nconfig:\n  filter:\n    askTimeout: 33\n")
	case "/api/v1/sync/profile/list":
		_, _ = io.WriteString(w, `[
			{"id":"local/aaa","source":"local","name":"App A"},
			{"id":"local/_system","source":"local","name":"System","special":true},
			{"id":"local/bbb","source":"local","name":"App B"},
			{"id":"local/ccc","source":"local","name":"Broken"},
			{"id":"special/x","source":"special","name":"X"}]`)
	case "/api/v1/sync/profile/export":
		id := r.URL.Query().Get("id")
		if id == f.failExpID {
			http.Error(w, "icon error", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, "type: profile\nsource: local\nname: "+id+"\n") //nolint:gosec // Test server, plain text.
	case "/api/v1/sync/settings/import", "/api/v1/sync/profile/import":
		body, _ := io.ReadAll(r.Body)
		if f.rejectID != "" && strings.Contains(string(body), f.rejectID) {
			http.Error(w, "invalid profile", http.StatusUnprocessableEntity)
			return
		}
		f.mu.Lock()
		f.imports = append(f.imports, r.URL.Path+"?"+r.URL.RawQuery)
		f.mu.Unlock()
		_, _ = io.WriteString(w, `{"restartRequired":false}`)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeSyncAPI) realImports() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, i := range f.imports {
		if !strings.Contains(i, "validate=") {
			out = append(out, i)
		}
	}
	return out
}

func useFakeAPI(t *testing.T, f *fakeSyncAPI) {
	t.Helper()
	srv := httptest.NewServer(f)
	oldAPI, oldVal, oldReset := syncAPIAddress, backupValidate, backupReset
	t.Cleanup(func() {
		srv.Close()
		syncAPIAddress, backupValidate, backupReset = oldAPI, oldVal, oldReset
	})
	syncAPIAddress = strings.TrimPrefix(srv.URL, "http://")
	backupValidate, backupReset = false, false
}

func TestBackupCreateRestore(t *testing.T) { //nolint:paralleltest // Changes package flags.
	f := &fakeSyncAPI{failExpID: "local/ccc"}
	useFakeAPI(t, f)
	dir := filepath.Join(t.TempDir(), "backup")

	m, err := createBackup(t.Context(), dir, time.Unix(1700000000, 0))
	if err == nil || !strings.Contains(err.Error(), "local/ccc") {
		t.Fatalf("want a partial backup error naming local/ccc, got %v", err)
	}
	if m == nil || len(m.Profiles) != 2 || len(m.Skipped) != 3 {
		t.Fatalf("want 2 profiles and 3 skipped, got %+v", m)
	}
	for _, name := range []string{"manifest.json", "settings.yaml", "profiles/local_aaa.yaml", "profiles/local_bbb.yaml"} {
		_, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(dir), ".backup.tmp-*")); len(left) > 0 {
		t.Errorf("temporary directory left: %v", left)
	}

	// A second backup into the same, now non-empty directory is refused.
	_, err = createBackup(t.Context(), dir, time.Now())
	if err == nil {
		t.Error("want an error for a non-empty directory")
	}

	// Validate only: nothing imported.
	backupValidate = true
	_, err = restoreBackup(t.Context(), dir)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := f.realImports(); len(got) != 0 {
		t.Fatalf("validate must not import, got %v", got)
	}

	// Restore with reset: settings and both profiles, replacing existing ones.
	backupValidate, backupReset = false, true
	report, err := restoreBackup(t.Context(), dir)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	got := f.realImports()
	if len(got) != 3 || !strings.Contains(got[0], "settings/import") || !strings.Contains(got[0], "reset=true") ||
		!strings.Contains(got[1], "allowReplace=true") {
		t.Fatalf("unexpected imports: %v", got)
	}
	if len(report.Profiles) != 2 || report.Profiles[0].Error != "" {
		t.Fatalf("unexpected report: %+v", report)
	}
	_, err = json.Marshal(report)
	if err != nil {
		t.Fatalf("report does not marshal: %v", err)
	}
}

func TestBackupRestoreRejectsInvalid(t *testing.T) { //nolint:paralleltest // Changes package flags.
	f := &fakeSyncAPI{}
	useFakeAPI(t, f)
	dir := filepath.Join(t.TempDir(), "backup")
	_, err := createBackup(t.Context(), dir, time.Now())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// One invalid profile: nothing is imported, not even the settings.
	f.rejectID = "local/bbb"
	report, err := restoreBackup(t.Context(), dir)
	if err == nil {
		t.Fatal("want an error for an invalid profile")
	}
	if got := f.realImports(); len(got) != 0 {
		t.Fatalf("nothing may be imported, got %v", got)
	}
	if report == nil || report.Profiles[1].Error == "" {
		t.Fatalf("report must name the invalid profile: %+v", report)
	}

	// A manifest pointing outside the backup directory is rejected.
	m := `{"format":1,"settings":"../settings.yaml","profiles":[]}`
	err = os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(m), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = restoreBackup(t.Context(), dir)
	if err == nil {
		t.Fatal("want an error for a file outside the backup")
	}
}
