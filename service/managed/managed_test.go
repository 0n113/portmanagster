package managed

import (
	"context"
	"encoding/json"
	"maps"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/safing/portmaster/mgmt/policy"
	"github.com/safing/portmaster/mgmt/server"
	"github.com/safing/portmaster/service/mgr"
)

const keyAskTimeout = "filter/askTimeout"

// fakeApplier keeps settings in a map.
type fakeApplier struct {
	mu       sync.Mutex
	settings map[string]any
	profiles []string
	imports  int
}

func newFakeApplier() *fakeApplier {
	return &fakeApplier{settings: map[string]any{}}
}

func (f *fakeApplier) userValue(key string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.settings[key]
}

func (f *fakeApplier) importSettings(s map[string]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.imports++
	maps.Copy(f.settings, s)
	return nil
}

func (f *fakeApplier) importProfile(export json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.profiles = append(f.profiles, string(export))
	return nil
}

func (f *fakeApplier) set(key string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settings[key] = v
}

func TestApplyPolicy(t *testing.T) {
	t.Parallel()

	a := newFakeApplier()
	a.set(keyAskTimeout, int64(33)) // same value, other type
	a.set("filter/lists", []string{"TRAC"})
	p := &policy.Policy{
		Settings: map[string]any{keyAskTimeout: float64(33), "filter/lists": []any{"TRAC", "MAL"}},
		Profiles: []json.RawMessage{json.RawMessage(`{"type":"profile","name":"a"}`)},
	}
	res, hash, err := applyPolicy(a, p, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Corrected) != 1 || res.Corrected[0] != "filter/lists" || res.Profiles != 1 || hash == "" {
		t.Fatalf("unexpected result %+v hash %q", res, hash)
	}

	// Again: nothing differs, profiles unchanged.
	res, hash2, err := applyPolicy(a, p, hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Corrected) != 0 || res.Profiles != 0 || hash2 != hash || a.imports != 1 {
		t.Fatalf("second apply changed something: %+v imports %d", res, a.imports)
	}
}

func TestSameValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		a, b any
		want bool
	}{
		{int64(3), float64(3), true},
		{[]string{"a"}, []any{"a"}, true},
		{true, false, false},
		{nil, nil, true},
		{nil, "x", false},
		{"x", "y", false},
	}
	for _, c := range cases {
		if got := sameValue(c.a, c.b); got != c.want {
			t.Errorf("sameValue(%#v, %#v) = %v", c.a, c.b, got)
		}
	}
}

type testEnv struct {
	srv   *server.Server
	ts    *httptest.Server
	token string
	keyFP string
	crtFP string
	m     *Managed
	a     *fakeApplier
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	now := time.Now()
	dir := t.TempDir()
	err := server.Init(filepath.Join(dir, "server"), "test", []string{"127.0.0.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.Load(filepath.Join(dir, "server"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Store.Close() })
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.TLS = srv.TLSConfig()
	ts.StartTLS()
	t.Cleanup(ts.Close)

	err = srv.Store.CreateGroup("office", now)
	if err != nil {
		t.Fatal(err)
	}
	err = srv.Store.SetGroupPolicy("office", map[string]any{keyAskTimeout: 33}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	token, err := srv.Store.CreateToken("office", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	crtFP, keyFP, err := srv.Fingerprints()
	if err != nil {
		t.Fatal(err)
	}
	a := newFakeApplier()
	m := &Managed{
		mgr:     mgr.New("managed-test"),
		dir:     stateDir(filepath.Join(dir, "client", stateDirName)),
		applier: a,
	}
	return &testEnv{srv: srv, ts: ts, token: token, keyFP: keyFP, crtFP: crtFP, m: m, a: a}
}

func (e *testEnv) enrollReq() *EnrollRequest {
	return &EnrollRequest{Server: e.ts.URL, Token: e.token, ServerFP: e.crtFP, PolicyKeyFP: e.keyFP}
}

func TestEnrollPins(t *testing.T) {
	t.Parallel()

	e := newTestEnv(t)
	ctx := context.Background()

	// A wrong server certificate fingerprint fails before the token is sent.
	r := e.enrollReq()
	r.ServerFP = "sha256:00"
	_, err := e.m.Enroll(ctx, r)
	if err == nil {
		t.Fatal("want an error for a wrong server fingerprint")
	}
	// A wrong policy key fingerprint fails and stores nothing. The token
	// was used by the server, so a new one is needed afterwards.
	r = e.enrollReq()
	r.PolicyKeyFP = "sha256:00"
	_, err = e.m.Enroll(ctx, r)
	if err == nil || !strings.Contains(err.Error(), "policy key") {
		t.Fatalf("want a policy key pin error, got %v", err)
	}
	if e.m.dir.enrolled() {
		t.Fatal("a failed enrollment must not leave a state")
	}
	// http URLs are refused.
	r = e.enrollReq()
	r.Server = strings.Replace(e.ts.URL, "https://", "http://", 1)
	err = enroll(ctx, e.m.dir, r, time.Now())
	if err == nil {
		t.Fatal("want an error for http://")
	}
}

func TestEnrollPullApply(t *testing.T) {
	t.Parallel()

	e := newTestEnv(t)
	ctx := context.Background()

	st, err := e.m.Enroll(ctx, e.enrollReq())
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if !st.Enrolled || st.Group != "office" || st.AppliedVersion == 0 || st.LastError != "" {
		t.Fatalf("unexpected status after enroll: %+v", st)
	}
	if v := e.a.userValue(keyAskTimeout); !sameValue(v, 33) {
		t.Fatalf("policy setting not applied: %v", v)
	}
	_, err = e.m.Enroll(ctx, e.enrollReq())
	if err == nil {
		t.Fatal("a second enrollment must fail")
	}
	for _, f := range []string{fileState, fileClientKey, fileClientCert, fileCA, filePolicy} {
		info, err := os.Stat(e.m.dir.path(f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v", f, info.Mode().Perm())
		}
	}

	// A local change is corrected on the next pull.
	e.a.set(keyAskTimeout, 99)
	err = e.m.pull(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v := e.a.userValue(keyAskTimeout); !sameValue(v, 33) {
		t.Fatalf("drift not corrected: %v", v)
	}
	if got := e.m.Status().LastCorrected; len(got) != 1 {
		t.Fatalf("corrected not reported: %v", got)
	}

	// A change on the server arrives with a higher version.
	before := e.m.Status().AppliedVersion
	err = e.srv.Store.SetGroupPolicy("office", map[string]any{keyAskTimeout: 44}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	err = e.m.pull(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v := e.a.userValue(keyAskTimeout); !sameValue(v, 44) || e.m.Status().AppliedVersion <= before {
		t.Fatalf("server change not applied: %v, version %d", v, e.m.Status().AppliedVersion)
	}

	// The stored policy is applied without the server (offline boot).
	e.a.set(keyAskTimeout, 1)
	err = e.m.applyStored()
	if err != nil {
		t.Fatal(err)
	}
	if v := e.a.userValue(keyAskTimeout); !sameValue(v, 44) {
		t.Fatalf("stored policy not applied: %v", v)
	}

	// A tampered stored policy is refused.
	data, err := os.ReadFile(e.m.dir.path(filePolicy))
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(e.m.dir.path(filePolicy), []byte(strings.Replace(string(data), "44", "45", 1)), 0o600) //nolint:gosec // Test file in a temp dir.
	if err != nil {
		t.Fatal(err)
	}
	err = e.m.applyStored()
	if err == nil {
		t.Fatal("tampered stored policy must be refused")
	}

	// Rollback: a policy older than the applied one is refused.
	st2, err := e.m.dir.loadState()
	if err != nil {
		t.Fatal(err)
	}
	st2.AppliedVersion += 100
	err = e.m.dir.saveState(st2)
	if err != nil {
		t.Fatal(err)
	}
	err = e.m.pull(ctx)
	if err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("want a rollback error, got %v", err)
	}
	st2.AppliedVersion -= 100
	err = e.m.dir.saveState(st2)
	if err != nil {
		t.Fatal(err)
	}

	// Revoked: the pull fails, the applied settings stay.
	err = e.srv.Store.Revoke(e.m.Status().ComputerID)
	if err != nil {
		t.Fatal(err)
	}
	err = e.m.pull(ctx)
	if err == nil {
		t.Fatal("pull of a revoked computer must fail")
	}
	if e.m.Status().LastError == "" {
		t.Fatal("the error must show in the status")
	}

	// Leave removes the enrollment.
	err = e.m.Leave()
	if err != nil {
		t.Fatal(err)
	}
	if e.m.Status().Enrolled {
		t.Fatal("still enrolled after leave")
	}
}
