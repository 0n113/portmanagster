package managed

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/safing/portmaster/mgmt/policy"
	"github.com/safing/portmaster/mgmt/server"
	"github.com/safing/portmaster/service/mgr"
)

const (
	keyAskTimeout = "filter/askTimeout"
	keyLists      = "filter/lists"
	keyNotify     = "filter/askWithSystemNotifications"

	ruleEvil = "- evil.example"
	listTRAC = "TRAC"
)

var errInvalidRule = errors.New("invalid rule")

// fakeApplier keeps the user settings and the policy layer in maps.
type fakeApplier struct {
	mu       sync.Mutex
	settings map[string]any
	policy   map[string]any
	locked   map[string]bool
	rules    *policy.Rules
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

func (f *fakeApplier) effectiveValue(key string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.policy[key]; ok && f.locked[key] {
		return v
	}
	if v, ok := f.settings[key]; ok {
		return v
	}
	return f.policy[key]
}

// setPolicy refuses keys starting with "unknown/".
func (f *fakeApplier) setPolicy(settings map[string]any, locked []string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var refused []string
	f.policy = map[string]any{}
	for key, v := range settings {
		if strings.HasPrefix(key, "unknown/") {
			refused = append(refused, key)
			continue
		}
		f.policy[key] = v
	}
	f.locked = map[string]bool{}
	for _, key := range locked {
		f.locked[key] = true
	}
	return refused
}

// setRules refuses rules that do not start with "+ " or "- ".
func (f *fakeApplier) setRules(rules *policy.Rules) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rules != nil {
		for _, r := range slices.Concat(rules.Endpoints, rules.ServiceEndpoints) {
			if !strings.HasPrefix(r, "+ ") && !strings.HasPrefix(r, "- ") {
				return errInvalidRule
			}
		}
	}
	f.rules = rules
	return nil
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
	a.set(keyLists, []string{listTRAC})
	a.set(keyNotify, false)
	p := &policy.Policy{
		Settings: map[string]any{
			keyAskTimeout: float64(33), keyLists: []any{listTRAC, "MAL"},
			keyNotify: true, "unknown/x": 1,
		},
		Locked:   []string{keyNotify},
		Rules:    &policy.Rules{Endpoints: []string{ruleEvil}},
		Profiles: []json.RawMessage{json.RawMessage(`{"type":"profile","name":"a"}`)},
	}
	res, hash, err := applyPolicy(a, p, "", true)
	if err != nil {
		t.Fatal(err)
	}
	// filter/lists is a default the user overrides; a different user value
	// of a locked key is not reported, it is not in force.
	if !slices.Equal(res.Overridden, []string{keyLists}) || !slices.Equal(res.Refused, []string{"unknown/x"}) ||
		res.Profiles != 1 || hash == "" {
		t.Fatalf("unexpected result %+v hash %q", res, hash)
	}
	if a.effectiveValue(keyNotify) != true || a.rules == nil || a.imports != 0 {
		t.Fatalf("policy layer not set: %v %v, imports %d", a.effectiveValue(keyNotify), a.rules, a.imports)
	}

	// Again: profiles unchanged; without profiles they are not imported.
	res, hash2, err := applyPolicy(a, p, hash, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Profiles != 0 || hash2 != hash {
		t.Fatalf("second apply imported again: %+v", res)
	}
	res, hash3, err := applyPolicy(a, p, "", false)
	if err != nil || res.Profiles != 0 || hash3 != "" {
		t.Fatalf("apply without profiles: %+v %q %v", res, hash3, err)
	}

	// Invalid rules are refused, the previous rules stay.
	p.Rules = &policy.Rules{Endpoints: []string{"bad"}}
	res, _, err = applyPolicy(a, p, hash, true)
	if err != nil || len(res.Refused) != 2 || !strings.HasPrefix(res.Refused[0], "rules:") ||
		a.rules == nil || a.rules.Endpoints[0] != ruleEvil {
		t.Fatalf("invalid rules: %+v %v %v", res, a.rules, err)
	}
}

func TestLeavePolicy(t *testing.T) {
	t.Parallel()

	a := newFakeApplier()
	a.set(keyLists, []string{listTRAC})
	a.set(keyNotify, false)
	a.set(cfgEndpoints, []any{"+ good.example"})
	p := &policy.Policy{
		Settings: map[string]any{keyAskTimeout: 88, keyLists: []any{"MAL"}, keyNotify: true},
		Locked:   []string{keyNotify},
		Rules:    &policy.Rules{Endpoints: []string{ruleEvil}, ServiceEndpoints: []string{"- *"}},
	}
	_, _, err := applyPolicy(a, p, "", false)
	if err != nil {
		t.Fatal(err)
	}
	err = leavePolicy(a, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.policy) != 0 || a.rules != nil {
		t.Fatalf("policy layer not removed: %v %v", a.policy, a.rules)
	}
	// Locked values and defaults without a user value are kept, the user
	// value of an overridden default stays.
	if !sameValue(a.userValue(keyAskTimeout), 88) || !sameValue(a.userValue(keyNotify), true) ||
		!sameValue(a.userValue(keyLists), []string{listTRAC}) {
		t.Fatalf("values not kept: %v", a.settings)
	}
	if !sameValue(a.userValue(cfgEndpoints), []string{ruleEvil, "+ good.example"}) ||
		!sameValue(a.userValue(cfgServiceEndpoints), []string{"- *"}) {
		t.Fatalf("rules not kept: %v %v", a.userValue(cfgEndpoints), a.userValue(cfgServiceEndpoints))
	}

	// Without a policy, leaving only removes the layer.
	a.imports = 0
	err = leavePolicy(a, nil)
	if err != nil || a.imports != 0 {
		t.Fatalf("leave without policy: %v, imports %d", err, a.imports)
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
		mgr:        mgr.New("managed-test"),
		dir:        stateDir(filepath.Join(dir, "client", stateDirName)),
		applier:    a,
		coreStatus: func() any { return map[string]any{"ready": true, "interception": true} },
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
	// A wrong policy key fingerprint fails before the token is used and
	// stores nothing.
	r = e.enrollReq()
	r.PolicyKeyFP = "sha256:00"
	_, err = e.m.Enroll(ctx, r)
	if err == nil || !strings.Contains(err.Error(), "policy key") {
		t.Fatalf("want a policy key pin error, got %v", err)
	}
	if e.m.dir.enrolled() {
		t.Fatal("a failed enrollment must not leave a state")
	}
	if list, _ := e.srv.Store.Computers(); len(list) != 0 {
		t.Fatalf("a failed pin check must not create a computer: %d", len(list))
	}
	// The token is still valid.
	_, err = e.m.Enroll(ctx, e.enrollReq())
	if err != nil {
		t.Fatalf("enroll with the unused token: %v", err)
	}
	err = e.m.Leave()
	if err != nil {
		t.Fatal(err)
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
	if v := e.a.effectiveValue(keyAskTimeout); !sameValue(v, 33) || e.a.userValue(keyAskTimeout) != nil {
		t.Fatalf("policy setting not applied as policy: %v", v)
	}
	if len(st.Overridden) != 0 {
		t.Fatalf("nothing is overridden yet: %v", st.Overridden)
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

	// A local override of the (unlocked) policy default is kept and
	// reported on the next pull.
	e.a.set(keyAskTimeout, 99)
	err = e.m.pull(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v := e.a.effectiveValue(keyAskTimeout); !sameValue(v, 99) {
		t.Fatalf("local override not kept: %v", v)
	}
	if got := e.m.Status().Overridden; len(got) != 1 {
		t.Fatalf("override not reported: %v", got)
	}

	// The report reaches the server with the override and the core status.
	c, err := e.srv.Store.Computer(e.m.Status().ComputerID)
	if err != nil {
		t.Fatal(err)
	}
	if c.Report == nil || c.AppliedVersion != e.m.Status().AppliedVersion ||
		len(c.Report.Overridden) != 1 || !strings.Contains(string(c.Report.Status), `"ready":true`) {
		t.Fatalf("report not stored on the server: %+v", c)
	}
	if e.m.Status().LastReport.IsZero() || e.m.Status().LastReportError != "" {
		t.Fatalf("report not shown in the status: %+v", e.m.Status())
	}

	// Profiles of the group are imported once, and again when they change.
	err = e.srv.Store.SetGroupProfiles("office", []json.RawMessage{json.RawMessage(`{"type":"profile","name":"restic"}`)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		err = e.m.pull(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(e.a.profiles) != 1 || !strings.Contains(e.a.profiles[0], "restic") {
		t.Fatalf("group profile not imported once: %v", e.a.profiles)
	}

	// A change on the server arrives with a higher version; the locked
	// value wins over the user value.
	before := e.m.Status().AppliedVersion
	err = e.srv.Store.SetGroupPolicy("office", map[string]any{keyAskTimeout: 44}, []string{keyAskTimeout}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	err = e.m.pull(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v := e.a.effectiveValue(keyAskTimeout); !sameValue(v, 44) || e.m.Status().AppliedVersion <= before ||
		len(e.m.Status().Overridden) != 0 {
		t.Fatalf("server change not applied: %v, version %d", v, e.m.Status().AppliedVersion)
	}

	// The rules of the group reach the client.
	err = e.srv.Store.SetGroupRules("office", &policy.Rules{Endpoints: []string{ruleEvil}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	err = e.m.pull(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if e.a.rules == nil || !slices.Equal(e.a.rules.Endpoints, []string{ruleEvil}) {
		t.Fatalf("group rules not applied: %+v", e.a.rules)
	}

	// The stored policy is applied without the server (offline boot).
	e.a.setPolicy(nil, nil)
	err = e.m.applyStored(false)
	if err != nil {
		t.Fatal(err)
	}
	if v := e.a.effectiveValue(keyAskTimeout); !sameValue(v, 44) {
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
	err = e.m.applyStored(true)
	if err == nil {
		t.Fatal("tampered stored policy must be refused")
	}
	err = os.WriteFile(e.m.dir.path(filePolicy), data, 0o600) //nolint:gosec // Test file in a temp dir.
	if err != nil {
		t.Fatal(err)
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

	// Leave removes the enrollment and keeps the locked value as a user
	// value.
	err = e.m.Leave()
	if err != nil {
		t.Fatal(err)
	}
	if e.m.Status().Enrolled {
		t.Fatal("still enrolled after leave")
	}
	if len(e.a.policy) != 0 || !sameValue(e.a.userValue(keyAskTimeout), 44) {
		t.Fatalf("leave: policy %v, user value %v", e.a.policy, e.a.userValue(keyAskTimeout))
	}
}
