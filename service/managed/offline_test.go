package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safing/jess"

	"github.com/safing/portmaster/mgmt/policy"
	"github.com/safing/portmaster/mgmt/server"
)

// offlineSetup turns offline signing on at the test server and returns the
// offline key and the fingerprint of its public key.
func offlineSetup(t *testing.T, e *testEnv) (*jess.Signet, string) {
	t.Helper()
	key, err := policy.GenerateKey("offline")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.Export(false)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := server.SetOfflineKey(e.srv.Dir, pub)
	if err != nil {
		t.Fatal(err)
	}
	return key, fp
}

// publish signs the current settings of the group and publishes them.
func publish(t *testing.T, e *testEnv, key *jess.Signet, at time.Time) {
	t.Helper()
	g, err := e.srv.Store.Group("office")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := policy.SignGroup(server.ExportGroup(g), key, at)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.srv.Publish("office", signed)
	if err != nil {
		t.Fatal(err)
	}
}

func TestOfflineSigningClient(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	ctx := context.Background()
	key, fp := offlineSetup(t, e)
	now := time.Now()

	// A wrong offline pin fails the enrollment before the token is used.
	r := e.enrollReq()
	r.OfflineKeyFP = wrongFP
	_, err := e.m.Enroll(ctx, r)
	if err == nil || e.m.dir.enrolled() {
		t.Fatalf("wrong offline pin: %v", err)
	}

	// Pinned at enrollment; without a signed policy nothing is applied.
	r.OfflineKeyFP = fp
	st, err := e.m.Enroll(ctx, r)
	if err != nil || !st.Enrolled || st.OfflineKeyFP != fp || st.AppliedVersion != 0 || !strings.Contains(st.LastError, "no policy") {
		t.Fatalf("enroll without signed policy: %v %+v", err, st)
	}

	publish(t, e, key, now)
	err = e.m.pull(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v := e.a.effectiveValue(keyAskTimeout); !sameValue(v, 33) {
		t.Fatalf("signed setting not applied: %v", v)
	}
	applied := e.m.Status().AppliedVersion

	// A draft change on the server is not applied until it is signed.
	err = e.srv.Store.SetGroupPolicy("office", map[string]any{keyAskTimeout: 44}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	err = e.m.pull(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v := e.a.effectiveValue(keyAskTimeout); !sameValue(v, 33) {
		t.Fatalf("unsigned draft applied: %v", v)
	}
	publish(t, e, key, now.Add(time.Second))
	err = e.m.pull(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v := e.a.effectiveValue(keyAskTimeout); !sameValue(v, 44) {
		t.Fatalf("newly signed setting not applied: %v", v)
	}

	// A server that turns offline signing off (e.g. taken over) gets its
	// policies refused; the applied one stays.
	err = os.Remove(filepath.Join(e.srv.Dir, server.FileOfflinePub))
	if err != nil {
		t.Fatal(err)
	}
	err = e.srv.Store.SetGroupPolicy("office", map[string]any{keyAskTimeout: 1}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	err = e.m.pull(ctx)
	if !errors.Is(err, policy.ErrNotOfflineSigned) {
		t.Fatalf("unsigned policy after pin: %v", err)
	}
	if v := e.a.effectiveValue(keyAskTimeout); !sameValue(v, 44) || e.m.Status().AppliedVersion <= applied {
		t.Fatalf("applied policy changed: %v", v)
	}

	// The stored policy is opened at start and kept on leave.
	err = e.m.applyStored(true)
	if err != nil {
		t.Fatal(err)
	}
	p, err := e.m.storedPolicy()
	if err != nil || !sameValue(p.Settings[keyAskTimeout], 44) {
		t.Fatalf("stored policy: %+v %v", p, err)
	}
}

func TestOfflineKeyTrustOnFirstUse(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	ctx := context.Background()

	// Enrolled before offline signing: plain policies.
	_, err := e.m.Enroll(ctx, e.enrollReq())
	if err != nil {
		t.Fatal(err)
	}
	if e.m.Status().OfflineKeyFP != "" {
		t.Fatal("offline key pinned without offline signing")
	}

	// The first signed policy pins the offline key.
	key, fp := offlineSetup(t, e)
	publish(t, e, key, time.Now())
	err = e.m.pull(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.m.Status().OfflineKeyFP; got != fp {
		t.Fatalf("pinned %q, want %q", got, fp)
	}
	st, _ := e.m.dir.loadState()
	if st.GroupVersions["office"] == 0 {
		t.Fatalf("group version not stored: %+v", st.Pins)
	}
}
