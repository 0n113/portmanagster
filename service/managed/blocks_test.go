package managed

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/safing/portmaster/mgmt/policy"
	"github.com/safing/portmaster/mgmt/server"
	"github.com/safing/portmaster/service/netquery"
)

const (
	appFirefox = "Firefox"
	listMAL    = "MAL"
	domainEvil = "evil.example."
	appCurl    = "Curl"
)

func TestSummarizeBlocks(t *testing.T) {
	t.Parallel()

	conns := []netquery.BlockedConn{
		{App: appFirefox, Domain: domainEvil, RemoteIP: "192.0.2.1", Reason: keyLists, Lists: []string{listTRAC, listMAL}},
		{App: appFirefox, Domain: domainEvil, RemoteIP: "192.0.2.2", Reason: keyLists, Lists: []string{listMAL, listTRAC}},
		{App: appFirefox, Domain: domainEvil, Reason: keyLists, Lists: []string{listMAL, listTRAC}, Inbound: true},
		{App: "System", RemoteIP: "198.51.100.7"},
		{App: strings.Repeat("ä", 200), Domain: "long.example."},
	}
	blocks := summarizeBlocks(conns)
	if len(blocks) != 4 {
		t.Fatalf("want 4 entries, got %+v", blocks)
	}
	want := policy.Block{App: appFirefox, Reason: keyLists, Lists: "MAL,TRAC", Target: "evil.example", Count: 2}
	if blocks[0] != want {
		t.Fatalf("largest entry: %+v", blocks[0])
	}
	for _, b := range blocks[1:] {
		if b.Count != 1 {
			t.Fatalf("entry %+v", b)
		}
		switch {
		case b.Inbound:
		case b.App == "System":
			if b.Target != "198.51.100.7" {
				t.Fatalf("IP target: %+v", b)
			}
		default:
			// Cut to maxBlockField bytes without splitting a character.
			if len(b.App) > maxBlockField || !strings.HasPrefix(strings.Repeat("ä", 200), b.App) {
				t.Fatalf("long app name: %d bytes", len(b.App))
			}
		}
	}

	// The summary is capped, the largest counts first.
	var many []netquery.BlockedConn
	for i := range policy.MaxBlocks + 50 {
		for range i%3 + 1 {
			many = append(many, netquery.BlockedConn{App: "a", Domain: strings.Repeat("x", i%40+1) + "-" + string(rune('a'+i%26)) + ".example", RemoteIP: string(rune(i))})
		}
	}
	blocks = summarizeBlocks(many)
	if len(blocks) > policy.MaxBlocks || blocks[0].Count < blocks[len(blocks)-1].Count {
		t.Fatalf("cap or order: %d entries, %d .. %d", len(blocks), blocks[0].Count, blocks[len(blocks)-1].Count)
	}
}

func TestBlockWindowStart(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	if got := blockWindowStart(time.Time{}, now); !got.Equal(now.Add(-maxBlockWindow)) {
		t.Fatalf("no previous summary: %v", got)
	}
	last := now.Add(-5 * time.Minute)
	if got := blockWindowStart(last, now); !got.Equal(last) {
		t.Fatalf("after a summary: %v", got)
	}
	if got := blockWindowStart(now.Add(-time.Hour), now); !got.Equal(now.Add(-maxBlockWindow)) {
		t.Fatalf("old summary: %v", got)
	}
}

func TestReportBlocks(t *testing.T) {
	t.Parallel()

	e := newTestEnv(t)
	ctx := context.Background()
	var (
		mu    sync.Mutex
		calls []time.Time
	)
	e.m.blocked = func(_ context.Context, since, until time.Time, limit int) ([]netquery.BlockedConn, error) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, since, until)
		if limit != maxBlockedRows {
			t.Errorf("limit %d", limit)
		}
		return []netquery.BlockedConn{{App: appFirefox, Domain: domainEvil, Reason: keyLists, Lists: []string{listMAL}}}, nil
	}
	e.m.apps = func(_ context.Context, _, _ time.Time, _ int) ([]netquery.ConnectedApp, error) {
		return []netquery.ConnectedApp{{Name: appFirefox, Path: "/usr/lib/firefox/firefox"}}, nil
	}

	st, err := e.m.Enroll(ctx, e.enrollReq())
	if err != nil {
		t.Fatal(err)
	}
	// Off by default: no summary is made.
	if st.BlockSummary || len(calls) != 0 {
		t.Fatalf("summary without opt-in: %+v, %d calls", st, len(calls))
	}

	err = e.srv.Store.SetGroupBlockSummary("office", true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		err = e.m.pull(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !e.m.Status().BlockSummary {
		t.Fatal("status does not show the block summary")
	}
	// Two summaries; the second starts where the first ended.
	if len(calls) != 4 || !calls[2].Equal(calls[1]) {
		t.Fatalf("windows: %v", calls)
	}
	rows, err := e.srv.Store.Blocks(server.BlockFilter{Since: time.Now().Add(-time.Hour), List: listMAL})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Count != 2 || rows[0].App != appFirefox || rows[0].Target != "evil.example" {
		t.Fatalf("blocks on the server: %+v", rows)
	}
	// The app list arrives with a hash instead of the path, and the
	// malware hit raised an alert.
	apps, err := e.srv.Store.Apps(st.ComputerID)
	if err != nil || len(apps) != 1 || apps[0].Name != appFirefox || len(apps[0].ID) != 32 {
		t.Fatalf("apps on the server: %+v %v", apps, err)
	}
	alerts, err := e.srv.Store.Alerts(server.AlertFilter{Kind: server.AlertMalware})
	if err != nil || len(alerts) != 1 || alerts[0].Count != 2 {
		t.Fatalf("malware alerts: %+v %v", alerts, err)
	}

	// Off again: no more summaries.
	err = e.srv.Store.SetGroupBlockSummary("office", false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	err = e.m.pull(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if e.m.Status().BlockSummary || len(calls) != 4 {
		t.Fatalf("summary after opt-out: %d calls", len(calls))
	}
}

func TestSummarizeApps(t *testing.T) {
	t.Parallel()

	apps := summarizeApps([]netquery.ConnectedApp{
		{Name: appFirefox, Path: "/usr/lib/firefox/firefox"},
		{Name: appCurl, Path: "/usr/bin/curl"},
		{Name: appFirefox, Path: "/opt/firefox/firefox"},
		{Name: appCurl, Path: "/usr/bin/curl"},
	})
	if len(apps) != 3 || apps[0].Name != appCurl || apps[1].Name != appFirefox || apps[2].Name != appFirefox {
		t.Fatalf("apps: %+v", apps)
	}
	for _, a := range apps {
		if len(a.ID) != 32 || strings.Contains(a.ID, "/") {
			t.Errorf("ID %q is not a short hash", a.ID)
		}
	}
	if apps[1].ID == apps[2].ID {
		t.Error("different paths have the same ID")
	}

	many := make([]netquery.ConnectedApp, policy.MaxApps+5)
	for n := range many {
		many[n] = netquery.ConnectedApp{Name: appFirefox, Path: strconv.Itoa(n)}
	}
	if got := summarizeApps(many); len(got) != policy.MaxApps {
		t.Errorf("%d apps, want %d", len(got), policy.MaxApps)
	}
}
