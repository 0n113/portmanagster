package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/safing/portmaster/mgmt/policy"
)

const (
	groupOffice = "office"
	appCurl     = "Curl"
	idCurl      = "0123456789abcdef0123456789abcdef"
	idFirefox   = "fedcba9876543210fedcba9876543210"
	hostPC1     = "pc-1"
)

// alertStore returns a store with a group "office" and one computer in it.
func alertStore(t *testing.T, now time.Time) (*Store, *Computer) {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	err = s.CreateGroup(groupOffice, now)
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.CreateToken(groupOffice, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	c := &Computer{Hostname: hostPC1, OS: osLinux}
	err = s.Enroll(token, c, now, func(string) (string, error) { return "fp", nil })
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

func kinds(events []AlertEvent) []string {
	list := make([]string, 0, len(events))
	for _, ev := range events {
		list = append(list, ev.Event+":"+ev.Alert.Kind)
	}
	return list
}

func statusJSON(ready, interception bool, problems ...string) json.RawMessage {
	st := map[string]any{"ready": ready, "interception": interception}
	list := make([]map[string]string, 0, len(problems))
	for _, p := range problems {
		list = append(list, map[string]string{"type": p, "message": "broken"})
	}
	st["problems"] = list
	data, _ := json.Marshal(st) //nolint:errchkjson // Plain map.
	return data
}

func TestConditionAlerts(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	s, c := alertStore(t, now)

	healthy := &policy.Report{Type: policy.TypeReport, Status: statusJSON(true, true)}
	events, err := s.EvaluateReport(c, healthy, now)
	if err != nil || len(events) != 0 {
		t.Fatalf("healthy report: %v %v", kinds(events), err)
	}

	bad := &policy.Report{
		Type:       policy.TypeReport,
		Status:     statusJSON(false, false, "module"),
		Refused:    []string{"filter/x"},
		Error:      "pull failed",
		Overridden: []string{reasonLists},
	}
	events, err = s.EvaluateReport(c, bad, now)
	if err != nil {
		t.Fatal(err)
	}
	want := "raised:interception raised:problems raised:refused raised:error raised:overridden"
	if got := strings.Join(kinds(events), " "); got != want {
		t.Fatalf("events %q, want %q", got, want)
	}
	levels := map[string]string{}
	for _, ev := range events {
		levels[ev.Alert.Kind] = ev.Alert.Level
	}
	if levels[AlertInterception] != LevelCritical || levels[AlertOverridden] != LevelInfo || levels[AlertRefused] != LevelWarning {
		t.Fatalf("levels: %v", levels)
	}

	// The same conditions again: no new events, one alert each.
	events, err = s.EvaluateReport(c, bad, now.Add(time.Minute))
	if err != nil || len(events) != 0 {
		t.Fatalf("repeated report: %v %v", kinds(events), err)
	}
	open, _ := s.Alerts(AlertFilter{})
	if len(open) != 5 {
		t.Fatalf("%d open alerts, want 5", len(open))
	}

	// An acknowledged condition alert stays until the condition ends.
	acked, err := s.AckAlerts([]int64{open[0].ID}, "admin:alice", now)
	if err != nil || len(acked) != 1 {
		t.Fatalf("ack: %v %v", acked, err)
	}
	events, _ = s.EvaluateReport(c, bad, now.Add(2*time.Minute))
	if len(events) != 0 {
		t.Fatalf("acknowledged alert raised again: %v", kinds(events))
	}

	// Healthy again: all resolved.
	events, err = s.EvaluateReport(c, healthy, now.Add(3*time.Minute))
	if err != nil || len(events) != 5 {
		t.Fatalf("resolve: %v %v", kinds(events), err)
	}
	for _, ev := range events {
		if ev.Event != EventResolved || ev.Alert.State != StateResolved {
			t.Errorf("not resolved: %+v", ev)
		}
	}
	if open, _ := s.Alerts(AlertFilter{}); len(open) != 0 {
		t.Fatalf("open alerts after resolve: %d", len(open))
	}
	if all, _ := s.Alerts(AlertFilter{State: StateAll}); len(all) != 5 {
		t.Fatalf("all alerts: %d", len(all))
	}
}

func TestProblemLevels(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	s, c := alertStore(t, now)
	warnOnly := json.RawMessage(`{"ready":true,"interception":true,"problems":[{"type":"warning","message":"lists downloading"}]}`)
	events, err := s.EvaluateReport(c, &policy.Report{Type: policy.TypeReport, Status: warnOnly}, now)
	if err != nil || len(events) != 1 || events[0].Alert.Level != LevelInfo {
		t.Fatalf("warning only: %+v %v", events, err)
	}
	// An error raises the level of the open alert.
	_, err = s.EvaluateReport(c, &policy.Report{Type: policy.TypeReport, Status: statusJSON(true, true, "error")}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	open, _ := s.Alerts(AlertFilter{Kind: AlertProblems})
	if len(open) != 1 || open[0].Level != LevelWarning || !strings.Contains(open[0].Message, "error: broken") {
		t.Fatalf("error: %+v", open)
	}
}

func TestMalwareAlerts(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	s, c := alertStore(t, now)

	r := &policy.Report{Type: policy.TypeReport, Blocks: []policy.Block{
		{App: appFirefox, Reason: reasonLists, Lists: "MAL,UHB", Target: targetEvil, Count: 3},
		// Not a malware list: no alert. "MALX" must not match "MAL".
		{App: appFirefox, Reason: reasonLists, Lists: "MALX,TRAC", Target: "ads.example", Count: 9},
	}}
	events, err := s.EvaluateReport(c, r, now)
	if err != nil || len(events) != 1 {
		t.Fatalf("events: %v %v", kinds(events), err)
	}
	a := events[0].Alert
	if a.Kind != AlertMalware || a.Level != LevelCritical || a.Count != 3 || !strings.Contains(a.Message, targetEvil) {
		t.Fatalf("alert: %+v", a)
	}

	// Further hits add to the count of the new alert.
	events, _ = s.EvaluateReport(c, r, now.Add(time.Minute))
	if len(events) != 0 {
		t.Fatalf("second hit raised: %v", kinds(events))
	}
	open, _ := s.Alerts(AlertFilter{Kind: AlertMalware})
	if len(open) != 1 || open[0].Count != 6 {
		t.Fatalf("alerts: %+v", open)
	}

	// After acknowledging, the next hit raises a new alert; event alerts
	// are not resolved by reports without hits.
	_, _ = s.AckAlerts([]int64{a.ID}, "cli", now)
	events, _ = s.EvaluateReport(c, &policy.Report{Type: policy.TypeReport}, now.Add(2*time.Minute))
	if len(events) != 0 {
		t.Fatalf("report without hits: %v", kinds(events))
	}
	events, _ = s.EvaluateReport(c, r, now.Add(3*time.Minute))
	if len(events) != 1 || events[0].Alert.ID == a.ID {
		t.Fatalf("hit after ack: %v", kinds(events))
	}

	// Pruning keeps open alerts and removes old acknowledged ones.
	n, err := s.PruneAlerts(now.Add(time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("pruned %d: %v", n, err)
	}
	if all, _ := s.Alerts(AlertFilter{State: StateAll}); len(all) != 1 {
		t.Fatalf("after prune: %d", len(all))
	}
}

func TestNewAppAlerts(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	s, c := alertStore(t, now)

	report := func(apps ...policy.App) *policy.Report {
		return &policy.Report{Type: policy.TypeReport, Apps: apps}
	}
	curl := policy.App{Name: appCurl, ID: idCurl}
	firefox := policy.App{Name: appFirefox, ID: idFirefox}

	// The first lists are learned without alerts.
	events, err := s.EvaluateReport(c, report(curl), now)
	if err != nil || len(events) != 0 {
		t.Fatalf("first list: %v %v", kinds(events), err)
	}
	events, _ = s.EvaluateReport(c, report(curl, firefox), now.Add(time.Hour))
	if len(events) != 0 {
		t.Fatalf("during learning: %v", kinds(events))
	}
	// After the learning period, a new app raises an alert, a known one not.
	other := policy.App{Name: appFirefox, ID: strings.Repeat("a", 32)}
	events, _ = s.EvaluateReport(c, report(curl, firefox, other), now.Add(AppLearning+time.Hour))
	if len(events) != 1 || events[0].Alert.Kind != AlertNewApp || events[0].Alert.Subject != other.ID {
		t.Fatalf("new app: %+v", events)
	}
	events, _ = s.EvaluateReport(c, report(other), now.Add(AppLearning+2*time.Hour))
	if len(events) != 0 {
		t.Fatalf("known app: %v", kinds(events))
	}
}

func TestCheckApps(t *testing.T) {
	t.Parallel()
	if err := CheckApps([]policy.App{{Name: appCurl, ID: idCurl}}); err != nil { //nolint:noinlineerr // Table of checks.
		t.Fatal(err)
	}
	for _, bad := range [][]policy.App{
		{{Name: appCurl, ID: "short"}},
		{{Name: appCurl, ID: strings.Repeat("G", 32)}},
		{{Name: strings.Repeat("x", 256), ID: idCurl}},
		make([]policy.App, policy.MaxApps+1),
	} {
		if !errors.Is(CheckApps(bad), ErrBadApps) {
			t.Errorf("accepted: %.40v", bad)
		}
	}
}

func TestSilentAlerts(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	s, c := alertStore(t, now)

	g, _ := s.Group(groupOffice)
	if g.SilentAfter != DefaultSilentAfter {
		t.Fatalf("default threshold %s", g.SilentAfter)
	}
	events, err := s.CheckSilent(now.Add(23 * time.Hour))
	if err != nil || len(events) != 0 {
		t.Fatalf("before the threshold: %v %v", kinds(events), err)
	}
	events, _ = s.CheckSilent(now.Add(25 * time.Hour))
	if len(events) != 1 || events[0].Alert.Kind != AlertSilent || events[0].Event != EventRaised {
		t.Fatalf("silent: %v", kinds(events))
	}
	events, _ = s.CheckSilent(now.Add(26 * time.Hour))
	if len(events) != 0 {
		t.Fatalf("still silent: %v", kinds(events))
	}

	// Contact resolves it.
	err = s.Seen(c.ID, now.Add(27*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	events, _ = s.CheckSilent(now.Add(27 * time.Hour))
	if len(events) != 1 || events[0].Event != EventResolved {
		t.Fatalf("after contact: %v", kinds(events))
	}

	// A shorter threshold of the group; zero turns the alert off.
	err = s.SetGroupSilentAfter(groupOffice, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	events, _ = s.CheckSilent(now.Add(29 * time.Hour))
	if len(events) != 1 || events[0].Event != EventRaised {
		t.Fatalf("1h threshold: %v", kinds(events))
	}
	err = s.SetGroupSilentAfter(groupOffice, 0)
	if err != nil {
		t.Fatal(err)
	}
	events, _ = s.CheckSilent(now.Add(30 * time.Hour))
	if len(events) != 1 || events[0].Event != EventResolved {
		t.Fatalf("turned off: %v", kinds(events))
	}
	if !errors.Is(s.SetGroupSilentAfter("nope", time.Hour), ErrNotFound) {
		t.Fatal("unknown group accepted")
	}

	// Revoked computers get their condition alerts resolved.
	_ = s.SetGroupSilentAfter(groupOffice, time.Hour)
	events, _ = s.CheckSilent(now.Add(40 * time.Hour))
	if len(events) != 1 {
		t.Fatalf("silent again: %v", kinds(events))
	}
	_ = s.Revoke(c.ID)
	events, _ = s.CheckSilent(now.Add(41 * time.Hour))
	if len(events) != 1 || events[0].Event != EventResolved {
		t.Fatalf("revoked: %v", kinds(events))
	}
}

func TestAlertFilterAndCounts(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	s, c := alertStore(t, now)
	_, err := s.EvaluateReport(c, &policy.Report{
		Type:       policy.TypeReport,
		Status:     statusJSON(true, false),
		Overridden: []string{"x"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	counts, err := s.CountAlerts()
	if err != nil || counts.Open != 2 || counts.New != 2 || counts.Critical != 1 || counts.Info != 1 {
		t.Fatalf("counts: %+v %v", counts, err)
	}
	if list, _ := s.Alerts(AlertFilter{MinLevel: LevelWarning}); len(list) != 1 || list[0].Kind != AlertInterception {
		t.Fatalf("min level: %+v", list)
	}
	if list, _ := s.Alerts(AlertFilter{Group: "other"}); len(list) != 0 {
		t.Fatalf("other group: %+v", list)
	}
	if list, _ := s.Alerts(AlertFilter{Computer: c.ID, State: StateNew}); len(list) != 2 || list[0].Hostname != hostPC1 {
		t.Fatalf("by computer: %+v", list)
	}
	if _, err := s.Alerts(AlertFilter{State: "bogus"}); !errors.Is(err, ErrBadState) { //nolint:noinlineerr // Table of checks.
		t.Fatalf("bad state: %v", err)
	}
	if _, err := s.Alerts(AlertFilter{MinLevel: "bogus"}); !errors.Is(err, ErrBadLevel) { //nolint:noinlineerr // Table of checks.
		t.Fatalf("bad level: %v", err)
	}
}

type hookReceiver struct {
	mu       sync.Mutex
	payloads []WebhookPayload
	fail     int
}

func (h *hookReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fail > 0 {
		h.fail--
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var p WebhookPayload
	if r.Header.Get("Content-Type") != "application/json" || json.Unmarshal(body, &p) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	h.payloads = append(h.payloads, p)
	w.WriteHeader(http.StatusNoContent)
}

func (h *hookReceiver) received() []WebhookPayload {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]WebhookPayload(nil), h.payloads...)
}

func TestWebhook(t *testing.T) {
	t.Parallel()
	recv := &hookReceiver{fail: 1}
	ts := httptest.NewServer(recv)
	defer ts.Close()

	for _, bad := range []string{"", "ftp://x", "http://", "::"} {
		if _, err := NewWebhook(bad, "", nil); !errors.Is(err, ErrBadWebhook) { //nolint:noinlineerr // Table of checks.
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
	if _, err := NewWebhook(ts.URL, "loud", nil); !errors.Is(err, ErrBadLevel) { //nolint:noinlineerr // Table of checks.
		t.Errorf("bad level: %v", err)
	}

	hook, err := NewWebhook(ts.URL+"/secret-path", LevelWarning, nil)
	if err != nil {
		t.Fatal(err)
	}
	ev := AlertEvent{Event: EventRaised, Alert: Alert{ID: 7, Hostname: hostPC1, Group: groupOffice, Kind: AlertInterception, Level: LevelCritical, Message: "off"}}

	// A failed delivery is an error and names the host only.
	err = hook.Send(context.Background(), ev)
	if err == nil || strings.Contains(err.Error(), "secret-path") {
		t.Fatalf("failed send: %v", err)
	}
	err = hook.Send(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	got := recv.received()
	if len(got) != 1 || got[0].Event != EventRaised || got[0].Alert.ID != 7 || got[0].Text != "[critical] pc-1 (office): off" {
		t.Fatalf("payload: %+v", got)
	}

	// Notify queues alerts of the minimum level and above; Run sends them.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hook.Run(ctx)
	info := ev
	info.Alert.Level = LevelInfo
	resolved := ev
	resolved.Event = EventResolved
	hook.Notify([]AlertEvent{info, resolved})
	deadline := time.Now().Add(5 * time.Second)
	for len(recv.received()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got = recv.received()
	if len(got) != 2 || got[1].Event != EventResolved || !strings.HasPrefix(got[1].Text, "Resolved: ") {
		t.Fatalf("notified: %+v", got)
	}
}

func TestReportAlerts(t *testing.T) {
	t.Parallel()
	s, ts := newTestServer(t)
	var (
		mu     sync.Mutex
		events []AlertEvent
	)
	s.Notify = func(evs []AlertEvent) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, evs...)
	}
	now := time.Now()
	if err := s.Store.CreateGroup(groupOffice, now); err != nil { //nolint:noinlineerr // Test setup.
		t.Fatal(err)
	}
	token, _ := s.Store.CreateToken(groupOffice, time.Hour, now)
	client, _, status := enroll(t, s, ts.URL, token)
	if status != http.StatusOK {
		t.Fatalf("enroll: %d", status)
	}
	r := &policy.Report{
		Type:   policy.TypeReport,
		Time:   now,
		Status: statusJSON(true, true),
		Blocks: []policy.Block{{App: appFirefox, Reason: reasonLists, Lists: listMAL, Target: targetEvil, Count: 1}},
		Apps:   []policy.App{{Name: appCurl, ID: idCurl}},
	}
	data, _ := json.Marshal(r) //nolint:errchkjson // Plain struct.

	// Without the opt-in, blocks and apps are dropped: no malware alert.
	if code := postReport(t, s, ts.URL, client.cert, data); code != http.StatusNoContent {
		t.Fatalf("report: %d", code)
	}
	mu.Lock()
	n := len(events)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("%d events without opt-in", n)
	}
	err := s.Store.SetGroupBlockSummary(groupOffice, true, now)
	if err != nil {
		t.Fatal(err)
	}
	if code := postReport(t, s, ts.URL, client.cert, data); code != http.StatusNoContent {
		t.Fatalf("report: %d", code)
	}
	mu.Lock()
	got := kinds(events)
	mu.Unlock()
	if strings.Join(got, " ") != "raised:malware" {
		t.Fatalf("events: %v", got)
	}

	// An invalid app list is refused.
	r.Apps = []policy.App{{Name: appCurl, ID: "x"}}
	data, _ = json.Marshal(r) //nolint:errchkjson // Plain struct.
	if code := postReport(t, s, ts.URL, client.cert, data); code != http.StatusBadRequest {
		t.Fatalf("bad apps: %d", code)
	}
}
