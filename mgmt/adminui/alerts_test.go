package adminui

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/safing/portmaster/mgmt/policy"
	"github.com/safing/portmaster/mgmt/server"
)

const (
	keyAskTimeout = "filter/askTimeout"
	noAlerts      = "No alerts match."
	fieldAfter    = "after"
)

// raiseAlerts raises an interception alert (critical) and an overridden
// alert (info) for the computer.
func raiseAlerts(t *testing.T, h *harness, id string) []server.AlertEvent {
	t.Helper()
	c, err := h.store.Computer(id)
	if err != nil {
		t.Fatal(err)
	}
	events, err := h.store.EvaluateReport(c, &policy.Report{
		Type:       policy.TypeReport,
		Status:     json.RawMessage(`{"ready":true,"interception":false,"problems":[]}`),
		Overridden: []string{keyAskTimeout},
	}, h.now)
	if err != nil || len(events) != 2 {
		t.Fatalf("raise: %d events, %v", len(events), err)
	}
	return events
}

func TestAlertPages(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addTOTPAdmin(testAdmin, server.RoleAdmin)
	ids := h.seed()
	cookie, csrf := h.login(testAdmin, secret)

	mustContain(t, "dashboard", h.get("/", cookie), "new alerts", "No open alerts.")
	mustContain(t, "alerts", h.get(alertsPath, cookie), noAlerts)

	events := raiseAlerts(t, h, ids["healthy"])
	critical := events[0].Alert
	mustContain(t, "dashboard", h.get("/", cookie), "Network interception is off", "All 2 open alerts", `href="/alerts?state=new"`)
	mustContain(t, "computer", h.get("/computers/"+ids["healthy"], cookie), "Open alerts", "Network interception is off", "Acknowledge")
	mustContain(t, "group", h.get(officePath, cookie), "Network interception is off", "silent alert after <strong>24h</strong>")

	for _, c := range []struct {
		query   string
		want    string
		notWant string
	}{
		{"", "Acknowledge all 2 new alerts shown", ""},
		{"?level=warning", "Network interception is off", "Policy defaults changed locally"},
		{"?kind=overridden", "Policy defaults changed locally", "Network interception is off"},
		{"?group=lab", noAlerts, ""},
		{"?computer=" + ids["broken"], noAlerts, ""},
		{"?state=resolved", noAlerts, ""},
		{"?limit=1", "Only the 1 last changed", ""},
	} {
		body := h.get(alertsPath+c.query, cookie)
		mustContain(t, "alerts"+c.query, body, c.want)
		if c.notWant != "" && strings.Contains(body, c.notWant) {
			t.Errorf("alerts%s: must not contain %q", c.query, c.notWant)
		}
	}
	if w := h.request(http.MethodGet, alertsPath+"?state=bogus", nil, cookie, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("bad state: %d", w.Code)
	}

	// Acknowledge one: audited, back to the page it came from.
	back := "/computers/" + ids["healthy"]
	w := h.post("/alerts/ack", url.Values{"id": {strconv.FormatInt(critical.ID, 10)}, "back": {back}}, cookie, csrf)
	wantRedirect(t, w, back, "alerts-acked")
	list, _ := h.store.Alerts(server.AlertFilter{State: server.StateAcknowledged})
	if len(list) != 1 || list[0].ID != critical.ID || list[0].AckedBy != actorPrefix+testAdmin {
		t.Fatalf("acknowledged: %+v", list)
	}
	log, _ := h.store.AuditLog(h.now.Add(-time.Second), 1)
	if len(log) != 1 || log[0].Action != "alert.ack" || log[0].Object != strconv.FormatInt(critical.ID, 10) {
		t.Fatalf("audit: %+v", log)
	}

	// A foreign or missing back path goes to the alerts page; a filter
	// query is kept.
	for back, want := range map[string]string{
		"https://evil.example/": alertsPath + "?msg=alerts-acked",
		"//evil.example/":       alertsPath + "?msg=alerts-acked",
		"":                      alertsPath + "?msg=alerts-acked",
		"/alerts?state=new":     alertsPath + "?state=new&msg=alerts-acked",
	} {
		w := h.post("/alerts/ack", url.Values{"id": {"999"}, "back": {back}}, cookie, csrf)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != want {
			t.Errorf("back %q: %d %s", back, w.Code, w.Header().Get("Location"))
		}
	}
	if w := h.post("/alerts/ack", url.Values{"id": {"x"}}, cookie, csrf); w.Code != http.StatusBadRequest {
		t.Fatalf("bad ID: %d", w.Code)
	}
}

func TestGroupSilentAfter(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addTOTPAdmin(testAdmin, server.RoleAdmin)
	h.seed()
	cookie, csrf := h.login(testAdmin, secret)

	wantRedirect(t, h.post(officePath+"/silentafter", url.Values{fieldAfter: {"90m"}}, cookie, csrf), officePath, "silent-after-saved")
	g, _ := h.store.Group("office")
	if g.SilentAfter != 90*time.Minute {
		t.Fatalf("threshold %s", g.SilentAfter)
	}
	log, _ := h.store.AuditLog(h.now.Add(-time.Second), 1)
	if len(log) != 1 || log[0].Action != "group.silentafter" || log[0].Detail != "1h30m0s" {
		t.Fatalf("audit: %+v", log)
	}
	mustContain(t, "group", h.get(officePath, cookie), "<strong>1h30m</strong>")

	wantRedirect(t, h.post(officePath+"/silentafter", url.Values{fieldAfter: {"0"}}, cookie, csrf), officePath, "silent-after-saved")
	mustContain(t, "group off", h.get(officePath, cookie), "the silent alert is off")

	wantError(t, h.post(officePath+"/silentafter", url.Values{fieldAfter: {"soon"}}, cookie, csrf), "Invalid duration")
	wantError(t, h.post(officePath+"/silentafter", url.Values{fieldAfter: {"-1h"}}, cookie, csrf), "Invalid duration")
	if w := h.post("/groups/nope/silentafter", url.Values{fieldAfter: {"1h"}}, cookie, csrf); w.Code != http.StatusNotFound {
		t.Fatalf("unknown group: %d", w.Code)
	}
}

func TestAlertsViewer(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addTOTPAdmin(testViewer, server.RoleViewer)
	ids := h.seed()
	raiseAlerts(t, h, ids["healthy"])
	cookie, csrf := h.login(testViewer, secret)

	body := h.get(alertsPath, cookie)
	mustContain(t, "alerts", body, "Network interception is off")
	if strings.Contains(body, "/alerts/ack") || strings.Contains(h.get(officePath, cookie), "/silentafter") {
		t.Fatal("a viewer must not see the alert forms")
	}
	if w := h.post("/alerts/ack", url.Values{"id": {"1"}}, cookie, csrf); w.Code != http.StatusForbidden {
		t.Fatalf("viewer ack: %d", w.Code)
	}
	if w := h.post(officePath+"/silentafter", url.Values{fieldAfter: {"1h"}}, cookie, csrf); w.Code != http.StatusForbidden {
		t.Fatalf("viewer silent-after: %d", w.Code)
	}
}

func TestShortDuration(t *testing.T) {
	t.Parallel()
	for d, want := range map[time.Duration]string{
		0:                             "off",
		24 * time.Hour:                "24h",
		90 * time.Minute:              "1h30m",
		30 * time.Minute:              "30m",
		100 * time.Minute:             "1h40m",
		90 * time.Second:              "1m30s",
		10*time.Hour + 20*time.Second: "10h0m20s",
	} {
		if got := shortDuration(d); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
}
