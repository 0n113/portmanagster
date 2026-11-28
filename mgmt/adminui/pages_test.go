package adminui

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/safing/portmaster/mgmt/policy"
	"github.com/safing/portmaster/mgmt/server"
)

const xssHost = `<script>alert(1)</script>`

// seed fills the store: a group with settings, rules and a profile, a
// healthy computer, a silent one, one with a policy error, a revoked one
// and tokens.
func (h *harness) seed() map[string]string {
	h.t.Helper()
	s := h.store
	must := func(err error) {
		h.t.Helper()
		if err != nil {
			h.t.Fatal(err)
		}
	}
	must(s.CreateGroup("office", h.now))
	must(s.SetGroupPolicy("office", map[string]any{"filter/lists": []any{"MAL"}, "filter/askTimeout": 30},
		[]string{"filter/lists"}, h.now))
	must(s.SetGroupRules("office", &policy.Rules{Endpoints: []string{"- ads.example.com"}}, h.now))
	must(s.SetGroupProfiles("office", []json.RawMessage{json.RawMessage(`{"type":"profile","name":"restic","config":{"filter":{"defaultAction":"permit"}}}`)}, h.now))
	must(s.CreateGroup("lab", h.now))

	ids := make(map[string]string)
	enroll := func(host string) {
		token, err := s.CreateToken("office", time.Hour, h.now)
		must(err)
		c := &server.Computer{Hostname: host, OS: "linux", CoreVersion: "2.1.0"}
		must(s.Enroll(token, c, h.now, func(string) (string, error) { return "sha256:fp", nil }))
		ids[host] = c.ID
	}
	h.now = h.now.Add(time.Minute)
	for _, host := range []string{"healthy", "silent", "broken", "gone", xssHost} {
		enroll(host)
	}
	status := json.RawMessage(`{"ready":true,"interception":true,"problems":[]}`)
	report := func(host string, r *policy.Report) {
		if r.Status == nil {
			r.Status = status
		}
		must(s.SaveReport(ids[host], r, h.now))
	}
	report("silent", &policy.Report{AppliedVersion: 5})
	h.now = h.now.Add(2 * server.SilentAfter)
	report("healthy", &policy.Report{AppliedVersion: 9, Overridden: []string{"filter/askTimeout"}})
	report("broken", &policy.Report{
		AppliedVersion: 7, Error: "signature mismatch",
		Status: json.RawMessage(`{"ready":true,"interception":false,"problems":[{"type":"interception","message":"no kext"}]}`),
	})
	report(xssHost, &policy.Report{AppliedVersion: 9})
	must(s.Revoke(ids["gone"]))
	_, err := s.CreateToken("lab", time.Hour, h.now)
	must(err)
	must(s.Audit("cli", "group.set", "office", "2 settings, 1 locked", h.now))
	return ids
}

func (h *harness) get(path, cookie string) string {
	h.t.Helper()
	w := h.request(http.MethodGet, path, nil, cookie, nil)
	if w.Code != http.StatusOK {
		h.t.Fatalf("GET %s: %d", path, w.Code)
	}
	return w.Body.String()
}

func mustContain(t *testing.T, page, body string, want ...string) {
	t.Helper()
	for _, s := range want {
		if !strings.Contains(body, s) {
			t.Errorf("%s: missing %q", page, s)
		}
	}
}

func TestReadOnlyPages(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addTOTPAdmin(testViewer, server.RoleViewer)
	ids := h.seed()
	cookie, _ := h.login(testViewer, secret)

	body := h.get("/", cookie)
	mustContain(t, "dashboard", body, "Needs attention", "silent since", "policy error: signature mismatch",
		"group.set", `aria-current="page">Dashboard`)
	if strings.Contains(body, ">gone<") {
		t.Error("dashboard: a revoked computer needs no attention")
	}

	body = h.get("/computers", cookie)
	mustContain(t, "computers", body, "healthy", "v9", "current", "1 overridden", "revoked", "silent", "5 of 5 computers")
	if strings.Contains(body, xssHost) || !strings.Contains(body, "&lt;script&gt;") {
		t.Error("computers: the hostname must be escaped")
	}
	body = h.get("/computers?show=attention", cookie)
	mustContain(t, "computers needing attention", body, "silent", "broken", "2 of 5 computers")
	body = h.get("/computers?show=revoked", cookie)
	mustContain(t, "revoked computers", body, "gone", "1 of 5 computers")
	body = h.get("/computers?group=lab", cookie)
	mustContain(t, "computers of lab", body, "No computer matches the filter.")

	body = h.get("/computers/"+ids["broken"], cookie)
	mustContain(t, "computer", body, "signature mismatch", "no kext", "<strong>off</strong>", "sha256:fp", "Full status as reported")
	body = h.get("/computers/"+ids["healthy"], cookie)
	mustContain(t, "computer", body, "<code>filter/askTimeout</code>")

	body = h.get("/groups", cookie)
	mustContain(t, "groups", body, `href="/groups/office"`, "lab")
	body = h.get("/groups/office", cookie)
	mustContain(t, "group", body, "<code>filter/lists</code>", "locked", "default", "- ads.example.com", "restic", "healthy")

	body = h.get("/tokens", cookie)
	mustContain(t, "tokens", body, "used", "valid")

	body = h.get("/audit?q=office", cookie)
	mustContain(t, "audit", body, "group.set", "2 settings, 1 locked")
	if strings.Contains(body, "admin.totp") {
		t.Error("audit: the search must filter")
	}
	body = h.get("/audit?limit=1", cookie)
	mustContain(t, "audit", body, "More entries match")

	for _, path := range []string{"/computers/nope", "/groups/nope"} {
		w := h.request(http.MethodGet, path, nil, cookie, nil)
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d", path, w.Code)
		}
	}
	for _, path := range []string{"/computers", "/computers/" + ids["healthy"], "/groups", "/groups/office", "/tokens", "/audit"} {
		w := h.request(http.MethodGet, path, nil, "", nil)
		if w.Code != http.StatusSeeOther {
			t.Errorf("anonymous GET %s: %d", path, w.Code)
		}
	}
}

func TestGroupNameInLinks(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addTOTPAdmin(testAdmin, server.RoleAdmin)
	err := h.store.CreateGroup("a b/c", h.now)
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := h.login(testAdmin, secret)
	body := h.get("/groups", cookie)
	mustContain(t, "groups", body, `href="/groups/a%20b%2Fc"`)
	h.get("/groups/"+url.PathEscape("a b/c"), cookie)
}
