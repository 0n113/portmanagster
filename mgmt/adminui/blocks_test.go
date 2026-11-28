package adminui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/safing/portmaster/mgmt/policy"
	"github.com/safing/portmaster/mgmt/server"
)

const (
	targetEvil = "evil.example"
	targetAds  = "ads.example"
)

func TestBlockSummary(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addTOTPAdmin(testAdmin, server.RoleAdmin)
	ids := h.seed()
	cookie, csrf := h.login(testAdmin, secret)

	mustContain(t, "group", h.get(officePath, cookie), "Block summary", "Off.", "Turn block summary on", "data-confirm=")
	mustContain(t, "computer", h.get("/computers/"+ids["healthy"], cookie), "has no block summary")

	// Turn it on: audited, the policy asks for it.
	wantRedirect(t, h.post(officePath+"/blocksummary", url.Values{"on": {"1"}}, cookie, csrf), officePath, "block-summary-on")
	g, _ := h.store.Group("office")
	if !g.BlockSummary {
		t.Fatal("block summary not on")
	}
	log, _ := h.store.AuditLog(h.now.Add(-1), 1)
	if len(log) != 1 || log[0].Action != "group.blocksummary" || log[0].Detail != "on" || log[0].Actor != actorPrefix+testAdmin {
		t.Fatalf("audit: %+v", log)
	}
	mustContain(t, "group on", h.get(officePath+"?msg=block-summary-on", cookie), "Block summary on.", "Turn block summary off",
		"No blocked connections in the last 24 hours.")

	// Reports with summaries show up on the computer, the group and the blocks page.
	blocks := []policy.Block{
		{App: "Firefox", Reason: keyLists, Lists: "MAL,TRAC", Target: targetEvil, Count: 4},
		{App: "<script>x</script>", Reason: "filter/endpoints", Target: targetAds, Count: 1},
	}
	for _, host := range []string{"healthy", "broken"} {
		err := h.store.SaveReport(ids[host], &policy.Report{Type: policy.TypeReport, Blocks: blocks}, h.now)
		if err != nil {
			t.Fatal(err)
		}
	}
	body := h.get("/computers/"+ids["healthy"], cookie)
	mustContain(t, "computer", body, "Recent blocks", targetEvil, `href="/blocks?list=MAL"`, `href="/blocks?computer=`+ids["healthy"])
	if strings.Contains(body, "<script>x</script>") {
		t.Fatal("app name not escaped")
	}
	mustContain(t, "group", h.get(officePath, cookie), targetEvil, `<td class="num">8</td>`, `href="/blocks?group=office"`)

	for _, c := range []struct {
		query   string
		want    string
		notWant string
	}{
		{"", targetEvil, ""},
		{"?list=MAL", targetEvil, targetAds},
		{"?app=Firefox", targetEvil, targetAds},
		{"?target=ads", targetAds, targetEvil},
		{"?group=lab", "No blocked connections match.", targetEvil},
		{"?computer=" + ids["healthy"] + "&period=1h", targetEvil, ""},
		{"?limit=1", "Only the 1 largest", targetAds},
	} {
		body := h.get("/blocks"+c.query, cookie)
		mustContain(t, "blocks"+c.query, body, c.want)
		if c.notWant != "" && strings.Contains(body, c.notWant) {
			t.Errorf("blocks%s: must not contain %q", c.query, c.notWant)
		}
	}

	// Off again.
	wantRedirect(t, h.post(officePath+"/blocksummary", url.Values{"on": {"0"}}, cookie, csrf), officePath, "block-summary-off")
	g, _ = h.store.Group("office")
	if g.BlockSummary {
		t.Fatal("block summary still on")
	}
	if w := h.post("/groups/nope/blocksummary", url.Values{"on": {"1"}}, cookie, csrf); w.Code != http.StatusNotFound {
		t.Fatalf("unknown group: %d", w.Code)
	}
}

func TestBlockSummaryViewer(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addTOTPAdmin(testViewer, server.RoleViewer)
	h.seed()
	cookie, csrf := h.login(testViewer, secret)
	if strings.Contains(h.get(officePath, cookie), "/blocksummary") {
		t.Fatal("a viewer must not see the block summary switch")
	}
	mustContain(t, "blocks", h.get("/blocks", cookie), "Blocked connections")
	if w := h.post(officePath+"/blocksummary", url.Values{"on": {"1"}}, cookie, csrf); w.Code != http.StatusForbidden {
		t.Fatalf("viewer: %d", w.Code)
	}
}
