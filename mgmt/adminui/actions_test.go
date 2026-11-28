package adminui

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/safing/portmaster/mgmt/server"
)

const (
	officePath    = "/groups/office"
	fieldSettings = "settings"
	fieldProfile  = "profile"
	fieldGroup    = "group"
	keyLists      = "filter/lists"
	groupLab      = "lab"
	fieldURL      = "url"
	fieldValid    = "valid"
)

// post sends a form with the CSRF token and returns the response.
func (h *harness) post(path string, form url.Values, cookie, csrf string) *httptest.ResponseRecorder {
	h.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set(csrfField, csrf)
	return h.request(http.MethodPost, path, form, cookie, nil)
}

// wantRedirect checks a redirect to path with a notice.
func wantRedirect(t *testing.T, w *httptest.ResponseRecorder, path, msg string) {
	t.Helper()
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != path+"?msg="+msg {
		t.Fatalf("want redirect to %s?msg=%s, got %d %s: %s", path, msg, w.Code, w.Header().Get("Location"), w.Body)
	}
}

func wantError(t *testing.T, w *httptest.ResponseRecorder, contains string) {
	t.Helper()
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), contains) {
		t.Fatalf("want 400 with %q, got %d: %s", contains, w.Code, w.Body)
	}
}

func TestGroupActions(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addTOTPAdmin(testAdmin, server.RoleAdmin)
	cookie, csrf := h.login(testAdmin, secret)

	wantRedirect(t, h.post("/groups", url.Values{fieldName: {"office"}}, cookie, csrf), officePath, "group-created")
	wantError(t, h.post("/groups", url.Values{fieldName: {"office"}}, cookie, csrf), "exists already")
	wantError(t, h.post("/groups", url.Values{fieldName: {""}}, cookie, csrf), "could not be created")
	mustContain(t, "group", h.get(officePath+"?msg=group-created", cookie), "Group created.", "Edit settings")

	// Settings.
	settings := "type: settings\nconfig:\n  filter:\n    askTimeout: 77\n    lists: [TRAC, MAL]\n"
	w := h.post(officePath+"/settings", url.Values{fieldSettings: {settings}, "locked": {keyLists + "\n"}}, cookie, csrf)
	wantRedirect(t, w, officePath, "settings-saved")
	g, err := h.store.Group("office")
	if err != nil || g.Settings["filter/askTimeout"] != float64(77) || len(g.Locked) != 1 || g.Locked[0] != keyLists {
		t.Fatalf("settings: %+v %v", g, err)
	}
	// The edit form shows the stored settings as an export.
	mustContain(t, "group", h.get(officePath, cookie), "askTimeout: 77", keyLists+"</textarea>")
	w = h.post(officePath+"/settings", url.Values{fieldSettings: {"config: [broken"}}, cookie, csrf)
	wantError(t, w, "The settings are invalid")
	mustContain(t, "failed form", w.Body.String(), "config: [broken")
	wantError(t, h.post(officePath+"/settings", url.Values{fieldSettings: {settings}, "locked": {"filter/nope"}}, cookie, csrf),
		"a locked key must be one of the settings")
	wantRedirect(t, h.post(officePath+"/settings", url.Values{fieldSettings: {settings}, "lockall": {"1"}}, cookie, csrf), officePath, "settings-saved")
	g, _ = h.store.Group("office")
	if len(g.Locked) != 2 {
		t.Fatalf("lock all: %v", g.Locked)
	}

	// Rules.
	w = h.post(officePath+"/rules", url.Values{"endpoints": {"- ads.example.com\n\n# comment\n- MAL\n"}, "serviceEndpoints": {"+ 10.0.0.0/8 TCP/22"}}, cookie, csrf)
	wantRedirect(t, w, officePath, "rules-saved")
	g, _ = h.store.Group("office")
	if g.Rules == nil || len(g.Rules.Endpoints) != 2 || len(g.Rules.ServiceEndpoints) != 1 {
		t.Fatalf("rules: %+v", g.Rules)
	}
	w = h.post(officePath+"/rules", url.Values{"endpoints": {"ads.example.com"}}, cookie, csrf)
	wantError(t, w, "a rule must start with")
	mustContain(t, "failed rules form", w.Body.String(), "askTimeout: 77")
	wantRedirect(t, h.post(officePath+"/rules", url.Values{}, cookie, csrf), officePath, "rules-saved")
	g, _ = h.store.Group("office")
	if g.Rules != nil {
		t.Fatalf("cleared rules: %+v", g.Rules)
	}

	// Profiles: upload, paste with the same name replaces, remove.
	restic := "type: profile\nname: restic\nsource: local\nconfig:\n  filter:\n    defaultAction: permit\n"
	wantRedirect(t, h.upload(officePath+"/profiles", restic, cookie, csrf), officePath, "profile-added")
	wantRedirect(t, h.post(officePath+"/profiles", url.Values{fieldProfile: {strings.Replace(restic, "permit", "block", 1)}}, cookie, csrf), officePath, "profile-added")
	g, _ = h.store.Group("office")
	if len(g.Profiles) != 1 || !strings.Contains(string(g.Profiles[0]), "block") {
		t.Fatalf("profiles: %s", g.Profiles)
	}
	wantError(t, h.post(officePath+"/profiles", url.Values{fieldProfile: {"type: settings\n"}}, cookie, csrf), "not a profile export")
	wantRedirect(t, h.post(officePath+"/profiles/remove", url.Values{fieldProfile: {"restic"}}, cookie, csrf), officePath, "profile-removed")
	wantError(t, h.post(officePath+"/profiles/remove", url.Values{fieldProfile: {"restic"}}, cookie, csrf), "no profile with this name")

	// Delete.
	wantRedirect(t, h.post(officePath+"/delete", nil, cookie, csrf), "/groups", "group-deleted")
	if w := h.post(officePath+"/delete", nil, cookie, csrf); w.Code != http.StatusNotFound {
		t.Fatalf("delete twice: %d", w.Code)
	}

	log, err := h.store.AuditLog(h.now.Add(-h.now.Sub(h.now)), 100)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range log {
		if e.Actor == "admin:"+testAdmin && e.Action != "login" && e.Action != "admin.totp" {
			got = append(got, e.Action+" "+e.Detail)
		}
	}
	want := []string{
		"group.delete ", "group.profiles removed restic", "group.profiles replaced restic", "group.profiles added restic",
		"group.rules cleared", "group.rules 2 endpoint rules, 1 service rules", "group.set 2 settings, 2 locked",
		"group.set 2 settings, 1 locked", "group.create ",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("audit:\n got %q\nwant %q", got, want)
	}
}

// upload sends a profile as multipart file.
func (h *harness) upload(path, content, cookie, csrf string) *httptest.ResponseRecorder {
	h.t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField(csrfField, csrf)
	fw, err := mw.CreateFormFile("file", "restic.yaml")
	if err != nil {
		h.t.Fatal(err)
	}
	_, _ = fw.Write([]byte(content))
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, path, &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set(headerOrigin, testOrigin)
	r.AddCookie(&http.Cookie{Name: sessionName, Value: cookie}) //nolint:gosec // Request cookie.
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, r)
	return w
}

var tokenRe = regexp.MustCompile(`--token ([0-9a-f]{48})`)

func TestTokenAndComputerActions(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.ui.cfg.ServerFP, h.ui.cfg.PolicyKeyFP = "sha256:srv", "sha256:key"
	secret := h.addTOTPAdmin(testAdmin, server.RoleAdmin)
	ids := h.seed()
	cookie, csrf := h.login(testAdmin, secret)

	// Create: the token and the enroll command are shown once.
	w := h.post("/tokens", url.Values{fieldGroup: {groupLab}, fieldValid: {"24h"}, fieldURL: {"https://pm.example.lan:8443"}}, cookie, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("create token: %d %s", w.Code, w.Body)
	}
	mustContain(t, "new token", w.Body.String(), "--server https://pm.example.lan:8443", "--server-fp sha256:srv", "--policy-key-fp sha256:key")
	m := tokenRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatal("no token in the page")
	}
	if strings.Contains(h.get("/tokens", cookie), m[1]) {
		t.Fatal("the token must be shown only once")
	}
	wantError(t, h.post("/tokens", url.Values{fieldGroup: {groupLab}, fieldValid: {"9999h"}, fieldURL: {"https://x:1"}}, cookie, csrf), "validity")
	wantError(t, h.post("/tokens", url.Values{fieldGroup: {groupLab}, fieldValid: {"1h"}, fieldURL: {"http://x:1"}}, cookie, csrf), "https://host:port")
	wantError(t, h.post("/tokens", url.Values{fieldGroup: {"nope"}, fieldValid: {"1h"}, fieldURL: {"https://x:1"}}, cookie, csrf), "no group")

	// Revoke the new token by its ID; used tokens cannot be revoked.
	tokens, _ := h.store.Tokens()
	var unused, used string
	for _, tk := range tokens {
		switch {
		case !tk.Used && tk.Group == groupLab && unused == "":
			unused = tk.ID
		case tk.Used:
			used = tk.ID
		}
	}
	wantRedirect(t, h.post("/tokens/"+unused+"/revoke", nil, cookie, csrf), "/tokens", "token-revoked")
	wantRedirect(t, h.post("/tokens/"+used+"/revoke", nil, cookie, csrf), "/tokens", "token-unknown")

	// Move: the policy is pending until the next report.
	path := "/computers/" + ids["healthy"]
	wantRedirect(t, h.post(path+"/move", url.Values{fieldGroup: {groupLab}}, cookie, csrf), path, "computer-moved")
	c, _ := h.store.Computer(ids["healthy"])
	lab, _ := h.store.Group(groupLab)
	if c.Group != groupLab || server.PolicyState(c, lab) != server.PolicyPending {
		t.Fatalf("moved computer: %s %s", c.Group, server.PolicyState(c, lab))
	}
	wantRedirect(t, h.post(path+"/move", url.Values{fieldGroup: {groupLab}}, cookie, csrf), path, "computer-same-group")
	if w := h.post(path+"/move", url.Values{fieldGroup: {"nope"}}, cookie, csrf); w.Code != http.StatusNotFound {
		t.Fatalf("move to unknown group: %d", w.Code)
	}

	// A group with computers cannot be deleted, revoked ones count.
	wantRedirect(t, h.post("/groups/"+groupLab+"/delete", nil, cookie, csrf), "/groups/"+groupLab, "group-not-deleted")

	// Revoke.
	wantRedirect(t, h.post(path+"/revoke", nil, cookie, csrf), path, "computer-revoked")
	c, _ = h.store.Computer(ids["healthy"])
	if !c.Revoked {
		t.Fatal("not revoked")
	}
	if strings.Contains(h.get(path, cookie), "Revoke computer") {
		t.Fatal("a revoked computer has no revoke button")
	}
	wantRedirect(t, h.post("/computers/nope/revoke", nil, cookie, csrf), "/computers", "computer-unknown")

	log, _ := h.store.AuditLog(c.Enrolled, 20)
	var actions []string
	for _, e := range log {
		if e.Actor == "admin:"+testAdmin && e.Action != "login" {
			actions = append(actions, e.Action)
		}
	}
	if strings.Join(actions, ",") != "computer.revoke,computer.move,token.revoke,token.create" {
		t.Fatalf("audit: %v", actions)
	}
}

func TestViewerSeesNoForms(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addTOTPAdmin(testViewer, server.RoleViewer)
	ids := h.seed()
	cookie, csrf := h.login(testViewer, secret)
	for _, path := range []string{"/groups", officePath, "/tokens", "/computers/" + ids["healthy"]} {
		body := h.get(path, cookie)
		if strings.Contains(body, `method="post" action="/groups`) || strings.Contains(body, `action="/tokens`) ||
			strings.Contains(body, `/move"`) || strings.Contains(body, `/revoke"`) {
			t.Errorf("%s: a viewer must see no write forms", path)
		}
	}
	if w := h.post("/groups", url.Values{fieldName: {"x"}}, cookie, csrf); w.Code != http.StatusForbidden {
		t.Fatalf("viewer create group: %d", w.Code)
	}
}
