package adminui

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/safing/portmaster/mgmt/policy"
	"github.com/safing/portmaster/mgmt/server"
)

const groupOffice = "office"

func TestOfflineSigningPages(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	dir := t.TempDir()
	h.ui.cfg.DataDir = dir
	secret := h.addTOTPAdmin(testAdmin, server.RoleAdmin)
	cookie, csrf := h.login(testAdmin, secret)
	wantRedirect(t, h.post("/groups", url.Values{fieldName: {groupOffice}}, cookie, csrf), officePath, "group-created")
	err := h.store.SetGroupPolicy(groupOffice, map[string]any{keyAskTimeout: 33}, []string{keyAskTimeout}, h.now)
	if err != nil {
		t.Fatal(err)
	}

	// Offline signing off: no section, no fingerprint in the enroll command.
	if body := h.get(officePath, cookie); strings.Contains(body, "Offline signing") {
		t.Fatal("offline section without offline key")
	}

	key, err := policy.GenerateKey("offline")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.Export(false)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := server.SetOfflineKey(dir, pub)
	if err != nil {
		t.Fatal(err)
	}
	body := h.get(officePath, cookie)
	mustContain(t, "group", body, "Offline signing", fp, "No signed policy yet", "/groups/office/export", "Publish signed policy")

	// The export is the draft, ready for signing.
	w := h.request(http.MethodGet, officePath+"/export", nil, cookie, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Disposition"), "office.json") {
		t.Fatalf("export: %d %v", w.Code, w.Header())
	}
	gp, err := policy.ParseGroupPolicy(w.Body.Bytes())
	if err != nil || gp.Group != groupOffice || gp.Settings[keyAskTimeout] != float64(33) {
		t.Fatalf("export: %+v %v", gp, err)
	}

	// Garbage and a policy signed with another key are refused.
	wantError(t, h.upload(officePath+"/publish", "{}", cookie, csrf), "not published")
	other, _ := policy.GenerateKey("other")
	bad, _ := policy.SignGroup(gp, other, h.now)
	wantError(t, h.upload(officePath+"/publish", string(bad), cookie, csrf), "not published")

	signed, err := policy.SignGroup(gp, key, h.now)
	if err != nil {
		t.Fatal(err)
	}
	wantRedirect(t, h.upload(officePath+"/publish", string(signed), cookie, csrf), officePath, "policy-published")
	wantError(t, h.upload(officePath+"/publish", string(signed), cookie, csrf), "not newer")
	body = h.get(officePath, cookie)
	mustContain(t, "group", body, "Published: version", "The draft is the same as the published policy")
	if strings.Contains(body, "No signed policy yet") {
		t.Fatal("still no signed policy")
	}

	// A draft change is shown as not signed yet.
	err = h.store.SetGroupPolicy(groupOffice, map[string]any{keyAskTimeout: 99}, nil, h.now)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, "group", h.get(officePath, cookie), "The draft differs from the published policy")

	// The enroll command pins the offline key.
	w = h.post("/tokens", url.Values{fieldGroup: {groupOffice}, fieldValid: {"1h"}, fieldURL: {"https://pm.example.lan:8443"}}, cookie, csrf)
	if !strings.Contains(w.Body.String(), "--offline-key-fp "+fp) {
		t.Fatalf("enroll command without offline key: %d %s", w.Code, w.Body)
	}

	entries, err := h.store.AuditLog(time.Time{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(entries, func(e *server.AuditEntry) bool { return e.Action == "group.publish" }) {
		t.Fatalf("publish not audited: %+v", entries)
	}
}

func TestOfflineSigningViewer(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	dir := t.TempDir()
	h.ui.cfg.DataDir = dir
	if err := h.store.CreateGroup(groupOffice, h.now); err != nil { //nolint:noinlineerr // Test setup.
		t.Fatal(err)
	}
	key, _ := policy.GenerateKey("offline")
	pub, _ := key.Export(false)
	if _, err := server.SetOfflineKey(dir, pub); err != nil { //nolint:noinlineerr // Test setup.
		t.Fatal(err)
	}
	secret := h.addTOTPAdmin(testViewer, server.RoleViewer)
	cookie, csrf := h.login(testViewer, secret)
	body := h.get(officePath, cookie)
	mustContain(t, "group", body, "Offline signing", "/groups/office/export")
	if strings.Contains(body, "Publish signed policy") {
		t.Fatal("viewer sees the publish form")
	}
	g, _ := h.store.Group(groupOffice)
	signed, _ := policy.SignGroup(server.ExportGroup(g), key, h.now)
	if w := h.upload(officePath+"/publish", string(signed), cookie, csrf); w.Code != http.StatusForbidden {
		t.Fatalf("viewer publish: %d", w.Code)
	}
}
