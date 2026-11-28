package server

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/safing/jess"

	"github.com/safing/portmaster/mgmt/policy"
)

// offlineKeys creates an offline key and returns it with its public key in
// jess text format.
func offlineKeys(t *testing.T) (*jess.Signet, string) {
	t.Helper()
	key, err := policy.GenerateKey("offline")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.Export(false)
	if err != nil {
		t.Fatal(err)
	}
	return key, pub
}

func TestSetOfflineKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, pub := offlineKeys(t)
	_, other := offlineKeys(t)

	if text, err := ReadOfflineKey(dir); err != nil || text != "" { //nolint:noinlineerr // Table of checks.
		t.Fatalf("off: %q %v", text, err)
	}
	fp, err := SetOfflineKey(dir, pub+"\n")
	if err != nil || len(fp) != len("sha256:")+64 {
		t.Fatalf("set: %q %v", fp, err)
	}
	if again, err := SetOfflineKey(dir, pub); err != nil || again != fp { //nolint:noinlineerr // Table of checks.
		t.Fatalf("same key again: %q %v", again, err)
	}
	if _, err := SetOfflineKey(dir, other); !errors.Is(err, ErrOfflineKeySet) { //nolint:noinlineerr // Table of checks.
		t.Fatalf("other key: %v", err)
	}
	if _, err := SetOfflineKey(t.TempDir(), "garbage"); err == nil { //nolint:noinlineerr // Table of checks.
		t.Fatal("garbage accepted")
	}
	if text, _ := ReadOfflineKey(dir); text != pub {
		t.Fatalf("stored %q", text)
	}
}

func TestDraftDiffers(t *testing.T) {
	t.Parallel()
	key, _ := offlineKeys(t)
	g := &Group{Name: groupOffice, Settings: map[string]any{keyAskTimeout: float64(33)}, Locked: []string{keyAskTimeout}}
	if differs, _ := DraftDiffers(g); !differs {
		t.Fatal("no signed policy must differ")
	}
	signed, err := policy.SignGroup(ExportGroup(g), key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	g.Signed = signed
	if differs, err := DraftDiffers(g); err != nil || differs { //nolint:noinlineerr // Table of checks.
		t.Fatalf("same content: %v %v", differs, err)
	}
	g.Rules = &policy.Rules{}
	if differs, _ := DraftDiffers(g); differs {
		t.Fatal("empty rules must count as none")
	}
	g.BlockSummary = true
	if differs, _ := DraftDiffers(g); !differs {
		t.Fatal("changed block summary must differ")
	}
}

func TestOfflineSigning(t *testing.T) {
	t.Parallel()
	s, ts := newTestServer(t)
	now := time.Now()
	if err := s.Store.CreateGroup(groupOffice, now); err != nil { //nolint:noinlineerr // Test setup.
		t.Fatal(err)
	}
	err := s.Store.SetGroupPolicy(groupOffice, map[string]any{keyAskTimeout: 33}, []string{keyAskTimeout}, now)
	if err != nil {
		t.Fatal(err)
	}
	key, pub := offlineKeys(t)
	other, _ := offlineKeys(t)
	serverKey, err := jess.RecipientFromTextFormat(s.PolicyPub)
	if err != nil {
		t.Fatal(err)
	}

	// Publishing needs an offline key on the server.
	g, _ := s.Store.Group(groupOffice)
	signed, err := policy.SignGroup(ExportGroup(g), key, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(groupOffice, signed); !errors.Is(err, ErrNoOfflineKeySet) { //nolint:noinlineerr // Table of checks.
		t.Fatalf("without key: %v", err)
	}
	_, err = SetOfflineKey(s.Dir, pub)
	if err != nil {
		t.Fatal(err)
	}

	// The enrollment response names the offline key; without a signed
	// policy the computer gets none.
	token, _ := s.Store.CreateToken(groupOffice, time.Hour, now)
	client, er, status := enroll(t, s, ts.URL, token)
	if status != http.StatusOK || er.OfflineKey != pub {
		t.Fatalf("enroll: %d, offline key %q", status, er.OfflineKey)
	}
	if _, code := getPolicy(t, s, ts.URL, client.cert); code != http.StatusServiceUnavailable {
		t.Fatalf("policy without signed group policy: %d", code)
	}

	// Wrong key, wrong group: refused.
	bad, _ := policy.SignGroup(ExportGroup(g), other, now)
	if _, err := s.Publish(groupOffice, bad); err == nil { //nolint:noinlineerr // Table of checks.
		t.Fatal("policy signed with another key published")
	}
	lab := ExportGroup(g)
	lab.Group = "lab"
	labSigned, _ := policy.SignGroup(lab, key, now)
	if _, err := s.Publish(groupOffice, labSigned); !errors.Is(err, ErrSignedGroup) { //nolint:noinlineerr // Table of checks.
		t.Fatalf("other group: %v", err)
	}

	gp, err := s.Publish(groupOffice, signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(groupOffice, signed); !errors.Is(err, ErrSignedRollback) { //nolint:noinlineerr // Table of checks.
		t.Fatalf("same version again: %v", err)
	}

	// The computer gets the signed group policy, wrapped for it.
	data, code := getPolicy(t, s, ts.URL, client.cert)
	if code != http.StatusOK {
		t.Fatalf("policy: %d", code)
	}
	p, err := policy.Verify(data, serverKey, er.ComputerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Settings) != 0 || len(p.Signed) == 0 || p.OfflineKey != pub {
		t.Fatalf("wrapped policy: %+v", p)
	}
	opened, pins, err := policy.Open(p, policy.Pins{})
	if err != nil {
		t.Fatal(err)
	}
	if opened.Settings[keyAskTimeout] != float64(33) || pins.GroupVersions[groupOffice] != gp.Version {
		t.Fatalf("opened: %+v %+v", opened, pins)
	}

	// A draft change does not reach the computer until it is signed.
	err = s.Store.SetGroupPolicy(groupOffice, map[string]any{keyAskTimeout: 99}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	g, _ = s.Store.Group(groupOffice)
	if differs, _ := DraftDiffers(g); !differs {
		t.Fatal("draft change not detected")
	}
	data, _ = getPolicy(t, s, ts.URL, client.cert)
	p, _ = policy.Verify(data, serverKey, er.ComputerID)
	opened, _, err = policy.Open(p, pins)
	if err != nil || opened.Settings[keyAskTimeout] != float64(33) {
		t.Fatalf("draft leaked: %+v %v", opened, err)
	}
}
