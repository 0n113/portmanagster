package policy

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

const (
	groupOffice = "office"
	keyAsk      = "filter/askTimeout"
)

func TestSignVerifyGroup(t *testing.T) {
	t.Parallel()

	offline, err := GenerateKey("offline")
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateKey("other")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	gp := &GroupPolicy{Group: groupOffice, Settings: map[string]any{keyAsk: 33}, Locked: []string{keyAsk}, BlockSummary: true}
	signed, err := SignGroup(gp, offline, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyGroup(signed, publicKey(t, offline))
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1_800_000_000 || got.Group != groupOffice || !got.BlockSummary || got.Settings[keyAsk] != float64(33) {
		t.Fatalf("group policy: %+v", got)
	}
	if _, err := VerifyGroup(signed, publicKey(t, other)); err == nil { //nolint:noinlineerr // Table of checks.
		t.Error("another key must fail")
	}
	tampered := bytes.Replace(signed, []byte(`33`), []byte(`34`), 1)
	if bytes.Equal(tampered, signed) {
		t.Fatal("tamper test did not change the document")
	}
	if _, err := VerifyGroup(tampered, publicKey(t, offline)); err == nil { //nolint:noinlineerr // Table of checks.
		t.Error("a changed document must fail")
	}

	// A plain policy signed with the offline key is no group policy.
	plain, err := Sign(&Policy{Computer: "c1"}, offline)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyGroup(plain, publicKey(t, offline)); !errors.Is(err, ErrWrongType) { //nolint:noinlineerr // Table of checks.
		t.Errorf("policy as group policy: %v", err)
	}

	if _, err := ParseGroupPolicy([]byte(`{"type":"group-policy"}`)); !errors.Is(err, ErrWrongType) { //nolint:noinlineerr // Table of checks.
		t.Errorf("without group: %v", err)
	}
}

func TestOpen(t *testing.T) {
	t.Parallel()

	offline, err := GenerateKey("offline")
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateKey("other")
	if err != nil {
		t.Fatal(err)
	}
	offlinePub, err := offline.Export(false)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := other.Export(false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	sign := func(key any, group string, at time.Time) []byte {
		t.Helper()
		k := offline
		if key == "other" {
			k = other
		}
		data, err := SignGroup(&GroupPolicy{Group: group, Settings: map[string]any{keyAsk: 33}, Locked: []string{keyAsk}}, k, at)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	wrap := func(signed []byte, key string) *Policy {
		// The server must not be able to add content around the signed
		// group policy: it is replaced.
		return &Policy{Group: groupOffice, Computer: "c1", Settings: map[string]any{"evil": true}, Signed: signed, OfflineKey: key}
	}

	// Without signed group policy and without pin: as it is.
	plain := &Policy{Group: groupOffice, Settings: map[string]any{keyAsk: 1}}
	got, pins, err := Open(plain, Pins{})
	if err != nil || got != plain || pins.OfflineKey != "" {
		t.Fatalf("plain: %v %+v", err, pins)
	}

	// First signed policy: the offline key is pinned, the content replaced.
	got, pins, err = Open(wrap(sign(nil, groupOffice, now), offlinePub), Pins{})
	if err != nil {
		t.Fatal(err)
	}
	if pins.OfflineKey != offlinePub || pins.GroupVersions[groupOffice] != 1_800_000_000 {
		t.Fatalf("pins: %+v", pins)
	}
	if _, ok := got.Settings["evil"]; ok || got.Settings[keyAsk] != float64(33) || len(got.Locked) != 1 {
		t.Fatalf("content: %+v", got)
	}

	for _, c := range []struct {
		name string
		p    *Policy
		want error
	}{
		{"plain after pin", plain, ErrNotOfflineSigned},
		{"other key named", wrap(sign(nil, groupOffice, now), otherPub), ErrOfflineKeyChanged},
		{"signed by other key", wrap(sign("other", groupOffice, now), ""), nil},
		{"other group", wrap(sign(nil, "lab", now), ""), ErrWrongGroup},
		{"older version", wrap(sign(nil, groupOffice, now.Add(-time.Hour)), ""), ErrGroupRollback},
	} {
		_, after, err := Open(c.p, pins)
		if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
		if after.OfflineKey != pins.OfflineKey || after.GroupVersions[groupOffice] != pins.GroupVersions[groupOffice] {
			t.Errorf("%s: pins changed on refusal: %+v", c.name, after)
		}
	}

	// The same and a newer version pass; the key may be left out.
	_, again, err := Open(wrap(sign(nil, groupOffice, now), ""), pins)
	if err != nil || again.GroupVersions[groupOffice] != pins.GroupVersions[groupOffice] {
		t.Fatalf("same version: %v %+v", err, again)
	}
	_, newer, err := Open(wrap(sign(nil, groupOffice, now.Add(time.Hour)), offlinePub), pins)
	if err != nil || newer.GroupVersions[groupOffice] != pins.GroupVersions[groupOffice]+3600 {
		t.Fatalf("newer: %v %+v", err, newer)
	}
	// Opening must not change the pins passed in.
	if pins.GroupVersions[groupOffice] != 1_800_000_000 {
		t.Fatalf("input pins changed: %+v", pins)
	}

	// No key at all.
	if _, _, err := Open(wrap(sign(nil, groupOffice, now), ""), Pins{}); !errors.Is(err, ErrNoOfflineKey) { //nolint:noinlineerr // Table of checks.
		t.Errorf("no key: %v", err)
	}
}
