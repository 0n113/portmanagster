package server

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAdmins(t *testing.T) {
	t.Parallel()
	s, err := OpenStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	now := time.Unix(1_800_000_000, 0)

	if !errors.Is(s.AddAdmin("a", "root", now), ErrBadRole) {
		t.Fatal("a bad role must be refused")
	}
	err = s.AddAdmin("a", RoleAdmin, now)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.AddAdmin("a", RoleViewer, now), ErrExists) {
		t.Fatal("a second account with the same name must be refused")
	}
	a, err := s.Admin("a")
	if err != nil || len(a.Handle) != 32 {
		t.Fatalf("admin: %+v %v", a, err)
	}
	byHandle, err := s.AdminByHandle(a.Handle)
	if err != nil || byHandle.Name != "a" {
		t.Fatalf("admin by handle: %v", err)
	}

	// A setup link works once and only until it expires.
	token, err := s.CreateSetupLink("a", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.SetupAdmin(token, now.Add(time.Minute))
	if !errors.Is(err, ErrBadSetup) {
		t.Fatalf("expired setup link: %v", err)
	}
	err = s.AddPasskey(token, []byte{1, 2}, json.RawMessage(`{"id":"AQI"}`), now)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.SetTOTP(token, "SECRET", 1, now), ErrBadSetup) {
		t.Fatal("a used setup link must be refused")
	}
	a, _ = s.Admin("a")
	if len(a.Credentials) != 1 {
		t.Fatalf("credentials: %d", len(a.Credentials))
	}

	// TOTP steps can be used once, in increasing order.
	token, _ = s.CreateSetupLink("a", time.Minute, now)
	err = s.SetTOTP(token, "SECRET", 10, now)
	if err != nil {
		t.Fatal(err)
	}
	for step, want := range map[int64]bool{10: false, 9: false, 11: true} {
		ok, err := s.UseTOTPStep("a", step)
		if err != nil || ok != want {
			t.Fatalf("step %d: %v %v", step, ok, err)
		}
	}

	// Reset removes the credentials and sessions.
	session, _, err := s.CreateSession("a", now)
	if err != nil {
		t.Fatal(err)
	}
	err = s.ResetAdmin("a")
	if err != nil {
		t.Fatal(err)
	}
	a, _ = s.Admin("a")
	if len(a.Credentials) != 0 || a.TOTPSecret != "" {
		t.Fatalf("reset admin: %+v", a)
	}
	_, err = s.Session(session, now, time.Hour, time.Hour)
	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("session after reset: %v", err)
	}

	// Remove deletes the sessions too.
	session, _, _ = s.CreateSession("a", now)
	err = s.RemoveAdmin("a")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Session(session, now, time.Hour, time.Hour)
	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("session after remove: %v", err)
	}
	if !errors.Is(s.RemoveAdmin("a"), ErrNotFound) {
		t.Fatal("removing a missing account must fail")
	}

	err = s.Audit("cli", "group.create", "office", "", now)
	if err != nil {
		t.Fatal(err)
	}
	log, err := s.AuditLog(now.Add(-time.Second), 10)
	if err != nil || len(log) != 1 || log[0].Actor != "cli" || !log[0].Time.Equal(now) {
		t.Fatalf("audit log: %+v %v", log, err)
	}
}
