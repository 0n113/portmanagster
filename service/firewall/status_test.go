package firewall

import (
	"testing"
	"time"

	"github.com/safing/portmaster/service/mgr"
	"github.com/safing/portmaster/service/updates"
)

func TestStatusProblems(t *testing.T) {
	t.Parallel()

	problems := statusProblems([]mgr.StateUpdate{
		{Module: "A", States: []mgr.State{
			{ID: "a1", Name: "hint", Type: mgr.StateTypeHint},
			{ID: "a2", Name: "warn", Type: mgr.StateTypeWarning},
		}},
		{Module: "B", States: []mgr.State{{ID: "b1", Name: "err", Type: mgr.StateTypeError, Message: "m"}}},
	})
	if len(problems) != 2 || problems[0].ID != "a2" || problems[1].Type != "error" || problems[1].Message != "m" {
		t.Errorf("unexpected problems: %+v", problems)
	}
	if statusProblems(nil) == nil {
		t.Error("problems must be an empty list, not null")
	}
}

func TestFillIntelStatus(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	s := &Status{}
	fillIntelStatus(s, &updates.Index{Version: "v1", Published: now.Add(-36 * time.Hour)}, now)
	if s.IntelVersion != "v1" || s.IntelAgeHours != 36 {
		t.Errorf("unexpected intel status: %+v", s)
	}
}
