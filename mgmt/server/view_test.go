package server

import (
	"testing"
	"time"

	"github.com/safing/portmaster/mgmt/policy"
)

func TestPolicyState(t *testing.T) {
	t.Parallel()
	changed := time.Unix(1000, 0)
	g := &Group{Updated: changed}
	cases := []struct {
		c    *Computer
		want string
	}{
		{&Computer{}, PolicyNoReport},
		{&Computer{Report: &policy.Report{Error: "x"}, LastReport: changed.Add(time.Minute)}, PolicyError},
		{&Computer{Report: &policy.Report{}, LastReport: changed}, PolicyPending},
		{&Computer{Report: &policy.Report{}, LastReport: changed.Add(time.Second)}, PolicyCurrent},
	}
	for i, c := range cases {
		if got := PolicyState(c.c, g); got != c.want {
			t.Errorf("case %d: got %s, want %s", i, got, c.want)
		}
	}
	now := changed.Add(SilentAfter + time.Second)
	if !Silent(&Computer{LastSeen: changed}, now) || Silent(&Computer{LastSeen: changed, Revoked: true}, now) {
		t.Error("silent")
	}
	if Silent(&Computer{Enrolled: now.Add(-time.Minute)}, now) || !Silent(&Computer{Enrolled: changed}, now) {
		t.Error("a new computer is silent only SilentAfter after its enrollment")
	}
}
