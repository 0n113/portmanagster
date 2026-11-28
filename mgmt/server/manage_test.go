package server

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestDeleteMoveRevokeToken(t *testing.T) {
	t.Parallel()
	s, err := OpenStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	now := time.Unix(1_800_000_000, 0)
	for _, g := range []string{"a", "b"} {
		err = s.CreateGroup(g, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !errors.Is(s.CreateGroup(" bad", now), ErrBadGroupName) || !errors.Is(s.CreateGroup("", now), ErrBadGroupName) {
		t.Fatal("bad group names must be refused")
	}
	token, _ := s.CreateToken("a", time.Hour, now)
	c := &Computer{Hostname: "h", OS: "linux"}
	err = s.Enroll(token, c, now, func(string) (string, error) { return "fp", nil })
	if err != nil {
		t.Fatal(err)
	}

	// Move.
	seq, _ := s.PolicySeq()
	err = s.MoveComputer(c.ID, "b", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	moved, _ := s.Computer(c.ID)
	seq2, _ := s.PolicySeq()
	if moved.Group != "b" || !moved.Moved.Equal(now.Add(time.Minute)) || seq2 <= seq {
		t.Fatalf("moved: %+v, seq %d -> %d", moved, seq, seq2)
	}
	if !errors.Is(s.MoveComputer(c.ID, "b", now), ErrSameGroup) || !errors.Is(s.MoveComputer(c.ID, "x", now), ErrNotFound) ||
		!errors.Is(s.MoveComputer("x", "a", now), ErrNotFound) {
		t.Fatal("move errors")
	}

	// Delete: a group with a computer (even revoked) stays; an empty one goes
	// with its tokens.
	err = s.Revoke(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.DeleteGroup("b"), ErrGroupInUse) {
		t.Fatal("a group with a revoked computer must not be deleted")
	}
	_, err = s.CreateToken("a", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	err = s.DeleteGroup("a")
	if err != nil {
		t.Fatal(err)
	}
	tokens, _ := s.Tokens()
	if len(tokens) != 0 {
		t.Fatalf("tokens of the deleted group: %d", len(tokens))
	}
	if !errors.Is(s.DeleteGroup("a"), ErrNotFound) {
		t.Fatal("deleting a missing group must fail")
	}

	// Revoke tokens by ID.
	_, _ = s.CreateToken("b", time.Hour, now)
	tokens, _ = s.Tokens()
	if _, err := s.RevokeToken(tokens[0].ID[:4]); !errors.Is(err, ErrNotFound) { //nolint:noinlineerr // Test.
		t.Fatal("a too short ID must be refused")
	}
	group, err := s.RevokeToken(tokens[0].ID)
	if err != nil || group != "b" {
		t.Fatalf("revoke token: %s %v", group, err)
	}
	if _, err := s.RevokeToken(tokens[0].ID); !errors.Is(err, ErrNotFound) { //nolint:noinlineerr // Test.
		t.Fatal("revoking twice must fail")
	}
}

const keyAskTimeout = "filter/askTimeout"

func TestParse(t *testing.T) {
	t.Parallel()
	settings, err := ParseSettings([]byte("type: settings\nconfig:\n  filter:\n    askTimeout: 33\n    lists: [MAL]\n"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := SettingsYAML(settings)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseSettings(data)
	if err != nil || !reflect.DeepEqual(settings, again) {
		t.Fatalf("round trip: %v %v\n%s", again, err, data)
	}
	if !reflect.DeepEqual(SortedKeys(settings), []string{keyAskTimeout, "filter/lists"}) {
		t.Fatal("sorted keys")
	}
	rules, err := RulesFromLines("- a.example\n\n# note\n  + b.example  \n", "")
	if err != nil || !reflect.DeepEqual(rules.Endpoints, []string{"- a.example", "+ b.example"}) || len(rules.ServiceEndpoints) != 0 {
		t.Fatalf("rules: %+v %v", rules, err)
	}
	if rules, err := RulesFromLines("", " \n"); rules != nil || err != nil { //nolint:noinlineerr // Test.
		t.Fatal("empty rules must be nil")
	}
	if _, err := RulesFromLines("a.example", ""); !errors.Is(err, ErrRuleFormat) { //nolint:noinlineerr // Test.
		t.Fatal("a rule without + or - must be refused")
	}
	for name, ok := range map[string]bool{"office": true, "a b": true, "": false, " x": false, "x\n": false, string(make([]byte, 65)): false} {
		if (CheckGroupName(name) == nil) != ok {
			t.Errorf("group name %q", name)
		}
	}
}
