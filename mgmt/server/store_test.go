package server

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/safing/portmaster/mgmt/policy"
)

// schemaV1 is the schema of the first release (phase A1).
const schemaV1 = `
CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
INSERT INTO meta (key, value) VALUES ('policy_seq', 5);
CREATE TABLE groups (name TEXT PRIMARY KEY, settings TEXT NOT NULL DEFAULT '{}', locked TEXT NOT NULL DEFAULT '[]', updated INTEGER NOT NULL);
INSERT INTO groups (name, updated) VALUES ('office', 1);
CREATE TABLE tokens (hash TEXT PRIMARY KEY, grp TEXT NOT NULL REFERENCES groups(name), expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
CREATE TABLE computers (id TEXT PRIMARY KEY, grp TEXT NOT NULL REFERENCES groups(name), hostname TEXT NOT NULL, os TEXT NOT NULL, core_version TEXT NOT NULL, cert_fp TEXT NOT NULL, enrolled INTEGER NOT NULL, last_seen INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0);
INSERT INTO computers (id, grp, hostname, os, core_version, cert_fp, enrolled) VALUES ('c1', 'office', 'h1', 'linux', '2.0', 'fp', 1);
`

func TestStoreMigratesV1(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "db")
	conn, err := sqlite.OpenConn(path, sqlite.OpenReadWrite|sqlite.OpenCreate)
	if err != nil {
		t.Fatal(err)
	}
	err = sqlitex.ExecuteScript(conn, schemaV1, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	s, err := OpenStore(path)
	if err != nil {
		t.Fatalf("open v1 database: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	now := time.Now()

	g, err := s.Group("office")
	if err != nil || len(g.Profiles) != 0 {
		t.Fatalf("group after migration: %+v %v", g, err)
	}
	err = s.SetGroupProfiles("office", []json.RawMessage{json.RawMessage(`{"type":"profile","name":"a"}`)}, now)
	if err != nil {
		t.Fatal(err)
	}
	g, err = s.Group("office")
	if err != nil || len(g.Profiles) != 1 {
		t.Fatalf("profiles not stored: %+v %v", g, err)
	}
	if seq, _ := s.PolicySeq(); seq != 6 {
		t.Fatalf("profile change must increase the policy sequence, got %d", seq)
	}
	err = s.SetGroupProfiles("nope", nil, now)
	if err == nil {
		t.Fatal("want an error for an unknown group")
	}

	err = s.SaveReport("c1", &policy.Report{Type: policy.TypeReport, AppliedVersion: 6, CoreVersion: "2.1", Overridden: []string{"filter/lists"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Computer("c1")
	if err != nil {
		t.Fatal(err)
	}
	if c.AppliedVersion != 6 || c.CoreVersion != "2.1" || c.LastReport.IsZero() || c.Report == nil || len(c.Report.Overridden) != 1 {
		t.Fatalf("report not stored: %+v", c)
	}
	err = s.SaveReport("unknown", &policy.Report{Type: policy.TypeReport}, now)
	if err == nil {
		t.Fatal("want an error for an unknown computer")
	}

	// Rules of a group.
	err = s.SetGroupRules("office", &policy.Rules{Endpoints: []string{"- example.org"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	g, err = s.Group("office")
	if err != nil || g.Rules == nil || g.Rules.Endpoints[0] != "- example.org" {
		t.Fatalf("rules not stored: %+v %v", g, err)
	}
	err = s.SetGroupRules("office", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if g, _ = s.Group("office"); g.Rules != nil {
		t.Fatalf("rules not removed: %+v", g.Rules)
	}

	// Opening again does not migrate twice.
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	_ = s2.Close()
}
