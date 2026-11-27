package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/safing/portmaster/mgmt/policy"
)

var (
	// ErrNotFound is returned when a group or computer does not exist.
	ErrNotFound = errors.New("not found")
	// ErrExists is returned when a group already exists.
	ErrExists = errors.New("already exists")
	// ErrBadToken is returned for an unknown, used or expired token.
	ErrBadToken = errors.New("invalid, used or expired enrollment token")
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value INTEGER NOT NULL
);
INSERT OR IGNORE INTO meta (key, value) VALUES ('policy_seq', 1);
CREATE TABLE IF NOT EXISTS groups (
	name     TEXT PRIMARY KEY,
	settings TEXT NOT NULL DEFAULT '{}',
	locked   TEXT NOT NULL DEFAULT '[]',
	profiles TEXT NOT NULL DEFAULT '[]',
	rules    TEXT NOT NULL DEFAULT '{}',
	updated  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
	hash    TEXT PRIMARY KEY,
	grp     TEXT NOT NULL REFERENCES groups(name),
	expires INTEGER NOT NULL,
	used    INTEGER NOT NULL DEFAULT 0,
	created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS computers (
	id           TEXT PRIMARY KEY,
	grp          TEXT NOT NULL REFERENCES groups(name),
	hostname     TEXT NOT NULL,
	os           TEXT NOT NULL,
	core_version TEXT NOT NULL,
	cert_fp      TEXT NOT NULL,
	enrolled     INTEGER NOT NULL,
	last_seen    INTEGER NOT NULL DEFAULT 0,
	revoked      INTEGER NOT NULL DEFAULT 0,
	applied_version INTEGER NOT NULL DEFAULT 0,
	last_report  INTEGER NOT NULL DEFAULT 0,
	report       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS admins (
	name      TEXT PRIMARY KEY,
	role      TEXT NOT NULL,
	handle    TEXT NOT NULL,
	totp      TEXT NOT NULL DEFAULT '',
	totp_step INTEGER NOT NULL DEFAULT 0,
	created   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_credentials (
	id      TEXT PRIMARY KEY,
	admin   TEXT NOT NULL REFERENCES admins(name) ON DELETE CASCADE,
	data    TEXT NOT NULL,
	created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_setup (
	hash    TEXT PRIMARY KEY,
	admin   TEXT NOT NULL REFERENCES admins(name) ON DELETE CASCADE,
	expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	hash      TEXT PRIMARY KEY,
	admin     TEXT NOT NULL REFERENCES admins(name) ON DELETE CASCADE,
	csrf      TEXT NOT NULL,
	created   INTEGER NOT NULL,
	last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	time   INTEGER NOT NULL,
	actor  TEXT NOT NULL,
	action TEXT NOT NULL,
	object TEXT NOT NULL,
	detail TEXT NOT NULL DEFAULT ''
);
`

// migrations add the columns of later versions to an existing database.
const tableComputers = "computers"

var migrations = []struct{ table, column, def string }{
	{"groups", "profiles", `TEXT NOT NULL DEFAULT '[]'`},
	{"groups", "rules", `TEXT NOT NULL DEFAULT '{}'`},
	{tableComputers, "applied_version", `INTEGER NOT NULL DEFAULT 0`},
	{tableComputers, "last_report", `INTEGER NOT NULL DEFAULT 0`},
	{tableComputers, "report", `TEXT NOT NULL DEFAULT ''`},
}

// Store holds the server state in SQLite. The admin commands and the
// running server open the same file; SQLite (WAL) handles the concurrency.
type Store struct {
	mu   sync.Mutex
	conn *sqlite.Conn
}

// Group is a group of computers with the same policy.
type Group struct {
	Name     string         `json:"name"`
	Settings map[string]any `json:"settings"`
	Locked   []string       `json:"locked"`
	// Profiles are profile exports (JSON) imported on every computer of
	// the group.
	Profiles []json.RawMessage `json:"profiles"`
	// Rules are the endpoint rules of the group's policy.
	Rules   *policy.Rules `json:"rules,omitempty"`
	Updated time.Time     `json:"updated"`
}

// Computer is an enrolled computer.
type Computer struct {
	ID          string    `json:"id"`
	Group       string    `json:"group"`
	Hostname    string    `json:"hostname"`
	OS          string    `json:"os"`
	CoreVersion string    `json:"coreVersion"`
	CertFP      string    `json:"certFingerprint"`
	Enrolled    time.Time `json:"enrolled"`
	LastSeen    time.Time `json:"lastSeen,omitzero"`
	Revoked     bool      `json:"revoked"`
	// AppliedVersion is the policy version in force according to the last report.
	AppliedVersion uint64    `json:"appliedVersion,omitempty"`
	LastReport     time.Time `json:"lastReport,omitzero"`
	// Report is the last report of the computer, nil if none arrived yet.
	Report *policy.Report `json:"report,omitempty"`
}

// OpenStore opens or creates the database file.
func OpenStore(path string) (*Store, error) {
	conn, err := sqlite.OpenConn(path, sqlite.OpenReadWrite|sqlite.OpenCreate|sqlite.OpenWAL)
	if err != nil {
		return nil, err
	}
	conn.SetBusyTimeout(10 * time.Second)
	// The pragma has no effect inside the transaction of ExecuteScript.
	err = sqlitex.ExecuteTransient(conn, "PRAGMA foreign_keys = ON", nil)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}
	err = sqlitex.ExecuteScript(conn, schema, nil)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	err = migrate(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("migrate schema: %w", err)
	}
	return &Store{conn: conn}, nil
}

func migrate(conn *sqlite.Conn) error {
	for _, m := range migrations {
		var n int64
		err := sqlitex.Execute(conn, `SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, &sqlitex.ExecOptions{
			Args: []any{m.table, m.column},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				n = stmt.ColumnInt64(0)
				return nil
			},
		})
		if err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		// Table, column and definition are constants above.
		err = sqlitex.ExecuteTransient(conn, `ALTER TABLE `+m.table+` ADD COLUMN `+m.column+` `+m.def, nil)
		if err != nil {
			return fmt.Errorf("add %s.%s: %w", m.table, m.column, err)
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.Close()
}

// PolicySeq returns the current policy sequence.
func (s *Store) PolicySeq() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var seq int64
	err := sqlitex.Execute(s.conn, `SELECT value FROM meta WHERE key = 'policy_seq'`, &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			seq = stmt.ColumnInt64(0)
			return nil
		},
	})
	return uint64(seq), err //nolint:gosec // The sequence starts at 1 and only increases.
}

// CreateGroup creates an empty group.
func (s *Store) CreateGroup(name string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.group(name)
	if err == nil {
		return fmt.Errorf("group %s: %w", name, ErrExists)
	}
	return s.exec(`INSERT INTO groups (name, updated) VALUES (?, ?)`, name, now.Unix())
}

// SetGroupPolicy replaces the settings and locked keys of a group.
func (s *Store) SetGroupPolicy(name string, settings map[string]any, locked []string, now time.Time) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if settings == nil {
		settings = map[string]any{}
	}
	if locked == nil {
		locked = []string{}
	}
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	lockedJSON, err := json.Marshal(locked)
	if err != nil {
		return err
	}

	defer sqlitex.Save(s.conn)(&err)
	err = s.exec(`UPDATE groups SET settings = ?, locked = ?, updated = ? WHERE name = ?`,
		string(settingsJSON), string(lockedJSON), now.Unix(), name)
	if err != nil {
		return err
	}
	if s.conn.Changes() == 0 {
		return fmt.Errorf("group %s: %w", name, ErrNotFound)
	}
	return s.bumpSeq()
}

// Group returns a group.
func (s *Store) Group(name string) (*Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.group(name)
}

// Groups returns all groups.
func (s *Store) Groups() ([]*Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var groups []*Group
	err := sqlitex.Execute(s.conn, `SELECT name, settings, locked, profiles, updated, rules FROM groups ORDER BY name`, &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			g, err := scanGroup(stmt)
			if err != nil {
				return err
			}
			groups = append(groups, g)
			return nil
		},
	})
	return groups, err
}

func scanGroup(stmt *sqlite.Stmt) (*Group, error) {
	g := &Group{
		Name:    stmt.ColumnText(0),
		Updated: time.Unix(stmt.ColumnInt64(4), 0).UTC(),
	}
	err := json.Unmarshal([]byte(stmt.ColumnText(1)), &g.Settings)
	if err != nil {
		return nil, fmt.Errorf("group %s settings: %w", g.Name, err)
	}
	g.Rules = &policy.Rules{}
	err = json.Unmarshal([]byte(stmt.ColumnText(5)), g.Rules)
	if err != nil {
		return nil, fmt.Errorf("group %s rules: %w", g.Name, err)
	}
	if g.Rules.Empty() {
		g.Rules = nil
	}
	err = json.Unmarshal([]byte(stmt.ColumnText(3)), &g.Profiles)
	if err != nil {
		return nil, fmt.Errorf("group %s profiles: %w", g.Name, err)
	}
	err = json.Unmarshal([]byte(stmt.ColumnText(2)), &g.Locked)
	if err != nil {
		return nil, fmt.Errorf("group %s locked: %w", g.Name, err)
	}
	return g, nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CreateToken creates a one-time enrollment token for a group. Only its hash
// is stored.
func (s *Store) CreateToken(group string, validFor time.Duration, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.group(group)
	if err != nil {
		return "", err
	}
	token, err := randomHex(24)
	if err != nil {
		return "", err
	}
	err = s.exec(`INSERT INTO tokens (hash, grp, expires, created) VALUES (?, ?, ?, ?)`,
		hashToken(token), group, now.Add(validFor).Unix(), now.Unix())
	if err != nil {
		return "", err
	}
	return token, nil
}

// Enroll uses the token once and records the computer. issue creates the
// client certificate for the new computer ID and returns its fingerprint.
func (s *Store) Enroll(token string, c *Computer, now time.Time, issue func(id string) (certFP string, err error)) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	defer sqlitex.Save(s.conn)(&err)
	var group string
	err = sqlitex.Execute(s.conn, `UPDATE tokens SET used = ? WHERE hash = ? AND used = 0 AND expires > ? RETURNING grp`, &sqlitex.ExecOptions{
		Args: []any{now.Unix(), hashToken(token), now.Unix()},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			group = stmt.ColumnText(0)
			return nil
		},
	})
	if err != nil {
		return err
	}
	if group == "" {
		return ErrBadToken
	}

	c.ID, err = randomHex(16)
	if err != nil {
		return err
	}
	c.Group = group
	c.Enrolled = now.UTC()
	c.CertFP, err = issue(c.ID)
	if err != nil {
		return err
	}
	err = s.exec(`INSERT INTO computers (id, grp, hostname, os, core_version, cert_fp, enrolled) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Group, c.Hostname, c.OS, c.CoreVersion, c.CertFP, now.Unix())
	if err != nil {
		return err
	}
	return s.bumpSeq()
}

const computerColumns = `id, grp, hostname, os, core_version, cert_fp, enrolled, last_seen, revoked, applied_version, last_report, report`

func scanComputer(stmt *sqlite.Stmt) *Computer {
	c := &Computer{
		ID:          stmt.ColumnText(0),
		Group:       stmt.ColumnText(1),
		Hostname:    stmt.ColumnText(2),
		OS:          stmt.ColumnText(3),
		CoreVersion: stmt.ColumnText(4),
		CertFP:      stmt.ColumnText(5),
		Enrolled:    time.Unix(stmt.ColumnInt64(6), 0).UTC(),
		Revoked:     stmt.ColumnInt64(8) != 0,
		// The version is stored from a uint64 and never negative.
		AppliedVersion: uint64(stmt.ColumnInt64(9)), //nolint:gosec // See above.
	}
	if seen := stmt.ColumnInt64(7); seen > 0 {
		c.LastSeen = time.Unix(seen, 0).UTC()
	}
	if reported := stmt.ColumnInt64(10); reported > 0 {
		c.LastReport = time.Unix(reported, 0).UTC()
	}
	if text := stmt.ColumnText(11); text != "" {
		r := &policy.Report{}
		// A report that cannot be read is left out; it was checked when stored.
		if json.Unmarshal([]byte(text), r) == nil {
			c.Report = r
		}
	}
	return c
}

// SetGroupProfiles replaces the profiles of a group.
func (s *Store) SetGroupProfiles(name string, profiles []json.RawMessage, now time.Time) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if profiles == nil {
		profiles = []json.RawMessage{}
	}
	data, err := json.Marshal(profiles)
	if err != nil {
		return err
	}
	defer sqlitex.Save(s.conn)(&err)
	err = s.exec(`UPDATE groups SET profiles = ?, updated = ? WHERE name = ?`, string(data), now.Unix(), name)
	if err != nil {
		return err
	}
	if s.conn.Changes() == 0 {
		return fmt.Errorf("group %s: %w", name, ErrNotFound)
	}
	return s.bumpSeq()
}

// SetGroupRules replaces the endpoint rules of a group; nil removes them.
func (s *Store) SetGroupRules(name string, rules *policy.Rules, now time.Time) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rules == nil {
		rules = &policy.Rules{}
	}
	data, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	defer sqlitex.Save(s.conn)(&err)
	err = s.exec(`UPDATE groups SET rules = ?, updated = ? WHERE name = ?`, string(data), now.Unix(), name)
	if err != nil {
		return err
	}
	if s.conn.Changes() == 0 {
		return fmt.Errorf("group %s: %w", name, ErrNotFound)
	}
	return s.bumpSeq()
}

// SaveReport stores the last report of a computer.
func (s *Store) SaveReport(id string, r *policy.Report, now time.Time) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err = s.exec(`UPDATE computers SET applied_version = ?, core_version = ?, last_report = ?, last_seen = ?, report = ? WHERE id = ?`,
		int64(r.AppliedVersion), r.CoreVersion, now.Unix(), now.Unix(), string(data), id) //nolint:gosec // Versions are far below 2^63.
	if err != nil {
		return err
	}
	if s.conn.Changes() == 0 {
		return fmt.Errorf("computer %s: %w", id, ErrNotFound)
	}
	return nil
}

// Computer returns a computer.
func (s *Store) Computer(id string) (*Computer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var c *Computer
	err := sqlitex.Execute(s.conn, `SELECT `+computerColumns+` FROM computers WHERE id = ?`, &sqlitex.ExecOptions{
		Args: []any{id},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			c = scanComputer(stmt)
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("computer %s: %w", id, ErrNotFound)
	}
	return c, nil
}

// Computers returns all computers.
func (s *Store) Computers() ([]*Computer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var list []*Computer
	err := sqlitex.Execute(s.conn, `SELECT `+computerColumns+` FROM computers ORDER BY hostname, id`, &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			list = append(list, scanComputer(stmt))
			return nil
		},
	})
	return list, err
}

// Seen records that the computer contacted the server.
func (s *Store) Seen(id string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exec(`UPDATE computers SET last_seen = ? WHERE id = ?`, now.Unix(), id)
}

// Revoke revokes a computer; the server rejects its certificate from then on.
func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.exec(`UPDATE computers SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if s.conn.Changes() == 0 {
		return fmt.Errorf("computer %s: %w", id, ErrNotFound)
	}
	return nil
}

func (s *Store) exec(query string, args ...any) error {
	return sqlitex.Execute(s.conn, query, &sqlitex.ExecOptions{Args: args})
}

// bumpSeq increases the policy sequence; every policy change gets a higher
// policy version.
func (s *Store) bumpSeq() error {
	return s.exec(`UPDATE meta SET value = value + 1 WHERE key = 'policy_seq'`)
}

func (s *Store) group(name string) (*Group, error) {
	var (
		g     *Group
		inner error
	)
	err := sqlitex.Execute(s.conn, `SELECT name, settings, locked, profiles, updated, rules FROM groups WHERE name = ?`, &sqlitex.ExecOptions{
		Args: []any{name},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			g, inner = scanGroup(stmt)
			return inner
		},
	})
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, fmt.Errorf("group %s: %w", name, ErrNotFound)
	}
	return g, nil
}
