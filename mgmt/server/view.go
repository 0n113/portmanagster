package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// Policy states of a computer, see PolicyState.
const (
	PolicyNoReport = "no report"
	PolicyError    = "error"
	PolicyPending  = "pending"
	PolicyCurrent  = "current"
)

// SilentAfter is the time without contact after which a computer counts as
// silent; clients pull every 5 minutes.
const SilentAfter = 30 * time.Minute

// Token is an enrollment token without its secret.
type Token struct {
	// ID is the start of the token hash, enough to tell tokens apart.
	ID      string    `json:"id"`
	Group   string    `json:"group"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	Used    bool      `json:"used"`
}

// Status of the token at the given time: "used", "expired" or "valid".
func (t *Token) Status(now time.Time) string {
	switch {
	case t.Used:
		return "used"
	case !now.Before(t.Expires):
		return "expired"
	default:
		return "valid"
	}
}

// Tokens returns all enrollment tokens, newest first.
func (s *Store) Tokens() ([]*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var list []*Token
	err := sqlitex.Execute(s.conn, `SELECT hash, grp, created, expires, used FROM tokens ORDER BY created DESC, hash`, &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			list = append(list, &Token{
				ID:      stmt.ColumnText(0)[:12],
				Group:   stmt.ColumnText(1),
				Created: time.Unix(stmt.ColumnInt64(2), 0),
				Expires: time.Unix(stmt.ColumnInt64(3), 0),
				Used:    stmt.ColumnInt64(4) != 0,
			})
			return nil
		},
	})
	return list, err
}

// PolicyState tells whether the computer runs the current policy of its
// group g: it does if its last report came after the last change of the
// group and has no error.
func PolicyState(c *Computer, g *Group) string {
	switch {
	case c.Report == nil:
		return PolicyNoReport
	case c.Report.Error != "":
		return PolicyError
	case g != nil && !c.LastReport.After(g.Updated):
		return PolicyPending
	default:
		return PolicyCurrent
	}
}

// Silent tells whether an active computer has not contacted the server for
// SilentAfter since its last contact or, without one, its enrollment.
func Silent(c *Computer, now time.Time) bool {
	return !c.Revoked && now.Sub(LastContact(c)) > SilentAfter
}

// LastContact is the last time the computer contacted the server, or its
// enrollment if it did not yet.
func LastContact(c *Computer) time.Time {
	if c.LastSeen.After(c.Enrolled) {
		return c.LastSeen
	}
	return c.Enrolled
}

// CoreStatus is the part of the core status in a report the server shows.
type CoreStatus struct {
	Ready        bool `json:"ready"`
	Interception bool `json:"interception"`
	Problems     []struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"problems"`
}

// ReportStatus decodes the core status of the last report; nil if there
// is none or it cannot be read.
func ReportStatus(c *Computer) *CoreStatus {
	if c.Report == nil || len(c.Report.Status) == 0 {
		return nil
	}
	st := &CoreStatus{}
	if json.Unmarshal(c.Report.Status, st) != nil {
		return nil
	}
	return st
}

// Health summarizes the core status and the policy findings of the last
// report: "-" without report, "ok" or a list of findings.
func Health(c *Computer) string {
	if c.Report == nil || len(c.Report.Status) == 0 {
		return "-"
	}
	st := ReportStatus(c)
	if st == nil {
		return "unknown"
	}
	var parts []string
	if !st.Ready {
		parts = append(parts, "not ready")
	}
	if !st.Interception {
		parts = append(parts, "no interception")
	}
	if len(st.Problems) > 0 {
		parts = append(parts, fmt.Sprintf("%d problem(s)", len(st.Problems)))
	}
	if len(c.Report.Overridden) > 0 {
		parts = append(parts, fmt.Sprintf("%d overridden", len(c.Report.Overridden)))
	}
	if len(c.Report.Refused) > 0 {
		parts = append(parts, fmt.Sprintf("%d refused", len(c.Report.Refused)))
	}
	if len(parts) == 0 {
		return "ok"
	}
	return strings.Join(parts, ", ")
}
