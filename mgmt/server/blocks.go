package server

import (
	"errors"
	"fmt"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/safing/portmaster/mgmt/policy"
)

// DefaultBlockRetention is how long the server keeps block summaries.
const DefaultBlockRetention = 30 * 24 * time.Hour

// ErrBadBlocks is returned for a block summary that is too large or invalid.
var ErrBadBlocks = errors.New("invalid block summary")

// SetGroupBlockSummary turns the block summary of a group on or off.
func (s *Store) SetGroupBlockSummary(name string, on bool, now time.Time) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer sqlitex.Save(s.conn)(&err)
	err = s.exec(`UPDATE groups SET block_summary = ?, updated = ? WHERE name = ?`, on, now.Unix(), name)
	if err != nil {
		return err
	}
	if s.conn.Changes() == 0 {
		return fmt.Errorf("group %s: %w", name, ErrNotFound)
	}
	return s.bumpSeq()
}

// CheckBlocks checks the size and the counts of a block summary.
func CheckBlocks(blocks []policy.Block) error {
	if len(blocks) > policy.MaxBlocks {
		return fmt.Errorf("%w: %d entries, at most %d", ErrBadBlocks, len(blocks), policy.MaxBlocks)
	}
	for _, b := range blocks {
		if b.Count <= 0 || b.App == "" && b.Target == "" {
			return fmt.Errorf("%w: entry without app, target or count", ErrBadBlocks)
		}
	}
	return nil
}

// addBlocks adds the counts of a summary to the hour of now. The caller holds
// the lock.
func (s *Store) addBlocks(computer string, blocks []policy.Block, now time.Time) error {
	hour := now.Truncate(time.Hour).Unix()
	for _, b := range blocks {
		err := s.exec(`INSERT INTO blocks (computer, hour, app, reason, lists, target, inbound, count)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (computer, hour, app, reason, lists, target, inbound) DO UPDATE SET count = count + excluded.count`,
			computer, hour, b.App, b.Reason, b.Lists, b.Target, b.Inbound, b.Count)
		if err != nil {
			return err
		}
	}
	return nil
}

// PruneBlocks deletes the block summaries of the hours before the given time
// and returns the number of deleted rows.
func (s *Store) PruneBlocks(before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.exec(`DELETE FROM blocks WHERE hour < ?`, before.Truncate(time.Hour).Unix())
	if err != nil {
		return 0, err
	}
	return s.conn.Changes(), nil
}

// BlockFilter selects block summaries; empty fields match everything.
type BlockFilter struct {
	Computer string
	Group    string
	// App matches the app name exactly.
	App string
	// List matches entries whose lists contain it, e.g. "MAL".
	List string
	// Target matches entries whose domain or IP contains it.
	Target string
	Since  time.Time
	Limit  int
}

// BlockRow is the sum of the blocked connections of an app with the same
// reason and target over the selected computers and hours.
type BlockRow struct {
	App     string
	Reason  string
	Lists   string
	Target  string
	Inbound bool
	Count   int64
	// Computers is the number of computers with such blocks.
	Computers int
	// Last is the hour of the last block.
	Last time.Time
}

// Blocks returns the summed block summaries, the largest counts first. The
// group is the current group of the computers.
func (s *Store) Blocks(f BlockFilter) ([]*BlockRow, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var rows []*BlockRow
	err := sqlitex.Execute(s.conn, `SELECT b.app, b.reason, b.lists, b.target, b.inbound,
			SUM(b.count), COUNT(DISTINCT b.computer), MAX(b.hour)
		FROM blocks b JOIN computers c ON c.id = b.computer
		WHERE b.hour >= :since
			AND (:computer = '' OR b.computer = :computer)
			AND (:group = '' OR c.grp = :group)
			AND (:app = '' OR b.app = :app)
			AND (:list = '' OR instr(','||b.lists||',', ','||:list||',') > 0)
			AND (:target = '' OR instr(b.target, :target) > 0)
		GROUP BY b.app, b.reason, b.lists, b.target, b.inbound
		ORDER BY SUM(b.count) DESC, b.app, b.target
		LIMIT :limit`, &sqlitex.ExecOptions{
		Named: map[string]any{
			":since":    f.Since.Truncate(time.Hour).Unix(),
			":computer": f.Computer,
			":group":    f.Group,
			":app":      f.App,
			":list":     f.List,
			":target":   f.Target,
			":limit":    f.Limit,
		},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			rows = append(rows, &BlockRow{
				App:       stmt.ColumnText(0),
				Reason:    stmt.ColumnText(1),
				Lists:     stmt.ColumnText(2),
				Target:    stmt.ColumnText(3),
				Inbound:   stmt.ColumnBool(4),
				Count:     stmt.ColumnInt64(5),
				Computers: stmt.ColumnInt(6),
				Last:      time.Unix(stmt.ColumnInt64(7), 0).UTC(),
			})
			return nil
		},
	})
	return rows, err
}
