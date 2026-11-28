package server

import (
	"fmt"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// DeleteGroup deletes a group without computers, with its unused tokens.
// Revoked computers count too: they keep their group for the record.
func (s *Store) DeleteGroup(name string) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.group(name)
	if err != nil {
		return err
	}
	var n int64
	err = sqlitex.Execute(s.conn, `SELECT COUNT(*) FROM computers WHERE grp = ?`, &sqlitex.ExecOptions{
		Args: []any{name},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			n = stmt.ColumnInt64(0)
			return nil
		},
	})
	if err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("group %s: %d computer(s): %w", name, n, ErrGroupInUse)
	}
	defer sqlitex.Save(s.conn)(&err)
	err = s.exec(`DELETE FROM tokens WHERE grp = ?`, name)
	if err != nil {
		return err
	}
	return s.exec(`DELETE FROM groups WHERE name = ?`, name)
}

// MoveComputer puts a computer into another group. Its next pull brings the
// policy of the new group.
func (s *Store) MoveComputer(id, group string, now time.Time) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.group(group)
	if err != nil {
		return err
	}
	var current string
	err = sqlitex.Execute(s.conn, `SELECT grp FROM computers WHERE id = ?`, &sqlitex.ExecOptions{
		Args: []any{id},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			current = stmt.ColumnText(0)
			return nil
		},
	})
	switch {
	case err != nil:
		return err
	case current == "":
		return fmt.Errorf("computer %s: %w", id, ErrNotFound)
	case current == group:
		return ErrSameGroup
	}
	defer sqlitex.Save(s.conn)(&err)
	err = s.exec(`UPDATE computers SET grp = ?, moved = ? WHERE id = ?`, group, now.Unix(), id)
	if err != nil {
		return err
	}
	return s.bumpSeq()
}

// RevokeToken deletes an unused enrollment token by its ID (the start of its
// hash, see Token). It returns the group of the token.
func (s *Store) RevokeToken(id string) (group string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(id) < 8 {
		return "", fmt.Errorf("token %s: %w", id, ErrNotFound)
	}
	var (
		hash  string
		used  bool
		count int
	)
	err = sqlitex.Execute(s.conn, `SELECT hash, grp, used FROM tokens WHERE substr(hash, 1, ?) = ?`, &sqlitex.ExecOptions{
		Args: []any{len(id), id},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			hash, group, used = stmt.ColumnText(0), stmt.ColumnText(1), stmt.ColumnInt64(2) != 0
			count++
			return nil
		},
	})
	switch {
	case err != nil:
		return "", err
	case count != 1:
		return "", fmt.Errorf("token %s: %w", id, ErrNotFound)
	case used:
		return "", fmt.Errorf("token %s: %w", id, ErrTokenUsed)
	}
	return group, s.exec(`DELETE FROM tokens WHERE hash = ?`, hash)
}
