package server

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// Admin roles.
const (
	// RoleAdmin may change everything.
	RoleAdmin = "admin"
	// RoleViewer may see everything and change nothing.
	RoleViewer = "viewer"
)

var (
	// ErrBadRole is returned for a role other than RoleAdmin and RoleViewer.
	ErrBadRole = errors.New("role must be admin or viewer")
	// ErrBadSetup is returned for an unknown or expired setup token.
	ErrBadSetup = errors.New("invalid or expired setup link")
	// ErrNoSession is returned for an unknown or expired session.
	ErrNoSession = errors.New("no valid session")
)

// Admin is an account of the admin web UI.
type Admin struct {
	Name string `json:"name"`
	Role string `json:"role"`
	// Handle is the random WebAuthn user handle.
	Handle []byte `json:"-"`
	// TOTPSecret is the base32 TOTP secret, empty if TOTP is not set up.
	TOTPSecret string `json:"-"`
	// TOTPStep is the last time step used for a TOTP login.
	TOTPStep int64 `json:"-"`
	// Credentials are the passkeys (webauthn.Credential as JSON).
	Credentials []json.RawMessage `json:"-"`
	Created     time.Time         `json:"created"`
}

// Session is a login session of an admin.
type Session struct {
	Admin    *Admin
	CSRF     string
	Created  time.Time
	LastSeen time.Time
}

// AuditEntry is one change in the audit log.
type AuditEntry struct {
	ID     int64     `json:"id"`
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Object string    `json:"object"`
	Detail string    `json:"detail,omitempty"`
}

// AddAdmin creates an admin account without credentials.
func (s *Store) AddAdmin(name, role string, now time.Time) error {
	if role != RoleAdmin && role != RoleViewer {
		return ErrBadRole
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.admin(name)
	if err == nil {
		return fmt.Errorf("admin %s: %w", name, ErrExists)
	}
	handle, err := randomHex(32)
	if err != nil {
		return err
	}
	return s.exec(`INSERT INTO admins (name, role, handle, created) VALUES (?, ?, ?, ?)`, name, role, handle, now.Unix())
}

// Admin returns an admin account with its credentials.
func (s *Store) Admin(name string) (*Admin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.admin(name)
}

// AdminByHandle returns the admin with the WebAuthn user handle.
func (s *Store) AdminByHandle(handle []byte) (*Admin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var name string
	err := sqlitex.Execute(s.conn, `SELECT name FROM admins WHERE handle = ?`, &sqlitex.ExecOptions{
		Args: []any{hex.EncodeToString(handle)},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			name = stmt.ColumnText(0)
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	if name == "" {
		return nil, fmt.Errorf("admin: %w", ErrNotFound)
	}
	return s.admin(name)
}

// Admins returns all admin accounts with their credentials.
func (s *Store) Admins() ([]*Admin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var names []string
	err := sqlitex.Execute(s.conn, `SELECT name FROM admins ORDER BY name`, &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlite.Stmt) error {
			names = append(names, stmt.ColumnText(0))
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	list := make([]*Admin, 0, len(names))
	for _, name := range names {
		a, err := s.admin(name)
		if err != nil {
			return nil, err
		}
		list = append(list, a)
	}
	return list, nil
}

// RemoveAdmin deletes an admin account with its credentials and sessions.
func (s *Store) RemoveAdmin(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.exec(`DELETE FROM admins WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if s.conn.Changes() == 0 {
		return fmt.Errorf("admin %s: %w", name, ErrNotFound)
	}
	return nil
}

// ResetAdmin removes the passkeys, the TOTP secret, the sessions and the
// setup links of an admin, who then needs a new setup link.
func (s *Store) ResetAdmin(name string) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.admin(name)
	if err != nil {
		return err
	}
	defer sqlitex.Save(s.conn)(&err)
	for _, q := range []string{
		`DELETE FROM admin_credentials WHERE admin = ?`,
		`DELETE FROM sessions WHERE admin = ?`,
		`DELETE FROM admin_setup WHERE admin = ?`,
		`UPDATE admins SET totp = '', totp_step = 0 WHERE name = ?`,
	} {
		err = s.exec(q, name)
		if err != nil {
			return err
		}
	}
	return nil
}

// CreateSetupLink creates a one-time token with which the admin sets up a
// passkey or TOTP. Only its hash is stored.
func (s *Store) CreateSetupLink(name string, validFor time.Duration, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.admin(name)
	if err != nil {
		return "", err
	}
	token, err := randomHex(24)
	if err != nil {
		return "", err
	}
	err = s.exec(`INSERT INTO admin_setup (hash, admin, expires) VALUES (?, ?, ?)`, hashToken(token), name, now.Add(validFor).Unix())
	if err != nil {
		return "", err
	}
	return token, nil
}

// SetupAdmin returns the admin of a valid setup token without using it up.
func (s *Store) SetupAdmin(token string, now time.Time) (*Admin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var name string
	err := sqlitex.Execute(s.conn, `SELECT admin FROM admin_setup WHERE hash = ? AND expires > ?`, &sqlitex.ExecOptions{
		Args: []any{hashToken(token), now.Unix()},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			name = stmt.ColumnText(0)
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	if name == "" {
		return nil, ErrBadSetup
	}
	return s.admin(name)
}

// AddPasskey stores a passkey (webauthn.Credential as JSON) of the admin
// of a valid setup token and uses the token up.
func (s *Store) AddPasskey(token string, id []byte, credential json.RawMessage, now time.Time) error {
	return s.useSetup(token, now, func(name string) error {
		return s.exec(`INSERT INTO admin_credentials (id, admin, data, created) VALUES (?, ?, ?, ?)`,
			hex.EncodeToString(id), name, string(credential), now.Unix())
	})
}

// SetTOTP stores the TOTP secret of the admin of a valid setup token and
// uses the token up. step is the time step of the code that confirmed it.
func (s *Store) SetTOTP(token, secret string, step int64, now time.Time) error {
	return s.useSetup(token, now, func(name string) error {
		return s.exec(`UPDATE admins SET totp = ?, totp_step = ? WHERE name = ?`, secret, step, name)
	})
}

// UpdatePasskey replaces the stored data of a passkey, e.g. its sign count.
func (s *Store) UpdatePasskey(id []byte, credential json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exec(`UPDATE admin_credentials SET data = ? WHERE id = ?`, string(credential), hex.EncodeToString(id))
}

// UseTOTPStep records a TOTP time step as used. It returns false if the
// step or a later one was already used (replay).
func (s *Store) UseTOTPStep(name string, step int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.exec(`UPDATE admins SET totp_step = ? WHERE name = ? AND totp_step < ?`, step, name, step)
	if err != nil {
		return false, err
	}
	return s.conn.Changes() == 1, nil
}

// CreateSession creates a login session and returns its token and CSRF
// token. Only the hash of the session token is stored.
func (s *Store) CreateSession(name string, now time.Time) (token, csrf string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, err = randomHex(32)
	if err != nil {
		return "", "", err
	}
	csrf, err = randomHex(32)
	if err != nil {
		return "", "", err
	}
	err = s.exec(`INSERT INTO sessions (hash, admin, csrf, created, last_seen) VALUES (?, ?, ?, ?, ?)`,
		hashToken(token), name, csrf, now.Unix(), now.Unix())
	if err != nil {
		return "", "", err
	}
	return token, csrf, nil
}

// Session returns a valid session and marks it as used now. A session is
// valid for maxAge after the login and idle after its last use; expired
// sessions are deleted.
func (s *Store) Session(token string, now time.Time, maxAge, idle time.Duration) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.exec(`DELETE FROM sessions WHERE created <= ? OR last_seen <= ?`,
		now.Add(-maxAge).Unix(), now.Add(-idle).Unix())
	if err != nil {
		return nil, err
	}
	var (
		sess *Session
		name string
	)
	hash := hashToken(token)
	err = sqlitex.Execute(s.conn, `SELECT admin, csrf, created, last_seen FROM sessions WHERE hash = ?`, &sqlitex.ExecOptions{
		Args: []any{hash},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			name = stmt.ColumnText(0)
			sess = &Session{
				CSRF:     stmt.ColumnText(1),
				Created:  time.Unix(stmt.ColumnInt64(2), 0),
				LastSeen: time.Unix(stmt.ColumnInt64(3), 0),
			}
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, ErrNoSession
	}
	sess.Admin, err = s.admin(name)
	if err != nil {
		return nil, err
	}
	err = s.exec(`UPDATE sessions SET last_seen = ? WHERE hash = ?`, now.Unix(), hash)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// DeleteSession ends a session.
func (s *Store) DeleteSession(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exec(`DELETE FROM sessions WHERE hash = ?`, hashToken(token))
}

// Audit records a change. actor is "cli" or "admin:NAME".
func (s *Store) Audit(actor, action, object, detail string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exec(`INSERT INTO audit (time, actor, action, object, detail) VALUES (?, ?, ?, ?, ?)`,
		now.Unix(), actor, action, object, detail)
}

// AuditLog returns the newest entries since the given time, newest first.
func (s *Store) AuditLog(since time.Time, limit int) ([]*AuditEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var list []*AuditEntry
	err := sqlitex.Execute(s.conn, `SELECT id, time, actor, action, object, detail FROM audit WHERE time >= ? ORDER BY id DESC LIMIT ?`, &sqlitex.ExecOptions{
		Args: []any{since.Unix(), limit},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			list = append(list, &AuditEntry{
				ID:     stmt.ColumnInt64(0),
				Time:   time.Unix(stmt.ColumnInt64(1), 0),
				Actor:  stmt.ColumnText(2),
				Action: stmt.ColumnText(3),
				Object: stmt.ColumnText(4),
				Detail: stmt.ColumnText(5),
			})
			return nil
		},
	})
	return list, err
}

// useSetup runs fn for the admin of a valid setup token and deletes the
// token, in one transaction.
func (s *Store) useSetup(token string, now time.Time, fn func(name string) error) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer sqlitex.Save(s.conn)(&err)
	var name string
	hash := hashToken(token)
	err = sqlitex.Execute(s.conn, `SELECT admin FROM admin_setup WHERE hash = ? AND expires > ?`, &sqlitex.ExecOptions{
		Args: []any{hash, now.Unix()},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			name = stmt.ColumnText(0)
			return nil
		},
	})
	if err != nil {
		return err
	}
	if name == "" {
		return ErrBadSetup
	}
	err = fn(name)
	if err != nil {
		return err
	}
	return s.exec(`DELETE FROM admin_setup WHERE hash = ?`, hash)
}

func (s *Store) admin(name string) (*Admin, error) {
	var a *Admin
	err := sqlitex.Execute(s.conn, `SELECT name, role, handle, totp, totp_step, created FROM admins WHERE name = ?`, &sqlitex.ExecOptions{
		Args: []any{name},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			handle, err := hex.DecodeString(stmt.ColumnText(2))
			if err != nil {
				return err
			}
			a = &Admin{
				Name:       stmt.ColumnText(0),
				Role:       stmt.ColumnText(1),
				Handle:     handle,
				TOTPSecret: stmt.ColumnText(3),
				TOTPStep:   stmt.ColumnInt64(4),
				Created:    time.Unix(stmt.ColumnInt64(5), 0),
			}
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, fmt.Errorf("admin %s: %w", name, ErrNotFound)
	}
	err = sqlitex.Execute(s.conn, `SELECT data FROM admin_credentials WHERE admin = ? ORDER BY created`, &sqlitex.ExecOptions{
		Args: []any{name},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			a.Credentials = append(a.Credentials, json.RawMessage(stmt.ColumnText(0)))
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}
