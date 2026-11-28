package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/safing/jess"

	"github.com/safing/portmaster/mgmt/policy"
)

// FileOfflinePub is the public offline key in the data directory. When it
// exists, the server only distributes group policies signed with the
// offline key.
const FileOfflinePub = "offline.pub"

var (
	// ErrOfflineKeySet is returned when another offline key is set already.
	ErrOfflineKeySet = errors.New("another offline key is set already; key rotation is not supported yet")
	// ErrNoOfflineKeySet is returned when a signed group policy is
	// published without an offline key on the server.
	ErrNoOfflineKeySet = errors.New("the server has no offline key; set it with offline-key set")
	// ErrNoSignedPolicy is returned for a group without a signed group
	// policy when offline signing is on.
	ErrNoSignedPolicy = errors.New("the group has no offline-signed policy yet")
	// ErrSignedRollback is returned when a signed group policy is not newer
	// than the published one.
	ErrSignedRollback = errors.New("the signed group policy is not newer than the published one")
	// ErrSignedGroup is returned when a signed group policy is for another
	// group.
	ErrSignedGroup = errors.New("the signed group policy is for another group")
	// ErrSignedTooLarge is returned for a signed group policy the clients
	// would not accept.
	ErrSignedTooLarge = errors.New("the signed group policy is too large")
)

// MaxSignedSize is the largest signed group policy; with the encoding in
// the policy it stays below the policy size limit of the clients (4 MiB).
const MaxSignedSize = 2 << 20

// ParseOfflineKey parses a public offline key in jess text format and
// returns it with its fingerprint.
func ParseOfflineKey(text string) (*jess.Signet, string, error) {
	key, err := jess.RecipientFromTextFormat(strings.TrimSpace(text))
	if err != nil {
		return nil, "", fmt.Errorf("offline key: %w", err)
	}
	fp, err := policy.KeyFingerprint(key)
	if err != nil {
		return nil, "", fmt.Errorf("offline key: %w", err)
	}
	return key, fp, nil
}

// ReadOfflineKey returns the public offline key of the data directory in
// jess text format, or "" if offline signing is off.
func ReadOfflineKey(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, FileOfflinePub))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(data)), nil
}

// SetOfflineKey turns offline signing on with the public key in jess text
// format and returns its fingerprint. Setting the same key again is no
// error; another key is refused.
func SetOfflineKey(dir, text string) (string, error) {
	_, fp, err := ParseOfflineKey(text)
	if err != nil {
		return "", err
	}
	text = strings.TrimSpace(text)
	current, err := ReadOfflineKey(dir)
	if err != nil {
		return "", err
	}
	switch current {
	case text:
		return fp, nil
	case "":
	default:
		return "", ErrOfflineKeySet
	}
	return fp, os.WriteFile(filepath.Join(dir, FileOfflinePub), []byte(text+"\n"), 0o644) //nolint:gosec // A public key.
}

// OfflineKey returns the public offline key of the server, "" if offline
// signing is off. It is read on every use, so that offline-key set takes
// effect without a restart.
func (s *Server) OfflineKey() (string, error) {
	return ReadOfflineKey(s.Dir)
}

// ExportGroup returns the unsigned group policy of the current settings of
// the group (the draft, when offline signing is on), for signing.
func ExportGroup(g *Group) *policy.GroupPolicy {
	settings := g.Settings
	if settings == nil {
		settings = map[string]any{}
	}
	return &policy.GroupPolicy{
		Type:         policy.TypeGroupPolicy,
		Group:        g.Name,
		Settings:     settings,
		Locked:       g.Locked,
		Rules:        g.Rules,
		Profiles:     g.Profiles,
		BlockSummary: g.BlockSummary,
	}
}

// contentJSON returns the content of a group policy without its version
// and signing time, to compare draft and signed policy.
func contentJSON(gp *policy.GroupPolicy) ([]byte, error) {
	c := *gp
	c.Type, c.Version, c.Signed = policy.TypeGroupPolicy, 0, time.Time{}
	if c.Settings == nil {
		c.Settings = map[string]any{}
	}
	if len(c.Locked) == 0 {
		c.Locked = nil
	}
	if len(c.Profiles) == 0 {
		c.Profiles = nil
	}
	if c.Rules.Empty() {
		c.Rules = nil
	}
	data, err := json.Marshal(&c)
	if err != nil {
		return nil, err
	}
	// Normalize numbers and key order by a round trip.
	var v any
	err = json.Unmarshal(data, &v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// SignedPolicy returns the published signed group policy of a group, nil if
// there is none. It is not verified again: it was checked when published.
func SignedPolicy(g *Group) (*policy.GroupPolicy, error) {
	if len(g.Signed) == 0 {
		return nil, nil //nolint:nilnil // No signed policy is not an error.
	}
	return policy.ParseGroupPolicy(g.Signed)
}

// DraftDiffers tells whether the current settings of the group differ from
// its published signed group policy, i.e. whether there are changes that
// are not signed yet. It is true if there is no signed policy.
func DraftDiffers(g *Group) (bool, error) {
	signed, err := SignedPolicy(g)
	if err != nil || signed == nil {
		return true, err
	}
	a, err := contentJSON(ExportGroup(g))
	if err != nil {
		return true, err
	}
	b, err := contentJSON(signed)
	if err != nil {
		return true, err
	}
	return !bytes.Equal(a, b), nil
}

// Publish checks a signed group policy against the offline key of the
// server and makes it the policy of the group.
func (s *Server) Publish(name string, signed []byte) (*policy.GroupPolicy, error) {
	return PublishSigned(s.Store, s.Dir, name, signed, s.Now())
}

// PublishSigned checks a signed group policy against the offline key in the
// data directory and makes it the policy of the group in the store.
func PublishSigned(store *Store, dir, name string, signed []byte, now time.Time) (*policy.GroupPolicy, error) {
	if len(signed) > MaxSignedSize {
		return nil, fmt.Errorf("%w: %d bytes, at most %d", ErrSignedTooLarge, len(signed), MaxSignedSize)
	}
	keyText, err := ReadOfflineKey(dir)
	if err != nil {
		return nil, err
	}
	if keyText == "" {
		return nil, ErrNoOfflineKeySet
	}
	key, _, err := ParseOfflineKey(keyText)
	if err != nil {
		return nil, err
	}
	gp, err := policy.VerifyGroup(signed, key)
	if err != nil {
		return nil, err
	}
	if gp.Group != name {
		return nil, fmt.Errorf("%w: %q", ErrSignedGroup, gp.Group)
	}
	return gp, store.PublishGroup(name, signed, gp.Version, now)
}

// PublishGroup stores a verified signed group policy of a group. Its
// version must be higher than the one of the published policy.
func (s *Store) PublishGroup(name string, signed []byte, version uint64, now time.Time) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, err := s.group(name)
	if err != nil {
		return err
	}
	if version <= g.SignedVersion {
		return fmt.Errorf("%w: version %d, published %d", ErrSignedRollback, version, g.SignedVersion)
	}
	defer sqlitex.Save(s.conn)(&err)
	err = s.exec(`UPDATE groups SET signed = ?, signed_version = ?, signed_at = ?, updated = ? WHERE name = ?`,
		string(signed), int64(version), now.Unix(), now.Unix(), name) //nolint:gosec // Versions are Unix seconds.
	if err != nil {
		return err
	}
	return s.bumpSeq()
}

// scanSigned reads the signed columns of a group row.
func scanSigned(g *Group, stmt *sqlite.Stmt, col int) {
	if text := stmt.ColumnText(col); text != "" {
		g.Signed = []byte(text)
	}
	g.SignedVersion = uint64(stmt.ColumnInt64(col + 1)) //nolint:gosec // Stored from a uint64.
	if at := stmt.ColumnInt64(col + 2); at > 0 {
		g.SignedAt = time.Unix(at, 0).UTC()
	}
}
