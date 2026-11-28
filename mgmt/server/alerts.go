package server

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/safing/portmaster/mgmt/policy"
)

// Kinds of alerts. Condition alerts (silent to overridden) are resolved
// when the condition ends; event alerts (malware, new app) stay until an
// admin acknowledges them.
const (
	AlertSilent       = "silent"
	AlertInterception = "interception"
	AlertProblems     = "problems"
	AlertRefused      = "refused"
	AlertError        = "error"
	AlertOverridden   = "overridden"
	AlertMalware      = "malware"
	AlertNewApp       = "new-app"
)

// Levels of alerts, from low to high.
const (
	LevelInfo     = "info"
	LevelWarning  = "warning"
	LevelCritical = "critical"
)

// States of alerts. Open alerts are new or acknowledged.
const (
	StateNew          = "new"
	StateAcknowledged = "acknowledged"
	StateResolved     = "resolved"
	// StateOpen selects new and acknowledged alerts in an AlertFilter.
	StateOpen = "open"
	// StateAll selects all alerts in an AlertFilter.
	StateAll = "all"
)

// Events of the alert notifications.
const (
	EventRaised   = "raised"
	EventResolved = "resolved"
)

const (
	// MalwareList is the filter list category of malware; the clients add
	// the categories to the lists of a block summary.
	MalwareList = "MAL"
	// DefaultSilentAfter is the silent threshold of new groups.
	DefaultSilentAfter = 24 * time.Hour
	// DefaultAlertRetention is how long the server keeps resolved and
	// acknowledged alerts.
	DefaultAlertRetention = 90 * 24 * time.Hour
	// AppLearning is the time after the first app list of a computer in
	// which new apps raise no alert: the first lists only hold the apps
	// that happened to be used.
	AppLearning = 24 * time.Hour
	// maxAlertText limits the message of an alert.
	maxAlertText = 1000
)

var (
	// ErrBadApps is returned for an invalid app list.
	ErrBadApps = errors.New("invalid app list")
	// ErrBadLevel is returned for an unknown alert level.
	ErrBadLevel = errors.New("unknown alert level, use info, warning or critical")
	// ErrBadState is returned for an unknown alert state filter.
	ErrBadState = errors.New("unknown alert state, use open, new, acknowledged, resolved or all")
)

// conditionKinds are the alerts resolved when their condition ends.
var conditionKinds = []string{AlertSilent, AlertInterception, AlertProblems, AlertRefused, AlertError, AlertOverridden}

// AlertKinds are all kinds of alerts, for filters.
var AlertKinds = []string{
	AlertSilent, AlertInterception, AlertProblems, AlertRefused, AlertError, AlertOverridden,
	AlertMalware, AlertNewApp,
}

// AlertStates are the state filters of AlertFilter.
var AlertStates = []string{StateOpen, StateNew, StateAcknowledged, StateResolved, StateAll}

// Alert is an alert about a computer.
type Alert struct {
	ID       int64  `json:"id"`
	Computer string `json:"computer"`
	Hostname string `json:"hostname"`
	// Group is the current group of the computer.
	Group string `json:"group"`
	Kind  string `json:"kind"`
	// Subject tells alerts of the same kind apart, e.g. the domain of a
	// malware hit; empty for condition alerts.
	Subject string    `json:"subject,omitempty"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	// Count is the number of blocked connections of a malware alert, else 1.
	Count    int64     `json:"count"`
	State    string    `json:"state"`
	AckedBy  string    `json:"ackedBy,omitempty"`
	AckedAt  time.Time `json:"ackedAt,omitzero"`
	Resolved time.Time `json:"resolved,omitzero"`
}

// AlertEvent is a raised or resolved alert, for the notifications.
type AlertEvent struct {
	Event string `json:"event"`
	Alert Alert  `json:"alert"`
}

// LevelRank orders the levels; unknown levels are -1.
func LevelRank(level string) int {
	return slices.Index([]string{LevelInfo, LevelWarning, LevelCritical}, level)
}

// CheckLevel returns ErrBadLevel for an unknown level.
func CheckLevel(level string) error {
	if LevelRank(level) < 0 {
		return fmt.Errorf("%w: %q", ErrBadLevel, level)
	}
	return nil
}

// CheckApps checks the size and the fields of an app list.
func CheckApps(apps []policy.App) error {
	if len(apps) > policy.MaxApps {
		return fmt.Errorf("%w: %d entries, at most %d", ErrBadApps, len(apps), policy.MaxApps)
	}
	for _, a := range apps {
		if len(a.ID) != 32 || strings.Trim(a.ID, "0123456789abcdef") != "" || len(a.Name) > 255 {
			return fmt.Errorf("%w: entry %q", ErrBadApps, a.Name)
		}
	}
	return nil
}

// SetGroupSilentAfter sets the silent threshold of a group; zero turns the
// silent alert off. It is not part of the policy.
func (s *Store) SetGroupSilentAfter(name string, d time.Duration) error {
	if d < 0 {
		d = 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.exec(`UPDATE groups SET silent_after = ? WHERE name = ?`, int64(d/time.Second), name)
	if err != nil {
		return err
	}
	if s.conn.Changes() == 0 {
		return fmt.Errorf("group %s: %w", name, ErrNotFound)
	}
	return nil
}

func clip(s string) string {
	if len(s) <= maxAlertText {
		return s
	}
	cut := maxAlertText
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}

// raise opens an alert or updates the open one with the same computer,
// kind and subject. Event alerts only update a new one: after an admin
// acknowledged it, the next hit raises a new alert. add is added to the
// count. It returns the event of a new alert, else nil. The caller holds
// the lock.
func (s *Store) raise(computer, kind, subject, level, message string, add int64, now time.Time) (*AlertEvent, error) {
	states := []any{StateNew, StateAcknowledged}
	if !slices.Contains(conditionKinds, kind) {
		states = []any{StateNew, StateNew}
	}
	message = clip(message)
	var id int64
	err := sqlitex.Execute(s.conn, `UPDATE alerts SET last = ?, count = count + ?, message = ?, level = ?
		WHERE computer = ? AND kind = ? AND subject = ? AND state IN (?, ?) RETURNING id`, &sqlitex.ExecOptions{
		Args: append([]any{now.Unix(), add, message, level, computer, kind, subject}, states...),
		ResultFunc: func(stmt *sqlite.Stmt) error {
			id = stmt.ColumnInt64(0)
			return nil
		},
	})
	if err != nil || id != 0 {
		return nil, err
	}
	count := max(add, 1)
	err = sqlitex.Execute(s.conn, `INSERT INTO alerts (computer, kind, subject, level, message, first, last, count, state)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`, &sqlitex.ExecOptions{
		Args: []any{computer, kind, subject, level, message, now.Unix(), now.Unix(), count, StateNew},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			id = stmt.ColumnInt64(0)
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	a, err := s.alert(id)
	if err != nil {
		return nil, err
	}
	return &AlertEvent{Event: EventRaised, Alert: *a}, nil
}

// resolve resolves the open condition alerts of the kinds of a computer and
// returns their events. The caller holds the lock.
func (s *Store) resolve(computer string, now time.Time, kinds ...string) ([]AlertEvent, error) {
	var ids []int64
	for _, kind := range kinds {
		err := sqlitex.Execute(s.conn, `UPDATE alerts SET state = ?, resolved = ?
			WHERE computer = ? AND kind = ? AND state IN (?, ?) RETURNING id`, &sqlitex.ExecOptions{
			Args: []any{StateResolved, now.Unix(), computer, kind, StateNew, StateAcknowledged},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				ids = append(ids, stmt.ColumnInt64(0))
				return nil
			},
		})
		if err != nil {
			return nil, err
		}
	}
	events := make([]AlertEvent, 0, len(ids))
	for _, id := range ids {
		a, err := s.alert(id)
		if err != nil {
			return nil, err
		}
		events = append(events, AlertEvent{Event: EventResolved, Alert: *a})
	}
	return events, nil
}

// condition raises the alert if on, else resolves it. The caller holds the
// lock.
func (s *Store) condition(events []AlertEvent, on bool, computer, kind, level, message string, now time.Time) ([]AlertEvent, error) {
	if !on {
		resolved, err := s.resolve(computer, now, kind)
		return append(events, resolved...), err
	}
	ev, err := s.raise(computer, kind, "", level, message, 0, now)
	if ev != nil {
		events = append(events, *ev)
	}
	return events, err
}

// EvaluateReport raises and resolves the alerts of a stored report of the
// computer and records its apps. It returns the events for the
// notifications.
func (s *Store) EvaluateReport(c *Computer, r *policy.Report, now time.Time) (events []AlertEvent, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer sqlitex.Save(s.conn)(&err)

	st := ReportStatus(&Computer{Report: r})
	events, err = s.condition(events, st != nil && !st.Interception, c.ID, AlertInterception, LevelCritical,
		"Network interception is off: the Portmaster does not filter connections.", now)
	if err != nil {
		return nil, err
	}
	// Errors and a core that is not ready are warnings; module warnings
	// alone, e.g. while the filter lists are downloaded after the start,
	// are info.
	var problems []string
	problemLevel := LevelInfo
	if st != nil {
		if !st.Ready {
			problems = append(problems, "not ready")
			problemLevel = LevelWarning
		}
		for _, p := range st.Problems {
			if p.Type != "warning" {
				problemLevel = LevelWarning
			}
			if p.Message != "" {
				problems = append(problems, p.Type+": "+p.Message)
			} else {
				problems = append(problems, p.Type)
			}
		}
	}
	events, err = s.condition(events, len(problems) > 0, c.ID, AlertProblems, problemLevel,
		"Portmaster problems: "+strings.Join(problems, "; "), now)
	if err != nil {
		return nil, err
	}
	events, err = s.condition(events, len(r.Refused) > 0, c.ID, AlertRefused, LevelWarning,
		"Policy settings refused: "+strings.Join(r.Refused, ", "), now)
	if err != nil {
		return nil, err
	}
	events, err = s.condition(events, r.Error != "", c.ID, AlertError, LevelWarning,
		"Policy not applied: "+r.Error, now)
	if err != nil {
		return nil, err
	}
	events, err = s.condition(events, len(r.Overridden) > 0, c.ID, AlertOverridden, LevelInfo,
		"Policy defaults changed locally: "+strings.Join(r.Overridden, ", "), now)
	if err != nil {
		return nil, err
	}

	for _, b := range r.Blocks {
		if !slices.Contains(strings.Split(b.Lists, ","), MalwareList) {
			continue
		}
		dir := "to"
		if b.Inbound {
			dir = "from"
		}
		msg := fmt.Sprintf("%s: connection %s %s blocked by a malware list (%s)", b.App, dir, b.Target, b.Lists)
		ev, err := s.raise(c.ID, AlertMalware, b.App+" "+b.Target, LevelCritical, msg, int64(b.Count), now)
		if err != nil {
			return nil, err
		}
		if ev != nil {
			events = append(events, *ev)
		}
	}

	newApps, err := s.addApps(c.ID, r.Apps, now)
	if err != nil {
		return nil, err
	}
	for _, a := range newApps {
		ev, err := s.raise(c.ID, AlertNewApp, a.ID, LevelInfo, "New app with network access: "+a.Name, 0, now)
		if err != nil {
			return nil, err
		}
		if ev != nil {
			events = append(events, *ev)
		}
	}
	return events, nil
}

// addApps records the apps of a computer and returns the ones that are new
// after the learning period. The caller holds the lock.
func (s *Store) addApps(computer string, apps []policy.App, now time.Time) ([]policy.App, error) {
	if len(apps) == 0 {
		return nil, nil
	}
	var first int64
	err := sqlitex.Execute(s.conn, `SELECT IFNULL(MIN(first), 0) FROM apps WHERE computer = ?`, &sqlitex.ExecOptions{
		Args: []any{computer},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			first = stmt.ColumnInt64(0)
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	learning := first == 0 || now.Sub(time.Unix(first, 0)) < AppLearning
	var added []policy.App
	for _, a := range apps {
		err = s.exec(`INSERT INTO apps (computer, id, name, first, last) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (computer, id) DO NOTHING`, computer, a.ID, a.Name, now.Unix(), now.Unix())
		if err != nil {
			return nil, err
		}
		if s.conn.Changes() > 0 {
			if !learning {
				added = append(added, a)
			}
			continue
		}
		err = s.exec(`UPDATE apps SET name = ?, last = ? WHERE computer = ? AND id = ?`, a.Name, now.Unix(), computer, a.ID)
		if err != nil {
			return nil, err
		}
	}
	return added, nil
}

// KnownApp is an app a computer reported.
type KnownApp struct {
	ID    string
	Name  string
	First time.Time
	Last  time.Time
}

// Apps returns the apps a computer reported, sorted by name.
func (s *Store) Apps(computer string) ([]*KnownApp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var list []*KnownApp
	err := sqlitex.Execute(s.conn, `SELECT id, name, first, last FROM apps WHERE computer = ? ORDER BY name, id`, &sqlitex.ExecOptions{
		Args: []any{computer},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			list = append(list, &KnownApp{
				ID:    stmt.ColumnText(0),
				Name:  stmt.ColumnText(1),
				First: time.Unix(stmt.ColumnInt64(2), 0).UTC(),
				Last:  time.Unix(stmt.ColumnInt64(3), 0).UTC(),
			})
			return nil
		},
	})
	return list, err
}

// CheckSilent raises the silent alerts of the computers without contact for
// the threshold of their group and resolves the others. Revoked computers
// get their condition alerts resolved.
func (s *Store) CheckSilent(now time.Time) (events []AlertEvent, err error) {
	computers, err := s.Computers()
	if err != nil {
		return nil, err
	}
	groups, err := s.Groups()
	if err != nil {
		return nil, err
	}
	thresholds := make(map[string]time.Duration, len(groups))
	for _, g := range groups {
		thresholds[g.Name] = g.SilentAfter
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	defer sqlitex.Save(s.conn)(&err)
	for _, c := range computers {
		if c.Revoked {
			resolved, err := s.resolve(c.ID, now, conditionKinds...)
			if err != nil {
				return nil, err
			}
			events = append(events, resolved...)
			continue
		}
		limit := thresholds[c.Group]
		last := LastContact(c)
		silent := limit > 0 && now.Sub(last) > limit
		msg := fmt.Sprintf("No contact since %s (%s).", last.UTC().Format("2006-01-02 15:04 MST"),
			now.Sub(last).Truncate(time.Minute))
		events, err = s.condition(events, silent, c.ID, AlertSilent, LevelWarning, msg, now)
		if err != nil {
			return nil, err
		}
	}
	return events, nil
}

// AckAlerts acknowledges new alerts and returns the IDs of the ones that
// changed.
func (s *Store) AckAlerts(ids []int64, by string, now time.Time) ([]int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var acked []int64
	for _, id := range ids {
		err := s.exec(`UPDATE alerts SET state = ?, acked_by = ?, acked_at = ? WHERE id = ? AND state = ?`,
			StateAcknowledged, by, now.Unix(), id, StateNew)
		if err != nil {
			return acked, err
		}
		if s.conn.Changes() > 0 {
			acked = append(acked, id)
		}
	}
	return acked, nil
}

// PruneAlerts deletes resolved alerts and acknowledged event alerts last
// changed before the given time and returns their number.
func (s *Store) PruneAlerts(before time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.exec(`DELETE FROM alerts WHERE last < ? AND (state = ? OR (state = ? AND kind IN (?, ?)))`,
		before.Unix(), StateResolved, StateAcknowledged, AlertMalware, AlertNewApp)
	if err != nil {
		return 0, err
	}
	return s.conn.Changes(), nil
}

// AlertFilter selects alerts; empty fields match everything.
type AlertFilter struct {
	// State is one of AlertStates; empty means open.
	State    string
	Computer string
	Group    string
	Kind     string
	// MinLevel selects alerts of this level and above.
	MinLevel string
	Limit    int
}

const alertColumns = `a.id, a.computer, c.hostname, c.grp, a.kind, a.subject, a.level, a.message,
	a.first, a.last, a.count, a.state, a.acked_by, a.acked_at, a.resolved`

func scanAlert(stmt *sqlite.Stmt) *Alert {
	a := &Alert{
		ID:       stmt.ColumnInt64(0),
		Computer: stmt.ColumnText(1),
		Hostname: stmt.ColumnText(2),
		Group:    stmt.ColumnText(3),
		Kind:     stmt.ColumnText(4),
		Subject:  stmt.ColumnText(5),
		Level:    stmt.ColumnText(6),
		Message:  stmt.ColumnText(7),
		First:    time.Unix(stmt.ColumnInt64(8), 0).UTC(),
		Last:     time.Unix(stmt.ColumnInt64(9), 0).UTC(),
		Count:    stmt.ColumnInt64(10),
		State:    stmt.ColumnText(11),
		AckedBy:  stmt.ColumnText(12),
	}
	if t := stmt.ColumnInt64(13); t > 0 {
		a.AckedAt = time.Unix(t, 0).UTC()
	}
	if t := stmt.ColumnInt64(14); t > 0 {
		a.Resolved = time.Unix(t, 0).UTC()
	}
	return a
}

// alert returns an alert by ID. The caller holds the lock.
func (s *Store) alert(id int64) (*Alert, error) {
	var a *Alert
	err := sqlitex.Execute(s.conn, `SELECT `+alertColumns+` FROM alerts a JOIN computers c ON c.id = a.computer WHERE a.id = ?`,
		&sqlitex.ExecOptions{
			Args: []any{id},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				a = scanAlert(stmt)
				return nil
			},
		})
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, fmt.Errorf("alert %d: %w", id, ErrNotFound)
	}
	return a, nil
}

// Alerts returns the selected alerts, the last changed first.
func (s *Store) Alerts(f AlertFilter) ([]*Alert, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.State == "" {
		f.State = StateOpen
	}
	if !slices.Contains(AlertStates, f.State) {
		return nil, fmt.Errorf("%w: %q", ErrBadState, f.State)
	}
	minRank := 0
	if f.MinLevel != "" {
		err := CheckLevel(f.MinLevel)
		if err != nil {
			return nil, err
		}
		minRank = LevelRank(f.MinLevel)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var list []*Alert
	err := sqlitex.Execute(s.conn, `SELECT `+alertColumns+`
		FROM alerts a JOIN computers c ON c.id = a.computer
		WHERE (:state = 'all' OR a.state = :state OR (:state = 'open' AND a.state IN ('new', 'acknowledged')))
			AND (:computer = '' OR a.computer = :computer)
			AND (:group = '' OR c.grp = :group)
			AND (:kind = '' OR a.kind = :kind)
			AND (CASE a.level WHEN 'critical' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END) >= :rank
		ORDER BY a.last DESC, a.id DESC
		LIMIT :limit`, &sqlitex.ExecOptions{
		Named: map[string]any{
			":state":    f.State,
			":computer": f.Computer,
			":group":    f.Group,
			":kind":     f.Kind,
			":rank":     minRank,
			":limit":    f.Limit,
		},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			list = append(list, scanAlert(stmt))
			return nil
		},
	})
	return list, err
}

// AlertCounts returns the number of new and of open alerts per level.
type AlertCounts struct {
	New      int
	Open     int
	Critical int
	Warning  int
	Info     int
}

// CountAlerts counts the open alerts.
func (s *Store) CountAlerts() (*AlertCounts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := &AlertCounts{}
	err := sqlitex.Execute(s.conn, `SELECT state, level, COUNT(*) FROM alerts WHERE state IN (?, ?) GROUP BY state, level`,
		&sqlitex.ExecOptions{
			Args: []any{StateNew, StateAcknowledged},
			ResultFunc: func(stmt *sqlite.Stmt) error {
				count := stmt.ColumnInt(2)
				n.Open += count
				if stmt.ColumnText(0) == StateNew {
					n.New += count
				}
				switch stmt.ColumnText(1) {
				case LevelCritical:
					n.Critical += count
				case LevelWarning:
					n.Warning += count
				default:
					n.Info += count
				}
				return nil
			},
		})
	return n, err
}
