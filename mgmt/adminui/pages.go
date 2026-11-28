package adminui

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/safing/portmaster/mgmt/server"
)

const (
	navDashboard = "Dashboard"
	navComputers = "Computers"
	navGroups    = "Groups"
	navTokens    = "Tokens"
	navAudit     = "Audit log"

	auditDefault = 200
	auditMax     = 2000
)

type navItem struct {
	Title string
	Path  string
}

var templateFuncs = template.FuncMap{
	"navItems": func() []navItem {
		return []navItem{
			{navDashboard, "/"},
			{navAlerts, alertsPath},
			{navComputers, "/computers"},
			{navGroups, "/groups"},
			{navTokens, "/tokens"},
			{navBlocks, "/blocks"},
			{navAudit, "/audit"},
		}
	},
	"datetime": func(t time.Time) string {
		if t.IsZero() || t.Unix() == 0 {
			return "never"
		}
		return t.UTC().Format(time.DateTime) + " UTC"
	},
	"ago":        ago,
	"alertTable": newAlertTable,
	"duration":   shortDuration,
	"splitLists": func(lists string) []string {
		if lists == "" {
			return nil
		}
		return strings.Split(lists, ",")
	},
	"json": func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(b)
	},
	"prettyJSON": func(raw json.RawMessage) string {
		var v any
		if json.Unmarshal(raw, &v) != nil {
			return string(raw)
		}
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return string(raw)
		}
		return string(b)
	},
	"pathEscape": url.PathEscape,
	"slice100":   func() []int { return []int{100, auditDefault, 500, 1000, auditMax} },
}

// ago tells how long ago t was, in a coarse unit.
func ago(now, t time.Time) string {
	if t.IsZero() || t.Unix() == 0 {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < 0:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

// computerRow is a computer with its derived state.
type computerRow struct {
	*server.Computer

	Policy string
	Health string
	Silent bool
	// Attention lists why the computer needs a look; empty if it is fine.
	Attention []string
}

func (row *computerRow) OK() bool { return len(row.Attention) == 0 }

// State is "revoked", "silent" or "active".
func (row *computerRow) State() string {
	switch {
	case row.Revoked:
		return "revoked"
	case row.Silent:
		return "silent"
	default:
		return "active"
	}
}

func newComputerRow(c *server.Computer, g *server.Group, now time.Time) *computerRow {
	row := &computerRow{Computer: c, Policy: server.PolicyState(c, g), Health: server.Health(c), Silent: server.Silent(c, now)}
	if c.Revoked {
		return row
	}
	if row.Silent {
		row.Attention = append(row.Attention, "silent since "+ago(now, server.LastContact(c)))
	}
	switch row.Policy {
	case server.PolicyError:
		row.Attention = append(row.Attention, "policy error: "+c.Report.Error)
	case server.PolicyNoReport:
		row.Attention = append(row.Attention, "no report yet")
	case server.PolicyPending:
		// The next pull brings the change; only a long wait is a problem.
		if g != nil && now.Sub(server.PolicyChanged(c, g)) > server.SilentAfter {
			row.Attention = append(row.Attention, "policy change not applied since "+ago(now, server.PolicyChanged(c, g)))
		}
	}
	// Overridden defaults are allowed and only shown in the health.
	if st := server.ReportStatus(c); st != nil {
		if !st.Ready {
			row.Attention = append(row.Attention, "not ready")
		}
		if !st.Interception {
			row.Attention = append(row.Attention, "no interception")
		}
		if n := len(st.Problems); n > 0 {
			row.Attention = append(row.Attention, fmt.Sprintf("%d problem(s)", n))
		}
	}
	if c.Report != nil && len(c.Report.Refused) > 0 {
		row.Attention = append(row.Attention, fmt.Sprintf("%d policy setting(s) refused", len(c.Report.Refused)))
	}
	return row
}

// loadComputers returns all computers with their state and the groups by name.
func (ui *UI) loadComputers() ([]*computerRow, map[string]*server.Group, error) {
	groups, err := ui.store.Groups()
	if err != nil {
		return nil, nil, err
	}
	byName := make(map[string]*server.Group, len(groups))
	for _, g := range groups {
		byName[g.Name] = g
	}
	list, err := ui.store.Computers()
	if err != nil {
		return nil, nil, err
	}
	now := ui.now()
	rows := make([]*computerRow, 0, len(list))
	for _, c := range list {
		rows = append(rows, newComputerRow(c, byName[c.Group], now))
	}
	return rows, byName, nil
}

func (ui *UI) internalError(w http.ResponseWriter, what string, err error) {
	ui.log.Error(what, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func (ui *UI) notFound(w http.ResponseWriter, r *http.Request, nav, msg string) {
	sess := ui.currentSession(r)
	ui.render(w, http.StatusNotFound, "message", &page{Title: "Not found", Nav: nav, Admin: sess.Admin, CSRF: sess.CSRF, Error: msg})
}

func (ui *UI) sessionPage(r *http.Request, title, nav string, data any) *page {
	sess := ui.currentSession(r)
	return &page{Title: title, Nav: nav, Admin: sess.Admin, CSRF: sess.CSRF, Data: data, Notice: notices[r.URL.Query().Get("msg")]}
}

// --- Dashboard ---

type dashboardData struct {
	Active    int
	Silent    int
	Revoked   int
	Current   int
	Groups    int
	Tokens    int
	Admins    int
	Attention []*computerRow
	Recent    []*server.AuditEntry
	Alerts    []*server.Alert
	Counts    *server.AlertCounts
}

func (ui *UI) handleDashboard(w http.ResponseWriter, r *http.Request) {
	rows, groups, err := ui.loadComputers()
	if err != nil {
		ui.internalError(w, "dashboard", err)
		return
	}
	now := ui.now()
	data := &dashboardData{Groups: len(groups)}
	for _, row := range rows {
		switch {
		case row.Revoked:
			data.Revoked++
			continue
		case row.Silent:
			data.Silent++
		default:
			data.Active++
		}
		if row.Policy == server.PolicyCurrent {
			data.Current++
		}
		if !row.OK() {
			data.Attention = append(data.Attention, row)
		}
	}
	tokens, err := ui.store.Tokens()
	if err != nil {
		ui.internalError(w, "dashboard", err)
		return
	}
	for _, t := range tokens {
		if t.Status(now) == "valid" {
			data.Tokens++
		}
	}
	admins, err := ui.store.Admins()
	if err != nil {
		ui.internalError(w, "dashboard", err)
		return
	}
	data.Admins = len(admins)
	data.Recent, err = ui.store.AuditLog(time.Time{}, 10)
	if err != nil {
		ui.internalError(w, "dashboard", err)
		return
	}
	data.Counts, err = ui.store.CountAlerts()
	if err != nil {
		ui.internalError(w, "dashboard", err)
		return
	}
	data.Alerts, err = ui.openAlerts(server.AlertFilter{})
	if err != nil {
		ui.internalError(w, "dashboard", err)
		return
	}
	ui.render(w, http.StatusOK, "dashboard", ui.sessionPage(r, navDashboard, navDashboard, data))
}

// --- Computers ---

type computersData struct {
	Rows   []*computerRow
	Total  int
	Groups []string
	Group  string
	Filter string
}

func (ui *UI) handleComputers(w http.ResponseWriter, r *http.Request) {
	rows, groups, err := ui.loadComputers()
	if err != nil {
		ui.internalError(w, "computers", err)
		return
	}
	q := r.URL.Query()
	data := &computersData{Total: len(rows), Group: q.Get("group"), Filter: q.Get("show")}
	for name := range groups {
		data.Groups = append(data.Groups, name)
	}
	slices.Sort(data.Groups)
	for _, row := range rows {
		if data.Group != "" && row.Group != data.Group {
			continue
		}
		switch data.Filter {
		case "attention":
			if row.OK() || row.Revoked {
				continue
			}
		case "revoked":
			if !row.Revoked {
				continue
			}
		default:
			data.Filter = ""
		}
		data.Rows = append(data.Rows, row)
	}
	ui.render(w, http.StatusOK, "computers", ui.sessionPage(r, navComputers, navComputers, data))
}

type computerData struct {
	*computerRow

	Status      *server.CoreStatus
	OtherGroups []string
	// BlockSummary tells whether the group of the computer asks for it.
	BlockSummary bool
	Blocks       []*server.BlockRow
	Alerts       []*server.Alert
}

func (ui *UI) handleComputer(w http.ResponseWriter, r *http.Request) {
	c, err := ui.store.Computer(r.PathValue("id"))
	if errors.Is(err, server.ErrNotFound) {
		ui.notFound(w, r, navComputers, "There is no computer with this ID.")
		return
	}
	if err != nil {
		ui.internalError(w, "computer", err)
		return
	}
	g, err := ui.store.Group(c.Group)
	if err != nil && !errors.Is(err, server.ErrNotFound) {
		ui.internalError(w, "computer", err)
		return
	}
	data := &computerData{computerRow: newComputerRow(c, g, ui.now()), Status: server.ReportStatus(c)}
	data.BlockSummary = g != nil && g.BlockSummary
	data.Blocks, err = ui.recent(server.BlockFilter{Computer: c.ID})
	if err != nil {
		ui.internalError(w, "computer", err)
		return
	}
	data.Alerts, err = ui.openAlerts(server.AlertFilter{Computer: c.ID})
	if err != nil {
		ui.internalError(w, "computer", err)
		return
	}
	groups, err := ui.store.Groups()
	if err != nil {
		ui.internalError(w, "computer", err)
		return
	}
	for _, other := range groups {
		if other.Name != c.Group {
			data.OtherGroups = append(data.OtherGroups, other.Name)
		}
	}
	title := c.Hostname
	if title == "" {
		title = c.ID
	}
	ui.render(w, http.StatusOK, "computer", ui.sessionPage(r, title, navComputers, data))
}

// --- Groups ---

type groupRow struct {
	*server.Group

	Computers int
}

func (ui *UI) handleGroups(w http.ResponseWriter, r *http.Request) {
	ui.renderGroups(w, r, http.StatusOK, "", "")
}

type groupsData struct {
	Groups []*groupRow
	// NewName is the submitted name after a failed create.
	NewName string
}

func (ui *UI) renderGroups(w http.ResponseWriter, r *http.Request, status int, errMsg, newName string) {
	rows, groups, err := ui.loadComputers()
	if err != nil {
		ui.internalError(w, "groups", err)
		return
	}
	count := make(map[string]int)
	for _, row := range rows {
		if !row.Revoked {
			count[row.Group]++
		}
	}
	list := make([]*groupRow, 0, len(groups))
	for _, g := range groups {
		list = append(list, &groupRow{Group: g, Computers: count[g.Name]})
	}
	slices.SortFunc(list, func(a, b *groupRow) int { return strings.Compare(a.Name, b.Name) })
	p := ui.sessionPage(r, navGroups, navGroups, &groupsData{Groups: list, NewName: newName})
	p.Error = errMsg
	ui.render(w, status, "groups", p)
}

type settingRow struct {
	Key    string
	Value  any
	Locked bool
}

type profileRow struct {
	Name     string
	Settings int
	JSON     json.RawMessage
}

type groupData struct {
	*server.Group

	Form        *groupForm
	OtherGroups []string
	Settings    []settingRow
	Profiles    []profileRow
	Computers   []*computerRow
	Blocks      []*server.BlockRow
	Alerts      []*server.Alert
}

func (ui *UI) handleGroup(w http.ResponseWriter, r *http.Request) {
	ui.renderGroup(w, r, http.StatusOK, "", nil)
}

// renderGroup shows the group of the path; with an error it shows the
// message and the submitted form instead of the stored values.
func (ui *UI) renderGroup(w http.ResponseWriter, r *http.Request, status int, errMsg string, form *groupForm) {
	g, err := ui.store.Group(r.PathValue("name"))
	if errors.Is(err, server.ErrNotFound) {
		ui.notFound(w, r, navGroups, "There is no group with this name.")
		return
	}
	if err != nil {
		ui.internalError(w, "group", err)
		return
	}
	if form == nil {
		form, err = newGroupForm(g)
		if err != nil {
			ui.internalError(w, "group", err)
			return
		}
	}
	data := &groupData{Group: g, Form: form}
	for key, value := range g.Settings {
		data.Settings = append(data.Settings, settingRow{Key: key, Value: value, Locked: slices.Contains(g.Locked, key)})
	}
	slices.SortFunc(data.Settings, func(a, b settingRow) int { return strings.Compare(a.Key, b.Key) })
	for _, raw := range g.Profiles {
		var p struct {
			Name   string         `json:"name"`
			Config map[string]any `json:"config"`
		}
		_ = json.Unmarshal(raw, &p)
		data.Profiles = append(data.Profiles, profileRow{Name: p.Name, Settings: len(p.Config), JSON: raw})
	}
	rows, _, err := ui.loadComputers()
	if err != nil {
		ui.internalError(w, "group", err)
		return
	}
	for _, row := range rows {
		if row.Group == g.Name {
			data.Computers = append(data.Computers, row)
		}
	}
	data.Blocks, err = ui.recent(server.BlockFilter{Group: g.Name})
	if err != nil {
		ui.internalError(w, "group", err)
		return
	}
	data.Alerts, err = ui.openAlerts(server.AlertFilter{Group: g.Name})
	if err != nil {
		ui.internalError(w, "group", err)
		return
	}
	groups, err := ui.store.Groups()
	if err != nil {
		ui.internalError(w, "group", err)
		return
	}
	for _, other := range groups {
		if other.Name != g.Name {
			data.OtherGroups = append(data.OtherGroups, other.Name)
		}
	}
	p := ui.sessionPage(r, "Group "+g.Name, navGroups, data)
	p.Error = errMsg
	ui.render(w, status, "group", p)
}

// --- Tokens ---

type tokenRow struct {
	*server.Token

	Status string
}

func (ui *UI) handleTokens(w http.ResponseWriter, r *http.Request) {
	ui.renderTokens(w, r, http.StatusOK, "", nil)
}

type tokensData struct {
	Tokens    []*tokenRow
	Groups    []string
	New       *newToken
	ClientURL string
	// Selected is the group preselected in the form.
	Selected string
}

func (ui *UI) renderTokens(w http.ResponseWriter, r *http.Request, status int, errMsg string, created *newToken) {
	tokens, err := ui.store.Tokens()
	if err != nil {
		ui.internalError(w, "tokens", err)
		return
	}
	groups, err := ui.store.Groups()
	if err != nil {
		ui.internalError(w, "tokens", err)
		return
	}
	now := ui.now()
	data := &tokensData{New: created, ClientURL: ui.cfg.ClientURL, Selected: r.URL.Query().Get("group")}
	if created != nil {
		data.Selected = created.Group
	} else if g := r.PostFormValue("group"); g != "" {
		data.Selected = g
	}
	for _, t := range tokens {
		data.Tokens = append(data.Tokens, &tokenRow{Token: t, Status: t.Status(now)})
	}
	for _, g := range groups {
		data.Groups = append(data.Groups, g.Name)
	}
	p := ui.sessionPage(r, navTokens, navTokens, data)
	p.Error = errMsg
	ui.render(w, status, "tokens", p)
}

// --- Audit log ---

type auditData struct {
	Entries []*server.AuditEntry
	Query   string
	Limit   int
	More    bool
}

func (ui *UI) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data := &auditData{Query: strings.TrimSpace(q.Get("q")), Limit: auditDefault}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 { //nolint:noinlineerr // Optional parameter.
		data.Limit = min(n, auditMax)
	}
	// Filter over the newest auditMax entries.
	entries, err := ui.store.AuditLog(time.Time{}, auditMax)
	if err != nil {
		ui.internalError(w, "audit log", err)
		return
	}
	needle := strings.ToLower(data.Query)
	for _, e := range entries {
		if needle != "" && !strings.Contains(strings.ToLower(e.Actor+" "+e.Action+" "+e.Object+" "+e.Detail), needle) {
			continue
		}
		if len(data.Entries) == data.Limit {
			data.More = true
			break
		}
		data.Entries = append(data.Entries, e)
	}
	ui.render(w, http.StatusOK, "audit", ui.sessionPage(r, navAudit, navAudit, data))
}
