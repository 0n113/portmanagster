package adminui

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/safing/portmaster/mgmt/server"
)

const (
	navAlerts  = "Alerts"
	alertsPath = "/alerts"
	// recentAlerts is the number of open alerts on the dashboard and the
	// computer page.
	recentAlerts = 10
	maxAlertRows = 500
)

// alertTable is the data of the "alerttable" partial.
type alertTable struct {
	Page   *page
	Alerts []*server.Alert
	// Back is the local path the acknowledge form returns to.
	Back string
}

func newAlertTable(p *page, alerts []*server.Alert, back string) *alertTable {
	return &alertTable{Page: p, Alerts: alerts, Back: back}
}

// NewIDs returns the IDs of the new alerts, for the "acknowledge all" form.
func (t *alertTable) NewIDs() []int64 {
	var ids []int64
	for _, a := range t.Alerts {
		if a.State == server.StateNew {
			ids = append(ids, a.ID)
		}
	}
	return ids
}

type alertsData struct {
	Filter    server.AlertFilter
	States    []string
	Kinds     []string
	Levels    []string
	Groups    []string
	Computers []*server.Computer
	Alerts    []*server.Alert
	More      bool
	// Back is this page with its filter, for the acknowledge forms.
	Back string
}

func (ui *UI) handleAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data := &alertsData{
		Filter: server.AlertFilter{
			State:    q.Get("state"),
			Group:    q.Get("group"),
			Computer: q.Get("computer"),
			Kind:     q.Get("kind"),
			MinLevel: q.Get("level"),
			Limit:    100,
		},
		States: server.AlertStates,
		Kinds:  server.AlertKinds,
		Levels: []string{server.LevelInfo, server.LevelWarning, server.LevelCritical},
		Back:   alertsPath,
	}
	if data.Filter.State == "" {
		data.Filter.State = server.StateOpen
	}
	back := r.URL.Query()
	back.Del("msg")
	if len(back) > 0 {
		data.Back += "?" + back.Encode()
	}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 { //nolint:noinlineerr // Optional parameter.
		data.Filter.Limit = min(n, maxAlertRows)
	}
	groups, err := ui.store.Groups()
	if err != nil {
		ui.internalError(w, "alerts", err)
		return
	}
	for _, g := range groups {
		data.Groups = append(data.Groups, g.Name)
	}
	data.Computers, err = ui.store.Computers()
	if err != nil {
		ui.internalError(w, "alerts", err)
		return
	}
	f := data.Filter
	f.Limit++
	data.Alerts, err = ui.store.Alerts(f)
	if errors.Is(err, server.ErrBadState) || errors.Is(err, server.ErrBadLevel) {
		p := ui.sessionPage(r, navAlerts, navAlerts, data)
		p.Error = err.Error()
		ui.render(w, http.StatusBadRequest, "alerts", p)
		return
	}
	if err != nil {
		ui.internalError(w, "alerts", err)
		return
	}
	if len(data.Alerts) > data.Filter.Limit {
		data.Alerts, data.More = data.Alerts[:data.Filter.Limit], true
	}
	ui.render(w, http.StatusOK, "alerts", ui.sessionPage(r, navAlerts, navAlerts, data))
}

// openAlerts returns the latest open alerts of a filter.
func (ui *UI) openAlerts(f server.AlertFilter) ([]*server.Alert, error) {
	f.State = server.StateOpen
	f.Limit = recentAlerts
	return ui.store.Alerts(f)
}

// shortDuration formats a duration as "24h", "90m" or "off" for zero.
func shortDuration(d time.Duration) string {
	if d <= 0 {
		return "off"
	}
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// localPath returns back if it is a path on this server, else "/alerts".
func localPath(back string) string {
	if !strings.HasPrefix(back, "/") || strings.HasPrefix(back, "//") || strings.ContainsAny(back, "\\\r\n") {
		return alertsPath
	}
	return back
}

func (ui *UI) handleAlertAck(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	var ids []int64
	for _, v := range r.PostForm["id"] {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			http.Error(w, "bad alert ID", http.StatusBadRequest)
			return
		}
		ids = append(ids, id)
	}
	acked, err := ui.store.AckAlerts(ids, ui.actor(r), ui.now())
	if err != nil {
		ui.internalError(w, "acknowledge alerts", err)
		return
	}
	for _, id := range acked {
		ui.audit(r, "alert.ack", strconv.FormatInt(id, 10), "")
	}
	back := localPath(r.PostFormValue("back"))
	sep := "?"
	if strings.Contains(back, "?") {
		sep = "&"
	}
	// back is a local path checked above, the message a fixed key.
	http.Redirect(w, r, back+sep+"msg=alerts-acked", http.StatusSeeOther) //nolint:gosec // See above.
}

func (ui *UI) handleGroupSilentAfter(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	d, err := time.ParseDuration(strings.TrimSpace(r.PostFormValue("after")))
	if err != nil || d < 0 {
		ui.renderGroup(w, r, http.StatusBadRequest, "Invalid duration: use e.g. 24h, 90m, or 0 to turn the alert off.", nil)
		return
	}
	err = ui.store.SetGroupSilentAfter(name, d)
	if errors.Is(err, server.ErrNotFound) {
		ui.notFound(w, r, navGroups, "There is no group with this name.")
		return
	}
	if err != nil {
		ui.internalError(w, "set silent threshold", err)
		return
	}
	ui.audit(r, "group.silentafter", name, d.String())
	redirect(w, r, groupPath(name), "silent-after-saved")
}
