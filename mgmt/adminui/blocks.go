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
	navBlocks = "Blocks"
	// recentBlocks is the number of rows on the computer and group pages.
	recentBlocks = 20
	// recentPeriod is the period of the rows on the computer and group pages.
	recentPeriod = 24 * time.Hour
	maxBlockRows = 500
)

// blockPeriods are the periods the blocks page offers.
var blockPeriods = []struct {
	Value string
	Label string
	D     time.Duration
}{
	{"1h", "1 hour", time.Hour},
	{"24h", "24 hours", 24 * time.Hour},
	{"168h", "7 days", 7 * 24 * time.Hour},
	{"720h", "30 days", 30 * 24 * time.Hour},
}

type blocksData struct {
	Filter    server.BlockFilter
	Period    string
	Periods   any
	Groups    []string
	Computers []*server.Computer
	Rows      []*server.BlockRow
	More      bool
}

func (ui *UI) handleBlocks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data := &blocksData{
		Filter: server.BlockFilter{
			Group:    q.Get("group"),
			Computer: q.Get("computer"),
			App:      strings.TrimSpace(q.Get("app")),
			List:     strings.TrimSpace(q.Get("list")),
			Target:   strings.TrimSpace(q.Get("target")),
			Limit:    100,
		},
		Period:  "24h",
		Periods: blockPeriods,
	}
	period := recentPeriod
	for _, p := range blockPeriods {
		if p.Value == q.Get("period") {
			data.Period, period = p.Value, p.D
		}
	}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 { //nolint:noinlineerr // Optional parameter.
		data.Filter.Limit = min(n, maxBlockRows)
	}
	data.Filter.Since = ui.now().Add(-period)

	groups, err := ui.store.Groups()
	if err != nil {
		ui.internalError(w, "blocks", err)
		return
	}
	for _, g := range groups {
		data.Groups = append(data.Groups, g.Name)
	}
	data.Computers, err = ui.store.Computers()
	if err != nil {
		ui.internalError(w, "blocks", err)
		return
	}
	// One more row tells whether there are more.
	f := data.Filter
	f.Limit++
	data.Rows, err = ui.store.Blocks(f)
	if err != nil {
		ui.internalError(w, "blocks", err)
		return
	}
	if len(data.Rows) > data.Filter.Limit {
		data.Rows, data.More = data.Rows[:data.Filter.Limit], true
	}
	ui.render(w, http.StatusOK, "blocks", ui.sessionPage(r, navBlocks, navBlocks, data))
}

// recent returns the largest blocks of the last recentPeriod.
func (ui *UI) recent(f server.BlockFilter) ([]*server.BlockRow, error) {
	f.Since = ui.now().Add(-recentPeriod)
	f.Limit = recentBlocks
	return ui.store.Blocks(f)
}

func (ui *UI) handleGroupBlockSummary(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	on := r.PostFormValue("on") == "1"
	err := ui.store.SetGroupBlockSummary(name, on, ui.now())
	if errors.Is(err, server.ErrNotFound) {
		ui.notFound(w, r, navGroups, "There is no group with this name.")
		return
	}
	if err != nil {
		ui.internalError(w, "set block summary", err)
		return
	}
	state, msg := "off", "block-summary-off"
	if on {
		state, msg = "on", "block-summary-on"
	}
	ui.audit(r, "group.blocksummary", name, state)
	redirect(w, r, groupPath(name), msg)
}
