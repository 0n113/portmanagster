package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	corebase "github.com/safing/portmaster/service/core/base"
	"github.com/safing/portmaster/service/netquery/orm"
	"github.com/safing/portmaster/service/network"
)

// The connections command exports the connection history of the running
// Portmaster as JSON lines, for SIEM and log shippers (Wazuh, Graylog,
// Elastic, Loki). With --cursor, repeated runs export each connection once.

const (
	connectionsPageSize = 1000
	colStarted          = "started"
)

var (
	connSince   time.Duration
	connBlocked bool
	connHistory bool
	connCursor  string
	connLimit   int

	errConnInvalidResponse = errors.New("invalid netquery response")
)

var connectionsCmd = &cobra.Command{
	Use:   "connections",
	Short: "Export the connection history of the running Portmaster as JSON lines",
	Long: `Export the connection history of the running Portmaster as JSON lines, one
connection per line, oldest first.

With --cursor FILE, the command remembers the newest exported connection in
FILE and the next run exports only connections that started later, so it can
run periodically (cron, systemd timer) and append to a log file that a SIEM
agent reads. Without a cursor, --since selects the time range.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return exportConnections(cmd.Context(), os.Stdout, time.Now())
	},
}

func init() {
	connectionsCmd.Flags().StringVar(&syncAPIAddress, "api", corebase.DefaultAPIListenAddress, "address of the Portmaster API")
	connectionsCmd.Flags().DurationVar(&connSince, "since", time.Hour, "export connections that started within this time (ignored with an existing cursor)")
	connectionsCmd.Flags().BoolVar(&connBlocked, "blocked", false, "export only blocked, dropped and failed connections")
	connectionsCmd.Flags().BoolVar(&connHistory, "history", false, "also search the network history (if enabled), not only recent connections")
	connectionsCmd.Flags().StringVar(&connCursor, "cursor", "", "file that remembers the last exported connection between runs")
	connectionsCmd.Flags().IntVar(&connLimit, "limit", 100000, "export at most this many connections per run")
	rootCmd.AddCommand(connectionsCmd)
}

// connectionCursor is stored in the cursor file.
type connectionCursor struct {
	// Started is the start time (unix seconds) of the newest exported connection.
	Started int64 `json:"started"`
	// Seen are the connections exported within cursorOverlap before Started,
	// by ID. Each run queries this time again, because netquery saves some
	// connections with a delay, and skips these.
	Seen map[string]int64 `json:"seen"`
}

// cursorOverlap is how far back each run with a cursor queries again.
const cursorOverlap = 120

// ConnectionEvent is one exported connection.
type ConnectionEvent struct {
	Time        string   `json:"time"`
	Ended       string   `json:"ended,omitempty"`
	Host        string   `json:"host"`
	ID          string   `json:"id"`
	Verdict     string   `json:"verdict"`
	Reason      string   `json:"reason,omitempty"`
	FilterLists []string `json:"filterLists,omitempty"`
	Direction   string   `json:"direction"`
	Type        string   `json:"type,omitempty"`
	Profile     string   `json:"profile,omitempty"`
	App         string   `json:"app,omitempty"`
	Path        string   `json:"path,omitempty"`
	PID         int      `json:"pid,omitempty"`
	Domain      string   `json:"domain,omitempty"`
	Protocol    int      `json:"protocol"`
	LocalIP     string   `json:"localIP,omitempty"`
	LocalPort   int      `json:"localPort,omitempty"`
	RemoteIP    string   `json:"remoteIP,omitempty"`
	RemotePort  int      `json:"remotePort,omitempty"`
	Country     string   `json:"country,omitempty"`
	ASN         int      `json:"asn,omitempty"`
	ASOwner     string   `json:"asOwner,omitempty"`
	BytesSent   int64    `json:"bytesSent,omitempty"`
	BytesRecv   int64    `json:"bytesReceived,omitempty"`
}

// netqueryRow is a result row of the netquery API.
type netqueryRow struct {
	ID            string  `json:"id"`
	Started       string  `json:"started"`
	Ended         *string `json:"ended"`
	Verdict       int     `json:"verdict"`
	Direction     string  `json:"direction"`
	Type          string  `json:"type"`
	Profile       string  `json:"profile"`
	ProfileName   string  `json:"profile_name"`
	Path          string  `json:"path"`
	Domain        string  `json:"domain"`
	IPProtocol    int     `json:"ip_protocol"`
	LocalIP       string  `json:"local_ip"`
	LocalPort     int     `json:"local_port"`
	RemoteIP      string  `json:"remote_ip"`
	RemotePort    int     `json:"remote_port"`
	Country       string  `json:"country"`
	ASN           int     `json:"asn"`
	ASOwner       string  `json:"as_owner"`
	BytesSent     int64   `json:"bytes_sent"`
	BytesReceived int64   `json:"bytes_received"`
	ExtraData     *struct {
		PID    int `json:"pid"`
		Reason *struct {
			Msg string `json:"Msg"`
		} `json:"reason"`
		BlockedByLists []string `json:"blockedByLists"`
	} `json:"extra_data"`
}

var connectionFields = []string{
	"id", colStarted, "ended", "verdict", "direction", "type", "profile", "profile_name", "path",
	"domain", "ip_protocol", "local_ip", "local_port", "remote_ip", "remote_port", "country",
	"asn", "as_owner", "bytes_sent", "bytes_received", "extra_data",
}

func exportConnections(ctx context.Context, out io.Writer, now time.Time) error {
	cur, err := loadConnectionCursor(connCursor)
	if err != nil {
		return err
	}
	from := now.Add(-connSince).Unix()
	next := &connectionCursor{Started: from, Seen: map[string]int64{}}
	if cur != nil {
		from = cur.Started - cursorOverlap
		next = cur
	}
	host, _ := os.Hostname()

	w := bufio.NewWriter(out)
	exported := 0
	for page := 0; exported < connLimit; page++ {
		rows, err := queryConnections(ctx, from, page)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if exported >= connLimit {
				break
			}
			if _, seen := next.Seen[row.ID]; seen {
				continue
			}
			started, err := parseNetqueryTime(row.Started)
			if err != nil {
				return err
			}
			line, err := json.Marshal(toConnectionEvent(row, started, host))
			if err != nil {
				return err
			}
			_, _ = w.Write(append(line, '\n'))
			exported++
			next.add(row.ID, started.Unix())
		}
		if len(rows) < connectionsPageSize {
			break
		}
	}
	err = w.Flush()
	if err != nil {
		return err
	}
	if connCursor != "" {
		next.prune()
		return saveConnectionCursor(connCursor, next)
	}
	return nil
}

// add records an exported connection.
func (c *connectionCursor) add(id string, started int64) {
	if c.Seen == nil {
		c.Seen = map[string]int64{}
	}
	c.Seen[id] = started
	if started > c.Started {
		c.Started = started
	}
}

// prune forgets connections that the next run does not query again.
func (c *connectionCursor) prune() {
	for id, started := range c.Seen {
		if started < c.Started-cursorOverlap {
			delete(c.Seen, id)
		}
	}
}

// parseNetqueryTime parses a time column of netquery, which stores UTC.
func parseNetqueryTime(s string) (time.Time, error) {
	t, err := time.ParseInLocation(orm.SqliteTimeFormat, s, time.UTC)
	if err == nil {
		return t, nil
	}
	t, err = time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: time %q", errConnInvalidResponse, s)
	}
	return t, nil
}

func queryConnections(ctx context.Context, from int64, page int) ([]netqueryRow, error) {
	query := map[string]any{
		colStarted: map[string]any{"$ge": from},
	}
	if connBlocked {
		query["verdict"] = map[string]any{"$in": []int{
			int(network.VerdictBlock), int(network.VerdictDrop), int(network.VerdictFailed),
		}}
	}
	databases := []string{"main"}
	if connHistory {
		databases = append(databases, "history")
	}
	body, err := json.Marshal(map[string]any{
		"select":    connectionFields,
		"query":     query,
		"orderBy":   []map[string]any{{"field": colStarted, "desc": false}, {"field": "id", "desc": false}},
		"databases": databases,
		"pageSize":  connectionsPageSize,
		"page":      page,
	})
	if err != nil {
		return nil, err
	}
	data, err := syncRequest(ctx, http.MethodPost, "netquery/query", nil, mimeJSON, body)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Results []netqueryRow `json:"results"`
	}
	err = json.Unmarshal(data, &resp)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errConnInvalidResponse, err)
	}
	return resp.Results, nil
}

func toConnectionEvent(row netqueryRow, started time.Time, host string) ConnectionEvent {
	ev := ConnectionEvent{
		Time:       started.UTC().Format(time.RFC3339),
		Host:       host,
		ID:         row.ID,
		Verdict:    network.Verdict(row.Verdict).Verb(), //nolint:gosec // Verdicts are small numbers.
		Direction:  row.Direction,
		Type:       row.Type,
		Profile:    row.Profile,
		App:        row.ProfileName,
		Path:       row.Path,
		Domain:     row.Domain,
		Protocol:   row.IPProtocol,
		LocalIP:    row.LocalIP,
		LocalPort:  row.LocalPort,
		RemoteIP:   row.RemoteIP,
		RemotePort: row.RemotePort,
		Country:    row.Country,
		ASN:        row.ASN,
		ASOwner:    row.ASOwner,
		BytesSent:  row.BytesSent,
		BytesRecv:  row.BytesReceived,
	}
	if row.Ended != nil {
		ended, err := parseNetqueryTime(*row.Ended)
		if err == nil {
			ev.Ended = ended.UTC().Format(time.RFC3339)
		}
	}
	if row.ExtraData != nil {
		ev.PID = row.ExtraData.PID
		ev.FilterLists = row.ExtraData.BlockedByLists
		if row.ExtraData.Reason != nil {
			ev.Reason = row.ExtraData.Reason.Msg
		}
	}
	return ev
}

func loadConnectionCursor(path string) (*connectionCursor, error) {
	if path == "" {
		return nil, nil //nolint:nilnil // No cursor is not an error.
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil //nolint:nilnil // No cursor yet.
	}
	if err != nil {
		return nil, err
	}
	c := &connectionCursor{}
	err = json.Unmarshal(data, c)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor file %s: %w", path, err)
	}
	return c, nil
}

func saveConnectionCursor(path string, c *connectionCursor) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	err = os.WriteFile(tmp, data, 0o600)
	if err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Clean(path))
}
