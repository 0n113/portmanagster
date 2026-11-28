package netquery

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/safing/portmaster/service/netquery/orm"
	"github.com/safing/portmaster/service/network"
)

// BlockedConn is a blocked connection with the fields of a block summary of
// the management client: no addresses, ports, paths or user names.
type BlockedConn struct {
	// App is the name of the app profile.
	App    string
	Domain string
	// RemoteIP is the remote address, for connections without a domain.
	RemoteIP string
	Inbound  bool
	// Reason is the setting that blocked (option key), or the reason
	// message if there is no option key.
	Reason string
	// Lists are the filter lists that matched.
	Lists []string
}

// Blocked returns the blocked connections of the live database that started
// in [since, until), at most limit.
func (db *Database) Blocked(ctx context.Context, since, until time.Time, limit int) ([]BlockedConn, error) {
	var rows []struct {
		App       string          `sqlite:"profile_name"`
		Domain    string          `sqlite:"domain"`
		RemoteIP  string          `sqlite:"remote_ip"`
		Direction string          `sqlite:"direction"`
		ExtraData json.RawMessage `sqlite:"extra_data"`
	}
	err := db.Execute(ctx, `SELECT profile_name, domain, remote_ip, direction, extra_data FROM main.connections
		WHERE verdict IN (:block, :drop)
		AND datetime(started) >= datetime(:since) AND datetime(started) < datetime(:until)
		ORDER BY started LIMIT :limit`,
		orm.WithNamedArgs(map[string]any{
			":block": int(network.VerdictBlock),
			":drop":  int(network.VerdictDrop),
			":since": since.UTC().Format(orm.SqliteTimeFormat),
			":until": until.UTC().Format(orm.SqliteTimeFormat),
			":limit": limit,
		}),
		orm.WithResult(&rows),
	)
	if err != nil {
		return nil, fmt.Errorf("query blocked connections: %w", err)
	}

	blocked := make([]BlockedConn, 0, len(rows))
	for _, r := range rows {
		b := BlockedConn{
			App:      r.App,
			Domain:   r.Domain,
			RemoteIP: r.RemoteIP,
			Inbound:  r.Direction == "inbound",
		}
		var extra struct {
			BlockedByLists []string `json:"blockedByLists"`
			Reason         *struct {
				Msg       string
				OptionKey string
			} `json:"reason"`
		}
		if len(r.ExtraData) > 0 && json.Unmarshal(r.ExtraData, &extra) == nil {
			b.Lists = extra.BlockedByLists
			if extra.Reason != nil {
				b.Reason = extra.Reason.OptionKey
				if b.Reason == "" {
					b.Reason = extra.Reason.Msg
				}
			}
		}
		blocked = append(blocked, b)
	}
	return blocked, nil
}
