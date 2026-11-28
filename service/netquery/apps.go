package netquery

import (
	"context"
	"fmt"
	"time"

	"github.com/safing/portmaster/service/netquery/orm"
	"github.com/safing/portmaster/service/network"
)

// ConnectedApp is an app with allowed connections, for the app list of the
// management client.
type ConnectedApp struct {
	// Name is the name of the app profile.
	Name string
	// Path is the path of the executable.
	Path string
}

// ConnectedApps returns the distinct apps of the live database with allowed
// connections that started in [since, until), at most limit.
func (db *Database) ConnectedApps(ctx context.Context, since, until time.Time, limit int) ([]ConnectedApp, error) {
	var rows []struct {
		Name string `sqlite:"profile_name"`
		Path string `sqlite:"path"`
	}
	err := db.Execute(ctx, `SELECT profile_name, path FROM main.connections
		WHERE verdict IN (:accept, :ns, :tunnel, :split)
		AND datetime(started) >= datetime(:since) AND datetime(started) < datetime(:until)
		GROUP BY profile_name, path ORDER BY profile_name, path LIMIT :limit`,
		orm.WithNamedArgs(map[string]any{
			":accept": int(network.VerdictAccept),
			":ns":     int(network.VerdictRerouteToNameserver),
			":tunnel": int(network.VerdictRerouteToTunnel),
			":split":  int(network.VerdictRerouteToSplitTun),
			":since":  since.UTC().Format(orm.SqliteTimeFormat),
			":until":  until.UTC().Format(orm.SqliteTimeFormat),
			":limit":  limit,
		}),
		orm.WithResult(&rows),
	)
	if err != nil {
		return nil, fmt.Errorf("query connected apps: %w", err)
	}
	apps := make([]ConnectedApp, 0, len(rows))
	for _, r := range rows {
		apps = append(apps, ConnectedApp(r))
	}
	return apps, nil
}
