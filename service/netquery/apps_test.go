package netquery

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safing/portmaster/service/network"
)

func TestConnectedApps(t *testing.T) { //nolint:paralleltest // uses the package-level module.
	db := newTestDatabase(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	const pathFirefox = "/usr/lib/firefox/firefox"
	conns := []Conn{
		// Two allowed connections of the same app: listed once.
		{ID: "a", ProfileName: appFirefox, Path: pathFirefox, ActiveVerdict: network.VerdictAccept, Started: now.Add(-time.Minute)},
		{ID: "b", ProfileName: appFirefox, Path: pathFirefox, ActiveVerdict: network.VerdictAccept, Started: now.Add(-2 * time.Minute)},
		// DNS query redirected to the nameserver: allowed.
		{ID: "c", ProfileName: "Curl", Path: "/usr/bin/curl", ActiveVerdict: network.VerdictRerouteToNameserver, Started: now.Add(-time.Minute)},
		// Blocked: not included.
		{ID: "d", ProfileName: "Evil", Path: "/tmp/evil", ActiveVerdict: network.VerdictBlock, Started: now.Add(-time.Minute)},
		// Allowed, but before the window.
		{ID: "e", ProfileName: "Old", Path: "/usr/bin/old", ActiveVerdict: network.VerdictAccept, Started: now.Add(-time.Hour)},
	}
	for _, c := range conns {
		require.NoError(t, db.Save(ctx, c, false))
	}

	apps, err := db.ConnectedApps(ctx, now.Add(-5*time.Minute), now, 100)
	require.NoError(t, err)
	assert.Equal(t, []ConnectedApp{
		{Name: "Curl", Path: "/usr/bin/curl"},
		{Name: appFirefox, Path: pathFirefox},
	}, apps)

	limited, err := db.ConnectedApps(ctx, now.Add(-5*time.Minute), now, 1)
	require.NoError(t, err)
	assert.Len(t, limited, 1)
}
