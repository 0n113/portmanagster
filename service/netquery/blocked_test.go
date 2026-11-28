package netquery

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safing/portmaster/service/network"
)

const appFirefox = "Firefox"

func TestBlocked(t *testing.T) { //nolint:paralleltest // uses the package-level module.
	db := newTestDatabase(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	extra := json.RawMessage(`{"blockedByLists":["MAL"],"pid":1,"processCreatedAt":0,"reason":{"Msg":"blocked by filter list","OptionKey":"filter/lists","Profile":"","Context":null}}`)
	conns := []Conn{
		// Blocked by a filter list, in the window.
		{ID: "a", ProfileName: appFirefox, Domain: "evil.example.", RemoteIP: "192.0.2.1", Direction: "outbound", ActiveVerdict: network.VerdictBlock, Started: now.Add(-time.Minute), ExtraData: extra},
		// Dropped incoming connection without extra data, in the window.
		{ID: "b", ProfileName: "System", RemoteIP: "198.51.100.7", Direction: "inbound", ActiveVerdict: network.VerdictDrop, Started: now.Add(-2 * time.Minute)},
		// Allowed: not included.
		{ID: "c", ProfileName: appFirefox, Domain: "ok.example.", ActiveVerdict: network.VerdictAccept, Started: now.Add(-time.Minute)},
		// Blocked, but before the window.
		{ID: "d", ProfileName: appFirefox, Domain: "old.example.", ActiveVerdict: network.VerdictBlock, Started: now.Add(-time.Hour)},
		// Blocked, but at the end of the window (exclusive).
		{ID: "e", ProfileName: appFirefox, Domain: "new.example.", ActiveVerdict: network.VerdictBlock, Started: now},
	}
	for _, c := range conns {
		require.NoError(t, db.Save(ctx, c, false))
	}

	blocked, err := db.Blocked(ctx, now.Add(-5*time.Minute), now, 100)
	require.NoError(t, err)
	assert.Equal(t, []BlockedConn{
		{App: "System", RemoteIP: "198.51.100.7", Inbound: true},
		{App: appFirefox, Domain: "evil.example.", RemoteIP: "192.0.2.1", Reason: "filter/lists", Lists: []string{"MAL"}},
	}, blocked)

	limited, err := db.Blocked(ctx, now.Add(-5*time.Minute), now, 1)
	require.NoError(t, err)
	assert.Len(t, limited, 1)
}
