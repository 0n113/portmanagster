package managed

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/safing/portmaster/mgmt/policy"
	"github.com/safing/portmaster/service/netquery"
	"github.com/safing/portmaster/service/network"
)

const (
	// maxBlockedRows limits the connections read for one summary.
	maxBlockedRows = 20000
	// maxBlockWindow is the longest time a summary covers: the live
	// connection database keeps ended connections only this long.
	maxBlockWindow = network.DeleteConnsAfterEndedThreshold
	// maxBlockField limits the length of the text fields of an entry.
	maxBlockField = 255
)

// blockSource returns the blocked connections that started in [since, until).
type blockSource func(ctx context.Context, since, until time.Time, limit int) ([]netquery.BlockedConn, error)

// appSource returns the apps with allowed connections that started in
// [since, until).
type appSource func(ctx context.Context, since, until time.Time, limit int) ([]netquery.ConnectedApp, error)

// summarizeApps returns the apps with a hash instead of the path, sorted by
// name, at most policy.MaxApps.
func summarizeApps(conns []netquery.ConnectedApp) []policy.App {
	apps := make([]policy.App, 0, len(conns))
	for _, c := range conns {
		sum := sha256.Sum256([]byte(c.Path))
		apps = append(apps, policy.App{
			Name: truncate(c.Name),
			ID:   hex.EncodeToString(sum[:16]),
		})
	}
	slices.SortFunc(apps, func(a, b policy.App) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})
	apps = slices.Compact(apps)
	if len(apps) > policy.MaxApps {
		apps = apps[:policy.MaxApps]
	}
	return apps
}

// blockWindowStart returns the start of the next summary: the end of the
// last sent one, but not before maxBlockWindow.
func blockWindowStart(lastUntil, now time.Time) time.Time {
	earliest := now.Add(-maxBlockWindow)
	if lastUntil.Before(earliest) {
		return earliest
	}
	return lastUntil
}

// summarizeBlocks counts the connections per app, reason, lists, target and
// direction and returns the policy.MaxBlocks largest entries.
func summarizeBlocks(conns []netquery.BlockedConn) []policy.Block {
	counts := make(map[policy.Block]int)
	for _, c := range conns {
		target := strings.TrimSuffix(c.Domain, ".")
		if target == "" {
			target = c.RemoteIP
		}
		lists := slices.Clone(c.Lists)
		slices.Sort(lists)
		key := policy.Block{
			App:     truncate(c.App),
			Reason:  truncate(c.Reason),
			Lists:   truncate(strings.Join(slices.Compact(lists), ",")),
			Target:  truncate(target),
			Inbound: c.Inbound,
		}
		counts[key]++
	}
	blocks := make([]policy.Block, 0, len(counts))
	for b, n := range counts {
		b.Count = n
		blocks = append(blocks, b)
	}
	slices.SortFunc(blocks, func(a, b policy.Block) int {
		return cmp.Or(
			cmp.Compare(b.Count, a.Count),
			cmp.Compare(a.App, b.App),
			cmp.Compare(a.Target, b.Target),
			cmp.Compare(a.Reason, b.Reason),
			cmp.Compare(a.Lists, b.Lists),
		)
	})
	if len(blocks) > policy.MaxBlocks {
		blocks = blocks[:policy.MaxBlocks]
	}
	return blocks
}

func truncate(s string) string {
	if len(s) <= maxBlockField {
		return s
	}
	// Do not cut a UTF-8 sequence.
	cut := maxBlockField
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}
