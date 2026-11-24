package network

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/safing/portmaster/service/intel"
	"github.com/safing/portmaster/service/network/packet"
	"github.com/safing/portmaster/service/process"
)

var errTestConntrack = errors.New("conntrack unavailable")

func newTestForwardedConn(permanent bool, lastSeen int64) *Connection {
	conn := &Connection{
		PID:              process.ForwardedProcessID,
		IPProtocol:       packet.TCP,
		LocalIP:          net.ParseIP("192.168.122.10"),
		LocalPort:        40000,
		VerdictPermanent: permanent,
		Entity: &intel.Entity{
			IP:       net.ParseIP("93.184.215.14"),
			Protocol: uint8(packet.TCP),
			Port:     443,
		},
	}
	conn.lastSeen.Store(lastSeen)
	return conn
}

func TestForwardedFlowCheck(t *testing.T) {
	t.Parallel()

	now := time.Now()
	endNotSeenSince := now.Add(-EndConnsAfterInactiveFor).Unix()
	recent := now.Unix()
	old := now.Add(-time.Hour).Unix()

	conn := newTestForwardedConn(true, old)
	key := FlowKey(conn.Entity.Protocol, conn.LocalIP, conn.LocalPort, conn.Entity.IP, conn.Entity.Port)
	tracked := func() (map[string]struct{}, error) { return map[string]struct{}{key: {}}, nil }
	untracked := func() (map[string]struct{}, error) { return map[string]struct{}{}, nil }
	failing := func() (map[string]struct{}, error) { return nil, errTestConntrack }

	tests := []struct {
		name                 string
		conn                 *Connection
		due                  bool
		lister               FlowLister
		wantActive, wantSeen bool
	}{
		{"recently seen", newTestForwardedConn(false, recent), true, untracked, true, true},
		{"not seen, no permanent verdict", newTestForwardedConn(false, old), true, tracked, false, true},
		{"permanent, tracked by the kernel", newTestForwardedConn(true, old), true, tracked, true, true},
		{"permanent, gone from the kernel", newTestForwardedConn(true, old), true, untracked, false, true},
		{"permanent, check not due", newTestForwardedConn(true, old), false, untracked, true, false},
		{"permanent, conntrack fails", newTestForwardedConn(true, old), true, failing, true, false},
		{"permanent, no lister", newTestForwardedConn(true, old), true, nil, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fc := &forwardedFlowCheck{due: tc.due, lister: tc.lister}
			active, checked := fc.active(tc.conn, endNotSeenSince)
			if active != tc.wantActive || checked != tc.wantSeen {
				t.Errorf("got active=%v checked=%v, want active=%v checked=%v", active, checked, tc.wantActive, tc.wantSeen)
			}
		})
	}
}

func TestForwardedFlowCheckListsOnce(t *testing.T) {
	t.Parallel()

	calls := 0
	fc := &forwardedFlowCheck{due: true, lister: func() (map[string]struct{}, error) {
		calls++
		return map[string]struct{}{}, nil
	}}
	endNotSeenSince := time.Now().Unix()
	for range 3 {
		fc.active(newTestForwardedConn(true, 0), endNotSeenSince)
	}
	if calls != 1 {
		t.Errorf("listed the flows %d times in one run, want 1", calls)
	}
}

func TestFlowKeyNormalizesIPv4(t *testing.T) {
	t.Parallel()

	a := FlowKey(6, net.ParseIP("10.0.0.1"), 1, net.ParseIP("10.0.0.2"), 2)
	b := FlowKey(6, net.ParseIP("10.0.0.1").To4(), 1, net.IP{10, 0, 0, 2}, 2)
	if a != b {
		t.Errorf("keys of the same IPv4 flow differ: %q != %q", a, b)
	}
}

func TestIsForwarded(t *testing.T) {
	t.Parallel()

	if !(&Connection{PID: process.ForwardedProcessID}).IsForwarded() {
		t.Error("forwarded connection not reported as forwarded")
	}
	if (&Connection{PID: process.UnidentifiedProcessID}).IsForwarded() {
		t.Error("unidentified connection reported as forwarded")
	}
}
