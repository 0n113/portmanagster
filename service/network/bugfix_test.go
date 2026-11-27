package network

import (
	"net"
	"strings"
	"testing"

	"github.com/safing/portmaster/service/intel"
)

func TestConnectionStoreActive(t *testing.T) {
	t.Parallel()

	cs := newConnectionStore()
	cs.add(&Connection{ID: "open-1"})
	cs.add(&Connection{ID: "open-2"})
	cs.add(&Connection{ID: "ended", Ended: 1})
	if got := cs.active(); got != 2 {
		t.Fatalf("active() = %d, want 2", got)
	}
}

func TestDebugInfoProcessHeaders(t *testing.T) {
	t.Parallel()

	newConn := func(id string, pid int, profile string) *Connection {
		return &Connection{
			ID:        id,
			IPVersion: 4,
			LocalIP:   net.ParseIP("10.0.0.1"),
			Entity:    &intel.Entity{IP: net.ParseIP("10.0.0.2"), Protocol: 6, Port: 443},
			ProcessContext: ProcessContext{
				PID:     pid,
				Profile: profile,
			},
		}
	}
	// A first connection with PID -1, and two connections of one PID with
	// different profiles: each needs its own header.
	conns := []*Connection{
		newConn("a", -1, "local/a"),
		newConn("b", 42, "local/b"),
		newConn("c", 42, "local/c"),
	}
	out := buildNetworkDebugInfoData(conns)
	if got := strings.Count(out, "ProfileName:"); got != 3 {
		t.Fatalf("got %d process headers, want 3:\n%s", got, out)
	}
}
