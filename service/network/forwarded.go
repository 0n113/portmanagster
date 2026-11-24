package network

import (
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/safing/portmaster/service/process"
)

// IsForwarded returns whether the connection is forwarded by the host for
// another device, e.g. a VM or container.
func (conn *Connection) IsForwarded() bool {
	return conn.PID == process.ForwardedProcessID
}

// FlowLister returns the address tuples (see FlowKey) of the flows with a
// permanent verdict that the OS integration still tracks.
type FlowLister func() (map[string]struct{}, error)

var forwardedFlowLister atomic.Pointer[FlowLister]

// SetForwardedFlowLister sets the function that lists the tracked flows with
// a permanent verdict. Forwarded connections have no local socket, so the
// cleaner uses it to find out whether they are still active.
func SetForwardedFlowLister(fn FlowLister) {
	forwardedFlowLister.Store(&fn)
}

// FlowKey returns the key of a flow in its original direction.
func FlowKey(protocol uint8, src net.IP, srcPort uint16, dst net.IP, dstPort uint16) string {
	return strconv.Itoa(int(protocol)) + "|" +
		net.JoinHostPort(src.String(), strconv.Itoa(int(srcPort))) + "|" +
		net.JoinHostPort(dst.String(), strconv.Itoa(int(dstPort)))
}

// forwardedFlowCheckInterval is how often the cleaner lists the tracked
// flows to check forwarded connections.
const forwardedFlowCheckInterval = 30 * time.Second

// forwardedFlowCheck holds the tracked flows for one cleaner run. The flows
// are only listed if there is a forwarded connection to check, and at most
// once per forwardedFlowCheckInterval.
type forwardedFlowCheck struct {
	due     bool
	lister  FlowLister
	listed  bool
	flows   map[string]struct{}
	listErr error
}

var lastForwardedFlowCheck atomic.Int64

func newForwardedFlowCheck(now time.Time) *forwardedFlowCheck {
	last := lastForwardedFlowCheck.Load()
	due := now.Unix()-last >= int64(forwardedFlowCheckInterval/time.Second)
	if due {
		lastForwardedFlowCheck.Store(now.Unix())
	}
	fc := &forwardedFlowCheck{due: due}
	if lister := forwardedFlowLister.Load(); lister != nil {
		fc.lister = *lister
	}
	return fc
}

// active returns whether the forwarded connection is still active, and
// whether that could be checked in this run.
func (fc *forwardedFlowCheck) active(conn *Connection, endNotSeenSince int64) (active, checked bool) {
	// Packets of connections without a permanent verdict update lastSeen.
	if conn.lastSeen.Load() > endNotSeenSince {
		return true, true
	}
	if !conn.VerdictPermanent {
		return false, true
	}

	// The packets of a permanent verdict are handled by the kernel only, so
	// ask it whether it still tracks the flow.
	if !fc.due {
		return true, false
	}
	if !fc.listed {
		fc.listed = true
		if fc.lister != nil {
			fc.flows, fc.listErr = fc.lister()
		}
	}
	if fc.flows == nil || fc.listErr != nil {
		// Unknown, keep the connection: ending it would stop the
		// re-evaluation of its verdict when settings change.
		return true, false
	}
	if conn.Entity == nil {
		return false, true
	}
	_, ok := fc.flows[FlowKey(conn.Entity.Protocol, conn.LocalIP, conn.LocalPort, conn.Entity.IP, conn.Entity.Port)]
	return ok, true
}
