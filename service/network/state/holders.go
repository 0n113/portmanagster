package state

import (
	"errors"

	"github.com/safing/portmaster/service/network/packet"
	"github.com/safing/portmaster/service/network/socket"
)

// ErrSocketHoldersUnsupported is returned by LookupSocketHolders on systems
// that cannot list all processes holding a socket.
var ErrSocketHoldersUnsupported = errors.New("listing the holders of a socket is not supported on this system")

var (
	errSocketHoldersOnlyTCP = errors.New("listing socket holders is only supported for TCP")
	errUnsupportedIPVersion = errors.New("unsupported IP version")
)

// LookupSocketHolders returns the PIDs of all processes that currently hold
// the socket of the given TCP connection.
//
// Lookup attributes a connection to one process only, but a socket can be
// held by several processes. Use this function where trust is derived from
// the process of a connection, as the first process found may not be the one
// that uses the socket.
func LookupSocketHolders(pktInfo *packet.Info) (pids []int, err error) {
	if findSocketHolders == nil {
		return nil, ErrSocketHoldersUnsupported
	}
	if pktInfo.Protocol != packet.TCP {
		return nil, errSocketHoldersOnlyTCP
	}

	// auto-detect version
	version := pktInfo.Version
	if version == 0 {
		if ip := pktInfo.LocalIP().To4(); ip != nil {
			version = packet.IPv4
		} else {
			version = packet.IPv6
		}
	}

	switch version {
	case packet.IPv4:
		return tcp4Table.lookupHolders(pktInfo, findSocketHolders)
	case packet.IPv6:
		return tcp6Table.lookupHolders(pktInfo, findSocketHolders)
	default:
		return nil, errUnsupportedIPVersion
	}
}

func (table *tcpTable) lookupHolders(pktInfo *packet.Info, findHolders func(inode int) ([]int, error)) (pids []int, err error) {
	var found bool
	for range lookupTries {
		// Always fetch new tables (at most once per 10ms): the current tables
		// may still hold a closed socket with the same addresses and ports,
		// whose inode nobody holds anymore.
		connections, _ := table.updateTables()
		socketInfo := findTCPConnection(pktInfo, connections)

		if socketInfo == nil && table.dualStack != nil {
			connections, _ = table.dualStack.updateTables()
			socketInfo = findTCPConnection(pktInfo, connections)
		}

		if socketInfo != nil {
			found = true
			_, inode := socketInfo.GetUIDandInode()
			pids, err = findHolders(inode)
			if err != nil {
				return nil, err
			}
			if len(pids) > 0 {
				return pids, nil
			}
			// Nobody holds the socket of these tables. They may be older than
			// the socket, try again with new tables.
		}
	}

	if found {
		return nil, ErrPIDNotFound
	}
	return nil, ErrConnectionNotFound
}

// findTCPConnection returns the connection that exactly matches the local and
// remote address and port of the packet. In contrast to findTCPSocket, it
// does not match listeners, as a listener on the same local port could be
// another socket than the one of the connection.
func findTCPConnection(pktInfo *packet.Info, connections []*socket.ConnectionInfo) *socket.ConnectionInfo {
	localIP := pktInfo.LocalIP()
	localPort := pktInfo.LocalPort()
	remoteIP := pktInfo.RemoteIP()
	remotePort := pktInfo.RemotePort()

	for _, socketInfo := range connections {
		if localPort == socketInfo.Local.Port &&
			remotePort == socketInfo.Remote.Port &&
			remoteIP.Equal(socketInfo.Remote.IP) &&
			localIP.Equal(socketInfo.Local.IP) {
			return socketInfo
		}
	}
	return nil
}
