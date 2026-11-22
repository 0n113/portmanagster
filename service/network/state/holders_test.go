package state

import (
	"errors"
	"net"
	"slices"
	"testing"

	"github.com/safing/portmaster/service/network/packet"
	"github.com/safing/portmaster/service/network/socket"
)

func TestLookupHolders(t *testing.T) {
	t.Parallel()

	client := net.IPv4(127, 0, 0, 1).To4()
	api := net.IPv4(127, 0, 0, 1).To4()
	// The API request as the firewall sees it: the client is the source.
	pkt := &packet.Info{
		Version:  packet.IPv4,
		Protocol: packet.TCP,
		Src:      client,
		SrcPort:  50000,
		Dst:      api,
		DstPort:  817,
	}
	clientSocket := &socket.ConnectionInfo{
		Local:  socket.Address{IP: client, Port: 50000},
		Remote: socket.Address{IP: api, Port: 817},
		Inode:  1001,
	}
	// The server side of the same connection, held by the core.
	serverSocket := &socket.ConnectionInfo{
		Local:  socket.Address{IP: api, Port: 817},
		Remote: socket.Address{IP: client, Port: 50000},
		Inode:  1002,
	}
	errScan := errors.New("scan failed")

	tests := []struct {
		name        string
		connections []*socket.ConnectionInfo
		holders     map[int][]int
		scanErr     error
		want        []int
		wantErr     error
	}{
		{
			name:        "single holder",
			connections: []*socket.ConnectionInfo{serverSocket, clientSocket},
			holders:     map[int][]int{1001: {10}, 1002: {1}},
			want:        []int{10},
		},
		{
			name:        "shared socket returns all holders",
			connections: []*socket.ConnectionInfo{serverSocket, clientSocket},
			holders:     map[int][]int{1001: {10, 20}, 1002: {1}},
			want:        []int{10, 20},
		},
		{
			name:        "scan error is returned",
			connections: []*socket.ConnectionInfo{clientSocket},
			scanErr:     errScan,
			wantErr:     errScan,
		},
		{
			name:        "socket held by nobody",
			connections: []*socket.ConnectionInfo{clientSocket},
			holders:     map[int][]int{},
			wantErr:     ErrPIDNotFound,
		},
		{
			name:        "connection not found",
			connections: []*socket.ConnectionInfo{serverSocket},
			holders:     map[int][]int{1002: {1}},
			wantErr:     ErrConnectionNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			table := newTestTCPTable(4, tc.connections)
			pids, err := table.lookupHolders(pkt, func(inode int) ([]int, error) {
				if tc.scanErr != nil {
					return nil, tc.scanErr
				}
				return tc.holders[inode], nil
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got error %v, want %v", err, tc.wantErr)
			}
			if !slices.Equal(pids, tc.want) {
				t.Errorf("got holders %v, want %v", pids, tc.want)
			}
		})
	}
}

// TestLookupHoldersIgnoresListeners checks that a listener on the local port
// of the client is not taken for the socket of the connection.
func TestLookupHoldersIgnoresListeners(t *testing.T) {
	t.Parallel()

	local := net.IPv4(127, 0, 0, 1).To4()
	table := newTestTCPTable(4, nil)
	table.fetchTable = func() ([]*socket.ConnectionInfo, []*socket.BindInfo, error) {
		return nil, []*socket.BindInfo{{
			Local: socket.Address{IP: net.IPv4zero.To4(), Port: 50000},
			Inode: 2001,
		}}, nil
	}

	_, err := table.lookupHolders(&packet.Info{
		Version:  packet.IPv4,
		Protocol: packet.TCP,
		Src:      local,
		SrcPort:  50000,
		Dst:      local,
		DstPort:  817,
	}, func(inode int) ([]int, error) {
		t.Errorf("scanned for holders of inode %d", inode)
		return nil, nil
	})
	if !errors.Is(err, ErrConnectionNotFound) {
		t.Errorf("got error %v, want %v", err, ErrConnectionNotFound)
	}
}
