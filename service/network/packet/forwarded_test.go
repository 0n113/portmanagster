package packet

import (
	"net"
	"strings"
	"testing"
)

func TestSetForwarded(t *testing.T) {
	t.Parallel()

	pkt := &Base{}
	pkt.SetPacketInfo(Info{
		Inbound:  true,
		Protocol: TCP,
		Src:      net.ParseIP("192.168.122.10"),
		SrcPort:  40000,
		Dst:      net.ParseIP("93.184.215.14"),
		DstPort:  443,
	})
	pkt.SetForwarded()

	info := pkt.Info()
	if !info.Forwarded || info.Inbound {
		t.Fatalf("got forwarded=%v inbound=%v, want forwarded outbound", info.Forwarded, info.Inbound)
	}
	// The sending device is the local side of a forwarded connection.
	if !info.LocalIP().Equal(info.Src) || !info.RemoteIP().Equal(info.Dst) {
		t.Errorf("local %s, remote %s: want the source as local side", info.LocalIP(), info.RemoteIP())
	}
	if s := pkt.FmtPacket(); !strings.HasPrefix(s, "FWD ") {
		t.Errorf("FmtPacket() = %q, want FWD prefix", s)
	}
}
