//go:build windows

package windowskext

import (
	"net"
	"testing"
)

func TestIPAddressToArrayIPv6(t *testing.T) {
	t.Parallel()

	got := ipAddressToArray(net.ParseIP("2001:db8::1"), true)
	want := [4]uint32{0x20010db8, 0, 0, 1}
	if got != want {
		t.Fatalf("ipAddressToArray = %x, want %x", got, want)
	}
	if ip := convertArrayToIP(got, true); !ip.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("round trip gave %s", ip)
	}
}
