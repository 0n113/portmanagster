package netenv

import (
	"strings"
	"testing"

	"github.com/safing/portmaster/service/intel/geoip"
	"github.com/safing/portmaster/service/network/packet"
)

func TestConnectivityDomainsAreFQDNs(t *testing.T) {
	t.Parallel()

	for _, d := range ConnectivityDomains {
		if !strings.HasSuffix(d, ".") {
			t.Errorf("connectivity domain %q has no trailing dot and never matches", d)
		}
	}
}

func TestIsMoreAccurateThanIsAsymmetric(t *testing.T) {
	t.Parallel()

	a := &DeviceLocation{IP: []byte{1, 2, 3, 4}, SourceAccuracy: 3, Location: &geoip.Location{}}
	b := &DeviceLocation{SourceAccuracy: 5, Location: &geoip.Location{}}
	if a.IsMoreAccurateThan(b) {
		t.Error("a location with lower source accuracy must not rank higher")
	}
	if !b.IsMoreAccurateThan(a) {
		t.Error("the location with higher source accuracy must rank higher")
	}
	if a.IsMoreAccurateThan(a) {
		t.Error("a location must not rank above itself")
	}
}

func TestAddLocationKeepsBothIPVersions(t *testing.T) {
	t.Parallel()

	dls := &DeviceLocations{}
	dls.AddLocation(&DeviceLocation{IPVersion: packet.IPv4, Location: &geoip.Location{}, Source: SourceTimezone})
	dls.AddLocation(&DeviceLocation{IPVersion: packet.IPv6, Location: &geoip.Location{}, Source: SourceTimezone})
	if dls.BestV4() == nil || dls.BestV6() == nil {
		t.Fatalf("want a v4 and a v6 location, got %d locations", len(dls.All))
	}
}

func TestDeviceLocationsCopyUsesReceiver(t *testing.T) {
	t.Parallel()

	dls := &DeviceLocations{All: []*DeviceLocation{{IPVersion: packet.IPv4, Location: &geoip.Location{}}}}
	cp := dls.Copy()
	if len(cp.All) != 1 || cp.All[0] != dls.All[0] {
		t.Fatalf("copy does not hold the receiver's locations: %+v", cp.All)
	}
}
