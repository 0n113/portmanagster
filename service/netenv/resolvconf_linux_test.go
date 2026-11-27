package netenv

import (
	"slices"
	"strings"
	"testing"
)

func TestParseResolvconf(t *testing.T) {
	t.Parallel()

	ns, err := parseResolvconf(strings.NewReader("# comment\nsearch a.com b.com\nnameserver\t1.1.1.1\nnameserver  8.8.8.8\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 2 {
		t.Fatalf("got %d nameservers, want 2: %+v", len(ns), ns)
	}
	if !slices.Equal(ns[0].Search, []string{"a.com", "b.com"}) {
		t.Fatalf("search domains: %v", ns[0].Search)
	}
	if ns[0].IP.String() != "1.1.1.1" || ns[1].IP.String() != "8.8.8.8" {
		t.Fatalf("nameservers: %v %v", ns[0].IP, ns[1].IP)
	}
}
