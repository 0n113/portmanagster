package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safing/portmaster/mgmt/policy"
)

const (
	appFirefox  = "Firefox"
	listMAL     = "MAL"
	targetEvil  = "evil.example"
	osLinux     = "linux"
	reasonLists = "filter/lists"
)

func TestBlockStore(t *testing.T) {
	t.Parallel()
	s, err := OpenStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	now := time.Unix(1_800_000_000, 0).UTC()
	for _, g := range []string{"a", "b"} {
		if err := s.CreateGroup(g, now); err != nil { //nolint:noinlineerr // Test setup.
			t.Fatal(err)
		}
	}
	ids := make([]string, 0, 3)
	for _, g := range []string{"a", "a", "b"} {
		token, _ := s.CreateToken(g, time.Hour, now)
		c := &Computer{Hostname: "h", OS: osLinux}
		err = s.Enroll(token, c, now, func(string) (string, error) { return "fp", nil })
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, c.ID)
	}

	// The opt-in raises the policy sequence.
	seq, _ := s.PolicySeq()
	err = s.SetGroupBlockSummary("a", true, now)
	if err != nil {
		t.Fatal(err)
	}
	g, _ := s.Group("a")
	seq2, _ := s.PolicySeq()
	if !g.BlockSummary || seq2 <= seq {
		t.Fatalf("block summary: %v, seq %d -> %d", g.BlockSummary, seq, seq2)
	}
	if !errors.Is(s.SetGroupBlockSummary("x", true, now), ErrNotFound) {
		t.Fatal("unknown group")
	}

	mal := policy.Block{App: appFirefox, Reason: reasonLists, Lists: "MAL,TRAC", Target: targetEvil, Count: 3}
	rule := policy.Block{App: "curl", Reason: "filter/endpoints", Target: "ads.example", Count: 1}
	report := func(id string, at time.Time, blocks ...policy.Block) {
		t.Helper()
		err := s.SaveReport(id, &policy.Report{Type: policy.TypeReport, Time: at, Blocks: blocks}, at)
		if err != nil {
			t.Fatal(err)
		}
	}
	// Two reports in the same hour add up; an older hour is separate.
	report(ids[0], now, mal, rule)
	report(ids[0], now.Add(time.Minute), mal)
	report(ids[1], now, mal)
	report(ids[2], now, rule)
	report(ids[0], now.Add(-48*time.Hour), mal)

	// The summary is not kept with the report.
	c, _ := s.Computer(ids[0])
	if c.Report == nil || c.Report.Blocks != nil {
		t.Fatalf("stored report: %+v", c.Report)
	}

	rows, err := s.Blocks(BlockFilter{Since: now.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Target != targetEvil || rows[0].Count != 9 || rows[0].Computers != 2 ||
		rows[1].Count != 2 || rows[1].Computers != 2 {
		t.Fatalf("all rows: %+v %+v", rows[0], rows[1])
	}
	for _, c := range []struct {
		f     BlockFilter
		count int64
		n     int
	}{
		{BlockFilter{Group: "b"}, 1, 1},
		{BlockFilter{Computer: ids[0]}, 6, 2},
		{BlockFilter{List: listMAL}, 9, 1},
		{BlockFilter{List: "MA"}, 0, 0},
		{BlockFilter{App: "curl"}, 2, 1},
		{BlockFilter{Target: "ads"}, 2, 1},
		{BlockFilter{List: listMAL, Since: now.Add(-72 * time.Hour)}, 12, 1},
	} {
		if c.f.Since.IsZero() {
			c.f.Since = now.Add(-time.Hour)
		}
		rows, err := s.Blocks(c.f)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != c.n || c.n > 0 && rows[0].Count != c.count {
			t.Errorf("filter %+v: %d rows, first %+v", c.f, len(rows), rows)
		}
	}

	n, err := s.PruneBlocks(now.Add(-24 * time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("prune: %d, %v", n, err)
	}
	rows, _ = s.Blocks(BlockFilter{Since: now.Add(-72 * time.Hour), List: listMAL})
	if len(rows) != 1 || rows[0].Count != 9 {
		t.Fatalf("after prune: %+v", rows)
	}
}

func TestCheckBlocks(t *testing.T) {
	t.Parallel()
	ok := policy.Block{App: "a", Target: "t", Count: 1}
	if CheckBlocks(nil) != nil || CheckBlocks([]policy.Block{ok}) != nil {
		t.Fatal("valid summaries refused")
	}
	if !errors.Is(CheckBlocks([]policy.Block{{App: "a", Target: "t"}}), ErrBadBlocks) ||
		!errors.Is(CheckBlocks([]policy.Block{{Count: 1}}), ErrBadBlocks) ||
		!errors.Is(CheckBlocks(make([]policy.Block, policy.MaxBlocks+1)), ErrBadBlocks) {
		t.Fatal("invalid summaries accepted")
	}
}

func TestReportBlocks(t *testing.T) {
	t.Parallel()
	s, ts := newTestServer(t)
	now := time.Now()
	if err := s.Store.CreateGroup("office", now); err != nil { //nolint:noinlineerr // Test setup.
		t.Fatal(err)
	}
	token, _ := s.Store.CreateToken("office", time.Hour, now)
	client, er, status := enroll(t, s, ts.URL, token)
	if status != http.StatusOK {
		t.Fatalf("enroll: %d", status)
	}
	post := func(r *policy.Report) int {
		t.Helper()
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return postReport(t, s, ts.URL, client.cert, data)
	}
	block := policy.Block{App: appFirefox, Reason: reasonLists, Lists: listMAL, Target: targetEvil, Count: 2}
	r := &policy.Report{Type: policy.TypeReport, Time: now, Blocks: []policy.Block{block}}
	since := now.Add(-time.Hour)

	// Without the opt-in of the group the server drops the summary.
	if code := post(r); code != http.StatusNoContent {
		t.Fatalf("report: %d", code)
	}
	if rows, _ := s.Store.Blocks(BlockFilter{Since: since}); len(rows) != 0 {
		t.Fatalf("blocks stored without opt-in: %+v", rows)
	}

	// With it, the policy asks for the summary and the server keeps it.
	err := s.Store.SetGroupBlockSummary("office", true, now)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := getPolicy(t, s, ts.URL, client.cert)
	if !strings.Contains(string(data), `"blockSummary": true`) {
		t.Fatalf("policy without blockSummary: %s", data)
	}
	if code := post(r); code != http.StatusNoContent {
		t.Fatalf("report: %d", code)
	}
	rows, _ := s.Store.Blocks(BlockFilter{Since: since, Computer: er.ComputerID})
	if len(rows) != 1 || rows[0].Count != 2 {
		t.Fatalf("stored blocks: %+v", rows)
	}

	// Too many entries, invalid entries and oversized reports are refused.
	r.Blocks = make([]policy.Block, policy.MaxBlocks+1)
	for i := range r.Blocks {
		r.Blocks[i] = block
	}
	if code := post(r); code != http.StatusBadRequest {
		t.Fatalf("too many entries: %d", code)
	}
	r.Blocks = []policy.Block{{App: "x"}}
	if code := post(r); code != http.StatusBadRequest {
		t.Fatalf("entry without count: %d", code)
	}
	big := bytes.Repeat([]byte("x"), maxReportSize)
	if code := postReport(t, s, ts.URL, client.cert, []byte(`{"type":"report","error":"`+string(big)+`"}`)); code != http.StatusBadRequest {
		t.Fatalf("oversized report: %d", code)
	}
}

func postReport(t *testing.T, s *Server, url string, cert *tls.Certificate, data []byte) int {
	t.Helper()
	resp, err := s.testHTTPClient(cert).Post(url+"/v1/report", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
