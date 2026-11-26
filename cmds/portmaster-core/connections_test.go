package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeNetquery struct {
	mu      sync.Mutex
	rows    []map[string]any
	queries []map[string]any
}

func (f *fakeNetquery) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	body, _ := io.ReadAll(r.Body)
	var q map[string]any
	_ = json.Unmarshal(body, &q)
	f.queries = append(f.queries, q)

	from := q["query"].(map[string]any)["started"].(map[string]any)["$ge"].(float64) //nolint:forcetypeassert
	page := int(q["page"].(float64))                                                 //nolint:forcetypeassert
	pageSize := int(q["pageSize"].(float64))                                         //nolint:forcetypeassert
	var match []map[string]any
	for _, row := range f.rows {
		t, _ := time.ParseInLocation("2006-01-02 15:04:05", row["started"].(string), time.UTC) //nolint:forcetypeassert
		if float64(t.Unix()) >= from {
			match = append(match, row)
		}
	}
	start := min(page*pageSize, len(match))
	end := min(start+pageSize, len(match))
	data, err := json.Marshal(map[string]any{"results": match[start:end]})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(data)
}

func fakeRow(id string, started time.Time, verdict int) map[string]any {
	return map[string]any{
		"id":           id,
		"started":      started.UTC().Format("2006-01-02 15:04:05"),
		"verdict":      verdict,
		"direction":    "outbound",
		"profile":      "local/abc",
		"profile_name": "Curl",
		"domain":       "example.com.",
		"remote_ip":    "93.184.215.14",
		"remote_port":  443,
		"ip_protocol":  6,
		"extra_data": map[string]any{
			"pid":            42,
			"reason":         map[string]any{"Msg": "blocked by filter list"},
			"blockedByLists": []string{"MAL"},
		},
	}
}

func exportLines(t *testing.T, now time.Time) []ConnectionEvent {
	t.Helper()

	var buf bytes.Buffer
	err := exportConnections(context.Background(), &buf, now)
	if err != nil {
		t.Fatal(err)
	}
	var events []ConnectionEvent
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var ev ConnectionEvent
		err := json.Unmarshal([]byte(line), &ev)
		if err != nil {
			t.Fatalf("invalid line %q: %s", line, err)
		}
		events = append(events, ev)
	}
	return events
}

func ids(events []ConnectionEvent) string {
	s := make([]string, 0, len(events))
	for _, ev := range events {
		s = append(s, ev.ID)
	}
	return strings.Join(s, ",")
}

func TestExportConnectionsCursor(t *testing.T) { //nolint:paralleltest // Changes package flags.
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	fake := &fakeNetquery{rows: []map[string]any{
		fakeRow("a", now.Add(-2*time.Hour), 2),
		fakeRow("b", now.Add(-30*time.Minute), 3),
		fakeRow("c", now.Add(-10*time.Second), 2),
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	oldAPI, oldCursor, oldSince := syncAPIAddress, connCursor, connSince
	defer func() { syncAPIAddress, connCursor, connSince = oldAPI, oldCursor, oldSince }()
	syncAPIAddress = strings.TrimPrefix(srv.URL, "http://")
	connCursor = filepath.Join(t.TempDir(), "cursor.json")
	connSince = time.Hour

	// First run: --since applies.
	got := exportLines(t, now)
	if ids(got) != "b,c" {
		t.Fatalf("first run exported %q, want b,c", ids(got))
	}
	if ev := got[0]; ev.Verdict != "blocked" || ev.Reason != "blocked by filter list" ||
		ev.FilterLists[0] != "MAL" || ev.PID != 42 || ev.Time != now.Add(-30*time.Minute).Format(time.RFC3339) {
		t.Errorf("unexpected event: %+v", ev)
	}

	// Second run: nothing new.
	if got := exportLines(t, now.Add(time.Minute)); len(got) != 0 {
		t.Fatalf("second run exported %q, want nothing", ids(got))
	}

	// A connection saved late with an earlier start, within the overlap, and a new one.
	fake.mu.Lock()
	fake.rows = append(fake.rows,
		fakeRow("late", now.Add(-60*time.Second), 2),
		fakeRow("d", now.Add(30*time.Second), 4),
	)
	fake.mu.Unlock()
	got = exportLines(t, now.Add(2*time.Minute))
	if ids(got) != "late,d" {
		t.Fatalf("third run exported %q, want late,d", ids(got))
	}
}

func TestExportConnectionsPaging(t *testing.T) { //nolint:paralleltest // Changes package flags.
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	fake := &fakeNetquery{}
	for i := range connectionsPageSize + 5 {
		fake.rows = append(fake.rows, fakeRow("r"+time.Duration(i).String(), now.Add(-time.Minute), 2))
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	oldAPI, oldCursor, oldLimit := syncAPIAddress, connCursor, connLimit
	defer func() { syncAPIAddress, connCursor, connLimit = oldAPI, oldCursor, oldLimit }()
	syncAPIAddress = strings.TrimPrefix(srv.URL, "http://")
	connCursor = ""

	connLimit = 100000
	if got := exportLines(t, now); len(got) != connectionsPageSize+5 {
		t.Errorf("exported %d, want %d", len(got), connectionsPageSize+5)
	}
	connLimit = 10
	if got := exportLines(t, now); len(got) != 10 {
		t.Errorf("with --limit 10 exported %d", len(got))
	}
}

func TestConnectionCursorPrune(t *testing.T) {
	t.Parallel()

	c := &connectionCursor{}
	c.add("old", 1000)
	c.add("new", 1000+cursorOverlap+5)
	c.prune()
	if _, ok := c.Seen["old"]; ok {
		t.Error("old entry was not pruned")
	}
	if _, ok := c.Seen["new"]; !ok || c.Started != 1000+cursorOverlap+5 {
		t.Errorf("unexpected cursor: %+v", c)
	}
}
