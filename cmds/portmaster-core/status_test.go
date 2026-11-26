package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var errUnreachableTest = errors.New("cannot reach\nmore")

func TestEvaluateStatus(t *testing.T) {
	t.Parallel()

	const week = 7 * 24 * time.Hour
	cases := []struct {
		name string
		data string
		err  error
		code int
		want string
	}{
		{"ok", `{"version":"0.3.5","ready":true,"interception":true,"filtering":true,"intelAgeHours":20,"problems":[]}`, nil, checkOK, "OK: Portmaster 0.3.5"},
		{"unreachable", "", errUnreachableTest, checkUnknown, "UNKNOWN: cannot reach"},
		{"garbage", "nope", nil, checkUnknown, "UNKNOWN: invalid status response"},
		{"no interception", `{"ready":true,"interception":false,"filtering":true}`, nil, checkCritical, "interception not active"},
		{"not ready", `{"ready":false,"interception":true,"filtering":true}`, nil, checkCritical, "not all modules running"},
		{"module error", `{"ready":true,"interception":true,"filtering":true,"problems":[{"module":"Resolver","type":"error","name":"No DNS"}]}`, nil, checkCritical, "Resolver: No DNS"},
		{"module warning", `{"ready":true,"interception":true,"filtering":true,"problems":[{"module":"Updates","type":"warning","name":"Update failed"}]}`, nil, checkWarning, "Updates: Update failed"},
		{"filtering off", `{"ready":true,"interception":true,"filtering":false}`, nil, checkWarning, "filtering disabled"},
		{"old lists", `{"ready":true,"interception":true,"filtering":true,"intelAgeHours":240}`, nil, checkWarning, "filter lists 10 days old"},
	}
	for _, c := range cases {
		code, line := evaluateStatus([]byte(c.data), c.err, week)
		if code != c.code || !strings.Contains(line, c.want) {
			t.Errorf("%s: got %d %q, want %d containing %q", c.name, code, line, c.code, c.want)
		}
	}
}
