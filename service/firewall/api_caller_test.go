package firewall

import (
	"context"
	"fmt"
	"testing"

	"github.com/safing/portmaster/service/process"
)

// TestAPICallerUID checks that the user of an API request is only known if
// all processes holding its socket run as the same user.
func TestAPICallerUID(t *testing.T) { //nolint:paralleltest // Replaces the package-level process getter.
	const (
		rootPid    = 100 // portmaster-core run with sudo.
		rootPid2   = 101 // Another process of root.
		userPid    = 200 // portmaster-core run by a normal user.
		missingPid = 300 // A process that exited.
		specialPid = 400 // Resolves to a special process.
	)
	processes := map[int]*process.Process{
		rootPid:    {Pid: rootPid, UserID: 0},
		rootPid2:   {Pid: rootPid2, UserID: 0},
		userPid:    {Pid: userPid, UserID: 1000},
		specialPid: {Pid: process.UnidentifiedProcessID, UserID: process.UnidentifiedProcessID},
	}
	originalGetAPIProcess := getAPIProcess
	getAPIProcess = func(_ context.Context, pid int) (*process.Process, error) {
		if p, ok := processes[pid]; ok {
			return p, nil
		}
		return nil, fmt.Errorf("%w: %d", errTestProcessNotFound, pid)
	}
	t.Cleanup(func() { getAPIProcess = originalGetAPIProcess })

	tests := []struct {
		name      string
		goos      string
		pid       int
		holders   []int
		wantUID   int
		wantKnown bool
	}{
		{name: "root", goos: "linux", pid: rootPid, holders: []int{rootPid}, wantUID: 0, wantKnown: true},
		{name: "root, holders unsupported", goos: "linux", pid: rootPid, wantUID: 0, wantKnown: true},
		{name: "two root processes", goos: "linux", pid: rootPid, holders: []int{rootPid, rootPid2}, wantUID: 0, wantKnown: true},
		{name: "user", goos: "linux", pid: userPid, holders: []int{userPid}, wantUID: 1000, wantKnown: true},
		{name: "root socket shared with a user process", goos: "linux", pid: rootPid, holders: []int{rootPid, userPid}},
		{name: "user socket shared with a root process", goos: "linux", pid: userPid, holders: []int{rootPid, userPid}},
		{name: "holder exited", goos: "linux", pid: rootPid, holders: []int{rootPid, missingPid}},
		{name: "special process", goos: "linux", pid: specialPid},
		{name: "not recorded on windows", goos: "windows", pid: rootPid, holders: []int{rootPid}},
		{name: "not recorded on macOS", goos: "darwin", pid: rootPid},
	}

	for _, tc := range tests { //nolint:paralleltest // See above.
		t.Run(tc.name, func(t *testing.T) {
			uid, known := apiCallerUID(t.Context(), tc.goos, tc.pid, tc.holders)
			if known != tc.wantKnown {
				t.Fatalf("known = %v, want %v (uid %d)", known, tc.wantKnown, uid)
			}
			if known && uid != tc.wantUID {
				t.Errorf("uid = %d, want %d", uid, tc.wantUID)
			}
		})
	}
}
