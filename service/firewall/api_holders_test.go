package firewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/safing/portmaster/base/api"
	"github.com/safing/portmaster/service/network/state"
	"github.com/safing/portmaster/service/process"
)

// TestCheckAPISocketHolders checks that API trust is only granted if every
// process holding the socket of the request is trusted on its own.
var (
	errTestProcessNotFound  = errors.New("process not found")
	errTestPermissionDenied = errors.New("permission denied")
)

func TestCheckAPISocketHolders(t *testing.T) { //nolint:paralleltest // Replaces the package-level process getter.
	root := t.TempDir()
	newExe := func(rel string) string {
		t.Helper()
		path := filepath.Join(root, rel)
		err := os.MkdirAll(filepath.Dir(path), 0o750)
		if err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile(path, nil, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		return path
	}
	newExe("install/portmaster")
	installDir, err := filepath.EvalSymlinks(filepath.Join(root, "install"))
	if err != nil {
		t.Fatal(err)
	}
	authenticatedPath := installDir + string(filepath.Separator)

	const (
		appPid         = 100 // The app, in the installation directory.
		webViewPid     = 101 // The webview process of the app.
		attackerPid    = 200 // Any other process of the user.
		attackerWebPid = 201 // A webview process started by another process.
		exitedPid      = 300 // A process that exited after the scan.
		tamperedAppPid = 400 // The app, started with LD_PRELOAD.
	)
	processes := map[int]*process.Process{
		appPid:         {Pid: appPid, ParentPid: 1, Path: newExe("install/portmaster")},
		webViewPid:     {Pid: webViewPid, ParentPid: appPid, Path: newExe("usr/libexec/webkit2gtk-4.1/WebKitNetworkProcess")},
		attackerPid:    {Pid: attackerPid, ParentPid: 1, Path: newExe("home/user/evil")},
		attackerWebPid: {Pid: attackerWebPid, ParentPid: attackerPid, Path: newExe("usr/libexec/webkit2gtk-4.1/WebKitWebProcess")},
		tamperedAppPid: {Pid: tamperedAppPid, ParentPid: 1, Path: newExe("install/portmaster")},
	}
	originalGetAPIProcess := getAPIProcess
	getAPIProcess = func(_ context.Context, pid int) (*process.Process, error) {
		if p, ok := processes[pid]; ok {
			return p, nil
		}
		return nil, fmt.Errorf("%w: %d", errTestProcessNotFound, pid)
	}
	t.Cleanup(func() { getAPIProcess = originalGetAPIProcess })

	// The pids are made up, so the tamper check must not look at /proc.
	originalCheckProcessTampered := checkProcessTampered
	checkProcessTampered = func(pid int) (bool, string) {
		if pid == tamperedAppPid {
			return true, "test"
		}
		return false, ""
	}
	t.Cleanup(func() { checkProcessTampered = originalCheckProcessTampered })

	tests := []struct {
		name       string
		trustedPid int
		holders    []int
		holdersErr error
		wantAccess bool
		wantRetry  bool
	}{
		{
			name:       "app holds its socket alone",
			trustedPid: appPid,
			holders:    []int{appPid},
			wantAccess: true,
		},
		{
			name:       "webview holds its socket alone",
			trustedPid: webViewPid,
			holders:    []int{webViewPid},
			wantAccess: true,
		},
		{
			name:       "socket shared by app and its webview",
			trustedPid: webViewPid,
			holders:    []int{appPid, webViewPid},
			wantAccess: true,
		},
		{
			name:       "socket shared with a tampered instance of the app",
			trustedPid: appPid,
			holders:    []int{appPid, tamperedAppPid},
		},
		{
			name:       "app inherited the socket of an untrusted parent",
			trustedPid: appPid,
			holders:    []int{attackerPid, appPid},
		},
		{
			name:       "untrusted holder found first",
			trustedPid: appPid,
			holders:    []int{appPid, attackerPid},
		},
		{
			name:       "webview of an untrusted process",
			trustedPid: appPid,
			holders:    []int{appPid, attackerWebPid},
		},
		{
			name:       "holder exited after the scan",
			trustedPid: appPid,
			holders:    []int{appPid, exitedPid},
		},
		{
			name:       "trusted process does not hold the socket anymore",
			trustedPid: appPid,
			holders:    []int{attackerPid},
		},
		{
			name:       "no holders",
			trustedPid: appPid,
			holders:    nil,
			wantRetry:  true,
		},
		{
			name:       "holders cannot be read",
			trustedPid: appPid,
			holdersErr: errTestPermissionDenied,
		},
		{
			name:       "socket not found yet",
			trustedPid: appPid,
			holdersErr: state.ErrConnectionNotFound,
			wantRetry:  true,
		},
		{
			name:       "holders unsupported keeps the result of the connection's process",
			trustedPid: appPid,
			holdersErr: state.ErrSocketHoldersUnsupported,
			wantAccess: true,
		},
	}

	for _, tc := range tests { //nolint:paralleltest // See above.
		t.Run(tc.name, func(t *testing.T) {
			retry, err := checkAPISocketHolders(t.Context(), tc.trustedPid, tc.holders, tc.holdersErr, authenticatedPath)
			if tc.wantAccess {
				if err != nil {
					t.Errorf("access denied: %s", err)
				}
				return
			}
			if err == nil {
				t.Fatal("access granted, expected denial")
			}
			// A denial must be reported as such, so that the request falls
			// back to unprivileged access instead of an internal error.
			if !errors.Is(err, api.ErrAPIAccessDeniedMessage) {
				t.Errorf("denial is not an access denied error: %s", err)
			}
			if retry != tc.wantRetry {
				t.Errorf("retry = %v, want %v", retry, tc.wantRetry)
			}
		})
	}
}
