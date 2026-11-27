package api

import (
	"errors"
	"net/http"
	"runtime"
	"testing"
)

func TestMayPerformRootAction(t *testing.T) {
	t.Parallel()

	root := &AuthToken{Read: PermitSelf, Write: PermitSelf, CallerUID: 0, CallerUIDKnown: true}
	user := &AuthToken{Read: PermitSelf, Write: PermitSelf, CallerUID: 1000, CallerUIDKnown: true}
	// A token without a known caller, e.g. of an API key or the dev mode.
	// Its CallerUID is 0, which must not be taken for root.
	unknown := &AuthToken{Read: PermitSelf, Write: PermitSelf}

	tests := []struct {
		name    string
		goos    string
		token   *AuthToken
		action  RootAction
		managed bool
		want    bool
	}{
		{"linux: root may manage", "linux", root, RootActionManage, false, true},
		{"linux: root may manage a managed computer", "linux", root, RootActionManage, true, true},
		{"linux: user may not manage", "linux", user, RootActionManage, false, false},
		{"linux: user may not manage a managed computer", "linux", user, RootActionManage, true, false},
		{"linux: unknown caller may not manage", "linux", unknown, RootActionManage, true, false},
		{"linux: no token may not manage", "linux", nil, RootActionManage, true, false},

		{"linux: user may import on an unmanaged computer", "linux", user, RootActionImport, false, true},
		{"linux: unknown caller may import on an unmanaged computer", "linux", unknown, RootActionImport, false, true},
		{"linux: user may not import on a managed computer", "linux", user, RootActionImport, true, false},
		{"linux: unknown caller may not import on a managed computer", "linux", unknown, RootActionImport, true, false},
		{"linux: root may import on a managed computer", "linux", root, RootActionImport, true, true},

		{"linux: unknown action is denied", "linux", root, RootAction("other"), true, false},

		// Not enforced on other systems yet, see MayPerformRootAction.
		{"windows: unchanged for manage", "windows", unknown, RootActionManage, true, true},
		{"windows: unchanged for import", "windows", unknown, RootActionImport, true, true},
		{"darwin: unchanged for manage", "darwin", unknown, RootActionManage, true, true},
		{"windows: unknown action is denied", "windows", root, RootAction("other"), true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := MayPerformRootAction(tc.goos, tc.token, tc.action, tc.managed)
			if got != tc.want {
				t.Errorf("MayPerformRootAction(%q, %+v, %q, %v) = %v, want %v", tc.goos, tc.token, tc.action, tc.managed, got, tc.want)
			}
		})
	}
}

func TestRequireRoot(t *testing.T) {
	t.Parallel()

	user := &Request{AuthToken: &AuthToken{Read: PermitSelf, Write: PermitSelf, CallerUID: 1000, CallerUIDKnown: true}}
	root := &Request{AuthToken: &AuthToken{Read: PermitSelf, Write: PermitSelf, CallerUID: 0, CallerUIDKnown: true}}

	if err := RequireRoot(root, RootActionManage, true); err != nil {
		t.Errorf("root denied: %s", err)
	}
	if err := RequireRoot(user, RootActionImport, false); err != nil {
		t.Errorf("import on an unmanaged computer denied: %s", err)
	}

	err := RequireRoot(user, RootActionManage, false)
	if runtime.GOOS != "linux" {
		// Not enforced on other systems yet.
		if err != nil {
			t.Errorf("denied on %s: %s", runtime.GOOS, err)
		}
		return
	}
	if err == nil {
		t.Fatal("user allowed to manage")
	}
	if !errors.Is(err, ErrRootRequired) {
		t.Errorf("error is not ErrRootRequired: %s", err)
	}
	var statusProvider HTTPStatusProvider
	if !errors.As(err, &statusProvider) || statusProvider.HTTPStatus() != http.StatusForbidden {
		t.Errorf("error has no status 403: %s", err)
	}
}
