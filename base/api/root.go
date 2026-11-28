package api

import (
	"errors"
	"fmt"
	"net/http"
	"runtime"
)

// RootAction is an action of the API that only root may perform.
type RootAction string

const (
	// RootActionManage enrolls this computer at a management server, pulls
	// the policy or leaves the management. Always only for root.
	RootActionManage RootAction = "change the management of this computer"

	// RootActionImport imports settings or profiles. Only for root while the
	// computer is managed; unchanged otherwise.
	RootActionImport RootAction = "import settings or profiles on a managed computer"
)

// ErrRootRequired is returned, with HTTP status 403, if a caller that is not
// root requests a root only action.
var ErrRootRequired = errors.New("only root may")

// MayPerformRootAction reports whether the caller of a request may perform
// the action. goos is the operating system (runtime.GOOS), token the
// AuthToken of the request (may be nil) and managed whether this computer
// is enrolled at a management server.
//
// On Linux the caller must be a local process with user ID 0, as recorded in
// the token by the authenticator. Requests without a known caller (API keys,
// dev mode, database bridge) are refused.
//
// OPEN: On other systems there is no reliable check for Administrator or
// SYSTEM yet (the process module does not record the user ID there), so the
// check is not enforced and these actions stay as before: open to every
// program in the Portmaster directory, whoever runs it.
func MayPerformRootAction(goos string, token *AuthToken, action RootAction, managed bool) bool {
	switch action {
	case RootActionManage:
		// Always root only.
	case RootActionImport:
		if !managed {
			return true
		}
	default:
		return false
	}

	if goos != "linux" {
		return true
	}
	return token != nil && token.CallerUIDKnown && token.CallerUID == 0
}

// RequireRoot returns an error with HTTP status 403 if the caller of the
// request may not perform the action, see MayPerformRootAction.
func RequireRoot(ar *Request, action RootAction, managed bool) error {
	var token *AuthToken
	if ar != nil {
		token = ar.AuthToken
	}
	if MayPerformRootAction(runtime.GOOS, token, action, managed) {
		return nil
	}
	return ErrorWithStatus(
		fmt.Errorf("%w %s: run the command as root, e.g. with sudo", ErrRootRequired, action),
		http.StatusForbidden,
	)
}
