package sync

import (
	"github.com/safing/portmaster/base/api"
)

// ManagedInstance is implemented by instances that know whether this
// computer is enrolled at a management server. While it is, settings and
// profiles may only be imported through the API by root.
type ManagedInstance interface {
	IsManaged() bool
}

// isManaged returns whether this computer is managed. Without an instance
// that knows (e.g. in tests), it is not.
func isManaged() bool {
	if module == nil {
		return false
	}
	mi, ok := module.instance.(ManagedInstance)
	return ok && mi.IsManaged()
}

// checkImportAllowed refuses imports through the API by callers that are not
// root while this computer is managed. The policy of the management server
// is applied with ImportSettings and ImportProfile directly and is not
// affected.
func checkImportAllowed(ar *api.Request) error {
	return api.RequireRoot(ar, api.RootActionImport, isManaged())
}
