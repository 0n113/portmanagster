//go:build !linux

package firewall

// checkProcessTampered is replaced in tests, which use made-up pids.
var checkProcessTampered = processTampered

// processTampered is not implemented on this platform.
func processTampered(pid int) (bool, string) {
	return false, ""
}
