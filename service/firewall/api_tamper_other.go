//go:build !linux

package firewall

// processTampered is not implemented on this platform.
func processTampered(pid int) (bool, string) {
	return false, ""
}
