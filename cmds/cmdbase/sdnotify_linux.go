package cmdbase

import (
	"net"
	"os"
)

// notifySystemd sends a state, like "READY=1", to systemd (sd_notify). It does
// nothing if the service does not run under systemd with Type=notify.
func notifySystemd(state string) error {
	socketPath := os.Getenv("NOTIFY_SOCKET")
	if socketPath == "" {
		return nil
	}
	// A leading "@" stands for the abstract namespace.
	if socketPath[0] == '@' {
		socketPath = "\x00" + socketPath[1:]
	}

	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socketPath, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	_, err = conn.Write([]byte(state))
	return err
}
