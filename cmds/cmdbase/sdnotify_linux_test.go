package cmdbase

import (
	"net"
	"path/filepath"
	"testing"
)

func TestNotifySystemd(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "notify")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socketPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	t.Setenv("NOTIFY_SOCKET", socketPath)
	err = notifySystemd("READY=1")
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 64)
	n, _, err := listener.ReadFromUnix(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Errorf("got %q, want READY=1", got)
	}

	t.Setenv("NOTIFY_SOCKET", "")
	err = notifySystemd("READY=1")
	if err != nil {
		t.Errorf("without NOTIFY_SOCKET: %s", err)
	}
}
