//go:build linux

package proc

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"testing"
)

// TestFindSocketHoldersFake checks the scan on a fake /proc tree.
func TestFindSocketHoldersFake(t *testing.T) {
	t.Parallel()

	procDir := t.TempDir()
	link := func(pid, fd, target string) {
		t.Helper()
		dir := filepath.Join(procDir, pid, "fd")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, fd)); err != nil {
			t.Fatal(err)
		}
	}
	link("100", "3", "socket:[42]")
	link("100", "4", "socket:[43]")
	link("200", "0", "/dev/null")
	link("200", "1", "socket:[420]")
	link("300", "7", "socket:[42]")  // A second holder, eg. an inherited descriptor.
	link("self", "3", "socket:[42]") // Not a PID, must be ignored.
	// A process that exited between listing /proc and reading its descriptors.
	if err := os.MkdirAll(filepath.Join(procDir, "400"), 0o755); err != nil {
		t.Fatal(err)
	}

	pids, err := findSocketHolders(procDir, "socket:[42]")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	slices.Sort(pids)
	if !slices.Equal(pids, []int{100, 300}) {
		t.Errorf("found holders %v, expected [100 300]", pids)
	}

	pids, err = findSocketHolders(procDir, "socket:[44]")
	if err != nil || len(pids) != 0 {
		t.Errorf("found holders %v (err=%v) for a socket nobody holds", pids, err)
	}
}

// TestFindSocketHoldersUnreadable checks that a process whose descriptors
// cannot be read fails the scan, instead of being skipped: it might hold the
// socket.
func TestFindSocketHoldersUnreadable(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("root can read directories without permissions")
	}

	procDir := t.TempDir()
	fdDir := filepath.Join(procDir, "500", "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[42]", filepath.Join(fdDir, "3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fdDir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(fdDir, 0o755) }) //nolint:gosec // Test directory.

	pids, err := findSocketHolders(procDir, "socket:[42]")
	if err == nil {
		t.Errorf("expected an error for an unreadable process, got holders %v", pids)
	}
}

// TestFindSocketHoldersInherited checks the scan of the real /proc entries of
// the test process and of a child that inherited its socket. Tests usually do
// not run as root and cannot read the descriptors of other users' processes,
// so the scan runs on a directory that links only to the own processes.
func TestFindSocketHoldersInherited(t *testing.T) {
	t.Parallel()

	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep not available")
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}
	defer func() { _ = listener.Close() }()
	file, err := listener.File()
	if err != nil {
		t.Fatalf("failed to get socket file: %s", err)
	}
	defer func() { _ = file.Close() }()
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil { //nolint:gosec // File descriptors fit into an int.
		t.Fatalf("failed to stat socket: %s", err)
	}
	inode := int(stat.Ino) //nolint:gosec // Inode numbers fit into an int.

	socketName := socketNameForInode(inode)
	procDir := t.TempDir()
	linkProc := func(pid int) {
		t.Helper()
		name := strconv.Itoa(pid)
		if err := os.Symlink("/proc/"+name, filepath.Join(procDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	linkProc(os.Getpid())

	pids, err := findSocketHolders(procDir, socketName)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !slices.Equal(pids, []int{os.Getpid()}) {
		t.Fatalf("found holders %v, expected only own pid %d", pids, os.Getpid())
	}

	// Start a child that inherits the socket.
	cmd := exec.Command(sleepPath, "30")
	cmd.ExtraFiles = []*os.File{file}
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start child: %s", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	linkProc(cmd.Process.Pid)
	pids, err = findSocketHolders(procDir, socketName)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	slices.Sort(pids)
	want := []int{os.Getpid(), cmd.Process.Pid}
	slices.Sort(want)
	if !slices.Equal(pids, want) {
		t.Errorf("found holders %v, expected %v", pids, want)
	}
}
