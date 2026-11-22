//go:build linux

package proc

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"syscall"
)

// FindSocketHolders returns the PIDs of all processes that currently hold a
// file descriptor of the socket with the given inode.
//
// A socket can be held by several processes at once: file descriptors are
// inherited by child processes and can be passed to other processes. findPID
// returns the first process it finds, which is good enough to attribute a
// connection, but not to decide whether a socket may be trusted, because the
// process that uses the socket may be another one than the one found.
//
// In contrast to findPID, this scans all processes of all users, uses no
// cache and does not stop at the first match. Processes that are not dumpable
// have their /proc entry owned by root, so a scan of the PIDs of the socket's
// user only would miss them. If any process cannot be checked, an error is
// returned instead of a possibly incomplete list.
func FindSocketHolders(inode int) (pids []int, err error) {
	if inode == 0 {
		// Sockets without an inode (eg. in TIME_WAIT) are not held by anyone.
		return nil, errors.New("socket has no inode")
	}
	return findSocketHolders("/proc", socketNameForInode(inode))
}

// socketNameForInode returns the link target of a file descriptor in
// /proc/<pid>/fd/ that refers to the socket with the given inode.
func socketNameForInode(inode int) string {
	// Inodes are unsigned 32-bit values, but stored in an int. On 32-bit
	// platforms, values above MaxInt32 wrap to negative, so format via uint32.
	return "socket:[" + strconv.FormatUint(uint64(uint32(inode)), 10) + "]" //nolint:gosec // Intentional truncation to the unsigned 32-bit inode, see comment above.
}

// findSocketHolders scans all processes in procDir for file descriptors
// linking to socketName. procDir is a parameter for testing.
func findSocketHolders(procDir, socketName string) (pids []int, err error) {
	// Read /proc directly instead of using the PID table of updatePids, which
	// may be up to 10ms old and miss a process that was just started.
	dir, err := os.Open(procDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", procDir, err)
	}
	entries, err := dir.Readdirnames(0)
	_ = dir.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", procDir, err)
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil || pid <= 0 {
			continue // Not a process, eg. "self" or "net".
		}
		held, err := processHoldsSocket(procDir+"/"+entry+"/fd", socketName)
		if err != nil {
			return nil, fmt.Errorf("failed to check file descriptors of pid %d: %w", pid, err)
		}
		if held {
			pids = append(pids, pid)
		}
	}

	return pids, nil
}

// processHoldsSocket returns whether any file descriptor in the given fd
// directory of a process links to socketName. A process that exited in the
// meantime holds nothing. Any other error is returned, as the process might
// hold the socket.
func processHoldsSocket(fdDir, socketName string) (bool, error) {
	dir, err := os.Open(fdDir)
	if err != nil {
		if processGone(err) {
			return false, nil
		}
		return false, err
	}
	names, err := dir.Readdirnames(0)
	_ = dir.Close()
	if err != nil {
		if processGone(err) {
			return false, nil
		}
		return false, err
	}

	for _, name := range names {
		link, err := os.Readlink(fdDir + "/" + name)
		if err != nil {
			if processGone(err) {
				continue // The descriptor was closed or the process exited.
			}
			return false, err
		}
		if link == socketName {
			return true, nil
		}
	}
	return false, nil
}

// processGone returns whether the error means that the process or the file
// descriptor does not exist (anymore).
func processGone(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}
