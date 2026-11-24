package firewall

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
)

// tamperEnvVars are environment variables that load foreign code into a
// process when it starts.
var tamperEnvVars = [][]byte{
	[]byte("LD_PRELOAD="),
	[]byte("LD_AUDIT="),
	[]byte("LD_LIBRARY_PATH="),
}

// processTampered reports whether the process may run foreign code: it is
// traced (ptrace), or was started with a variable that loads libraries.
// Anyone can start the trusted app binary like that, so such a process does
// not get the trust of the app.
//
// This raises the bar only: a process of the same user can still change the
// app in other ways. Errors count as tampered (fail closed), except a process
// that is gone.
func processTampered(pid int) (bool, string) {
	if pid <= 0 {
		return false, ""
	}
	procDir := "/proc/" + strconv.Itoa(pid)

	status, err := os.ReadFile(procDir + "/status")
	if err != nil {
		if os.IsNotExist(err) {
			return false, ""
		}
		return true, fmt.Sprintf("failed to read status: %s", err)
	}
	for line := range bytes.SplitSeq(status, []byte("\n")) {
		if value, ok := bytes.CutPrefix(line, []byte("TracerPid:")); ok {
			if tracer := string(bytes.TrimSpace(value)); tracer != "0" {
				return true, "traced by pid " + tracer
			}
			break
		}
	}

	environ, err := os.ReadFile(procDir + "/environ")
	if err != nil {
		if os.IsNotExist(err) {
			return false, ""
		}
		return true, fmt.Sprintf("failed to read environment: %s", err)
	}
	for entry := range bytes.SplitSeq(environ, []byte{0}) {
		for _, prefix := range tamperEnvVars {
			if bytes.HasPrefix(entry, prefix) && len(entry) > len(prefix) {
				return true, "started with " + string(prefix[:len(prefix)-1])
			}
		}
	}
	return false, ""
}
