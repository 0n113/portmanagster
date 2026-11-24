package firewall

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func TestProcessTampered(t *testing.T) {
	t.Parallel()

	start := func(env []string) *exec.Cmd {
		cmd := exec.Command("sleep", "5")
		cmd.Env = env
		err := cmd.Start()
		if err != nil {
			t.Skipf("cannot start sleep: %s", err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
		// Start returns while the kernel may still set up the new program;
		// until then, /proc/<pid>/environ is empty.
		environ := "/proc/" + strconv.Itoa(cmd.Process.Pid) + "/environ"
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			data, err := os.ReadFile(environ)
			if err == nil && bytes.Contains(data, []byte("PATH=")) {
				break
			}
		}
		return cmd
	}

	clean := start([]string{"PATH=/usr/bin:/bin"})
	if tampered, reason := processTampered(clean.Process.Pid); tampered {
		t.Errorf("clean process reported as tampered: %s", reason)
	}

	preload := start([]string{"PATH=/usr/bin:/bin", "LD_LIBRARY_PATH=/nonexistent"})
	if tampered, _ := processTampered(preload.Process.Pid); !tampered {
		t.Error("process with LD_LIBRARY_PATH not reported as tampered")
	}

	if tampered, _ := processTampered(1 << 30); tampered {
		t.Error("missing process reported as tampered")
	}
}
