package tags

import (
	"testing"

	"github.com/safing/portmaster/service/process"
)

func TestInterpHandlerEmptyCmdLine(t *testing.T) {
	t.Parallel()

	for _, cmdLine := range []string{"", "   ", "\t"} {
		p := &process.Process{Path: "/usr/bin/python3", CmdLine: cmdLine}
		h := new(InterpHandler)
		h.AddTags(p) // Must not panic.
		if len(p.Tags) != 0 || p.MatchingPath != "" {
			t.Errorf("cmdline %q: unexpected tags/matching path", cmdLine)
		}
		_ = h.CreateProfile(p) // Must not panic.
	}
}
