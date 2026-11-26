package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	corebase "github.com/safing/portmaster/service/core/base"
	"github.com/safing/portmaster/service/firewall"
)

// Exit codes of "status --check", as used by Nagios, Icinga, Zabbix and
// most RMM tools.
const (
	checkOK       = 0
	checkWarning  = 1
	checkCritical = 2
	checkUnknown  = 3
)

var (
	statusCheck       bool
	statusMaxIntelAge time.Duration

	// osExit is replaced in tests.
	osExit = os.Exit
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the health of the running Portmaster as JSON, or check it with --check",
	Long: `Show the health of the running Portmaster as JSON.

With --check, print one line and exit with 0 (OK), 1 (warning), 2 (critical)
or 3 (unknown, e.g. the Portmaster is not running), for monitoring and remote
administration tools.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		data, err := syncRequest(cmd.Context(), http.MethodGet, "core/status", nil, mimeJSON, nil)
		if !statusCheck {
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(append(data, '\n'))
			return err
		}

		code, line := evaluateStatus(data, err, statusMaxIntelAge)
		_, _ = fmt.Fprintln(os.Stdout, line)
		osExit(code)
		return nil
	},
}

func init() {
	statusCmd.Flags().StringVar(&syncAPIAddress, "api", corebase.DefaultAPIListenAddress, "address of the Portmaster API")
	statusCmd.Flags().BoolVar(&statusCheck, "check", false, "print one line and exit with a monitoring exit code")
	statusCmd.Flags().DurationVar(&statusMaxIntelAge, "max-intel-age", 14*24*time.Hour, "warn if the filter lists are older than this (0 disables)")
	rootCmd.AddCommand(statusCmd)
}

// evaluateStatus returns the exit code and summary line for a status response.
func evaluateStatus(data []byte, reqErr error, maxIntelAge time.Duration) (int, string) {
	if reqErr != nil {
		return checkUnknown, "UNKNOWN: " + firstLine(reqErr.Error())
	}
	var s firewall.Status
	err := json.Unmarshal(data, &s)
	if err != nil {
		return checkUnknown, "UNKNOWN: invalid status response: " + err.Error()
	}

	var crit, warn []string
	if !s.Ready {
		crit = append(crit, "not all modules running")
	}
	if !s.Interception {
		crit = append(crit, "interception not active")
	}
	if !s.Filtering {
		warn = append(warn, "filtering disabled")
	}
	for _, p := range s.Problems {
		msg := p.Module + ": " + p.Name
		if p.Type == "error" {
			crit = append(crit, msg)
		} else {
			warn = append(warn, msg)
		}
	}
	if maxIntelAge > 0 && s.IntelAgeHours > maxIntelAge.Hours() {
		warn = append(warn, fmt.Sprintf("filter lists %.0f days old", s.IntelAgeHours/24))
	}

	summary := "Portmaster " + s.Version
	switch {
	case len(crit) > 0:
		return checkCritical, "CRITICAL: " + summary + ": " + strings.Join(append(crit, warn...), "; ")
	case len(warn) > 0:
		return checkWarning, "WARNING: " + summary + ": " + strings.Join(warn, "; ")
	default:
		return checkOK, "OK: " + summary + ", filtering active"
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
