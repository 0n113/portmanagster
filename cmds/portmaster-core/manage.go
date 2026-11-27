package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/cobra"

	corebase "github.com/safing/portmaster/service/core/base"
)

// The manage commands enroll this computer at a portmanagster server. The
// running Portmaster does the enrollment itself; these commands only call
// its local API.

var (
	manageServer   string
	manageToken    string
	manageServerFP string
	manageKeyFP    string
)

var manageCmd = &cobra.Command{
	Use:   "manage",
	Short: "Enroll this computer at a portmanagster management server",
}

var manageEnrollCmd = &cobra.Command{
	Use:           "enroll",
	Short:         "Enroll with a one-time token; pin the server certificate and the policy key",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true, // main prints the error.
	RunE: func(cmd *cobra.Command, _ []string) error {
		body, err := json.Marshal(map[string]string{
			"server":      manageServer,
			"token":       manageToken,
			"serverFp":    manageServerFP,
			"policyKeyFp": manageKeyFP,
		})
		if err != nil {
			return err
		}
		return printAPIResult(syncRequest(cmd.Context(), http.MethodPost, "managed/enroll", url.Values{}, mimeJSON, body))
	},
}

var manageStatusCmd = &cobra.Command{
	Use:           "status",
	Short:         "Show whether this computer is managed and the state of its policy",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true, // main prints the error.
	RunE: func(cmd *cobra.Command, _ []string) error {
		return printAPIResult(syncRequest(cmd.Context(), http.MethodGet, "managed/status", url.Values{}, mimeJSON, nil))
	},
}

var manageLeaveCmd = &cobra.Command{
	Use:           "leave",
	Short:         "Remove the enrollment; the applied settings stay",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true, // main prints the error.
	RunE: func(cmd *cobra.Command, _ []string) error {
		return printAPIResult(syncRequest(cmd.Context(), http.MethodPost, "managed/leave", url.Values{}, mimeJSON, []byte("{}")))
	},
}

func init() {
	manageCmd.PersistentFlags().StringVar(&syncAPIAddress, "api", corebase.DefaultAPIListenAddress, "address of the Portmaster API")
	manageEnrollCmd.Flags().StringVar(&manageServer, "server", "", "server URL, e.g. https://pm.example.lan:8443")
	manageEnrollCmd.Flags().StringVar(&manageToken, "token", "", "one-time enrollment token")
	manageEnrollCmd.Flags().StringVar(&manageServerFP, "server-fp", "", "fingerprint of the server certificate (sha256:...)")
	manageEnrollCmd.Flags().StringVar(&manageKeyFP, "policy-key-fp", "", "fingerprint of the policy key (sha256:...)")
	for _, f := range []string{"server", "token", "server-fp", "policy-key-fp"} {
		_ = manageEnrollCmd.MarkFlagRequired(f)
	}
	manageCmd.AddCommand(manageEnrollCmd, manageStatusCmd, manageLeaveCmd)
	rootCmd.AddCommand(manageCmd)
}

func printAPIResult(data []byte, err error) error {
	if err != nil {
		return err
	}
	var out bytes.Buffer
	if json.Indent(&out, bytes.TrimSpace(data), "", "  ") != nil {
		out.Reset()
		out.Write(bytes.TrimSpace(data))
	}
	out.WriteByte('\n')
	_, err = os.Stdout.Write(out.Bytes())
	return err
}
