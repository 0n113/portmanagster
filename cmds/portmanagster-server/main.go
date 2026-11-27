// Command portmanagster-server is the management server for Portmaster
// clients: it enrolls computers and serves each one its signed policy.
// The admin commands work directly on the data directory of the server
// host and need root.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/safing/portmaster/mgmt/server"
)

var (
	dataDir    string
	initName   string
	initHosts  []string
	listenAddr string
	tokenGroup string
	tokenValid time.Duration
	lockKeys   []string
	lockAll    bool
	serverURL  string

	errNoConfig = errors.New("the file has no config section")
)

var rootCmd = &cobra.Command{
	Use:           "portmanagster-server",
	Short:         "Management server for Portmaster clients",
	SilenceUsage:  true,
	SilenceErrors: true,
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create the CA, server certificate, policy signing key and database",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		err := server.Init(dataDir, initName, initHosts, time.Now())
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stdout, "initialized %s\n", dataDir)
		return printFingerprints()
	},
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the client API (HTTPS with client certificates)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		s, err := server.Load(dataDir, logger)
		if err != nil {
			return err
		}
		defer func() { _ = s.Store.Close() }()
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		logger.Info("serving", "listen", listenAddr, "dir", dataDir)
		return s.Serve(ctx, listenAddr)
	},
}

var fingerprintsCmd = &cobra.Command{
	Use:   "fingerprints",
	Short: "Print the fingerprints clients pin at enrollment",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		return printFingerprints()
	},
}

var groupCmd = &cobra.Command{Use: "group", Short: "Manage groups and their policy"}

var groupCreateCmd = &cobra.Command{
	Use:   "create NAME",
	Short: "Create an empty group",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return withStore(func(s *server.Store) error {
			return s.CreateGroup(args[0], time.Now())
		})
	},
}

var groupSetCmd = &cobra.Command{
	Use:   "set NAME SETTINGS-FILE",
	Short: "Set the settings of a group from a settings export (YAML or JSON); replaces the previous ones",
	Args:  cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		settings, err := readSettingsFile(args[1])
		if err != nil {
			return err
		}
		locked := lockKeys
		if lockAll {
			locked = make([]string, 0, len(settings))
			for k := range settings {
				locked = append(locked, k)
			}
			sort.Strings(locked)
		}
		return withStore(func(s *server.Store) error {
			return s.SetGroupPolicy(args[0], settings, locked, time.Now())
		})
	},
}

var groupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the groups with their settings as JSON",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		return withStore(func(s *server.Store) error {
			groups, err := s.Groups()
			if err != nil {
				return err
			}
			return printJSON(groups)
		})
	},
}

var tokenCmd = &cobra.Command{Use: "token", Short: "Manage enrollment tokens"}

var tokenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a one-time enrollment token for a group and print the enroll command",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		var token string
		err := withStore(func(s *server.Store) error {
			var err error
			token, err = s.CreateToken(tokenGroup, tokenValid, time.Now())
			return err
		})
		if err != nil {
			return err
		}
		srv, err := server.Load(dataDir, nil)
		if err != nil {
			return err
		}
		defer func() { _ = srv.Store.Close() }()
		certFP, keyFP, err := srv.Fingerprints()
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stdout, "token (valid %s, one use): %s\n\nOn the client, as root:\n", tokenValid, token)
		_, _ = fmt.Fprintf(os.Stdout, "  portmaster-core manage enroll --server %s --token %s \\\n    --server-fp %s \\\n    --policy-key-fp %s\n",
			serverURL, token, certFP, keyFP)
		return nil
	},
}

var computerCmd = &cobra.Command{Use: "computer", Short: "List and revoke computers"}

var computerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the enrolled computers",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		return withStore(func(s *server.Store) error {
			list, err := s.Computers()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "ID\tHOSTNAME\tGROUP\tOS\tVERSION\tLAST SEEN\tSTATE")
			for _, c := range list {
				seen := "never"
				if !c.LastSeen.IsZero() {
					seen = c.LastSeen.Format(time.DateTime) + " UTC"
				}
				state := "active"
				if c.Revoked {
					state = "revoked"
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.ID, c.Hostname, c.Group, c.OS, c.CoreVersion, seen, state)
			}
			return w.Flush()
		})
	},
}

var computerRevokeCmd = &cobra.Command{
	Use:   "revoke ID",
	Short: "Revoke a computer: the server rejects its certificate from now on",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return withStore(func(s *server.Store) error {
			return s.Revoke(args[0])
		})
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&dataDir, "dir", "/var/lib/portmanagster", "data directory")
	initCmd.Flags().StringVar(&initName, "name", "portmanagster", "name of the server, used in the certificates")
	initCmd.Flags().StringSliceVar(&initHosts, "host", nil, "DNS name or IP address of the server (repeatable, required)")
	_ = initCmd.MarkFlagRequired("host")
	serveCmd.Flags().StringVar(&listenAddr, "listen", ":8443", "listen address")
	groupSetCmd.Flags().StringSliceVar(&lockKeys, "lock", nil, "settings key a local admin must not change (repeatable)")
	groupSetCmd.Flags().BoolVar(&lockAll, "lock-all", false, "lock all settings of the file")
	tokenCreateCmd.Flags().StringVar(&tokenGroup, "group", "", "group of the computer (required)")
	_ = tokenCreateCmd.MarkFlagRequired("group")
	tokenCreateCmd.Flags().DurationVar(&tokenValid, "valid", 24*time.Hour, "validity of the token")
	tokenCreateCmd.Flags().StringVar(&serverURL, "url", "https://<server>:8443", "server URL for the printed enroll command")

	groupCmd.AddCommand(groupCreateCmd, groupSetCmd, groupListCmd)
	tokenCmd.AddCommand(tokenCreateCmd)
	computerCmd.AddCommand(computerListCmd, computerRevokeCmd)
	rootCmd.AddCommand(initCmd, serveCmd, fingerprintsCmd, groupCmd, tokenCmd, computerCmd)
}

func main() {
	err := rootCmd.ExecuteContext(context.Background())
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func withStore(fn func(s *server.Store) error) error {
	s, err := server.OpenStore(dataDir + "/" + server.FileDB)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	return fn(s)
}

func printFingerprints() error {
	s, err := server.Load(dataDir, nil)
	if err != nil {
		return err
	}
	defer func() { _ = s.Store.Close() }()
	certFP, keyFP, err := s.Fingerprints()
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "server certificate: %s\npolicy key:         %s\n", certFP, keyFP)
	return nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// readSettingsFile reads a settings export (YAML or JSON) and returns its
// config with slash-joined keys.
func readSettingsFile(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var export struct {
		Config map[string]any `json:"config" yaml:"config"`
	}
	// YAML is a superset of JSON.
	err = yaml.Unmarshal(data, &export)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if export.Config == nil {
		return nil, fmt.Errorf("%s: %w", path, errNoConfig)
	}
	return flatten(export.Config, ""), nil
}

// flatten turns nested maps into slash-joined keys; lists are values.
func flatten(m map[string]any, prefix string) map[string]any {
	out := make(map[string]any)
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "/" + k
		}
		if sub, ok := v.(map[string]any); ok && !strings.Contains(k, "/") {
			maps.Copy(out, flatten(sub, key))
			continue
		}
		out[key] = v
	}
	return out
}
