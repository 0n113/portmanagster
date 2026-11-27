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
	"slices"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/safing/portmaster/mgmt/adminui"
	"github.com/safing/portmaster/mgmt/policy"
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
	clearProfs bool
	clearRules bool

	errNoConfig     = errors.New("the file has no config section")
	errNoProfile    = errors.New("the file is not a profile export (type: profile, name)")
	errProfileFiles = errors.New("give profile files or --clear")
	errRulesFile    = errors.New("give a rules file or --clear")
	errRuleFormat   = errors.New(`a rule must start with "+ " (allow) or "- " (block)`)
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
		if adminListen == "" {
			return s.Serve(ctx, listenAddr)
		}
		ui, err := adminui.New(adminui.Config{Store: s.Store, URL: adminURL, Logger: logger.With("part", "admin-ui")})
		if err != nil {
			return err
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		errCh := make(chan error, 2)
		go func() { errCh <- s.Serve(ctx, listenAddr) }()
		go func() {
			logger.Info("serving admin UI", "listen", adminListen, "url", adminURL)
			errCh <- ui.Serve(ctx, adminListen, adminCert, adminKey)
		}()
		// The first listener that stops ends both.
		err = <-errCh
		cancel()
		return errors.Join(err, <-errCh)
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
		return audited("group.create", args[0], "", func(s *server.Store) error {
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
		detail := fmt.Sprintf("%d settings, %d locked", len(settings), len(locked))
		return audited("group.set", args[0], detail, func(s *server.Store) error {
			return s.SetGroupPolicy(args[0], settings, locked, time.Now())
		})
	},
}

var groupProfilesCmd = &cobra.Command{
	Use:   "profiles NAME [PROFILE-FILE...]",
	Short: "Set the app profiles of a group from profile exports (YAML or JSON); replaces the previous ones",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		if len(args) == 1 && !clearProfs {
			return errProfileFiles
		}
		profiles := make([]json.RawMessage, 0, len(args)-1)
		for _, path := range args[1:] {
			p, err := readProfileFile(path)
			if err != nil {
				return err
			}
			profiles = append(profiles, p)
		}
		detail := fmt.Sprintf("%d profiles", len(profiles))
		return audited("group.profiles", args[0], detail, func(s *server.Store) error {
			return s.SetGroupProfiles(args[0], profiles, time.Now())
		})
	},
}

var groupRulesCmd = &cobra.Command{
	Use:   "rules NAME [RULES-FILE]",
	Short: "Set the endpoint rules of a group (YAML or JSON with endpoints and serviceEndpoints); they come before all app and global rules",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(_ *cobra.Command, args []string) error {
		var rules *policy.Rules
		switch {
		case len(args) == 2:
			var err error
			rules, err = readRulesFile(args[1])
			if err != nil {
				return err
			}
		case !clearRules:
			return errRulesFile
		}
		detail := "cleared"
		if rules != nil {
			detail = fmt.Sprintf("%d endpoint rules, %d service rules", len(rules.Endpoints), len(rules.ServiceEndpoints))
		}
		return audited("group.rules", args[0], detail, func(s *server.Store) error {
			return s.SetGroupRules(args[0], rules, time.Now())
		})
	},
}

var groupListCmd = &cobra.Command{
	Use:   useList,
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
		err := audited("token.create", tokenGroup, "valid "+tokenValid.String(), func(s *server.Store) error {
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

var computerCmd = &cobra.Command{Use: "computer", Short: "List, show and revoke computers"}

var computerListCmd = &cobra.Command{
	Use:   useList,
	Short: "List the enrolled computers",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		return withStore(func(s *server.Store) error {
			list, err := s.Computers()
			if err != nil {
				return err
			}
			seq, err := s.PolicySeq()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "ID\tHOSTNAME\tGROUP\tOS\tVERSION\tLAST SEEN\tPOLICY\tHEALTH\tSTATE")
			for _, c := range list {
				seen := "never"
				if !c.LastSeen.IsZero() {
					seen = c.LastSeen.Format(time.DateTime) + " UTC"
				}
				state := "active"
				if c.Revoked {
					state = "revoked"
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					c.ID, c.Hostname, c.Group, c.OS, c.CoreVersion, seen, policyState(c, seq), health(c), state)
			}
			return w.Flush()
		})
	},
}

var computerShowCmd = &cobra.Command{
	Use:   "show ID",
	Short: "Show a computer with its last report as JSON",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return withStore(func(s *server.Store) error {
			c, err := s.Computer(args[0])
			if err != nil {
				return err
			}
			return printJSON(c)
		})
	},
}

var computerRevokeCmd = &cobra.Command{
	Use:   "revoke ID",
	Short: "Revoke a computer: the server rejects its certificate from now on",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return audited("computer.revoke", args[0], "", func(s *server.Store) error {
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
	groupProfilesCmd.Flags().BoolVar(&clearProfs, "clear", false, "remove all profiles of the group")
	groupRulesCmd.Flags().BoolVar(&clearRules, "clear", false, "remove the rules of the group")
	tokenCreateCmd.Flags().StringVar(&tokenGroup, "group", "", "group of the computer (required)")
	_ = tokenCreateCmd.MarkFlagRequired("group")
	tokenCreateCmd.Flags().DurationVar(&tokenValid, "valid", 24*time.Hour, "validity of the token")
	tokenCreateCmd.Flags().StringVar(&serverURL, "url", "https://<server>:8443", "server URL for the printed enroll command")

	groupCmd.AddCommand(groupCreateCmd, groupSetCmd, groupProfilesCmd, groupRulesCmd, groupListCmd)
	tokenCmd.AddCommand(tokenCreateCmd)
	computerCmd.AddCommand(computerListCmd, computerShowCmd, computerRevokeCmd)
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

// readProfileFile reads a profile export (YAML or JSON) and returns it as
// JSON, the form the client imports.
func readProfileFile(path string) (json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var export map[string]any
	// YAML is a superset of JSON.
	err = yaml.Unmarshal(data, &export)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if export["type"] != "profile" || export["name"] == nil || export["name"] == "" {
		return nil, fmt.Errorf("%s: %w", path, errNoProfile)
	}
	// The checksum of a JSON export does not match the re-encoded JSON.
	delete(export, "_jess-checksum")
	out, err := json.Marshal(export)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

// policyState tells whether the computer runs the current policy.
func policyState(c *server.Computer, seq uint64) string {
	switch {
	case c.Report == nil:
		return "no report"
	case c.Report.Error != "":
		return fmt.Sprintf("v%d error", c.AppliedVersion)
	case c.AppliedVersion < seq:
		// The sequence counts all changes; an older version may still be
		// the current one for this computer's group.
		return fmt.Sprintf("v%d", c.AppliedVersion)
	default:
		return fmt.Sprintf("v%d current", c.AppliedVersion)
	}
}

// health summarizes the core status of the last report.
func health(c *server.Computer) string {
	if c.Report == nil || len(c.Report.Status) == 0 {
		return "-"
	}
	var st struct {
		Ready        bool `json:"ready"`
		Interception bool `json:"interception"`
		Problems     []struct {
			Type string `json:"type"`
		} `json:"problems"`
	}
	if json.Unmarshal(c.Report.Status, &st) != nil {
		return "unknown"
	}
	var parts []string
	if !st.Ready {
		parts = append(parts, "not ready")
	}
	if !st.Interception {
		parts = append(parts, "no interception")
	}
	if len(st.Problems) > 0 {
		parts = append(parts, fmt.Sprintf("%d problems", len(st.Problems)))
	}
	if len(c.Report.Overridden) > 0 {
		parts = append(parts, fmt.Sprintf("%d overridden", len(c.Report.Overridden)))
	}
	if len(c.Report.Refused) > 0 {
		parts = append(parts, fmt.Sprintf("%d refused", len(c.Report.Refused)))
	}
	if len(parts) == 0 {
		return "ok"
	}
	return strings.Join(parts, ", ")
}

// readRulesFile reads endpoint rules (YAML or JSON) and checks their form;
// the client validates them fully.
func readRulesFile(path string) (*policy.Rules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rules := &policy.Rules{}
	// YAML is a superset of JSON.
	err = yaml.Unmarshal(data, rules)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, rule := range append(slices.Clone(rules.Endpoints), rules.ServiceEndpoints...) {
		if !strings.HasPrefix(rule, "+ ") && !strings.HasPrefix(rule, "- ") {
			return nil, fmt.Errorf("%s: %q: %w", path, rule, errRuleFormat)
		}
	}
	if rules.Empty() {
		return nil, nil //nolint:nilnil // No rules.
	}
	return rules, nil
}
