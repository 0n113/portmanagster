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
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

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

	errProfileFiles = errors.New("give profile files or --clear")
	errRulesFile    = errors.New("give a rules file or --clear")
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
		go pruneBlocks(ctx, s.Store, blockRetention, logger)
		err = setupAlerts(ctx, s, logger)
		if err != nil {
			return err
		}
		logger.Info("serving", "listen", listenAddr, "dir", dataDir)
		if adminListen == "" {
			return s.Serve(ctx, listenAddr)
		}
		certFP, keyFP, err := s.Fingerprints()
		if err != nil {
			return err
		}
		ui, err := adminui.New(adminui.Config{
			Store: s.Store, URL: adminURL, Logger: logger.With("part", "admin-ui"),
			ClientURL: clientURL, ServerFP: certFP, PolicyKeyFP: keyFP,
		})
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
			locked = server.SortedKeys(settings)
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

var groupDeleteCmd = &cobra.Command{
	Use:   "delete NAME",
	Short: "Delete a group without computers, with its unused tokens",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return audited("group.delete", args[0], "", func(s *server.Store) error {
			return s.DeleteGroup(args[0])
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

var tokenListCmd = &cobra.Command{
	Use:   useList,
	Short: "List the enrollment tokens (ID, group, expiry, state)",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		return withStore(func(s *server.Store) error {
			list, err := s.Tokens()
			if err != nil {
				return err
			}
			now := time.Now()
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "ID\tGROUP\tCREATED (UTC)\tEXPIRES (UTC)\tSTATE")
			for _, t := range list {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", t.ID, t.Group,
					t.Created.UTC().Format(time.DateTime), t.Expires.UTC().Format(time.DateTime), t.Status(now))
			}
			return w.Flush()
		})
	},
}

var tokenRevokeCmd = &cobra.Command{
	Use:   "revoke ID",
	Short: "Delete an unused enrollment token (ID from token list)",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return withStore(func(s *server.Store) error {
			group, err := s.RevokeToken(args[0])
			if err != nil {
				return err
			}
			return s.Audit(cliActor, "token.revoke", group, "token "+args[0], time.Now())
		})
	},
}

var computerCmd = &cobra.Command{Use: "computer", Short: "List, show, move and revoke computers"}

var computerMoveCmd = &cobra.Command{
	Use:   "move ID GROUP",
	Short: "Move a computer to another group; its next pull brings the new policy",
	Args:  cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		return audited("computer.move", args[0], "to "+args[1], func(s *server.Store) error {
			return s.MoveComputer(args[0], args[1], time.Now())
		})
	},
}

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
			groups, err := s.Groups()
			if err != nil {
				return err
			}
			byName := make(map[string]*server.Group, len(groups))
			for _, g := range groups {
				byName[g.Name] = g
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
					c.ID, c.Hostname, c.Group, c.OS, c.CoreVersion, seen, policyState(c, byName[c.Group]), server.Health(c), state)
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

	groupCmd.AddCommand(groupCreateCmd, groupSetCmd, groupProfilesCmd, groupRulesCmd, groupListCmd, groupDeleteCmd)
	tokenCmd.AddCommand(tokenCreateCmd, tokenListCmd, tokenRevokeCmd)
	computerCmd.AddCommand(computerListCmd, computerShowCmd, computerMoveCmd, computerRevokeCmd)
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
	settings, err := server.ParseSettings(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return settings, nil
}

// readProfileFile reads a profile export (YAML or JSON) and returns it as
// JSON, the form the client imports.
func readProfileFile(path string) (json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	profile, err := server.ParseProfile(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return profile, nil
}

// readRulesFile reads endpoint rules (YAML or JSON) and checks their form;
// the client validates them fully.
func readRulesFile(path string) (*policy.Rules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rules, err := server.ParseRules(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rules, nil
}

// policyState shows the applied policy version and whether it is current.
func policyState(c *server.Computer, g *server.Group) string {
	state := server.PolicyState(c, g)
	if state == server.PolicyNoReport {
		return state
	}
	return fmt.Sprintf("v%d %s", c.AppliedVersion, state)
}
