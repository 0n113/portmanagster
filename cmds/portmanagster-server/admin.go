package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/safing/portmaster/mgmt/server"
)

const (
	// cliActor is the audit actor of the admin commands.
	cliActor = "cli"
	useList  = "list"
)

var (
	adminRole   string
	adminURL    string
	adminValid  time.Duration
	auditSince  time.Duration
	auditLimit  int
	adminListen string
	adminCert   string
	adminKey    string
)

var adminCmd = &cobra.Command{Use: "admin", Short: "Manage the accounts of the admin web UI"}

var adminAddCmd = &cobra.Command{
	Use:   "add NAME",
	Short: "Create an account and print its one-time setup link",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		name := args[0]
		return withStore(func(s *server.Store) error {
			now := time.Now()
			err := s.AddAdmin(name, adminRole, now)
			if err != nil {
				return err
			}
			err = s.Audit(cliActor, "admin.add", name, "role "+adminRole, now)
			if err != nil {
				return err
			}
			return printSetupLink(s, name, now)
		})
	},
}

var adminResetCmd = &cobra.Command{
	Use:   "reset NAME",
	Short: "Remove the passkeys, TOTP and sessions of an account and print a new setup link",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		name := args[0]
		return withStore(func(s *server.Store) error {
			now := time.Now()
			err := s.ResetAdmin(name)
			if err != nil {
				return err
			}
			err = s.Audit(cliActor, "admin.reset", name, "", now)
			if err != nil {
				return err
			}
			return printSetupLink(s, name, now)
		})
	},
}

var adminRemoveCmd = &cobra.Command{
	Use:   "remove NAME",
	Short: "Delete an account with its passkeys and sessions",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return audited("admin.remove", args[0], "", func(s *server.Store) error {
			return s.RemoveAdmin(args[0])
		})
	},
}

var adminListCmd = &cobra.Command{
	Use:   useList,
	Short: "List the accounts",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		return withStore(func(s *server.Store) error {
			list, err := s.Admins()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "NAME\tROLE\tPASSKEYS\tTOTP\tCREATED")
			for _, a := range list {
				totp := "no"
				if a.TOTPSecret != "" {
					totp = "yes"
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", a.Name, a.Role, len(a.Credentials), totp, a.Created.UTC().Format(time.DateTime))
			}
			return w.Flush()
		})
	},
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Show the audit log of changes, newest first",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		return withStore(func(s *server.Store) error {
			since := time.Time{}
			if auditSince > 0 {
				since = time.Now().Add(-auditSince)
			}
			list, err := s.AuditLog(since, auditLimit)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "TIME (UTC)\tACTOR\tACTION\tOBJECT\tDETAIL")
			for _, e := range list {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", e.Time.UTC().Format(time.DateTime), e.Actor, e.Action, e.Object, e.Detail)
			}
			return w.Flush()
		})
	},
}

func init() {
	adminAddCmd.Flags().StringVar(&adminRole, "role", server.RoleAdmin, "role: admin (may change everything) or viewer (read only)")
	for _, c := range []*cobra.Command{adminAddCmd, adminResetCmd} {
		c.Flags().StringVar(&adminURL, "url", "http://localhost:8444", "URL of the admin UI for the printed setup link")
		c.Flags().DurationVar(&adminValid, "valid", 15*time.Minute, "validity of the setup link")
	}
	auditCmd.Flags().DurationVar(&auditSince, "since", 0, "only entries of this last duration (e.g. 24h)")
	auditCmd.Flags().IntVar(&auditLimit, "limit", 100, "maximum number of entries")
	serveCmd.Flags().StringVar(&adminListen, "admin-listen", "127.0.0.1:8444", "listen address of the admin UI (empty: off)")
	serveCmd.Flags().StringVar(&adminURL, "admin-url", "http://localhost:8444", "URL under which admins open the admin UI; passkeys are bound to its host")
	serveCmd.Flags().StringVar(&adminCert, "admin-cert", "", "TLS certificate of the admin UI (PEM; without it the UI uses plain HTTP)")
	serveCmd.Flags().StringVar(&adminKey, "admin-key", "", "TLS key of the admin UI (PEM)")

	adminCmd.AddCommand(adminAddCmd, adminListCmd, adminRemoveCmd, adminResetCmd)
	rootCmd.AddCommand(adminCmd, auditCmd)
}

// audited runs fn on the store and records the change in the audit log.
func audited(action, object, detail string, fn func(s *server.Store) error) error {
	return withStore(func(s *server.Store) error {
		err := fn(s)
		if err != nil {
			return err
		}
		return s.Audit(cliActor, action, object, detail, time.Now())
	})
}

func printSetupLink(s *server.Store, name string, now time.Time) error {
	token, err := s.CreateSetupLink(name, adminValid, now)
	if err != nil {
		return err
	}
	link := strings.TrimSuffix(adminURL, "/") + "/setup?token=" + url.QueryEscape(token)
	_, _ = fmt.Fprintf(os.Stdout, "setup link for %s (valid %s, one use):\n  %s\n", name, adminValid, link)
	return nil
}
