package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/safing/jess"

	"github.com/safing/portmaster/mgmt/policy"
	"github.com/safing/portmaster/mgmt/server"
)

var (
	offlineOut  string
	signKeyFile string
	signOut     string
	signYes     bool
	exportOut   string

	errFileExists = errors.New("the file exists already")
	errNotSigned  = errors.New("not signed: no confirmation")
)

var offlineKeyCmd = &cobra.Command{
	Use:   "offline-key",
	Short: "Offline signing of the group policies: the server only distributes them",
	Long: `Offline signing of the group policies.

With an offline key set on the server, the computers apply only group
policies signed with it. The key stays on an admin computer that is not
the server; the server cannot change what the computers apply, even if it
is taken over.

  1. On the admin computer: offline-key create --out offline.key
  2. On the server:         offline-key set offline.key.pub
  3. For every group:       group export NAME --out office.json (server)
                            sign --key offline.key office.json  (admin computer)
                            group publish NAME office.signed.json (server)

Until a group has a signed policy, its computers keep their last policy.`,
}

var offlineKeyCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an offline key (run on the admin computer, not on the server)",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		if offlineOut == "" {
			return errors.New("--out is required") //nolint:err113 // CLI usage error.
		}
		for _, path := range []string{offlineOut, offlineOut + ".pub"} {
			if _, err := os.Stat(path); err == nil { //nolint:noinlineerr // Existence check.
				return fmt.Errorf("%s: %w", path, errFileExists)
			}
		}
		key, err := policy.GenerateKey("portmanagster offline")
		if err != nil {
			return err
		}
		secret, err := key.Backup(false)
		if err != nil {
			return err
		}
		pub, err := key.Export(false)
		if err != nil {
			return err
		}
		_, fp, err := server.ParseOfflineKey(pub)
		if err != nil {
			return err
		}
		err = os.WriteFile(offlineOut, []byte(secret+"\n"), 0o600)
		if err != nil {
			return err
		}
		err = os.WriteFile(offlineOut+".pub", []byte(pub+"\n"), 0o644) //nolint:gosec // A public key.
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stdout, "offline key:  %s (secret, keep it off the server)\npublic key:   %s.pub\nfingerprint:  %s\n",
			offlineOut, offlineOut, fp)
		return nil
	},
}

var offlineKeySetCmd = &cobra.Command{
	Use:   "set PUBLIC_KEY_FILE",
	Short: "Turn offline signing on with the public offline key (run on the server)",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		data, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		if !strings.HasPrefix(strings.TrimSpace(string(data)), "recipient:") {
			// Refuse a secret key before it lands on the server.
			return errors.New("not a public key: use the .pub file of offline-key create") //nolint:err113 // CLI usage error.
		}
		_, fp, err := server.ParseOfflineKey(string(data))
		if err != nil {
			return err
		}
		err = audited("offlinekey.set", "server", fp, func(*server.Store) error {
			_, err := server.SetOfflineKey(dataDir, string(data))
			return err
		})
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stdout, "offline signing on, key %s\n", fp)
		_, _ = fmt.Fprintln(os.Stdout, "Computers now get only signed group policies; groups without one keep their last policy until one is published.")
		return nil
	},
}

var offlineKeyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the fingerprint of the offline key of the server",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		text, err := server.ReadOfflineKey(dataDir)
		if err != nil {
			return err
		}
		if text == "" {
			_, _ = fmt.Fprintln(os.Stdout, "offline signing is off")
			return nil
		}
		_, fp, err := server.ParseOfflineKey(text)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stdout, "offline signing on, key %s\n", fp)
		return nil
	},
}

var groupExportCmd = &cobra.Command{
	Use:   "export NAME",
	Short: "Export the policy of a group for signing with the offline key",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return withStore(func(s *server.Store) error {
			g, err := s.Group(args[0])
			if err != nil {
				return err
			}
			data, err := json.MarshalIndent(server.ExportGroup(g), "", "  ")
			if err != nil {
				return err
			}
			data = append(data, '\n')
			if exportOut == "" {
				_, err = os.Stdout.Write(data)
				return err
			}
			return os.WriteFile(exportOut, data, 0o600)
		})
	},
}

var signCmd = &cobra.Command{
	Use:   "sign --key OFFLINE_KEY GROUP_POLICY_FILE",
	Short: "Sign an exported group policy with the offline key (run on the admin computer)",
	Long: `Sign an exported group policy with the offline key.

It shows what is signed and asks for confirmation (unless --yes): check it,
as the export comes from the server. The version is the signing time.`,
	Args: cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		if signKeyFile == "" {
			return errors.New("--key is required") //nolint:err113 // CLI usage error.
		}
		data, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		gp, err := policy.ParseGroupPolicy(data)
		if err != nil {
			return err
		}
		keyText, err := os.ReadFile(signKeyFile)
		if err != nil {
			return err
		}
		key, err := jess.SenderFromTextFormat(strings.TrimSpace(string(keyText)))
		if err != nil {
			return fmt.Errorf("offline key: %w", err)
		}
		printGroupPolicy(os.Stderr, gp)
		if !signYes {
			ok, err := confirm(os.Stdin, os.Stderr, "Sign this policy?")
			if err != nil {
				return err
			}
			if !ok {
				return errNotSigned
			}
		}
		signed, err := policy.SignGroup(gp, key, time.Now())
		if err != nil {
			return err
		}
		out := signOut
		if out == "" {
			out = strings.TrimSuffix(args[0], ".json") + ".signed.json"
		}
		err = os.WriteFile(out, signed, 0o600)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stdout, "signed %s version %d: %s\n", gp.Group, gp.Version, out)
		return nil
	},
}

var groupPublishCmd = &cobra.Command{
	Use:   "publish NAME SIGNED_FILE",
	Short: "Publish a group policy signed with the offline key to the computers of the group",
	Args:  cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		signed, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		srv, err := server.Load(dataDir, nil)
		if err != nil {
			return err
		}
		defer func() { _ = srv.Store.Close() }()
		gp, err := srv.Publish(args[0], signed)
		if err != nil {
			return err
		}
		detail := fmt.Sprintf("version %d", gp.Version)
		err = srv.Store.Audit(cliActor, "group.publish", args[0], detail, time.Now())
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stdout, "published %s %s, signed %s\n", args[0], detail, gp.Signed.Format(time.DateTime+" MST"))
		return nil
	},
}

// printGroupPolicy writes a summary of a group policy for the review
// before signing.
func printGroupPolicy(w io.Writer, gp *policy.GroupPolicy) {
	_, _ = fmt.Fprintf(w, "Group: %s\n", gp.Group)
	keys := make([]string, 0, len(gp.Settings))
	for k := range gp.Settings {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	_, _ = fmt.Fprintf(w, "Settings (%d, * = locked):\n", len(keys))
	for _, k := range keys {
		mark := " "
		if slices.Contains(gp.Locked, k) {
			mark = "*"
		}
		v, _ := json.Marshal(gp.Settings[k]) //nolint:errchkjson // Decoded from JSON.
		_, _ = fmt.Fprintf(w, "  %s %s = %s\n", mark, k, v)
	}
	if gp.Rules != nil {
		_, _ = fmt.Fprintf(w, "Outgoing rules (%d):\n", len(gp.Rules.Endpoints))
		for _, r := range gp.Rules.Endpoints {
			_, _ = fmt.Fprintf(w, "    %s\n", r)
		}
		_, _ = fmt.Fprintf(w, "Incoming rules (%d):\n", len(gp.Rules.ServiceEndpoints))
		for _, r := range gp.Rules.ServiceEndpoints {
			_, _ = fmt.Fprintf(w, "    %s\n", r)
		}
	}
	_, _ = fmt.Fprintf(w, "App profiles (%d):\n", len(gp.Profiles))
	for _, raw := range gp.Profiles {
		var p struct {
			Name   string         `json:"name"`
			Config map[string]any `json:"config"`
		}
		_ = json.Unmarshal(raw, &p)
		_, _ = fmt.Fprintf(w, "    %s (%d settings)\n", p.Name, len(p.Config))
	}
	state := "off"
	if gp.BlockSummary {
		state = "on (the computers send summaries of blocked connections and their app list)"
	}
	_, _ = fmt.Fprintf(w, "Block summary: %s\n", state)
}

// confirm asks a yes/no question; it refuses without a terminal, so that
// scripts must pass --yes.
func confirm(in *os.File, out io.Writer, question string) (bool, error) {
	if !isatty.IsTerminal(in.Fd()) && !isatty.IsCygwinTerminal(in.Fd()) {
		return false, errors.New("no terminal to confirm; check the summary and pass --yes") //nolint:err113 // CLI usage error.
	}
	_, _ = fmt.Fprintf(out, "%s [y/N] ", question)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

func init() {
	offlineKeyCreateCmd.Flags().StringVar(&offlineOut, "out", "", "file for the secret key; the public key goes to FILE.pub")
	groupExportCmd.Flags().StringVar(&exportOut, "out", "", "file to write instead of stdout")
	signCmd.Flags().StringVar(&signKeyFile, "key", "", "secret offline key file")
	signCmd.Flags().StringVar(&signOut, "out", "", "signed file (default: NAME.signed.json next to the input)")
	signCmd.Flags().BoolVar(&signYes, "yes", false, "sign without asking")
	offlineKeyCmd.AddCommand(offlineKeyCreateCmd, offlineKeySetCmd, offlineKeyShowCmd)
	groupCmd.AddCommand(groupExportCmd, groupPublishCmd)
	rootCmd.AddCommand(offlineKeyCmd, signCmd)
}
