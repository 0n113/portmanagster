package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	corebase "github.com/safing/portmaster/service/core/base"
)

// The settings and profile commands talk to the local API of the running
// Portmaster. The API grants full access to requests from programs installed
// in the Portmaster directory, so these commands need no token. They are
// meant for configuration management tools (Ansible, Salt, RMM agents) that
// run them as root on each machine. While the computer is managed, the
// imports are only accepted from root (Linux, see api.RequireRoot).

const (
	mimeJSON = "application/json"
	mimeYAML = "application/yaml"
)

var (
	syncAPIAddress string
	syncFormat     string
	syncOutput     string
	syncKeys       []string
	syncEffective  bool
	syncValidate   bool
	syncReset      bool
	syncAllowUnkn  bool
	syncAllowRepl  bool
	syncTimeout    = 30 * time.Second

	errSyncAPI         = errors.New("portmaster api error")
	errSyncInvalidFmt  = errors.New("invalid format, use json or yaml")
	errSyncEmptyImport = errors.New("import data is empty")
)

var settingsCmd = &cobra.Command{
	Use:   "settings",
	Short: "Export or import the global settings of the running Portmaster",
}

var settingsExportCmd = &cobra.Command{
	Use:           "export",
	Short:         "Export all changed global settings, or only the given keys",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true, // main prints the error.
	RunE: func(cmd *cobra.Command, _ []string) error {
		q := url.Values{}
		q.Set("from", "global")
		for _, key := range syncKeys {
			q.Add("key", key)
		}
		if syncEffective {
			q.Set("effective", "true")
		}
		err := syncExport(cmd.Context(), "sync/settings/export", q)
		if err != nil && strings.Contains(err.Error(), errMsgUnchanged) {
			// Nothing is set: write an empty export, which imports fine.
			return writeExport(emptySettingsExport(syncFormat))
		}
		return err
	},
}

var settingsImportCmd = &cobra.Command{
	Use:           "import FILE|-",
	Short:         "Import global settings from a settings export",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true, // main prints the error.
	RunE: func(cmd *cobra.Command, args []string) error {
		rootErr := checkRunAsRootIfManaged(cmd.Context(), "import settings")
		if rootErr != nil {
			return rootErr
		}
		q := url.Values{}
		q.Set("to", "global")
		addImportFlags(q)
		return syncImport(cmd.Context(), "sync/settings/import", q, args[0])
	},
}

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Export or import app profiles of the running Portmaster",
}

var profileExportCmd = &cobra.Command{
	Use:           "export ID",
	Short:         "Export an app profile, e.g. local/<id>",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true, // main prints the error.
	RunE: func(cmd *cobra.Command, args []string) error {
		q := url.Values{}
		q.Set("id", args[0])
		return syncExport(cmd.Context(), "sync/profile/export", q)
	},
}

var profileImportCmd = &cobra.Command{
	Use:           "import FILE|-",
	Short:         "Import an app profile from a profile export",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true, // main prints the error.
	RunE: func(cmd *cobra.Command, args []string) error {
		rootErr := checkRunAsRootIfManaged(cmd.Context(), "import profiles")
		if rootErr != nil {
			return rootErr
		}
		q := url.Values{}
		// The API reads the body as a raw export only if the request has
		// query parameters; without them it expects a JSON import request.
		q.Set("raw", "true")
		addImportFlags(q)
		if syncAllowRepl {
			q.Set("allowReplace", "true")
		}
		return syncImport(cmd.Context(), "sync/profile/import", q, args[0])
	},
}

func init() {
	for _, c := range []*cobra.Command{settingsCmd, profileCmd} {
		c.PersistentFlags().StringVar(&syncAPIAddress, "api", corebase.DefaultAPIListenAddress, "address of the Portmaster API")
	}

	for _, c := range []*cobra.Command{settingsExportCmd, profileExportCmd} {
		c.Flags().StringVar(&syncFormat, "format", "yaml", "export format: json or yaml")
		c.Flags().StringVarP(&syncOutput, "output", "o", "", "write the export to this file instead of stdout")
	}
	settingsExportCmd.Flags().StringArrayVar(&syncKeys, "key", nil, "only export this setting key (repeatable)")
	settingsExportCmd.Flags().BoolVar(&syncEffective, "effective", false, "export the values in force, including defaults and the management policy, instead of the changed settings")

	for _, c := range []*cobra.Command{settingsImportCmd, profileImportCmd} {
		c.Flags().BoolVar(&syncValidate, "validate", false, "only check the import and report what it would change")
		c.Flags().BoolVar(&syncReset, "reset", false, "remove all existing settings of the target before the import")
		c.Flags().BoolVar(&syncAllowUnkn, "allow-unknown", false, "accept setting keys this version does not know")
	}
	profileImportCmd.Flags().BoolVar(&syncAllowRepl, "allow-replace", false, "replace an existing profile with the same ID")

	settingsCmd.AddCommand(settingsExportCmd, settingsImportCmd)
	profileCmd.AddCommand(profileExportCmd, profileImportCmd)
	rootCmd.AddCommand(settingsCmd, profileCmd)
}

func addImportFlags(q url.Values) {
	if syncValidate {
		q.Set("validate", "true")
	}
	if syncReset {
		q.Set("reset", "true")
	}
	if syncAllowUnkn {
		q.Set("allowUnknown", "true")
	}
}

func syncExport(ctx context.Context, path string, q url.Values) error {
	mime, err := formatMime(syncFormat)
	if err != nil {
		return err
	}

	data, err := syncRequest(ctx, http.MethodGet, path, q, mime, nil)
	if err != nil {
		return err
	}
	return writeExport(data)
}

func writeExport(data []byte) error {
	if syncOutput == "" || syncOutput == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(syncOutput, data, 0o600)
}

func syncImport(ctx context.Context, path string, q url.Values, file string) error {
	var (
		data []byte
		err  error
	)
	if file == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(file)
	}
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return errSyncEmptyImport
	}

	result, err := syncRequest(ctx, http.MethodPost, path, q, detectMime(file, data), data)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(bytes.TrimSpace(result), '\n'))
	return err
}

func syncRequest(ctx context.Context, method, path string, q url.Values, mime string, body []byte) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()

	u := url.URL{
		Scheme:   "http",
		Host:     syncAPIAddress,
		Path:     "/api/v1/" + path,
		RawQuery: q.Encode(),
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", mime)
	} else {
		req.Header.Set("Accept", mime)
	}

	// The API is local only; never use a proxy from the environment.
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the Portmaster API at %s (is the Portmaster running?): %w", syncAPIAddress, err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s: %s", errSyncAPI, resp.Status, strings.TrimSpace(string(data)))
	}
	return data, nil
}

// errMsgUnchanged is the message of sync.ErrUnchanged, returned when no
// selected setting differs from its default.
const errMsgUnchanged = "cannot export unchanged setting"

func emptySettingsExport(format string) []byte {
	if mime, _ := formatMime(format); mime == mimeJSON {
		return []byte(`{"type":"settings","config":{}}`)
	}
	return []byte("type: settings\nconfig: {}\n")
}

func formatMime(format string) (string, error) {
	switch strings.ToLower(format) {
	case "json":
		return mimeJSON, nil
	case "yaml", "yml":
		return mimeYAML, nil
	default:
		return "", errSyncInvalidFmt
	}
}

func detectMime(file string, data []byte) string {
	switch strings.ToLower(filepath.Ext(file)) {
	case ".json":
		return mimeJSON
	case ".yaml", ".yml":
		return mimeYAML
	}
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 && trimmed[0] == '{' {
		return mimeJSON
	}
	return mimeYAML
}
