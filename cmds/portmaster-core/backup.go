package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	corebase "github.com/safing/portmaster/service/core/base"
)

// The backup commands save the global settings and all local app profiles of
// the running Portmaster to a directory, and restore them from there. They use
// the same local API as the settings and profile commands.

const (
	backupManifestFile = "manifest.json"
	backupSettingsFile = "settings.yaml"
	backupProfilesDir  = "profiles"
	backupFormatV1     = 1
	sourceLocal        = "local"
)

var (
	backupValidate bool
	backupReset    bool
	backupAllowUnk bool

	errBackupDirNotEmpty = errors.New("backup directory exists and is not empty")
	errBackupInvalid     = errors.New("invalid backup")
	errBackupPartial     = errors.New("backup written, but some profiles could not be exported")
	errRestoreInvalid    = errors.New("the backup does not validate, nothing was imported")
	errRestoreFailed     = errors.New("restore failed")

	unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)
)

// profileListEntry is an entry of the sync/profile/list API.
type profileListEntry struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Name     string `json:"name"`
	Special  bool   `json:"special,omitempty"`
	Internal bool   `json:"internal,omitempty"`
}

// backupManifest describes the content of a backup directory.
type backupManifest struct {
	Format   int                  `json:"format"`
	Created  time.Time            `json:"created"`
	Host     string               `json:"host,omitempty"`
	Settings string               `json:"settings"`
	Profiles []backupProfileEntry `json:"profiles"`
	Skipped  []backupProfileEntry `json:"skipped,omitempty"`
}

type backupProfileEntry struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	File   string `json:"file,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// restoreReport is printed by backup restore.
type restoreReport struct {
	Validated bool                  `json:"validated"`
	Settings  json.RawMessage       `json:"settings,omitempty"`
	Profiles  []restoreProfileState `json:"profiles"`
}

type restoreProfileState struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

var profileListCmd = &cobra.Command{
	Use:           "list",
	Short:         "List all app profiles as JSON (scoped ID, name, special profiles)",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true, // main prints the error.
	RunE: func(cmd *cobra.Command, _ []string) error {
		list, err := listProfiles(cmd.Context())
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(list)
	},
}

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Back up or restore the global settings and all local app profiles",
}

var backupCreateCmd = &cobra.Command{
	Use:           "create DIR",
	Short:         "Write settings.yaml, profiles/*.yaml and manifest.json to a new or empty DIR",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true, // main prints the error.
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := createBackup(cmd.Context(), args[0], time.Now())
		if m != nil {
			_, _ = fmt.Fprintf(os.Stdout, "wrote %s: settings, %d profiles, %d skipped\n", args[0], len(m.Profiles), len(m.Skipped))
		}
		return err
	},
}

var backupRestoreCmd = &cobra.Command{
	Use:   "restore DIR",
	Short: "Validate the whole backup, then import the settings and all profiles",
	Long: "Validates the settings and every profile of the backup first and imports nothing if one is invalid. " +
		"Then imports the settings (merged, or replacing all with --reset) and the profiles, replacing existing ones.",
	Args:          cobra.ExactArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true, // main prints the error.
	RunE: func(cmd *cobra.Command, args []string) error {
		report, err := restoreBackup(cmd.Context(), args[0])
		if report != nil {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			encErr := enc.Encode(report)
			if err == nil {
				err = encErr
			}
		}
		return err
	},
}

func init() {
	backupCmd.PersistentFlags().StringVar(&syncAPIAddress, "api", corebase.DefaultAPIListenAddress, "address of the Portmaster API")
	backupRestoreCmd.Flags().BoolVar(&backupValidate, "validate", false, "only validate the backup, import nothing")
	backupRestoreCmd.Flags().BoolVar(&backupReset, "reset", false, "remove all global settings that are not in the backup")
	backupRestoreCmd.Flags().BoolVar(&backupAllowUnk, "allow-unknown", false, "accept setting keys this version does not know")

	profileCmd.AddCommand(profileListCmd)
	backupCmd.AddCommand(backupCreateCmd, backupRestoreCmd)
	rootCmd.AddCommand(backupCmd)
}

func listProfiles(ctx context.Context) ([]profileListEntry, error) {
	data, err := syncRequest(ctx, http.MethodGet, "sync/profile/list", url.Values{}, mimeJSON, nil)
	if err != nil {
		return nil, err
	}
	var list []profileListEntry
	err = json.Unmarshal(data, &list)
	if err != nil {
		return nil, fmt.Errorf("invalid profile list: %w", err)
	}
	return list, nil
}

// createBackup writes the backup to a temporary directory next to dir and
// renames it to dir when complete, so dir never holds a partial backup.
func createBackup(ctx context.Context, dir string, now time.Time) (*backupManifest, error) {
	entries, err := os.ReadDir(dir)
	if err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%w: %s", errBackupDirNotEmpty, dir)
	}

	settings, err := syncRequest(ctx, http.MethodGet, "sync/settings/export", url.Values{"from": {"global"}}, mimeYAML, nil)
	if err != nil {
		if !strings.Contains(err.Error(), errMsgUnchanged) {
			return nil, fmt.Errorf("settings export: %w", err)
		}
		settings = emptySettingsExport("yaml")
	}
	list, err := listProfiles(ctx)
	if err != nil {
		return nil, err
	}

	host, _ := os.Hostname()
	m := &backupManifest{
		Format:   backupFormatV1,
		Created:  now.UTC().Truncate(time.Second),
		Host:     host,
		Settings: backupSettingsFile,
		Profiles: make([]backupProfileEntry, 0, len(list)),
	}
	files := map[string][]byte{backupSettingsFile: settings}
	for _, p := range list {
		switch {
		case p.Source != sourceLocal:
			m.Skipped = append(m.Skipped, backupProfileEntry{ID: p.ID, Name: p.Name, Reason: "not a local profile"})
			continue
		case p.Special:
			m.Skipped = append(m.Skipped, backupProfileEntry{ID: p.ID, Name: p.Name, Reason: "special profile, cannot be imported"})
			continue
		}
		data, err := syncRequest(ctx, http.MethodGet, "sync/profile/export", url.Values{"id": {p.ID}}, mimeYAML, nil)
		if err != nil {
			m.Skipped = append(m.Skipped, backupProfileEntry{ID: p.ID, Name: p.Name, Reason: "export failed: " + err.Error()})
			continue
		}
		file := filepath.ToSlash(filepath.Join(backupProfilesDir, unsafeFileChars.ReplaceAllString(p.ID, "_")+".yaml"))
		files[file] = data
		m.Profiles = append(m.Profiles, backupProfileEntry{ID: p.ID, Name: p.Name, File: file})
	}
	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	files[backupManifestFile] = append(manifest, '\n')

	err = writeBackupDir(dir, files)
	if err != nil {
		return nil, err
	}
	for _, s := range m.Skipped {
		if strings.HasPrefix(s.Reason, "export failed") {
			return m, fmt.Errorf("%w: %s: %s", errBackupPartial, s.ID, s.Reason)
		}
	}
	return m, nil
}

func writeBackupDir(dir string, files map[string][]byte) error {
	dir = filepath.Clean(dir)
	err := os.MkdirAll(filepath.Dir(dir), 0o700)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(filepath.Dir(dir), "."+filepath.Base(dir)+".tmp-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	err = os.Mkdir(filepath.Join(tmp, backupProfilesDir), 0o700)
	if err != nil {
		return err
	}
	for name, data := range files {
		err := os.WriteFile(filepath.Join(tmp, filepath.FromSlash(name)), data, 0o600)
		if err != nil {
			return err
		}
	}
	// An existing dir is empty (checked before); remove it so the rename also
	// works on Windows.
	err = os.Remove(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(tmp, dir)
}

func readBackup(dir string) (*backupManifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, backupManifestFile))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errBackupInvalid, err)
	}
	m := &backupManifest{}
	err = json.Unmarshal(data, m)
	if err != nil {
		return nil, fmt.Errorf("%w: manifest: %w", errBackupInvalid, err)
	}
	if m.Format != backupFormatV1 {
		return nil, fmt.Errorf("%w: unsupported format %d", errBackupInvalid, m.Format)
	}
	for _, f := range append([]string{m.Settings}, profileFiles(m)...) {
		// Files must stay inside the backup directory.
		if f == "" || !filepath.IsLocal(filepath.FromSlash(f)) {
			return nil, fmt.Errorf("%w: file %q", errBackupInvalid, f)
		}
	}
	return m, nil
}

func profileFiles(m *backupManifest) []string {
	files := make([]string, 0, len(m.Profiles))
	for _, p := range m.Profiles {
		files = append(files, p.File)
	}
	return files
}

// restoreBackup validates the settings and all profiles, and imports them only
// if all are valid.
func restoreBackup(ctx context.Context, dir string) (*restoreReport, error) {
	m, err := readBackup(dir)
	if err != nil {
		return nil, err
	}
	settings, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(m.Settings)))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errBackupInvalid, err)
	}
	profiles := make([][]byte, len(m.Profiles))
	for i, p := range m.Profiles {
		profiles[i], err = os.ReadFile(filepath.Join(dir, filepath.FromSlash(p.File)))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errBackupInvalid, err)
		}
	}

	settingsQuery := func(validate bool) url.Values {
		q := url.Values{"to": {"global"}}
		setImportFlags(q, validate)
		if backupReset {
			q.Set("reset", "true")
		}
		return q
	}
	profileQuery := func(validate bool) url.Values {
		q := url.Values{"allowReplace": {"true"}}
		setImportFlags(q, validate)
		return q
	}

	// Validate everything first.
	report := &restoreReport{Validated: true, Profiles: make([]restoreProfileState, len(m.Profiles))}
	invalid := 0
	res, err := importData(ctx, "sync/settings/import", settingsQuery(true), settings)
	if err != nil {
		return nil, fmt.Errorf("%w: settings: %w", errRestoreInvalid, err)
	}
	report.Settings = res
	for i, p := range m.Profiles {
		report.Profiles[i].ID = p.ID
		res, err := importData(ctx, "sync/profile/import", profileQuery(true), profiles[i])
		if err != nil {
			report.Profiles[i].Error = err.Error()
			invalid++
			continue
		}
		report.Profiles[i].Result = res
	}
	if invalid > 0 {
		return report, fmt.Errorf("%w: %d profiles invalid", errRestoreInvalid, invalid)
	}
	if backupValidate {
		return report, nil
	}

	// Import.
	report.Validated = false
	failed := 0
	res, err = importData(ctx, "sync/settings/import", settingsQuery(false), settings)
	if err != nil {
		return report, fmt.Errorf("%w: settings: %w", errRestoreFailed, err)
	}
	report.Settings = res
	for i := range m.Profiles {
		res, err := importData(ctx, "sync/profile/import", profileQuery(false), profiles[i])
		if err != nil {
			report.Profiles[i].Error = err.Error()
			failed++
			continue
		}
		report.Profiles[i].Result = res
	}
	if failed > 0 {
		return report, fmt.Errorf("%w: %d profiles not imported", errRestoreFailed, failed)
	}
	return report, nil
}

func setImportFlags(q url.Values, validate bool) {
	if validate {
		q.Set("validate", "true")
	}
	if backupAllowUnk {
		q.Set("allowUnknown", "true")
	}
}

func importData(ctx context.Context, path string, q url.Values, data []byte) (json.RawMessage, error) {
	res, err := syncRequest(ctx, http.MethodPost, path, q, mimeYAML, data)
	if err != nil {
		return nil, err
	}
	res = bytes.TrimSpace(res)
	if json.Valid(res) {
		return res, nil
	}
	// Keep a non-JSON answer as a JSON string in the report.
	quoted, err := json.Marshal(string(res))
	if err != nil {
		return nil, err
	}
	return quoted, nil
}
