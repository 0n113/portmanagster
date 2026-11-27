package managed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/safing/portmaster/base/config"
	"github.com/safing/portmaster/mgmt/policy"
	"github.com/safing/portmaster/service/profile"
	"github.com/safing/portmaster/service/sync"
)

// applier changes the local configuration. It is an interface so that the
// apply logic can be tested without the config system.
type applier interface {
	// userValue returns the value the user (or a previous policy) set for
	// key, or nil.
	userValue(key string) any
	// importSettings merges the settings into the global settings.
	importSettings(settings map[string]any) error
	// importProfile imports a profile export, replacing an existing one.
	importProfile(export json.RawMessage) error
}

// applyResult describes what applying a policy changed.
type applyResult struct {
	// Corrected lists the settings that differed from the policy and were
	// set again.
	Corrected []string `json:"corrected,omitempty"`
	// Profiles is the number of imported profiles (0 if unchanged).
	Profiles int `json:"profiles,omitempty"`
}

// applyPolicy sets the settings of the policy that differ from the current
// values, and imports the profiles if they changed since the last apply.
// It returns the new profiles hash.
func applyPolicy(a applier, p *policy.Policy, appliedProfilesHash string) (*applyResult, string, error) {
	res := &applyResult{}

	changed := make(map[string]any)
	for key, want := range p.Settings {
		if !sameValue(a.userValue(key), want) {
			changed[key] = want
			res.Corrected = append(res.Corrected, key)
		}
	}
	slices.Sort(res.Corrected)
	if len(changed) > 0 {
		err := a.importSettings(changed)
		if err != nil {
			return nil, appliedProfilesHash, fmt.Errorf("settings: %w", err)
		}
	}

	hash := profilesHash(p.Profiles)
	if hash != appliedProfilesHash {
		for i, export := range p.Profiles {
			err := a.importProfile(export)
			if err != nil {
				return nil, appliedProfilesHash, fmt.Errorf("profile %d: %w", i+1, err)
			}
		}
		res.Profiles = len(p.Profiles)
	}
	return res, hash, nil
}

// sameValue compares two setting values by their JSON form, so that e.g.
// int64(33) and float64(33) or []string and []any are equal.
func sameValue(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

func profilesHash(profiles []json.RawMessage) string {
	if len(profiles) == 0 {
		return ""
	}
	h := sha256.New()
	for _, p := range profiles {
		_, _ = h.Write(p)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// coreApplier applies to the running Portmaster.
type coreApplier struct{}

func (coreApplier) userValue(key string) any {
	opt, err := config.GetOption(key)
	if err != nil {
		return nil
	}
	return opt.UserValue()
}

func (coreApplier) importSettings(settings map[string]any) error {
	_, err := sync.ImportSettings(&sync.SettingsImportRequest{
		ImportRequest: sync.ImportRequest{Target: sync.ExportTargetGlobal},
		Export:        &sync.SettingsExport{Type: sync.TypeSettings, Config: settings},
	})
	return err
}

func (coreApplier) importProfile(export json.RawMessage) error {
	pe := &sync.ProfileExport{}
	err := json.Unmarshal(export, pe)
	if err != nil {
		return err
	}
	_, err = sync.ImportProfile(&sync.ProfileImportRequest{
		AllowReplace: true,
		Export:       pe,
	}, profile.SourceLocal)
	return err
}
