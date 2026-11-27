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
	// userValue returns the value the user set for key, or nil.
	userValue(key string) any
	// setPolicy replaces the policy layer of the settings and returns the
	// keys it could not apply (invalid value or unknown setting).
	setPolicy(settings map[string]any, locked []string) (refused []string)
	// setRules replaces the policy endpoint rules.
	setRules(rules *policy.Rules) error
	// importProfile imports a profile export, replacing an existing one.
	importProfile(export json.RawMessage) error
	// importSettings merges the settings into the global user settings.
	importSettings(settings map[string]any) error
	// effectiveValue returns the value in force for key, or nil.
	effectiveValue(key string) any
}

// applyResult describes what applying a policy found.
type applyResult struct {
	// Overridden lists the policy defaults (unlocked settings) that a local
	// admin set to another value.
	Overridden []string `json:"overridden,omitempty"`
	// Refused lists the policy settings that were not applied.
	Refused []string `json:"refused,omitempty"`
	// Profiles is the number of imported profiles (0 if unchanged).
	Profiles int `json:"profiles,omitempty"`
}

// applyPolicy sets the policy layer and the policy rules and, if
// withProfiles is set, imports the profiles if they changed since the last
// apply. It returns the new profiles hash.
func applyPolicy(a applier, p *policy.Policy, appliedProfilesHash string, withProfiles bool) (*applyResult, string, error) {
	res := &applyResult{}

	res.Refused = a.setPolicy(p.Settings, p.Locked)
	err := a.setRules(p.Rules)
	if err != nil {
		// The previous rules stay in force.
		res.Refused = append(res.Refused, "rules: "+err.Error())
	}

	locked := make(map[string]bool, len(p.Locked))
	for _, key := range p.Locked {
		locked[key] = true
	}
	for key, want := range p.Settings {
		if locked[key] {
			continue
		}
		if uv := a.userValue(key); uv != nil && !sameValue(uv, want) {
			res.Overridden = append(res.Overridden, key)
		}
	}
	slices.Sort(res.Overridden)
	slices.Sort(res.Refused)

	if !withProfiles {
		return res, appliedProfilesHash, nil
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

// leavePolicy removes the policy layer and keeps its values as user
// settings: locked values and defaults the user did not override become
// user values, and the policy rules are put before the global rules.
func leavePolicy(a applier, p *policy.Policy) error {
	keep := make(map[string]any)
	if p != nil {
		locked := make(map[string]bool, len(p.Locked))
		for _, key := range p.Locked {
			locked[key] = true
		}
		for key, value := range p.Settings {
			if locked[key] || a.userValue(key) == nil {
				keep[key] = value
			}
		}
		if !p.Rules.Empty() {
			keep[cfgEndpoints] = prependRules(p.Rules.Endpoints, keep[cfgEndpoints], a.effectiveValue(cfgEndpoints))
			keep[cfgServiceEndpoints] = prependRules(p.Rules.ServiceEndpoints, keep[cfgServiceEndpoints], a.effectiveValue(cfgServiceEndpoints))
		}
	}

	a.setPolicy(nil, nil)
	err := a.setRules(nil)
	if err != nil {
		return err
	}
	if len(keep) == 0 {
		return nil
	}
	return a.importSettings(keep)
}

const (
	cfgEndpoints        = "filter/endpoints"
	cfgServiceEndpoints = "filter/serviceEndpoints"
)

// prependRules returns the policy rules followed by the rules that applied
// so far (the kept policy value, else the value in force).
func prependRules(rules []string, kept, effective any) []string {
	out := slices.Clone(rules)
	current := kept
	if current == nil {
		current = effective
	}
	switch list := current.(type) {
	case []string:
		out = append(out, list...)
	case []any:
		for _, v := range list {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
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

func (coreApplier) effectiveValue(key string) any {
	opt, err := config.GetOption(key)
	if err != nil {
		return nil
	}
	return opt.EffectiveValue()
}

func (coreApplier) setPolicy(settings map[string]any, locked []string) []string {
	var refused []string
	for _, vErr := range config.SetPolicy(settings, locked) {
		if vErr.Option != nil {
			refused = append(refused, vErr.Option.Key)
		}
	}
	// Settings unknown to this version are kept by the config, in case
	// the option is registered later, but are not in force.
	for key := range settings {
		_, err := config.GetOption(key)
		if err != nil {
			refused = append(refused, key)
		}
	}
	return refused
}

func (coreApplier) setRules(rules *policy.Rules) error {
	if rules == nil {
		return profile.SetPolicyRules(nil, nil)
	}
	return profile.SetPolicyRules(rules.Endpoints, rules.ServiceEndpoints)
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
