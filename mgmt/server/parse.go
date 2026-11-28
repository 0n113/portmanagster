package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/safing/portmaster/mgmt/policy"
)

// Validation errors of the shared parsers; the command line and the admin
// UI use the same functions.
var (
	ErrNoConfig     = errors.New("the settings have no config section")
	ErrNoProfile    = errors.New("not a profile export (type: profile, name)")
	ErrRuleFormat   = errors.New(`a rule must start with "+ " (allow) or "- " (block)`)
	ErrLockNotSet   = errors.New("a locked key must be one of the settings")
	ErrGroupInUse   = errors.New("the group still has computers")
	ErrTokenUsed    = errors.New("the token was used already")
	ErrSameGroup    = errors.New("the computer is in this group already")
	ErrBadGroupName = errors.New("a group name must be 1-64 characters without control characters")
)

// ParseSettings reads a settings export (YAML or JSON) and returns its config
// with slash-joined keys.
func ParseSettings(data []byte) (map[string]any, error) {
	var export struct {
		Config map[string]any `json:"config" yaml:"config"`
	}
	// YAML is a superset of JSON.
	err := yaml.Unmarshal(data, &export)
	if err != nil {
		return nil, err
	}
	if export.Config == nil {
		return nil, ErrNoConfig
	}
	return flatten(export.Config, ""), nil
}

// SettingsYAML returns settings with slash-joined keys as a settings export
// in YAML, the form ParseSettings reads.
func SettingsYAML(settings map[string]any) ([]byte, error) {
	nested := make(map[string]any)
	for key, value := range settings {
		m := nested
		parts := strings.Split(key, "/")
		for _, p := range parts[:len(parts)-1] {
			sub, ok := m[p].(map[string]any)
			if !ok {
				sub = make(map[string]any)
				m[p] = sub
			}
			m = sub
		}
		m[parts[len(parts)-1]] = value
	}
	// A struct keeps "type" first, as in an export.
	return yaml.Marshal(struct {
		Type   string         `yaml:"type"`
		Config map[string]any `yaml:"config"`
	}{"settings", nested})
}

// SortedKeys returns the keys of the settings in order, e.g. to lock all.
func SortedKeys(settings map[string]any) []string {
	keys := slices.Collect(maps.Keys(settings))
	sort.Strings(keys)
	return keys
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

// ParseProfile reads a profile export (YAML or JSON) and returns it as JSON,
// the form the client imports.
func ParseProfile(data []byte) (json.RawMessage, error) {
	var export map[string]any
	// YAML is a superset of JSON.
	err := yaml.Unmarshal(data, &export)
	if err != nil {
		return nil, err
	}
	if export["type"] != "profile" || export["name"] == nil || export["name"] == "" {
		return nil, ErrNoProfile
	}
	// The checksum of a JSON export does not match the re-encoded JSON.
	delete(export, "_jess-checksum")
	return json.Marshal(export)
}

// ProfileName returns the name of a profile export.
func ProfileName(profile json.RawMessage) string {
	var p struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(profile, &p)
	return p.Name
}

// ParseRules reads endpoint rules (YAML or JSON) and checks their form; nil
// if there are none.
func ParseRules(data []byte) (*policy.Rules, error) {
	rules := &policy.Rules{}
	// YAML is a superset of JSON.
	err := yaml.Unmarshal(data, rules)
	if err != nil {
		return nil, err
	}
	return CheckRules(rules)
}

// RulesFromLines builds rules from one rule per line; empty lines and lines
// starting with # are skipped.
func RulesFromLines(endpoints, serviceEndpoints string) (*policy.Rules, error) {
	lines := func(s string) []string {
		var out []string
		for line := range strings.Lines(s) {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				out = append(out, line)
			}
		}
		return out
	}
	return CheckRules(&policy.Rules{Endpoints: lines(endpoints), ServiceEndpoints: lines(serviceEndpoints)})
}

// CheckRules checks the form of the rules; the client validates them fully.
// It returns nil for empty rules.
func CheckRules(rules *policy.Rules) (*policy.Rules, error) {
	for _, rule := range append(slices.Clone(rules.Endpoints), rules.ServiceEndpoints...) {
		if !strings.HasPrefix(rule, "+ ") && !strings.HasPrefix(rule, "- ") {
			return nil, fmt.Errorf("%q: %w", rule, ErrRuleFormat)
		}
	}
	if rules.Empty() {
		return nil, nil //nolint:nilnil // No rules.
	}
	return rules, nil
}

// CheckGroupName checks the name of a new group.
func CheckGroupName(name string) error {
	if name == "" || len(name) > 64 || strings.TrimSpace(name) != name ||
		strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return ErrBadGroupName
	}
	return nil
}
