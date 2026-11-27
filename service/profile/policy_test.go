package profile

import (
	"context"
	"errors"
	"testing"

	"github.com/safing/portmaster/base/config"
	"github.com/safing/portmaster/service/intel"
	"github.com/safing/portmaster/service/profile/endpoints"
)

// registerEndpointsOption registers filter/endpoints for the test if the
// profile module did not.
func registerEndpointsOption(t *testing.T) {
	t.Helper()
	_, err := config.GetOption(CfgOptionEndpointsKey)
	if err == nil {
		return
	}
	err = config.Register(&config.Option{
		Name:         "Outgoing Rules",
		Key:          CfgOptionEndpointsKey,
		Description:  "Outgoing rules for the policy test.",
		OptType:      config.OptTypeStringArray,
		DefaultValue: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestLayeredProfilePolicy checks that locked settings ignore the app
// profile, unlocked policy values do not, and the policy rules come first.
//
//nolint:paralleltest // Uses the global config and active profiles.
func TestLayeredProfilePolicy(t *testing.T) {
	const id = "test-policy"
	defer removeTestLayeredProfile(id)
	registerEndpointsOption(t)
	t.Cleanup(func() {
		config.SetPolicy(nil, nil)
		_ = SetPolicyRules(nil, nil)
	})

	p := newTestLayeredProfileVersion(t, id, false)
	p.Config[CfgOptionEndpointsKey] = []any{"+ example.org"}
	p = New(&Profile{ID: id, Source: SourceLocal, Config: p.Config})
	addActiveProfile(p)
	lp := NewLayeredProfile(p)
	global := config.GetAsBool(testLayeredOptionKey, false)
	option := lp.wrapBoolOption(testLayeredOptionKey, global)
	ctx := context.Background()
	entity := func() *intel.Entity { return (&intel.Entity{Domain: "example.org."}).Init(0) }

	match := func() endpoints.EPResult {
		lp.RLock()
		defer lp.RUnlock()
		result, _ := lp.MatchEndpoint(ctx, entity())
		return result
	}
	update := func() {
		if !lp.NeedsUpdate() {
			t.Fatal("a policy change must mark the layered profile for an update")
		}
		lp.Update(nil, nil)
	}

	if option() || match() != endpoints.Permitted {
		t.Fatal("without policy the app profile must win")
	}

	// Unlocked policy value: the app profile still wins.
	config.SetPolicy(map[string]any{testLayeredOptionKey: true}, nil)
	update()
	if option() {
		t.Fatal("an unlocked policy value must not override the app profile")
	}

	// Locked: the policy value wins over the app profile.
	config.SetPolicy(map[string]any{testLayeredOptionKey: true, CfgOptionEndpointsKey: []string{}},
		[]string{testLayeredOptionKey, CfgOptionEndpointsKey})
	update()
	if !option() {
		t.Fatal("a locked setting must ignore the app profile")
	}
	if src := lp.GetProfileSource(testLayeredOptionKey); src != "" {
		t.Fatalf("the source of a locked setting is the global config, got %q", src)
	}
	if r := match(); r == endpoints.Permitted {
		t.Fatal("locked endpoints must ignore the app rules")
	}

	// Policy rules come before the app rules.
	config.SetPolicy(nil, nil)
	update()
	if match() != endpoints.Permitted {
		t.Fatal("without the lock the app rule must apply again")
	}
	err := SetPolicyRules([]string{"- example.org"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if match() != endpoints.Denied {
		t.Fatal("a policy rule must win over an app allow rule")
	}
	if SetPolicyRules([]string{"invalid rule"}, nil) == nil {
		t.Fatal("an invalid rule must be refused")
	}
	if match() != endpoints.Denied {
		t.Fatal("a refused rule list must not change the rules")
	}
}

//nolint:paralleltest // Uses the global config.
func TestCheckLockedChanges(t *testing.T) {
	newTestLayeredProfileVersion(t, "test-check-locked", false)
	defer removeTestLayeredProfile("test-check-locked")
	config.SetPolicy(map[string]any{testLayeredOptionKey: true}, []string{testLayeredOptionKey})
	t.Cleanup(func() { config.SetPolicy(nil, nil) })

	set := config.Expand(map[string]any{testLayeredOptionKey: false})
	other := config.Expand(map[string]any{testLayeredOptionKey: true})
	cases := []struct {
		name     string
		old, new map[string]any
		refused  bool
	}{
		{"new profile with locked key", nil, set, true},
		{"locked key added", map[string]any{}, set, true},
		{"locked key changed", other, set, true},
		{"locked key unchanged", set, set, false},
		{"locked key removed", set, map[string]any{}, false},
		{"no locked key", nil, map[string]any{"filter": map[string]any{"x": 1}}, false},
	}
	for _, c := range cases {
		err := checkLockedChanges(c.old, c.new)
		if c.refused != errors.Is(err, config.ErrLockedByPolicy) {
			t.Errorf("%s: got %v", c.name, err)
		}
	}
	// The Portmaster writes special profiles, e.g. the global config
	// profile with the values in force.
	err := checkLockedProfileChanges(&Profile{Source: SourceSpecial, ID: "global-config", Config: set})
	if err != nil {
		t.Errorf("special profile refused: %v", err)
	}
}
