package profile

import (
	"context"
	"fmt"
	"sync"

	"github.com/safing/portmaster/base/config"
	"github.com/safing/portmaster/service/intel"
	"github.com/safing/portmaster/service/profile/endpoints"
)

// Policy rules of the management policy. They are evaluated before the rules
// of all app profiles and the global rules, and cannot be overridden.
var (
	policyRulesLock        sync.RWMutex
	policyEndpoints        endpoints.Endpoints
	policyServiceEndpoints endpoints.Endpoints
)

// SetPolicyRules replaces the endpoint rules of the management policy for
// outgoing (endpoints) and incoming (serviceEndpoints) connections. Empty
// lists remove them. Nothing is changed if a list is invalid.
// Connections already decided are re-evaluated when the config changes,
// so set the rules together with config.SetPolicy.
func SetPolicyRules(outgoing, incoming []string) error {
	ep, err := endpoints.ParseEndpoints(outgoing)
	if err != nil {
		return fmt.Errorf("policy endpoints: %w", err)
	}
	sep, err := endpoints.ParseEndpoints(incoming)
	if err != nil {
		return fmt.Errorf("policy service endpoints: %w", err)
	}
	policyRulesLock.Lock()
	defer policyRulesLock.Unlock()
	policyEndpoints = ep
	policyServiceEndpoints = sep
	return nil
}

func matchPolicyRules(ctx context.Context, entity *intel.Entity, inbound bool) (endpoints.EPResult, endpoints.Reason) {
	policyRulesLock.RLock()
	defer policyRulesLock.RUnlock()
	list := policyEndpoints
	if inbound {
		list = policyServiceEndpoints
	}
	if !list.IsSet() {
		return endpoints.NoMatch, nil
	}
	return list.Match(ctx, entity)
}

// lockedKeys tells which settings of the app layers are overridden by the
// management policy. It is part of the immutable option state.
type lockedKeys map[string]struct{}

func (lk lockedKeys) has(key string) bool {
	_, ok := lk[key]
	return ok
}

// currentLockedKeys returns the locked settings, or nil if there are none.
func currentLockedKeys() lockedKeys {
	keys := config.LockedKeys()
	if len(keys) == 0 {
		return nil
	}
	lk := make(lockedKeys, len(keys))
	for _, key := range keys {
		lk[key] = struct{}{}
	}
	return lk
}

// checkLockedChanges returns an error if the new profile config sets or
// changes a setting locked by the management policy compared to the old
// one (nil for a new profile). Values that were set before the lock stay
// allowed; they have no effect while locked.
func checkLockedChanges(oldConfig, newConfig map[string]any) error {
	locked := config.LockedKeys()
	if len(locked) == 0 {
		return nil
	}
	oldFlat := config.Flatten(oldConfig)
	newFlat := config.Flatten(newConfig)
	var changed []string
	for _, key := range locked {
		newValue, inNew := newFlat[key]
		oldValue, inOld := oldFlat[key]
		switch {
		case inNew && !inOld:
			changed = append(changed, key)
		case inNew && inOld && fmt.Sprint(newValue) != fmt.Sprint(oldValue):
			changed = append(changed, key)
		}
	}
	if len(changed) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %v", config.ErrLockedByPolicy, changed)
}

// checkLockedProfileChanges compares the profile with the stored one and
// refuses changes of locked settings.
func checkLockedProfileChanges(p *Profile) error {
	// Special profiles are written by the Portmaster itself: the global
	// config profile mirrors the values in force, including the locked
	// ones, and the built-in profiles set their settings in code.
	if p.Source == SourceSpecial || len(config.LockedKeys()) == 0 {
		return nil
	}
	var oldConfig map[string]any
	r, err := profileDB.Get(ProfilesDBPath + p.ScopedID())
	if err == nil {
		old, err := EnsureProfile(r)
		if err == nil {
			oldConfig = old.Config
		}
	}
	err = checkLockedChanges(oldConfig, p.Config)
	if err != nil {
		return fmt.Errorf("profile %s: %w", p.ScopedID(), err)
	}
	return nil
}
