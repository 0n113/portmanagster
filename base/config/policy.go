package config

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
)

// ErrLockedByPolicy is returned when a setting locked by the management
// policy is changed.
var ErrLockedByPolicy = errors.New("managed by policy")

// PolicyAnnotation marks an option whose value comes from the management
// policy. Its value is PolicyLocked or PolicyDefault.
const PolicyAnnotation = "safing/portmaster:config:policy"

// Values of PolicyAnnotation.
const (
	// PolicyLocked: the policy value is in force and cannot be changed.
	PolicyLocked = "locked"
	// PolicyDefault: the policy value replaces the default; a user value
	// still wins.
	PolicyDefault = "default"
)

// policyState is the policy layer as last set by SetPolicy. It is kept so
// that options registered later get their policy value at registration.
var (
	policyLock   sync.Mutex
	policyValues map[string]any
	policyLocked map[string]struct{}
)

// SetPolicy replaces the policy layer. values holds the policy value per
// option key; the keys in locked are enforced, the others are a default a
// user value overrides. Keys of options that are not registered yet are
// applied when they are registered. Invalid values are left out and
// returned as validation errors; the other values are applied. An empty
// policy (nil, nil) removes the layer.
func SetPolicy(values map[string]any, locked []string) []*ValidationError {
	policyLock.Lock()
	defer policyLock.Unlock()

	policyValues = maps.Clone(values)
	policyLocked = make(map[string]struct{}, len(locked))
	for _, key := range locked {
		policyLocked[key] = struct{}{}
	}

	var validationErrors []*ValidationError
	optionsLock.RLock()
	for _, option := range options {
		func() {
			option.Lock()
			defer option.Unlock()
			err := applyPolicyLocked(option)
			if err != nil {
				validationErrors = append(validationErrors, err)
			}
			handleOptionUpdate(option, true)
		}()
	}
	optionsLock.RUnlock()

	signalChanges()
	return validationErrors
}

// applyPolicyLocked sets the policy value of the option from the policy
// layer. The caller must hold policyLock and the option lock.
func applyPolicyLocked(option *Option) *ValidationError {
	option.policyValue = nil
	option.policyLocked = false
	if option.Annotations != nil {
		delete(option.Annotations, PolicyAnnotation)
	}

	value, ok := policyValues[option.Key]
	if !ok {
		return nil
	}
	value = migrateValue(option, value)
	vc, err := validateValue(option, value)
	if err != nil {
		return err
	}
	option.policyValue = vc
	_, option.policyLocked = policyLocked[option.Key]
	if option.policyLocked {
		option.setAnnotation(PolicyAnnotation, PolicyLocked)
	} else {
		option.setAnnotation(PolicyAnnotation, PolicyDefault)
	}
	return nil
}

// IsLocked returns whether the policy locks the option.
func (option *Option) IsLocked() bool {
	option.Lock()
	defer option.Unlock()
	return option.policyLocked
}

// PolicyValue returns the policy value of the option and whether it is
// locked, or nil if the policy does not set it.
func (option *Option) PolicyValue() (value any, locked bool) {
	option.Lock()
	defer option.Unlock()
	if option.policyValue == nil {
		return nil, false
	}
	return option.policyValue.getData(option), option.policyLocked
}

// EffectiveValue returns the value in force: the locked policy value, the
// user value, the policy default or the default.
func (option *Option) EffectiveValue() any {
	option.Lock()
	defer option.Unlock()
	return option.effectiveValueCache().getData(option)
}

// IsLocked returns whether the policy locks the option with the given key.
// It returns false for unknown keys.
func IsLocked(key string) bool {
	option, err := GetOption(key)
	if err != nil {
		return false
	}
	return option.IsLocked()
}

// LockedKeys returns the keys of the options the policy locks, sorted.
func LockedKeys() []string {
	optionsLock.RLock()
	defer optionsLock.RUnlock()
	var keys []string
	for key, option := range options {
		if option.IsLocked() {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return keys
}

// CheckNotLocked returns an error wrapping ErrLockedByPolicy if one of the
// keys is locked by the policy.
func CheckNotLocked(keys ...string) error {
	var locked []string
	for _, key := range keys {
		if IsLocked(key) {
			locked = append(locked, key)
		}
	}
	if len(locked) == 0 {
		return nil
	}
	slices.Sort(locked)
	return fmt.Errorf("%w: %v", ErrLockedByPolicy, locked)
}

// effectiveValueCache returns the value in force. The caller must hold the
// option lock.
func (option *Option) effectiveValueCache() *valueCache {
	switch {
	case option.policyValue != nil && option.policyLocked:
		return option.policyValue
	case option.ReleaseLevel <= getReleaseLevel() && option.activeValue != nil:
		return option.activeValue
	case option.policyValue != nil:
		return option.policyValue
	case option.activeDefaultValue != nil:
		return option.activeDefaultValue
	default:
		return option.activeFallbackValue
	}
}
