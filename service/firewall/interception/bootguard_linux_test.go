package interception

import (
	"slices"
	"strings"
	"testing"
)

// TestBootGuardRules checks that every boot guard rule is in one of its own
// chains, that the chains are only used from the hooks that allow their
// interface matches, and that each chain ends with a drop.
func TestBootGuardRules(t *testing.T) {
	t.Parallel()

	for name, rules := range map[string][]string{"IPv4": bootGuardV4Rules, "IPv6": bootGuardV6Rules} {
		last := map[string]string{}
		for _, rule := range rules {
			parts := strings.Fields(rule)
			chain := parts[0] + " " + parts[1]
			if !slices.Contains(bootGuardV4Chains, chain) {
				t.Errorf("%s: rule %q is not in a boot guard chain", name, rule)
			}
			switch {
			case strings.HasSuffix(parts[1], "-IN") && slices.Contains(parts, "-o"),
				strings.HasSuffix(parts[1], "-OUT") && slices.Contains(parts, "-i"):
				t.Errorf("%s: rule %q matches an interface its hook does not have", name, rule)
			}
			last[parts[1]] = rule
		}
		for _, chain := range bootGuardV4Chains {
			c := strings.Fields(chain)[1]
			if !strings.HasSuffix(last[c], "-j DROP") {
				t.Errorf("%s: chain %s does not end with a drop: %q", name, c, last[c])
			}
		}
	}

	for _, rule := range bootGuardOnce {
		target := strings.Fields(rule)[3]
		if !slices.Contains(bootGuardV4Chains, "filter "+target) {
			t.Errorf("jump rule %q targets an unknown chain", rule)
		}
	}
}

// TestJumpRulesOnePerChain checks that no two jump rules of the Portmaster
// compete for the first position of the same chain.
func TestJumpRulesOnePerChain(t *testing.T) {
	t.Parallel()

	for name, once := range map[string][]string{"IPv4": v4once, "IPv6": v6once, "boot guard": bootGuardOnce} {
		seen := map[string]bool{}
		for _, rule := range once {
			parts := strings.Fields(rule)
			chain := parts[0] + " " + parts[1]
			if seen[chain] {
				t.Errorf("%s: more than one jump rule in %s", name, chain)
			}
			seen[chain] = true
		}
	}
}
