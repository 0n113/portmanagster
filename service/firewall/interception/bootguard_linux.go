package interception

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"

	"github.com/safing/portmaster/base/log"
)

// The boot guard blocks the network from early boot until the core has set
// its own rules, so that nothing connects unfiltered in between. It is set by
// portmaster-boot-guard.service before network-pre.target and removed by the
// core once its rules are in place, or by recover-iptables.
//
// It allows loopback, DHCP and (for IPv6) ICMPv6, which address
// configuration needs, and connections that already exist, so that starting
// it on a running system does not cut them.
var (
	bootGuardV4Chains = []string{
		"filter PORTMASTER-BOOT-IN",
		"filter PORTMASTER-BOOT-OUT",
		"filter PORTMASTER-BOOT-FWD",
	}
	bootGuardV4Rules = []string{
		"filter PORTMASTER-BOOT-IN -i lo -j ACCEPT",
		"filter PORTMASTER-BOOT-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"filter PORTMASTER-BOOT-IN -p udp --sport 67 --dport 68 -j ACCEPT",
		"filter PORTMASTER-BOOT-IN -j DROP",
		"filter PORTMASTER-BOOT-OUT -o lo -j ACCEPT",
		"filter PORTMASTER-BOOT-OUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"filter PORTMASTER-BOOT-OUT -p udp --sport 68 --dport 67 -j ACCEPT",
		"filter PORTMASTER-BOOT-OUT -j DROP",
		"filter PORTMASTER-BOOT-FWD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"filter PORTMASTER-BOOT-FWD -j DROP",
	}
	bootGuardV6Chains = bootGuardV4Chains
	bootGuardV6Rules  = []string{
		"filter PORTMASTER-BOOT-IN -i lo -j ACCEPT",
		"filter PORTMASTER-BOOT-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"filter PORTMASTER-BOOT-IN -p icmpv6 -j ACCEPT",
		"filter PORTMASTER-BOOT-IN -p udp --sport 547 --dport 546 -j ACCEPT",
		"filter PORTMASTER-BOOT-IN -j DROP",
		"filter PORTMASTER-BOOT-OUT -o lo -j ACCEPT",
		"filter PORTMASTER-BOOT-OUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"filter PORTMASTER-BOOT-OUT -p icmpv6 -j ACCEPT",
		"filter PORTMASTER-BOOT-OUT -p udp --sport 546 --dport 547 -j ACCEPT",
		"filter PORTMASTER-BOOT-OUT -j DROP",
		"filter PORTMASTER-BOOT-FWD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"filter PORTMASTER-BOOT-FWD -j DROP",
	}
	bootGuardOnce = []string{
		"filter INPUT -j PORTMASTER-BOOT-IN",
		"filter OUTPUT -j PORTMASTER-BOOT-OUT",
		"filter FORWARD -j PORTMASTER-BOOT-FWD",
	}
)

// ActivateBootGuard sets the boot guard rules. IPv6 is skipped if the system
// has no IPv6 support.
func ActivateBootGuard() error {
	iptablesLock.Lock()
	defer iptablesLock.Unlock()

	err := activateIPTables(iptables.ProtocolIPv4, bootGuardV4Rules, bootGuardOnce, bootGuardV4Chains)
	if err != nil {
		return fmt.Errorf("boot guard (IPv4): %w", err)
	}

	err = activateIPTables(iptables.ProtocolIPv6, bootGuardV6Rules, bootGuardOnce, bootGuardV6Chains)
	if err != nil {
		log.Warningf("interception: boot guard not set for IPv6: %s", err)
	}
	return nil
}

// removeBootGuard removes the boot guard rules, if there are any, and
// reports whether it found them. The caller must hold iptablesLock.
func removeBootGuard() (removed bool) {
	for _, protocol := range []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6} {
		tbls, err := iptables.NewWithProtocol(protocol)
		if err != nil {
			continue
		}
		for _, rule := range bootGuardOnce {
			parts := strings.Split(rule, " ")
			ok, err := tbls.Exists(parts[0], parts[1], parts[2:]...)
			if err != nil || !ok {
				continue
			}
			err = tbls.Delete(parts[0], parts[1], parts[2:]...)
			if err != nil {
				log.Warningf("interception: failed to remove boot guard rule %q: %s", rule, err)
				continue
			}
			removed = true
		}
		for _, chain := range bootGuardV4Chains {
			parts := strings.Split(chain, " ")
			exists, err := tbls.ChainExists(parts[0], parts[1])
			if err != nil || !exists {
				continue
			}
			_ = tbls.ClearChain(parts[0], parts[1])
			_ = tbls.DeleteChain(parts[0], parts[1])
		}
	}
	return removed
}
