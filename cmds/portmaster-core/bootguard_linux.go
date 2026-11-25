package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/safing/portmaster/service/firewall/interception"
)

var bootGuardCmd = &cobra.Command{
	Use:   "boot-guard",
	Short: "Block the network until the Portmaster has set its rules (run by portmaster-boot-guard.service)",
	RunE: func(_ *cobra.Command, _ []string) error {
		// go-iptables parses the output of the iptables binary.
		_ = os.Setenv("LC_ALL", "C")
		return interception.ActivateBootGuard()
	},
}

func init() {
	rootCmd.AddCommand(bootGuardCmd)
}
