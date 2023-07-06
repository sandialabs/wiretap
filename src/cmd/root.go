// Package cmd handles command line arguments.
package cmd

import (
	"fmt"
	"log"
	"net/netip"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// Defaults shared by multiple commands.
var (
	Version            = "v0.0.0"
	Endpoint           = ""
	Port               = 51820
	E2EEPort           = 51821
	ConfigRelay        = "wiretap_relay.conf"
	ConfigE2EE         = "wiretap.conf"
	ConfigServer       = "wiretap_server.conf"
	Keepalive          = 25
	MTU                = 1420
	ShowHidden         = false
	ApiSubnets         = netip.MustParsePrefix("::/8")
	ApiV4Subnets       = netip.MustParsePrefix("192.0.2.0/24")
	ApiPort            = 80
	ClientRelaySubnet4 = netip.MustParsePrefix("172.16.0.0/16")
	ClientRelaySubnet6 = netip.MustParsePrefix("fd:16::/40")
	RelaySubnets4      = netip.MustParsePrefix("172.17.0.0/16")
	RelaySubnets6      = netip.MustParsePrefix("fd:17::/40")
	E2EESubnets4       = netip.MustParsePrefix("172.18.0.0/16")
	E2EESubnets6       = netip.MustParsePrefix("fd:18::/40")
	ClientE2EESubnet4  = netip.MustParsePrefix("172.19.0.0/16")
	ClientE2EESubnet6  = netip.MustParsePrefix("fd:19::/40")
	SubnetV4Bits       = 24
	SubnetV6Bits       = 48
	APIBits            = 16
	APIV4Bits          = 24
)

// Define colors.
var (
	Green     = color.New(color.FgGreen).SprintFunc()
	GreenBold = color.New(color.FgGreen, color.Bold).SprintFunc()
	Red       = color.New(color.FgRed).SprintFunc()
	RedBold   = color.New(color.FgRed, color.Bold).SprintFunc()
	WhiteBold = color.New(color.FgWhite, color.Bold).SprintFunc()
	Cyan      = color.New(color.FgCyan).SprintFunc()
)

// Root wiretap command, doesn't do much on its own.
// Prints help by default.
var rootCmd = &cobra.Command{
	Use: "wiretap",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			err := cmd.Help()
			if err != nil {
				fmt.Println("Failed to print help:", err)
			}
			os.Exit(0)
		}
	},
	Version: Version,
	CompletionOptions: cobra.CompletionOptions{
		HiddenDefaultCmd: true,
	},
}

// Execute starts command handling, called by main.
func Execute() {
	rootCmd.PersistentFlags().BoolVarP(&ShowHidden, "show-hidden", "", ShowHidden, "show hidden flag options")
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// check is a helper function that logs and exits if an error is not nil.
func check(message string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", message, err)
	}
}
