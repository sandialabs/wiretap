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
	Version      = "v0.0.0"
	Endpoint     = ""
	Port         = 51820
	Config       = "wiretap.conf"
	ServerConfig = "wiretap_server.conf"
	Keepalive    = 25
	ShowHidden   = false
	ApiAddr      = netip.MustParsePrefix("a::/128")
	ApiPort      = 80
	Subnet4      = netip.MustParsePrefix("192.168.0.0/24")
	Subnet6      = netip.MustParsePrefix("fd::/64")
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
