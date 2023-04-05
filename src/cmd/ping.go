package cmd

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"wiretap/api"
)

type pingCmdConfig struct {
	apiAddr string
}

// Defaults for ping command.
// See root command for shared defaults.
var pingCmd = pingCmdConfig{
	apiAddr: ApiSubnets.Addr().Next().Next().String(),
}

// Add command and set flags.
func init() {
	// Usage info.
	cmd := &cobra.Command{
		Use:   "ping",
		Short: "Ping wiretap server API",
		Long:  `Test connectivity with wiretap server by querying ping API endpoint`,
		Run: func(cmd *cobra.Command, args []string) {
			pingCmd.Run()
		},
	}

	rootCmd.AddCommand(cmd)

	cmd.Flags().StringVarP(&pingCmd.apiAddr, "api", "0", pingCmd.apiAddr, "address of server API service")

	cmd.Flags().SortFlags = false
}

// Run attempts to ping server API and prints response.
func (c pingCmdConfig) Run() {
	var err error

	apiAddr, err := netip.ParseAddr(c.apiAddr)
	check("failed to parse API address", err)

	start := time.Now()
	response, err := api.Ping(netip.AddrPortFrom(apiAddr, uint16(ApiPort)))
	check("request failed", err)

	duration := time.Since(start)

	fmt.Fprintf(color.Output, "%s: %s\n", GreenBold("response"), Green(string(response)))
	fmt.Fprintf(color.Output, "  %s: %v\n", WhiteBold("from"), apiAddr)
	fmt.Fprintf(color.Output, "  %s: %f %s\n", WhiteBold("time"), float64(duration)/float64(time.Millisecond), Cyan("milliseconds"))
}
