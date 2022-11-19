package cmd

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
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
	apiAddr: ApiAddr.String(),
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

	apiPrefix, err := netip.ParsePrefix(c.apiAddr)
	check("failed to parse API address", err)
	apiAddr := apiPrefix.Addr()

	req := api.Request{
		URL:    fmt.Sprintf("http://%s/ping", net.JoinHostPort(apiAddr.String(), strconv.Itoa(ApiPort))),
		Method: "GET",
	}

	start := time.Now()
	body, err := api.MakeRequest(req)
	check("request failed", err)

	duration := time.Since(start)

	fmt.Fprintf(color.Output, "%s: %s\n", GreenBold("response"), Green(string(body)))
	fmt.Fprintf(color.Output, "  %s: %v\n", WhiteBold("from"), apiAddr)
	fmt.Fprintf(color.Output, "  %s: %f %s\n", WhiteBold("time"), float64(duration)/float64(time.Millisecond), Cyan("milliseconds"))
}
