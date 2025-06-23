package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

type addCmdConfig struct {
	endpoint         string
	outboundEndpoint string
	keepalive        int
}

// Defaults for add command.
// See root command for shared defaults.
var addCmdArgs = addCmdConfig{
	endpoint:         Endpoint,
	outboundEndpoint: Endpoint,
	keepalive:        Keepalive,
}

// addCmd represents the add command.
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add peer to wiretap",
	Long:  `Add client or server to wiretap network`,
}

// Add command and set flags.
func init() {
	rootCmd.AddCommand(addCmd)

	addCmd.PersistentFlags().StringVarP(&addCmdArgs.endpoint, "endpoint", "e", addCmdArgs.endpoint, "IP:PORT (or [IP]:PORT for IPv6) of wireguard listener that server will connect to (example \"1.2.3.4:51820\")")
	addCmd.PersistentFlags().StringVarP(&addCmdArgs.outboundEndpoint, "outbound-endpoint", "o", addCmdArgs.outboundEndpoint, "IP:PORT (or [IP]:PORT for IPv6) of wireguard listener that client will connect to (example \"4.3.2.1:51820\"")

	addCmd.PersistentFlags().IntVarP(&addCmdArgs.keepalive, "keepalive", "k", addCmdArgs.keepalive, "tunnel keepalive in seconds")

	addCmd.Flags().SortFlags = false
	addCmd.PersistentFlags().SortFlags = false

	helpFunc := addCmd.HelpFunc()
	addCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if !ShowHidden {
			for _, f := range []string{
				"keepalive",
			} {
				err := cmd.Flags().MarkHidden(f)
				if err != nil {
					fmt.Printf("Failed to hide flag %v: %v\n", f, err)
				}
			}
		}
		helpFunc(cmd, args)
	})
}
