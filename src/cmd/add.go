package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

type addCmdConfig struct {
	endpoint  string
	outbound  bool
	keepalive int
}

// Defaults for add command.
// See root command for shared defaults.
var addCmdArgs = addCmdConfig{
	endpoint:  Endpoint,
	outbound:  false,
	keepalive: Keepalive,
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

	addCmd.PersistentFlags().StringVarP(&addCmdArgs.endpoint, "endpoint", "e", addCmdArgs.endpoint, "[REQUIRED] socket address of wireguard listener; client address if inbound handshake and server address if outbound (example \"1.2.3.4:51820\")")
	addCmd.PersistentFlags().BoolVar(&addCmdArgs.outbound, "outbound", addCmdArgs.outbound, "use endpoint to initiate handshake out to server instead of the other way around")

	addCmd.PersistentFlags().IntVarP(&addCmdArgs.keepalive, "keepalive", "k", addCmdArgs.keepalive, "tunnel keepalive in seconds")

	err := addCmd.MarkPersistentFlagRequired("endpoint")
	check("failed to mark flag required", err)

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
