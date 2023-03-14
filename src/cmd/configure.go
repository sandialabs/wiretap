package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"wiretap/peer"

	"github.com/atotto/clipboard"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type configureCmdConfig struct {
	allowedIPs       []string
	endpoint         string
	port             int
	configFile       string
	writeToClipboard bool
	addr4            string
	addr6            string
	apiAddr          string
	disableApi       bool
}

// Defaults for configure command.
// See root command for shared defaults.
var configureCmd = configureCmdConfig{
	allowedIPs:       []string{"0.0.0.0/32"},
	endpoint:         Endpoint,
	port:             Port,
	configFile:       Config,
	writeToClipboard: false,
	addr4:            Subnet4.Addr().Next().Next().String() + "/32",
	addr6:            Subnet6.Addr().Next().Next().String() + "/128",
	apiAddr:          ApiAddr.String(),
	disableApi:       false,
}

// Add command and set flags.
func init() {
	// Usage info.
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Build wireguard config",
		Long:  `Build wireguard config and print command line arguments for deployment`,
		Run: func(cmd *cobra.Command, args []string) {
			configureCmd.Run()
		},
	}

	rootCmd.AddCommand(cmd)

	cmd.Flags().StringSliceVarP(&configureCmd.allowedIPs, "routes", "r", configureCmd.allowedIPs, "CIDR IP ranges that will be routed through wiretap")
	cmd.Flags().StringVarP(&configureCmd.endpoint, "endpoint", "e", configureCmd.endpoint, "socket address of wireguard listener that server will connect to (example \"1.2.3.4:51820\")")
	cmd.Flags().IntVarP(&configureCmd.port, "port", "p", configureCmd.port, "port of local wireguard listener")
	cmd.Flags().StringVarP(&configureCmd.configFile, "output", "o", configureCmd.configFile, "wireguard config output filename")
	cmd.Flags().BoolVarP(&configureCmd.writeToClipboard, "clipboard", "c", configureCmd.writeToClipboard, "copy configuration args to clipboard")

	cmd.Flags().StringVarP(&configureCmd.addr4, "ipv4", "4", configureCmd.addr4, "virtual wireguard interface ipv4 address")
	cmd.Flags().StringVarP(&configureCmd.addr6, "ipv6", "6", configureCmd.addr6, "virtual wireguard interface ipv6 address")
	cmd.Flags().StringVarP(&configureCmd.apiAddr, "api", "0", configureCmd.apiAddr, "address of server API service")
	cmd.Flags().BoolVarP(&configureCmd.disableApi, "disable-api", "d", configureCmd.disableApi, "remove API address from AllowedIPs")

	cmd.Flags().SortFlags = false

	helpFunc := cmd.HelpFunc()
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if !ShowHidden {
			for _, f := range []string{"ipv4", "ipv6", "api", "disable-api"} {
				err := cmd.Flags().MarkHidden(f)
				if err != nil {
					fmt.Printf("Failed to hide flag %v: %v\n", f, err)
				}
			}
		}
		helpFunc(cmd, args)
	})
}

// Run builds a Wireguard config and prints/writes it to a file.
// Also prints out a command to paste into a remote machine.
func (c configureCmdConfig) Run() {
	var err error

	// Set API address if not disabled.
	if !c.disableApi {
		c.allowedIPs = append(c.allowedIPs, c.apiAddr)
	}

	// Use arguments to configure peer.
	configArgs := peer.ConfigArgs{
		ListenPort: c.port,
		Peers: []peer.PeerConfigArgs{
			{
				Endpoint:   c.endpoint,
				AllowedIPs: c.allowedIPs,
			},
		},
		Addresses: []string{c.addr4, c.addr6},
	}

	config, err := peer.GetConfig(configArgs)
	check("failed to generate config", err)

	// Add number to filename if it already exists.
	count := 1
	ext := filepath.Ext(c.configFile)
	basename := strings.TrimSuffix(c.configFile, ext)
	for {
		_, err = os.Stat(c.configFile)
		if os.IsNotExist(err) {
			break
		}
		c.configFile = fmt.Sprintf("%s_%d%s", basename, count, ext)
		count += 1
	}

	// Write config file and get status string.
	var fileStatus string
	err = os.WriteFile(c.configFile, []byte(config.AsFile()), 0600)
	if err != nil {
		fileStatus = fmt.Sprintf("%s %s", RedBold("config:"), Red(fmt.Sprintf("error writing config file: %v", err)))
	} else {
		fileStatus = fmt.Sprintf("%s %s", GreenBold("config:"), Green(c.configFile))
	}

	// Generate argument string.
	argString := fmt.Sprintf("serve --private %s --public %s",
		config.GetPeerPrivateKey(0),
		config.GetPublicKey(),
	)

	if len(config.GetPeerEndpoint(0)) > 0 {
		argString = fmt.Sprintf("%s --endpoint %s", argString, config.GetPeerEndpoint(0))
	}

	var clipboardStatus string
	if c.writeToClipboard {
		err = clipboard.WriteAll(argString)
		if err != nil {
			clipboardStatus = fmt.Sprintf("%s %s", RedBold("clipboard:"), Red(fmt.Sprintf("error copying to clipboard: %v", err)))
		} else {
			clipboardStatus = fmt.Sprintf("%s %s", GreenBold("clipboard:"), Green("successfully copied"))
		}
	}

	// Generate server config file.
	serverConfig := fmt.Sprintf("[Interface]\nPrivate = %s\n[Peer]\nPublic = %s\n",
		config.GetPeerPrivateKey(0),
		config.GetPublicKey(),
	)

	if len(config.GetPeerEndpoint(0)) > 0 {
		serverConfig = fmt.Sprintf("%sEndpoint = %s\n", serverConfig, config.GetPeerEndpoint(0))
	}

	// Write and format output.
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, "Configuration successfully generated.")
	fmt.Fprintln(color.Output, "Import the config into WireGuard locally and pass the arguments below to Wiretap on the remote machine.")
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, fileStatus)
	fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
	fmt.Fprint(color.Output, WhiteBold(config.AsFile()))
	fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, GreenBold("args:"), Green(argString))
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, GreenBold("server config:"))
	fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
	fmt.Fprint(color.Output, WhiteBold(serverConfig))
	fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
	fmt.Fprintln(color.Output)
	if c.writeToClipboard {
		fmt.Fprintln(color.Output, clipboardStatus)
		fmt.Fprintln(color.Output)
	}
}
