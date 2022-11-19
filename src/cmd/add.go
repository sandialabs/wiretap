package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"wiretap/api"
	"wiretap/peer"
)

type addCmdConfig struct {
	allowedIPs []string
	endpoint   string
	port       int
	configFile string
	addr4      string
	addr6      string
	apiAddr    string
	disableApi bool
	keepalive  int
}

// Defaults for add command.
// See root command for shared defaults.
var addCmd = addCmdConfig{
	allowedIPs: []string{"0.0.0.0/32"},
	endpoint:   Endpoint,
	port:       Port,
	configFile: Config,
	addr4:      "",
	addr6:      "",
	apiAddr:    ApiAddr.String(),
	disableApi: false,
	keepalive:  Keepalive,
}

// Add command and set flags.
func init() {
	// Usage info.
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add peer to wiretap",
		Long:  `Generate configuration for an additional peer and push it to server via API`,
		Run: func(cmd *cobra.Command, args []string) {
			addCmd.Run()
		},
	}

	rootCmd.AddCommand(cmd)

	cmd.Flags().StringSliceVarP(&addCmd.allowedIPs, "routes", "r", addCmd.allowedIPs, "CIDR IP ranges that will be routed through wiretap")
	cmd.Flags().StringVarP(&addCmd.endpoint, "endpoint", "e", addCmd.endpoint, "socket address of wireguard listener that server will connect to (example \"1.2.3.4:51820\")")
	cmd.Flags().IntVarP(&addCmd.port, "port", "p", addCmd.port, "port of local wireguard listener")
	cmd.Flags().StringVarP(&addCmd.configFile, "output", "o", addCmd.configFile, "wireguard config output filename")
	cmd.Flags().StringVarP(&addCmd.addr4, "ipv4", "4", addCmd.addr4, "virtual wireguard interface ipv4 address, leave default to let server choose address")
	cmd.Flags().StringVarP(&addCmd.addr6, "ipv6", "6", addCmd.addr6, "virtual wireguard interface ipv6 address, leave default to let server choose address")

	cmd.Flags().StringVarP(&addCmd.apiAddr, "api", "0", addCmd.apiAddr, "address of server API service")
	cmd.Flags().BoolVarP(&addCmd.disableApi, "disable-api", "d", addCmd.disableApi, "remove API address from AllowedIPs")
	cmd.Flags().IntVarP(&addCmd.keepalive, "keepalive", "k", addCmd.keepalive, "tunnel keepalive in seconds")

	cmd.Flags().SortFlags = false

	helpFunc := cmd.HelpFunc()
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if !ShowHidden {
			for _, f := range []string{"api", "disable-api", "keepalive"} {
				err := cmd.Flags().MarkHidden(f)
				if err != nil {
					fmt.Printf("Failed to hide flag %v: %v\n", f, err)
				}
			}
		}
		helpFunc(cmd, args)
	})
}

// Run attempts to add peer to serve and write new file configuration.
func (c addCmdConfig) Run() {
	var err error

	// Disable API
	if !c.disableApi {
		c.allowedIPs = append(c.allowedIPs, c.apiAddr)
	}

	// Query server for public key information. More portable than reading device.
	apiPrefix, err := netip.ParsePrefix(c.apiAddr)
	check("failed to parse API address", err)
	apiAddr := net.JoinHostPort(apiPrefix.Addr().String(), strconv.Itoa(ApiPort))

	req := api.Request{
		URL:    fmt.Sprintf("http://%s/serverinfo", apiAddr),
		Method: "GET",
	}
	body, err := api.MakeRequest(req)
	check("request failed", err)

	var serverConfig peer.Config
	err = json.Unmarshal(body, &serverConfig)
	check("failed to decode response from server", err)

	// Make new configuration for new peer.
	configArgs := peer.ConfigArgs{
		ListenPort: c.port,
		Addresses:  []string{c.addr4, c.addr6},
		Peers: []peer.PeerConfigArgs{
			{
				PublicKey:  serverConfig.GetPublicKey(),
				Endpoint:   c.endpoint,
				AllowedIPs: c.allowedIPs,
			},
		},
	}

	config, err := peer.GetConfig(configArgs)
	check("failed to generate config", err)

	// Server only needs a portion of the information we need to send.
	newPeerConfig, err := peer.GetPeerConfig(peer.PeerConfigArgs{
		PublicKey:                   config.GetPublicKey(),
		Endpoint:                    c.endpoint,
		PersistentKeepaliveInterval: c.keepalive,
		AllowedIPs:                  []string{c.addr4, c.addr6},
	})
	check("failed to generate peer config", err)

	// Serialize peer config and send to server.
	body, err = json.Marshal(&newPeerConfig)
	check("failed to marshal peer config", err)
	req = api.Request{
		URL:    fmt.Sprintf("http://%s/peers/add", apiAddr),
		Method: "POST",
		Body:   body,
	}
	body, err = api.MakeRequest(req)
	check("request failed", err)

	err = json.Unmarshal(body, &newPeerConfig)
	check("failed to parse response", err)

	newAddrs := newPeerConfig.GetAllowedIPs()
	var newAddrStrings []string
	for _, addr := range newAddrs {
		newAddrStrings = append(newAddrStrings, addr.String())
	}
	err = config.SetAddresses(newAddrStrings)
	check("failed to set new addresses", err)

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
		fileStatus = Red(fmt.Sprintf("error writing config file: %v", err))
	} else {
		fileStatus = Green(c.configFile)
	}

	// Write and format output.
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, "Configuration successfully generated and pushed to server.")
	fmt.Fprintln(color.Output, "Import this config locally or send it to a friend.")
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, GreenBold("config:"), fileStatus)
	fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
	fmt.Fprint(color.Output, WhiteBold(config.AsFile()))
	fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
	fmt.Fprintln(color.Output)
}
