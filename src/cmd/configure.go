package cmd

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"wiretap/peer"

	"github.com/atotto/clipboard"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type configureCmdConfig struct {
	allowedIPs       []string
	endpoint         string
	outboundEndpoint string
	port             int
	sport            int
	nickname         string
	configFileRelay  string
	configFileE2EE   string
	configFileServer string
	writeToClipboard bool
	simple           bool
	clientAddr4Relay string
	clientAddr6Relay string
	clientAddr4E2EE  string
	clientAddr6E2EE  string
	serverAddr4Relay string
	serverAddr6Relay string
	apiAddr          string
	apiv4Addr        string
	keepalive        int
	mtu              int
	disableV6        bool
	localhostIP      string
}

// Defaults for configure command.
// See root command for shared defaults.
var configureCmdArgs = configureCmdConfig{
	allowedIPs:       []string{""},
	endpoint:         Endpoint,
	outboundEndpoint: Endpoint,
	port:             USE_ENDPOINT_PORT,
	sport:            USE_ENDPOINT_PORT,
	nickname:         "",
	configFileRelay:  ConfigRelay,
	configFileE2EE:   ConfigE2EE,
	configFileServer: ConfigServer,
	writeToClipboard: false,
	simple:           false,
	clientAddr4Relay: ClientRelaySubnet4.Addr().Next().String() + "/32",
	clientAddr6Relay: ClientRelaySubnet6.Addr().Next().String() + "/128",
	clientAddr4E2EE:  ClientE2EESubnet4.Addr().Next().String() + "/32",
	clientAddr6E2EE:  ClientE2EESubnet6.Addr().Next().String() + "/128",
	serverAddr4Relay: RelaySubnets4.Addr().Next().Next().String() + "/32",
	serverAddr6Relay: RelaySubnets6.Addr().Next().Next().String() + "/128",
	apiAddr:          ApiSubnets.Addr().Next().Next().String() + "/128",
	apiv4Addr:        ApiV4Subnets.Addr().Next().Next().String() + "/32",
	keepalive:        Keepalive,
	mtu:              MTU,
	disableV6:        false,
	localhostIP:      "",
}

// configureCmd represents the configure command.
var configureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Build wireguard config",
	Long:  `Build wireguard config and print command line arguments for deployment`,
	Run: func(cmd *cobra.Command, args []string) {
		configureCmdArgs.Run()
	},
}

// Add command and set flags.
func init() {
	rootCmd.AddCommand(configureCmd)

	configureCmd.Flags().StringSliceVarP(&configureCmdArgs.allowedIPs, "routes", "r", configureCmdArgs.allowedIPs, "[REQUIRED] CIDR IP ranges that will be routed through wiretap (example \"10.0.0.1/24\")")
	configureCmd.Flags().StringVarP(&configureCmdArgs.endpoint, "endpoint", "e", configureCmdArgs.endpoint, "IP:PORT (or [IP]:PORT for IPv6) of wireguard listener that server will connect to (example \"1.2.3.4:51820\")")
	configureCmd.Flags().StringVarP(&configureCmdArgs.outboundEndpoint, "outbound-endpoint", "o", configureCmdArgs.outboundEndpoint, "IP:PORT (or [IP]:PORT for IPv6) of wireguard listener that client will connect to (example \"1.2.3.4:51820\"")
	configureCmd.Flags().IntVarP(&configureCmdArgs.port, "port", "p", configureCmdArgs.port, "listener port for client wireguard relay. Default is to copy the --endpoint port.")
	configureCmd.Flags().IntVarP(&configureCmdArgs.sport, "sport", "S", configureCmdArgs.sport, "listener port for server wireguard relay. Default is to copy the --outbound-endpoint port.")
	configureCmd.Flags().StringVarP(&configureCmdArgs.nickname, "nickname", "n", configureCmdArgs.nickname, "Server nickname to display in 'status' command")
	configureCmd.Flags().StringVarP(&configureCmdArgs.localhostIP, "localhost-ip", "i", configureCmdArgs.localhostIP, "[EXPERIMENTAL] Redirect wiretap packets destined for this IPv4 address to server's localhost")

	configureCmd.Flags().StringVarP(&configureCmdArgs.configFileRelay, "relay-output", "", configureCmdArgs.configFileRelay, "wireguard relay config output filename")
	configureCmd.Flags().StringVarP(&configureCmdArgs.configFileE2EE, "e2ee-output", "", configureCmdArgs.configFileE2EE, "wireguard E2EE config output filename")
	configureCmd.Flags().StringVarP(&configureCmdArgs.configFileServer, "server-output", "s", configureCmdArgs.configFileServer, "wiretap server config output filename")
	configureCmd.Flags().BoolVarP(&configureCmdArgs.writeToClipboard, "clipboard", "c", configureCmdArgs.writeToClipboard, "copy configuration args to clipboard")
	configureCmd.Flags().BoolVarP(&configureCmdArgs.simple, "simple", "", configureCmdArgs.simple, "disable multihop and multiclient features for a simpler setup")

	configureCmd.Flags().StringVarP(&configureCmdArgs.apiAddr, "api", "0", configureCmdArgs.apiAddr, "address of server API service")
	configureCmd.Flags().IntVarP(&configureCmdArgs.keepalive, "keepalive", "k", configureCmdArgs.keepalive, "tunnel keepalive in seconds, only applies to outbound handshakes")
	configureCmd.Flags().IntVarP(&configureCmdArgs.mtu, "mtu", "m", configureCmdArgs.mtu, "tunnel MTU")
	configureCmd.Flags().BoolVarP(&configureCmdArgs.disableV6, "disable-ipv6", "", configureCmdArgs.disableV6, "disables IPv6")

	configureCmd.Flags().StringVarP(&configureCmdArgs.clientAddr4Relay, "ipv4-relay", "", configureCmdArgs.clientAddr4Relay, "ipv4 relay address")
	configureCmd.Flags().StringVarP(&configureCmdArgs.clientAddr6Relay, "ipv6-relay", "", configureCmdArgs.clientAddr6Relay, "ipv6 relay address")
	configureCmd.Flags().StringVarP(&configureCmdArgs.clientAddr4E2EE, "ipv4-e2ee", "", configureCmdArgs.clientAddr4E2EE, "ipv4 e2ee address")
	configureCmd.Flags().StringVarP(&configureCmdArgs.clientAddr6E2EE, "ipv6-e2ee", "", configureCmdArgs.clientAddr6E2EE, "ipv6 e2ee address")
	configureCmd.Flags().StringVarP(&configureCmdArgs.serverAddr4Relay, "ipv4-relay-server", "", configureCmdArgs.serverAddr4Relay, "ipv4 relay address of server")
	configureCmd.Flags().StringVarP(&configureCmdArgs.serverAddr6Relay, "ipv6-relay-server", "", configureCmdArgs.serverAddr6Relay, "ipv6 relay address of server")

	err := configureCmd.MarkFlagRequired("routes")
	check("failed to mark flag required", err)

	configureCmd.Flags().SortFlags = false

	helpFunc := configureCmd.HelpFunc()
	configureCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if !ShowHidden {
			for _, f := range []string{
				"api",
				"ipv4-relay",
				"ipv6-relay",
				"ipv4-e2ee",
				"ipv6-e2ee",
				"ipv4-relay-server",
				"ipv6-relay-server",
				"keepalive",
				"mtu",
				"disable-ipv6",
				"relay-output",
				"e2ee-output",
				"server-output",
				"simple",
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

// Run builds Wireguard relay and E2EE configs, and prints/writes them to a file.
// Also prints out a command to paste into a remote machine.
func (c configureCmdConfig) Run() {
	var err error

	if c.localhostIP != "" {
		c.allowedIPs = append(c.allowedIPs, c.localhostIP+"/32")
	}
	if c.disableV6 && netip.MustParsePrefix(c.apiAddr).Addr().Is6() {
		c.apiAddr = c.apiv4Addr
	}
	c.allowedIPs = append(c.allowedIPs, c.apiAddr)

	// Generate client and server configs.
	serverConfigRelayArgs := peer.ConfigArgs{}
	serverConfigE2EEArgs := peer.ConfigArgs{}
	serverConfigRelay, err := peer.GetConfig(serverConfigRelayArgs)
	check("failed to generate server relay config", err)
	serverConfigE2EE, err := peer.GetConfig(serverConfigE2EEArgs)
	check("failed to generate server E2EE config", err)

	// Parse first client relay subnet.
	relaySubnet4, err := netip.ParsePrefix(c.serverAddr4Relay)
	check("invalid cidr range", err)
	relaySubnet6, err := netip.ParsePrefix(c.serverAddr6Relay)
	check("invalid cidr range", err)

	relaySubnet4 = netip.PrefixFrom(relaySubnet4.Addr(), SubnetV4Bits).Masked()
	relaySubnet6 = netip.PrefixFrom(relaySubnet6.Addr(), SubnetV6Bits).Masked()

	relaySubnets := []netip.Prefix{relaySubnet4}
	if !c.disableV6 {
		relaySubnets = append(relaySubnets, relaySubnet6)
	}

	clientRelayAddrs := []string{c.clientAddr4Relay}
	if !c.disableV6 {
		clientRelayAddrs = append(clientRelayAddrs, c.clientAddr6Relay)
	}

	clientE2EEAddrs := []string{c.clientAddr4E2EE}
	if !c.disableV6 {
		clientE2EEAddrs = append(clientE2EEAddrs, c.clientAddr6E2EE)
	}

	// Check for how client and server should connect
	if c.endpoint == Endpoint && c.outboundEndpoint == Endpoint {
		check("endpoint error", errors.New("connection between client and server not set"))
	} else if len(c.endpoint) > 0 && len(c.outboundEndpoint) > 0 {
		check("endpoint error", errors.New("conflicting connection configuration"))
	}

	if len(c.endpoint) > 0 {
		c.port = portFromEndpoint(c.endpoint)
	} else if c.port == USE_ENDPOINT_PORT {
		c.port = Port
	}

	if len(c.outboundEndpoint) > 0 {
		c.sport = portFromEndpoint(c.outboundEndpoint)
	} else if c.sport == USE_ENDPOINT_PORT {
		c.sport = Port
	}

	var clientPort int
	var serverPort int

	clientPort = c.port
	serverPort = c.sport

	err = serverConfigRelay.SetPort(serverPort)
	check("failed to set port", err)

	clientConfigRelayArgs := peer.ConfigArgs{
		ListenPort: clientPort,
		Peers: []peer.PeerConfigArgs{
			{
				PublicKey: serverConfigRelay.GetPublicKey(),
				AllowedIPs: func() []string {
					if c.simple {
						return c.allowedIPs
					} else {
						return func() []string {
							var s []string
							for _, r := range relaySubnets {
								s = append(s, r.String())
							}
							return s
						}()
					}
				}(),
				Endpoint: func() string {
					if len(c.outboundEndpoint) > 0 {
						return c.outboundEndpoint
					} else {
						return ""
					}
				}(),
				PersistentKeepaliveInterval: func() int {
					if len(c.outboundEndpoint) > 0 {
						return c.keepalive
					} else {
						return 0
					}
				}(),
			},
		},
		Addresses: clientRelayAddrs,
	}

	clientConfigE2EEArgs := peer.ConfigArgs{
		ListenPort: E2EEPort,
		Peers: []peer.PeerConfigArgs{
			{
				PublicKey:  serverConfigE2EE.GetPublicKey(),
				AllowedIPs: c.allowedIPs,
				Endpoint:   net.JoinHostPort(relaySubnet4.Addr().Next().Next().String(), fmt.Sprint(E2EEPort)),
				Nickname:   c.nickname,
			},
		},
		Addresses: clientE2EEAddrs,
		MTU:       c.mtu - 80,
	}

	clientConfigRelay, err := peer.GetConfig(clientConfigRelayArgs)
	check("failed to generate client relay config", err)

	clientConfigE2EE, err := peer.GetConfig(clientConfigE2EEArgs)
	check("failed to generate client E2EE config", err)

	clientPeerConfigRelay, err := clientConfigRelay.AsPeer()
	check("failed to parse relay config as peer", err)

	clientPeerConfigE2EE, err := clientConfigE2EE.AsPeer()
	check("failed to parse e2ee config as peer", err)

	if len(c.endpoint) > 0 {
		err = clientPeerConfigRelay.SetEndpoint(c.endpoint)
		check("failed to set endpoint", err)
	}

	err = clientPeerConfigE2EE.SetEndpoint(net.JoinHostPort(clientConfigRelay.GetAddresses()[0].IP.String(), fmt.Sprint(E2EEPort)))
	check("failed to set endpoint", err)

	serverConfigRelay.AddPeer(clientPeerConfigRelay)
	serverConfigE2EE.AddPeer(clientPeerConfigE2EE)
	if c.mtu != MTU {
		err = serverConfigRelay.SetMTU(c.mtu)
		check("failed to set mtu", err)
	}
	if c.localhostIP != "" {
		err = serverConfigRelay.SetLocalhostIP(c.localhostIP)
		check("failed to set localhost IP", err)
	}

	// Add number to filename if it already exists.
	c.configFileRelay = peer.FindAvailableFilename(c.configFileRelay)
	c.configFileE2EE = peer.FindAvailableFilename(c.configFileE2EE)
	c.configFileServer = peer.FindAvailableFilename(c.configFileServer)

	if c.simple {
		c.configFileRelay = c.configFileE2EE
	}

	// Write config file and get status string.
	var fileStatusRelay string
	err = os.WriteFile(c.configFileRelay, []byte(clientConfigRelay.AsFile()), 0600)
	if err != nil {
		fileStatusRelay = fmt.Sprintf("%s %s", RedBold("config:"), Red(fmt.Sprintf("error writing config file: %v", err)))
	} else {
		fileStatusRelay = fmt.Sprintf("%s %s", GreenBold("config:"), Green(c.configFileRelay))
	}

	// Write config file and get status string.
	var fileStatusE2EE string
	if !c.simple {
		err = os.WriteFile(c.configFileE2EE, []byte(clientConfigE2EE.AsFile()), 0600)
		if err != nil {
			fileStatusE2EE = fmt.Sprintf("%s %s", RedBold("config:"), Red(fmt.Sprintf("error writing config file: %v", err)))
		} else {
			fileStatusE2EE = fmt.Sprintf("%s %s", GreenBold("config:"), Green(c.configFileE2EE))
		}
	}

	// Write server config file and get status string.
	var fileStatusServer string
	file, err := os.Create(c.configFileServer)
	if err != nil {
		fileStatusServer = fmt.Sprintf("%s %s", RedBold("server config:"), Red(fmt.Sprintf("error creating server config file: %v", err)))
	} else {
		defer file.Close()

		data := []string{
			peer.CreateServerFile(serverConfigRelay, serverConfigE2EE, c.simple),
			"# POSIX Shell: " + peer.CreateServerCommand(serverConfigRelay, serverConfigE2EE, peer.POSIX, c.simple, c.disableV6),
			"# Powershell: " + peer.CreateServerCommand(serverConfigRelay, serverConfigE2EE, peer.PowerShell, c.simple, c.disableV6),
		}

		_, err = file.WriteString((strings.Join(data, "\n\n")))
		if err != nil {
			fileStatusServer = fmt.Sprintf("%s %s", RedBold("server config:"), Red(fmt.Sprintf("error writing config file: %v", err)))
		} else {
			fileStatusServer = fmt.Sprintf("%s %s", GreenBold("server config:"), Green(c.configFileServer))
		}
	}

	// Make config file string
	serverConfigFile := fmt.Sprintf("./wiretap serve -f %s", c.configFileServer)
	if c.disableV6 {
		serverConfigFile = fmt.Sprintf("%s --disable-ipv6", serverConfigFile)
	}

	// Copy to clipboard if requested.
	var clipboardStatus string
	if c.writeToClipboard {
		err = clipboard.WriteAll(peer.CreateServerCommand(serverConfigRelay, serverConfigE2EE, peer.POSIX, c.simple, c.disableV6))
		if err != nil {
			clipboardStatus = fmt.Sprintf("%s %s", RedBold("clipboard:"), Red(fmt.Sprintf("error copying to clipboard: %v", err)))
		} else {
			clipboardStatus = fmt.Sprintf("%s %s", GreenBold("clipboard:"), Green("successfully copied"))
		}
	}

	// Write and format output.
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, "Configurations successfully generated.")
	fmt.Fprintln(color.Output, "Import the config(s) into WireGuard locally and pass the arguments below to Wiretap on the remote machine.")
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, fileStatusRelay)
	fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
	fmt.Fprint(color.Output, WhiteBold(clientConfigRelay.AsFile()))
	fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
	fmt.Fprintln(color.Output)
	if !c.simple {
		fmt.Fprintln(color.Output, fileStatusE2EE)
		fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
		fmt.Fprint(color.Output, WhiteBold(clientConfigE2EE.AsFile()))
		fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
		fmt.Fprintln(color.Output)
	}
	fmt.Fprintln(color.Output, fileStatusServer)
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, GreenBold("server command:"))
	fmt.Fprintln(color.Output, Cyan("POSIX Shell: "), Green(peer.CreateServerCommand(serverConfigRelay, serverConfigE2EE, peer.POSIX, c.simple, c.disableV6)))
	fmt.Fprintln(color.Output, Cyan(" PowerShell: "), Green(peer.CreateServerCommand(serverConfigRelay, serverConfigE2EE, peer.PowerShell, c.simple, c.disableV6)))
	fmt.Fprintln(color.Output, Cyan("Config File: "), Green(serverConfigFile))
	fmt.Fprintln(color.Output)
	if c.writeToClipboard {
		fmt.Fprintln(color.Output, clipboardStatus)
		fmt.Fprintln(color.Output)
	}
}
