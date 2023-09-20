package cmd

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"

	"wiretap/api"
	"wiretap/peer"

	"github.com/atotto/clipboard"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type addServerCmdConfig struct {
	allowedIPs       []string
	serverAddress    string
	configFileRelay  string
	configFileE2EE   string
	configFileServer string
	writeToClipboard bool
}

var addServerCmdArgs = addServerCmdConfig{
	allowedIPs:       []string{},
	serverAddress:    "",
	configFileRelay:  ConfigRelay,
	configFileE2EE:   ConfigE2EE,
	configFileServer: ConfigServer,
	writeToClipboard: false,
}

// addServerCmd represents the server command.
var addServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Add a server to the wiretap network",
	Long:  `Add a server to the existing wiretap network`,
	Run: func(cmd *cobra.Command, args []string) {
		addServerCmdArgs.Run()
	},
}

func init() {
	addCmd.AddCommand(addServerCmd)

	addServerCmd.Flags().StringSliceVarP(&addServerCmdArgs.allowedIPs, "routes", "r", addServerCmdArgs.allowedIPs, "CIDR IP ranges that will be routed through wiretap")
	addServerCmd.Flags().StringVarP(&addServerCmdArgs.serverAddress, "server-address", "s", addServerCmdArgs.serverAddress, "API address of server that new server will connect to, connects to client by default")
	addServerCmd.Flags().StringVarP(&addServerCmdArgs.configFileRelay, "relay-input", "", addServerCmdArgs.configFileRelay, "filename of input relay config file")
	addServerCmd.Flags().StringVarP(&addServerCmdArgs.configFileE2EE, "e2ee-input", "", addServerCmdArgs.configFileE2EE, "filename of input E2EE config file")
	addServerCmd.Flags().StringVarP(&addServerCmdArgs.configFileServer, "server-output", "", addServerCmdArgs.configFileServer, "filename of server config output file")
	addServerCmd.Flags().BoolVarP(&addServerCmdArgs.writeToClipboard, "clipboard", "c", addServerCmdArgs.writeToClipboard, "copy configuration args to clipboard")

	err := addServerCmd.MarkFlagRequired("routes")
	check("failed to mark flag required", err)

	addServerCmd.Flags().SortFlags = false
	addServerCmd.PersistentFlags().SortFlags = false
}

func (c addServerCmdConfig) Run() {
	addArgs := addCmdArgs

	// Read client's relay and e2ee configs to get client interface info.
	clientConfigE2EE, err := peer.ParseConfig(c.configFileE2EE)
	check("failed to parse e2ee config file", err)
	clientConfigRelay, err := peer.ParseConfig(c.configFileRelay)
	check("failed to parse relay config file", err)

	// Make new configs for server.
	serverConfigRelay, err := peer.GetConfig(peer.ConfigArgs{})
	check("failed to generate server relay config", err)
	serverConfigE2EE, err := peer.GetConfig(peer.ConfigArgs{})
	check("failed to generate server e2ee config", err)

	// Set APIBits based on v4/v6 address.
	disableV6 := false
	apiAddr := clientConfigE2EE.GetPeers()[0].GetApiAddr()
	if apiAddr.Is4() {
		disableV6 = true
		APIBits = APIV4Bits
	}

	// Connect new server directly to client if no server address was provided.
	// This branch sets up the server and client configs like `configure` does.
	if len(c.serverAddress) == 0 {
		// Find next Relay subnets
		relayPeers := clientConfigRelay.GetPeers()
		if len(relayPeers) == 0 {
			check("failed to add server", errors.New("cannot add server if no relay peers exist, try `configure`"))
		}

		newRelayPrefixes := peer.GetNextPrefixesForPeers(relayPeers)
		basePrefix := netip.PrefixFrom(apiAddr, APIBits).Masked()
		e2eePeers := clientConfigE2EE.GetPeers()
		for _, p := range e2eePeers {
			apiAddr := p.GetApiAddr()

			apiPrefix := netip.PrefixFrom(apiAddr, APIBits).Masked()
			if basePrefix.Addr().Less(apiPrefix.Addr()) {
				basePrefix = apiPrefix
			}
		}
		apiPrefix := peer.GetNextPrefix(basePrefix)

		// Add new server as relay peer.
		serverRelayPeer, err := peer.GetPeerConfig(peer.PeerConfigArgs{
			PublicKey: serverConfigRelay.GetPublicKey(),
			AllowedIPs: func() []string {
				allowedIPs := []string{}
				for _, prefix := range newRelayPrefixes {
					allowedIPs = append(allowedIPs, prefix.String())
				}
				return allowedIPs
			}(),
			Endpoint: func() string {
				if addArgs.outbound {
					return addArgs.endpoint
				} else {
					return ""
				}
			}(),
			PersistentKeepaliveInterval: func() int {
				if addArgs.outbound {
					return addArgs.keepalive
				} else {
					return 0
				}
			}(),
		})
		check("failed to generate new relay peer", err)
		clientConfigRelay.AddPeer(serverRelayPeer)

		// Add new server as E2EE peer.
		c.allowedIPs = append(c.allowedIPs, fmt.Sprintf("%s/%d", apiPrefix.Addr().Next().Next().String(), apiPrefix.Addr().BitLen()))
		serverE2EEPeer, err := peer.GetPeerConfig(peer.PeerConfigArgs{
			PublicKey:  serverConfigE2EE.GetPublicKey(),
			AllowedIPs: c.allowedIPs,
			Endpoint:   net.JoinHostPort(newRelayPrefixes[0].Addr().Next().Next().String(), fmt.Sprint(E2EEPort)),
		})
		check("failed to generate new e2ee peer", err)
		clientConfigE2EE.AddPeer(serverE2EEPeer)

		// Add client peers to server configs.
		clientPeerConfigRelay, err := clientConfigRelay.AsPeer()
		check("failed to parse relay config as peer", err)

		clientPeerConfigE2EE, err := clientConfigE2EE.AsPeer()
		check("failed to parse e2ee config as peer", err)
		if len(addArgs.endpoint) > 0 {
			if !addArgs.outbound {
				err = clientPeerConfigRelay.SetEndpoint(addArgs.endpoint)
				check("failed to set endpoint", err)

				err = clientPeerConfigE2EE.SetEndpoint(net.JoinHostPort(clientConfigRelay.GetAddresses()[0].IP.String(), fmt.Sprint(E2EEPort)))
				check("failed to set endpoint", err)
			}
		}
		serverConfigRelay.AddPeer(clientPeerConfigRelay)
		serverConfigE2EE.AddPeer(clientPeerConfigE2EE)

		relayAddrs := []string{newRelayPrefixes[0].Addr().Next().Next().String() + "/32"}
		if !disableV6 {
			relayAddrs = append(relayAddrs, newRelayPrefixes[1].Addr().Next().Next().String()+"/128")
		}
		err = serverConfigRelay.SetAddresses(relayAddrs)
		check("failed to set addresses", err)

		err = serverConfigE2EE.SetAddresses([]string{fmt.Sprintf("%s/%d", apiPrefix.Addr().Next().Next().String(), apiPrefix.Addr().BitLen())})
		check("failed to set addresses", err)
	} else {
		// Get leaf server info
		leafApiAddr, err := netip.ParseAddr(c.serverAddress)
		check("invalid server address", err)
		leafApiAddrPort := netip.AddrPortFrom(leafApiAddr, uint16(ApiPort))
		leafServerConfigRelay, _, err := api.ServerInfo(leafApiAddrPort)
		check("failed to get leaf server info", err)
		leafServerPeerConfigRelay, err := leafServerConfigRelay.AsPeer()
		check("failed to parse client server config as peer", err)

		// Relay node has the lowest API address in a node's API prefix.
		leafApiPrefix := netip.PrefixFrom(leafApiAddr, APIBits)
		apiAddr := leafApiAddr
		for _, p := range clientConfigE2EE.GetPeers() {
			aa := p.GetApiAddr()
			if leafApiPrefix.Contains(aa) && aa.Less(apiAddr) {
				apiAddr = aa
			}
		}
		apiAddrPort := netip.AddrPortFrom(apiAddr, uint16(ApiPort))

		// Allocate address information for new server.
		addresses, err := api.AllocateServerNode(apiAddrPort)
		check("failed to retrieve address allocation from server", err)

		// Convert client's E2EE config to peer for server.
		clientPeerConfigE2EE, err := clientConfigE2EE.AsPeer()
		check("failed to parse e2ee config as peer", err)

		// Assign endpoints if inbound-initiated communication is used.
		if len(addArgs.endpoint) > 0 {
			if !addArgs.outbound {
				err = leafServerPeerConfigRelay.SetEndpoint(addArgs.endpoint)
				check("failed to set endpoint", err)

				err = clientPeerConfigE2EE.SetEndpoint(net.JoinHostPort(clientConfigRelay.GetAddresses()[0].IP.String(), fmt.Sprint(E2EEPort)))
				check("failed to set endpoint", err)
			}
		}

		// Make allowed IPs all of current peer's allowed IPs:
		relayAddrs := []string{}
		for _, p := range leafServerConfigRelay.GetPeers() {
			for _, aip := range p.GetAllowedIPs() {
				relayAddrs = append(relayAddrs, aip.String())
			}
		}
		for _, a := range leafServerConfigRelay.GetAddresses() {
			relayAddrs = append(relayAddrs, a.String())
		}
		err = leafServerPeerConfigRelay.SetAllowedIPs(relayAddrs)
		check("failed to set allowedIPs", err)

		serverConfigRelay.AddPeer(leafServerPeerConfigRelay)
		serverConfigE2EE.AddPeer(clientPeerConfigE2EE)

		// Make E2EE peer for local config.
		c.allowedIPs = append(c.allowedIPs, fmt.Sprintf("%s/%d", addresses.ApiAddr.String(), addresses.ApiAddr.BitLen()))
		serverPeerConfigE2EE, err := peer.GetPeerConfig(peer.PeerConfigArgs{
			PublicKey:  serverConfigE2EE.GetPublicKey(),
			AllowedIPs: c.allowedIPs,
			Endpoint:   net.JoinHostPort(addresses.NextServerRelayAddr4.String(), fmt.Sprint(E2EEPort)),
		})
		check("failed to parse server as peer", err)
		clientConfigE2EE.AddPeer(serverPeerConfigE2EE)

		// Make peer config for the server that this new server will connect to.
		addrs := []string{addresses.NextServerRelayAddr4.String() + "/32"}
		if !disableV6 {
			addrs = append(addrs, addresses.NextServerRelayAddr6.String()+"/128")
		}
		serverPeerConfigRelay, err := peer.GetPeerConfig(peer.PeerConfigArgs{
			PublicKey:  serverConfigRelay.GetPublicKey(),
			AllowedIPs: addrs,
			Endpoint: func() string {
				if addArgs.outbound {
					return addArgs.endpoint
				} else {
					return ""
				}
			}(),
			PersistentKeepaliveInterval: func() int {
				if addArgs.outbound {
					return addArgs.keepalive
				} else {
					return 0
				}
			}(),
		})
		check("failed to parse server as peer", err)

		// Push peer config to relay peer.
		err = api.AddRelayPeer(leafApiAddrPort, serverPeerConfigRelay)
		check("failed to add peer to leaf server", err)

		err = serverConfigRelay.SetAddresses(addrs)
		check("failed to set addresses", err)
		err = serverConfigE2EE.SetAddresses([]string{fmt.Sprintf("%s/%d", addresses.ApiAddr.String(), addresses.ApiAddr.BitLen())})
		check("failed to set addresses", err)

		// Push new route to every server.
		for _, p := range clientConfigE2EE.GetPeers() {
			apiAddrPort := netip.AddrPortFrom(p.GetApiAddr(), uint16(ApiPort))
			// Skip leaf and new peer.
			if apiAddrPort == leafApiAddrPort || p.GetApiAddr() == serverPeerConfigE2EE.GetApiAddr() {
				continue
			}

			relay, _, err := api.ServerInfo(apiAddrPort)
			if err != nil {
				log.Println("failed to query server info:", err)
				continue
			}

			// Find leaf-facing relay peer and push route.
		outer:
			for i, rp := range relay.GetPeers() {
				for _, ap := range rp.GetAllowedIPs() {
					if ap.Contains(leafServerConfigRelay.GetAddresses()[0].IP) {
						err = api.AddAllowedIPs(apiAddrPort, rp.GetPublicKey(), serverPeerConfigRelay.GetAllowedIPs())
						check("failed to add new client IP to peer", err)
						break outer
					}
				}
				if i == len(relay.GetPeers())-1 {
					check("failed to find leaf-facing peer", errors.New("peer's relay interface has no leaf-facing route"))
				}
			}
		}

		// Leaf server is the relay peer for the new server.
		clientConfigRelay = leafServerConfigRelay
	}

	if addArgs.port != Port {
		err = serverConfigRelay.SetPort(addArgs.port)
		check("failed to set port", err)
	}

	// Overwrite Relay file with new server peer if adding a server directly to the client.
	var fileStatusRelay string
	if len(c.serverAddress) == 0 {
		err = os.WriteFile(c.configFileRelay, []byte(clientConfigRelay.AsFile()), 0600)
		if err != nil {
			fileStatusRelay = fmt.Sprintf("%s %s", RedBold("config:"), Red(fmt.Sprintf("error writing config file: %v", err)))
		} else {
			fileStatusRelay = fmt.Sprintf("%s %s", GreenBold("config:"), Green(c.configFileRelay))
		}
	}

	// Overwrite E2EE file with new server peer.
	var fileStatusE2EE string
	err = os.WriteFile(c.configFileE2EE, []byte(clientConfigE2EE.AsFile()), 0600)
	if err != nil {
		fileStatusE2EE = fmt.Sprintf("%s %s", RedBold("config:"), Red(fmt.Sprintf("error writing config file: %v", err)))
	} else {
		fileStatusE2EE = fmt.Sprintf("%s %s", GreenBold("config:"), Green(c.configFileE2EE))
	}

	// Add number to filename if it already exists.
	c.configFileServer = peer.FindAvailableFilename(c.configFileServer)

	// Write server config file and get status string.
	var fileStatusServer string
	err = os.WriteFile(c.configFileServer, []byte(peer.CreateServerFile(serverConfigRelay, serverConfigE2EE)), 0600)
	if err != nil {
		fileStatusServer = fmt.Sprintf("%s %s", RedBold("server config:"), Red(fmt.Sprintf("error writing config file: %v", err)))
	} else {
		fileStatusServer = fmt.Sprintf("%s %s", GreenBold("server config:"), Green(c.configFileServer))
	}

	// Copy to clipboard if requested.
	var clipboardStatus string
	if c.writeToClipboard {
		err = clipboard.WriteAll(peer.CreateServerCommand(serverConfigRelay, serverConfigE2EE, peer.POSIX, false, disableV6))
		if err != nil {
			clipboardStatus = fmt.Sprintf("%s %s", RedBold("clipboard:"), Red(fmt.Sprintf("error copying to clipboard: %v", err)))
		} else {
			clipboardStatus = fmt.Sprintf("%s %s", GreenBold("clipboard:"), Green("successfully copied"))
		}
	}

	// Write and format output.
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, "Configurations successfully generated.")
	fmt.Fprintln(color.Output, "Import the updated config(s) into WireGuard locally and pass the arguments below to Wiretap on the new remote server.")
	if len(c.serverAddress) == 0 {
		fmt.Fprintln(color.Output)
		fmt.Fprintln(color.Output, fileStatusRelay)
		fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
		fmt.Fprint(color.Output, WhiteBold(clientConfigRelay.AsFile()))
		fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
	}
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, fileStatusE2EE)
	fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
	fmt.Fprint(color.Output, WhiteBold(clientConfigE2EE.AsFile()))
	fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, fileStatusServer)
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, Cyan("POSIX Shell: "), Green(peer.CreateServerCommand(serverConfigRelay, serverConfigE2EE, peer.POSIX, false, disableV6)))
	fmt.Fprintln(color.Output, Cyan(" PowerShell: "), Green(peer.CreateServerCommand(serverConfigRelay, serverConfigE2EE, peer.PowerShell, false, disableV6)))
	fmt.Fprintln(color.Output, Cyan("Config File: "), Green("./wiretap serve -f "+c.configFileServer))
	fmt.Fprintln(color.Output)
	if c.writeToClipboard {
		fmt.Fprintln(color.Output, clipboardStatus)
		fmt.Fprintln(color.Output)
	}
}
