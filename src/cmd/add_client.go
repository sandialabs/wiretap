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

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type addClientCmdConfig struct {
	inputConfigFileRelay  string
	inputConfigFileE2EE   string
	outputConfigFileRelay string
	outputConfigFileE2EE  string
	serverAddress         string
	mtu                   int
}

var addClientCmdArgs = addClientCmdConfig{
	inputConfigFileRelay:  ConfigRelay,
	inputConfigFileE2EE:   ConfigE2EE,
	outputConfigFileRelay: ConfigRelay,
	outputConfigFileE2EE:  ConfigE2EE,
	serverAddress:         "",
	mtu:                   MTU,
}

// addClientCmd represents the client command.
var addClientCmd = &cobra.Command{
	Use:   "client",
	Short: "Add a client to the wiretap network",
	Long:  `Add a client to the existing wiretap network`,
	Run: func(cmd *cobra.Command, args []string) {
		addClientCmdArgs.Run()
	},
}

func init() {
	addCmd.AddCommand(addClientCmd)

	addClientCmd.Flags().StringVarP(&addClientCmdArgs.outputConfigFileRelay, "relay-output", "", addClientCmdArgs.outputConfigFileRelay, "filename of output relay config file")
	addClientCmd.Flags().StringVarP(&addClientCmdArgs.outputConfigFileE2EE, "e2ee-output", "", addClientCmdArgs.outputConfigFileE2EE, "filename of output E2EE config file")
	addClientCmd.Flags().StringVarP(&addClientCmdArgs.inputConfigFileRelay, "relay-input", "", addClientCmdArgs.inputConfigFileRelay, "filename of input relay config file")
	addClientCmd.Flags().StringVarP(&addClientCmdArgs.inputConfigFileE2EE, "e2ee-input", "", addClientCmdArgs.inputConfigFileE2EE, "filename of input E2EE config file")
	addClientCmd.Flags().StringVarP(&addClientCmdArgs.serverAddress, "server-address", "s", addClientCmdArgs.serverAddress, "API address of server that new client will connect to. By default new clients connect to existing relay servers")
	addClientCmd.Flags().IntVarP(&addClientCmdArgs.mtu, "mtu", "m", addClientCmdArgs.mtu, "tunnel MTU")

	addClientCmd.Flags().SortFlags = false
	addClientCmd.PersistentFlags().SortFlags = false
}

func (c addClientCmdConfig) Run() {
	addArgs := addCmdArgs

	// Read first client's relay and e2ee configs to get client interface info.
	baseConfigE2EE, err := peer.ParseConfig(c.inputConfigFileE2EE)
	check("failed to parse e2ee config file", err)
	baseConfigRelay, err := peer.ParseConfig(c.inputConfigFileRelay)
	check("failed to parse relay config file", err)

	// Allocate client using first relay server.
	serverApiAddr := baseConfigE2EE.GetPeers()[0].GetApiAddr()
	apiAddrPort := netip.AddrPortFrom(serverApiAddr, uint16(ApiPort))
	addresses, err := api.AllocateClientNode(apiAddrPort)
	check("failed to retrieve address allocation from server", err)

	disableV6 := false
	if len(baseConfigE2EE.GetAddresses()) == 1 {
		disableV6 = true
	}

	// Make new configs for client.
	relayAddrs := []string{addresses.NextClientRelayAddr4.String() + "/32"}
	if !disableV6 {
		relayAddrs = append(relayAddrs, addresses.NextClientRelayAddr6.String()+"/128")
	}
	clientConfigRelay, err := peer.GetConfig(peer.ConfigArgs{
		ListenPort: addCmdArgs.port,
		Addresses:  relayAddrs,
	})
	check("failed to generate client relay config", err)

	e2eeAddrs := []string{addresses.NextClientE2EEAddr4.String() + "/32"}
	if !disableV6 {
		e2eeAddrs = append(e2eeAddrs, addresses.NextClientE2EEAddr6.String()+"/128")
	}
	clientConfigE2EE, err := peer.GetConfig(peer.ConfigArgs{
		ListenPort: E2EEPort,
		Addresses:  e2eeAddrs,
		MTU:        c.mtu - 80,
	})
	check("failed to generate relay e2ee config", err)

	// Copy peers.
	leafAddr := baseConfigRelay.GetAddresses()[0].IP
	if c.serverAddress == "" {
		for _, p := range baseConfigRelay.GetPeers() {
			clientConfigRelay.AddPeer(p)
		}
	} else {
		// Get leaf server info
		leafApiAddr, err := netip.ParseAddr(c.serverAddress)
		check("invalid server address", err)
		leafApiAddrPort := netip.AddrPortFrom(leafApiAddr, uint16(ApiPort))
		leafServerConfigRelay, _, err := api.ServerInfo(leafApiAddrPort)
		check("failed to get leaf server info", err)
		leafServerPeerConfigRelay, err := leafServerConfigRelay.AsPeer()
		check("failed to parse client server config as peer", err)

		// Search base relay config for this server's relay peer and copy routes.
	out:
		for _, p := range baseConfigRelay.GetPeers() {
			for _, a := range p.GetAllowedIPs() {
				if a.Contains(leafServerConfigRelay.GetAddresses()[0].IP) {
					for _, aip := range p.GetAllowedIPs() {
						err = leafServerPeerConfigRelay.AddAllowedIPs(aip.String())
						check("failed to copy routes from leaf server", err)
					}
					break out
				}
			}
		}

		clientConfigRelay.AddPeer(leafServerPeerConfigRelay)

		leafAddr = leafServerConfigRelay.GetAddresses()[0].IP
	}
	for _, p := range baseConfigE2EE.GetPeers() {
		clientConfigE2EE.AddPeer(p)
	}

	// Push new client peer to all servers.
	// Relay nodes need a new relay peer on top of the e2ee peer.
	// Relay nodes have a relay peer that matches our baseConfig public key.
	clientPubKey, err := wgtypes.ParseKey(baseConfigRelay.GetPublicKey())
	check("failed to get client public key", err)

	// Make peer configs to populate server peers.
	clientPeerConfigRelay, err := peer.GetPeerConfig(peer.PeerConfigArgs{
		PublicKey: clientConfigRelay.GetPublicKey(),
		AllowedIPs: func() []string {
			allowed := []string{}
			for _, prefix := range clientConfigRelay.GetAddresses() {
				allowed = append(allowed, prefix.String())
			}
			return allowed
		}(),
		Endpoint: func() string {
			if addArgs.outbound {
				return ""
			} else {
				return addArgs.endpoint
			}
		}(),
		PersistentKeepaliveInterval: func() int {
			if addArgs.outbound {
				return 0
			} else {
				return addArgs.keepalive
			}
		}(),
	})
	check("failed to parse client as peer", err)

	clientPeerConfigE2EE, err := peer.GetPeerConfig(peer.PeerConfigArgs{
		PublicKey: clientConfigE2EE.GetPublicKey(),
		AllowedIPs: func() []string {
			allowed := []string{}
			for _, prefix := range clientConfigE2EE.GetAddresses() {
				allowed = append(allowed, prefix.String())
			}
			return allowed
		}(),
		Endpoint: net.JoinHostPort(clientConfigE2EE.GetAddresses()[0].IP.String(), fmt.Sprint(E2EEPort)),
	})
	check("failed to parse client as peer", err)

	for _, p := range clientConfigE2EE.GetPeers() {
		apiAddrPort := netip.AddrPortFrom(p.GetApiAddr(), uint16(ApiPort))
		relay, _, err := api.ServerInfo(apiAddrPort)
		if err != nil {
			log.Println("failed to query server info:", err)
			continue
		}

		// Push client e2ee peer.
		err = api.AddE2EEPeer(apiAddrPort, clientPeerConfigE2EE)
		check("failed to add peer", err)

		// This is a relay node.
		if (relay.GetPeer(clientPubKey) != nil && c.serverAddress == "") || (c.serverAddress == p.GetApiAddr().String()) {
			err = api.AddRelayPeer(apiAddrPort, clientPeerConfigRelay)
			check("failed to add peer", err)
		} else {
			// This is an e2ee node. Add client IP to client/leaf-facing relay peer.
			// Find client-facing relay peer.
		outer:
			for i, rp := range relay.GetPeers() {
				for _, ap := range rp.GetAllowedIPs() {
					if ap.Contains(leafAddr) {
						err = api.AddAllowedIPs(apiAddrPort, rp.GetPublicKey(), clientPeerConfigRelay.GetAllowedIPs())
						check("failed to add new client IP to peer", err)
						break outer
					}
				}
				if i == len(relay.GetPeers())-1 {
					check("failed to find client-facing peer", errors.New("peer's relay interface has no client-facing route"))
				}
			}
		}
	}

	// Write config files.
	// Add number to filename if it already exists.
	c.outputConfigFileRelay = peer.FindAvailableFilename(c.outputConfigFileRelay)
	c.outputConfigFileE2EE = peer.FindAvailableFilename(c.outputConfigFileE2EE)

	// Write config file and get status string.
	var fileStatusRelay string
	err = os.WriteFile(c.outputConfigFileRelay, []byte(clientConfigRelay.AsFile()), 0600)
	if err != nil {
		fileStatusRelay = fmt.Sprintf("%s %s", RedBold("config:"), Red(fmt.Sprintf("error writing config file: %v", err)))
	} else {
		fileStatusRelay = fmt.Sprintf("%s %s", GreenBold("config:"), Green(c.outputConfigFileRelay))
	}
	// Write config file and get status string.
	var fileStatusE2EE string
	err = os.WriteFile(c.outputConfigFileE2EE, []byte(clientConfigE2EE.AsFile()), 0600)
	if err != nil {
		fileStatusE2EE = fmt.Sprintf("%s %s", RedBold("config:"), Red(fmt.Sprintf("error writing config file: %v", err)))
	} else {
		fileStatusE2EE = fmt.Sprintf("%s %s", GreenBold("config:"), Green(c.outputConfigFileE2EE))
	}

	// Write and format output.
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, "Configurations successfully generated.")
	fmt.Fprintln(color.Output, "Have a friend import these files into WireGuard")
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, fileStatusRelay)
	fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
	fmt.Fprint(color.Output, WhiteBold(clientConfigRelay.AsFile()))
	fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
	fmt.Fprintln(color.Output)
	fmt.Fprintln(color.Output, fileStatusE2EE)
	fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
	fmt.Fprint(color.Output, WhiteBold(clientConfigE2EE.AsFile()))
	fmt.Fprintln(color.Output, Green(strings.Repeat("─", 32)))
	fmt.Fprintln(color.Output)
}
