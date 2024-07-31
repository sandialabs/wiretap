package cmd

import (
	"fmt"
	"log"
	"net/netip"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"wiretap/api"
	"wiretap/peer"
)

type exposeCmdConfig struct {
	serverAddr string
	localPort  uint
	remotePort uint
	protocol   string
	dynamic    bool
	configFile string
}

// Defaults for expose command.
// See root command for shared defaults.
var exposeCmd = exposeCmdConfig{
	serverAddr: "",
	localPort:  0,
	remotePort: 0,
	protocol:   "tcp",
	dynamic:    false,
	configFile: ConfigE2EE,
}

// Add command and set flags.
func init() {
	// Base command.
	cmd := &cobra.Command{
		Use:       "expose",
		Short:     "Expose local services to servers",
		Long:      `Expose a port statically or allow dynamic forwarding through a remote server to the local network`,
		ValidArgs: []string{"remove", "list"},
		Args:      cobra.OnlyValidArgs,
		Run: func(cmd *cobra.Command, args []string) {
			exposeCmd.Run()
		},
	}

	rootCmd.AddCommand(cmd)

	cmd.Flags().UintVarP(&exposeCmd.localPort, "local", "l", exposeCmd.localPort, "Local port to expose")
	cmd.Flags().UintVarP(&exposeCmd.remotePort, "remote", "r", exposeCmd.remotePort, "Remote port to forward if different from local port")
	cmd.Flags().StringVarP(&exposeCmd.protocol, "protocol", "p", exposeCmd.protocol, "Port protocol, tcp/udp")
	cmd.Flags().BoolVarP(&exposeCmd.dynamic, "dynamic", "d", exposeCmd.dynamic, "Dynamic port forwarding, SOCKS proxy service opens on remote port")
	cmd.PersistentFlags().StringVarP(&exposeCmd.serverAddr, "server-address", "s", exposeCmd.serverAddr, "API address of server that ports should be forwarded from, exposes service to all servers by default")
	cmd.PersistentFlags().StringVarP(&exposeCmd.configFile, "config", "c", exposeCmd.configFile, "Config file needed when talking to all servers (the default)")

	cmd.MarkFlagsMutuallyExclusive("dynamic", "local")

	cmd.Flags().SortFlags = false

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List exposed ports",
		Long:  `List all static and dynamically forwarded ports`,
		Run: func(cmd *cobra.Command, args []string) {
			exposeCmd.List()
		},
	}

	cmd.AddCommand(listCmd)

	deleteCmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove exposed ports",
		Long:  `Remove exposed ports`,
		Run: func(cmd *cobra.Command, args []string) {
			exposeCmd.Delete()
		},
	}

	deleteCmd.Flags().UintVarP(&exposeCmd.localPort, "local", "l", exposeCmd.localPort, "Local port")
	deleteCmd.Flags().UintVarP(&exposeCmd.remotePort, "remote", "r", exposeCmd.remotePort, "Remote port")
	deleteCmd.Flags().StringVarP(&exposeCmd.protocol, "protocol", "p", exposeCmd.protocol, "Port protocol, tcp/udp")
	deleteCmd.Flags().BoolVarP(&exposeCmd.dynamic, "dynamic", "d", exposeCmd.dynamic, "Dynamic port forwarding")

	cmd.AddCommand(deleteCmd)
}

// Run attempts to ping server API and prints response.
func (c exposeCmdConfig) Run() {
	var apiAddrs []netip.Addr

	// Get list of all API addrs *or* just use provided addr
	if c.serverAddr != "" {
		apiAddr, err := netip.ParseAddr(c.serverAddr)
		check("failed to parse server address", err)

		apiAddrs = append(apiAddrs, apiAddr)
	} else {
		config, err := peer.ParseConfig(c.configFile)
		check("failed to parse config file", err)

		for _, p := range config.GetPeers() {
			apiAddrs = append(apiAddrs, p.GetApiAddr())
		}
	}

	if c.dynamic {
		// Validate options required for dynamic forwarding.
		if c.remotePort < 1 || c.remotePort > 65535 {
			log.Fatalln("invalid remote port:", c.remotePort)
		}
	} else {
		// Validate options required for static forwarding.
		if c.localPort < 1 || c.localPort > 65535 {
			log.Fatalln("invalid local port:", c.localPort)
		}
		if c.remotePort == 0 {
			c.remotePort = c.localPort
		} else {
			if c.remotePort > 65535 {
				log.Fatalln("invalid remote port:", c.remotePort)
			}
		}

		if c.protocol != "tcp" && c.protocol != "udp" {
			log.Fatalln("invalid protocol:", c.protocol)
		}
	}

	// Make API requests to the list of API addresses with the parameters: localPort, remotePort, protocol, dynamic
	fmt.Fprintf(color.Output, "%s: local %s <- remote %d\n", GreenBold("expose"), func() string {
		if c.dynamic {
			return "*"
		} else {
			return fmt.Sprint(c.localPort)
		}
	}(), c.remotePort)
	for _, a := range apiAddrs {
		err := api.Expose(netip.AddrPortFrom(a, uint16(ApiPort)), c.localPort, c.remotePort, c.protocol, c.dynamic)
		if err != nil {
			fmt.Fprintf(color.Output, "\t[%v] %s: %s\n", RedBold(a), RedBold("error"), Red(err))
		} else {
			fmt.Fprintf(color.Output, "\t[%v] %s\n", GreenBold(a), Green("OK"))
		}
	}
}

// List lists the exposed port configuration for server(s).
func (c exposeCmdConfig) List() {
	var apiAddrs []netip.Addr

	// Get list of all API addrs *or* just use provided addr
	if c.serverAddr != "" {
		apiAddr, err := netip.ParseAddr(c.serverAddr)
		check("failed to parse server address", err)

		apiAddrs = append(apiAddrs, apiAddr)
	} else {
		config, err := peer.ParseConfig(c.configFile)
		check("failed to parse config file", err)

		for _, p := range config.GetPeers() {
			apiAddrs = append(apiAddrs, p.GetApiAddr())
		}
	}

	for _, a := range apiAddrs {
		tuples, err := api.ExposeList(netip.AddrPortFrom(a, uint16(ApiPort)))
		if err != nil {
			fmt.Fprintf(color.Output, "[%v] %s: %s\n", RedBold(a), RedBold("error"), Red(err))
		} else {
			fmt.Fprintf(color.Output, "[%v]: %s\n", GreenBold(a), Cyan(len(tuples)))
			for _, t := range tuples {
				fmt.Fprintf(color.Output, "\tlocal %s <- remote %d/%s\n", func() string {
					if t.LocalPort == 0 {
						return "*"
					} else {
						return fmt.Sprintf("%d/%s", t.LocalPort, t.Protocol)
					}
				}(), t.RemotePort, t.Protocol)
			}
		}
	}
}

// Delete removes
func (c exposeCmdConfig) Delete() {
	var apiAddrs []netip.Addr

	// Get list of all API addrs *or* just use provided addr
	if c.serverAddr != "" {
		apiAddr, err := netip.ParseAddr(c.serverAddr)
		check("failed to parse server address", err)

		apiAddrs = append(apiAddrs, apiAddr)
	} else {
		config, err := peer.ParseConfig(c.configFile)
		check("failed to parse config file", err)

		for _, p := range config.GetPeers() {
			apiAddrs = append(apiAddrs, p.GetApiAddr())
		}
	}

	if c.dynamic {
		// Validate options required for dynamic forwarding.
		if c.remotePort < 1 || c.remotePort > 65535 {
			log.Fatalln("invalid remote port:", c.remotePort)
		}
	} else {
		// Validate options required for static forwarding.
		if c.localPort < 1 || c.localPort > 65535 {
			log.Fatalln("invalid local port:", c.localPort)
		}
		if c.remotePort == 0 {
			c.remotePort = c.localPort
		} else {
			if c.remotePort > 65535 {
				log.Fatalln("invalid remote port:", c.remotePort)
			}
		}

		if c.protocol != "tcp" && c.protocol != "udp" {
			log.Fatalln("invalid protocol:", c.protocol)
		}
	}

	// Make API requests to the list of API addresses with the parameters: localPort, remotePort, protocol, dynamic
	fmt.Fprintf(color.Output, "%s: local %s <- remote %d\n", GreenBold("delete"), func() string {
		if c.dynamic {
			return "*"
		} else {
			return fmt.Sprint(c.localPort)
		}
	}(), c.remotePort)
	for _, a := range apiAddrs {
		err := api.ExposeDelete(netip.AddrPortFrom(a, uint16(ApiPort)), c.localPort, c.remotePort, c.protocol, c.dynamic)
		if err != nil {
			fmt.Fprintf(color.Output, "\t[%v] %s: %s\n", RedBold(a), RedBold("error"), Red(err))
		} else {
			fmt.Fprintf(color.Output, "\t[%v] %s\n", GreenBold(a), Green("Removed"))
		}
	}
}
