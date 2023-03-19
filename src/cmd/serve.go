package cmd

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"wiretap/peer"
	"wiretap/transport/api"
	"wiretap/transport/icmp"
	"wiretap/transport/tcp"
	"wiretap/transport/udp"
)

type serveCmdConfig struct {
	configFile string
	quiet      bool
	debug      bool
	logging    bool
	logFile    string
}

// Defaults for serve command.
var serveCmd = serveCmdConfig{
	configFile: "",
	quiet:      false,
	debug:      false,
	logging:    false,
	logFile:    "wiretap.log",
}

// Add serve command and set flags.
func init() {
	// Usage info.
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Listen and proxy traffic into target network",
		Long:  `Listen and proxy traffic into target network`,
		Run: func(cmd *cobra.Command, args []string) {
			serveCmd.Run()
		},
	}

	rootCmd.AddCommand(cmd)

	// Flags.
	cmd.Flags().StringVarP(&serveCmd.configFile, "config-file", "f", serveCmd.configFile, "wireguard config file to read from")
	cmd.Flags().BoolVarP(&serveCmd.quiet, "quiet", "q", serveCmd.quiet, "silence wiretap log messages")
	cmd.Flags().BoolVarP(&serveCmd.debug, "debug", "d", serveCmd.debug, "enable wireguard log messages")
	cmd.Flags().BoolVarP(&serveCmd.logging, "log", "l", serveCmd.logging, "enable logging to file")
	cmd.Flags().StringVarP(&serveCmd.logFile, "log-file", "o", serveCmd.logFile, "write log to this filename")

	// Quiet and debug flags must be used independently.
	cmd.MarkFlagsMutuallyExclusive("debug", "quiet")

	// Deprecated flags, kept for backwards compatibility.
	cmd.Flags().StringP("private", "", "", "wireguard private key")
	cmd.Flags().StringP("public", "", "", "wireguard public key of remote peer")
	cmd.Flags().StringP("endpoint", "e", Endpoint, "socket address of remote peer that server will connect to (example \"1.2.3.4:51820\")")
	cmd.Flags().IntP("port", "p", Port, "wireguard listener port")
	cmd.Flags().StringSliceP("allowed", "a", []string{Subnet4.Addr().Next().Next().String() + "/32", Subnet6.Addr().Next().Next().String() + "/128"}, "comma-separated list of CIDR IP ranges to associate with peer")
	cmd.Flags().StringP("ipv4", "4", Subnet4.Addr().Next().String() + "/32", "virtual ipv4 address of wireguard interface")
	cmd.Flags().StringP("ipv6", "6", Subnet6.Addr().Next().String() + "/128", "virtual ipv6 address of wireguard interface")
	cmd.Flags().StringP("api", "0", ApiAddr.String(), "address of API service")
	cmd.Flags().IntP("keepalive", "k", Keepalive, "tunnel keepalive in seconds")
	cmd.Flags().IntP("mtu", "m", 1420, "tunnel MTU")

	// Bind deprecated flags to viper.
	viper.BindPFlag("Interface.privatekey", cmd.Flags().Lookup("private"))
	viper.BindPFlag("Interface.port", cmd.Flags().Lookup("port"))
	viper.BindPFlag("Interface.ipv4", cmd.Flags().Lookup("ipv4"))
	viper.BindPFlag("Interface.ipv6", cmd.Flags().Lookup("ipv6"))
	viper.BindPFlag("Interface.api", cmd.Flags().Lookup("api"))
	viper.BindPFlag("Interface.mtu", cmd.Flags().Lookup("mtu"))
	viper.BindPFlag("Peer.publickey", cmd.Flags().Lookup("public"))
	viper.BindPFlag("Peer.endpoint", cmd.Flags().Lookup("endpoint"))
	viper.BindPFlag("Peer.allowed", cmd.Flags().Lookup("allowed"))
	viper.BindPFlag("Peer.keepalive", cmd.Flags().Lookup("keepalive"))

	cmd.Flags().SortFlags = false

	// Hide deprecated flags and log flags.
	helpFunc := cmd.HelpFunc()
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if !ShowHidden {
			for _, f := range []string{"private", "public", "endpoint", "port", "allowed", "ipv4", "ipv6", "api", "keepalive", "mtu", "log", "log-file"} {
				err := cmd.Flags().MarkHidden(f)
				if err != nil {
					fmt.Printf("Failed to hide flag %v: %v\n", f, err)
				}
			}
		}
		helpFunc(cmd, args)
	})
}

// Run parses/processes/validates args and then connects to peer,
// proxying traffic from peer into local network.
func (c serveCmdConfig) Run() {
	// Read config from file and/or environment.
	viper.AutomaticEnv()
	viper.SetEnvPrefix("WIRETAP")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if c.configFile != "" {
		viper.SetConfigType("ini")
		viper.SetConfigFile(c.configFile)
		if err := viper.ReadInConfig(); err != nil {
			check("error reading config file", err)
		}
	}

	// Synchronization vars.
	var (
		wg   sync.WaitGroup
		lock sync.Mutex
	)

	// Configure logging.
	log.SetOutput(os.Stdout)
	log.SetPrefix("WIRETAP: ")
	if c.quiet {
		log.SetOutput(io.Discard)
	}
	if c.logging {
		f, err := os.OpenFile(c.logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		check("error opening log file", err)
		defer f.Close()

		if c.quiet {
			log.SetOutput(f)
		} else {
			log.SetOutput(io.MultiWriter(os.Stdout, f))
		}
	}

	// Check for required flags.
	if !viper.IsSet("Peer.publickey") {
		check("Public key is required", errors.New("Public key is required"))
	}

	configArgs := peer.ConfigArgs{
		PrivateKey: viper.GetString("Interface.privatekey"),
		ListenPort: viper.GetInt("Interface.port"),
		Peers: []peer.PeerConfigArgs{
			{
				PublicKey:                   viper.GetString("Peer.publickey"),
				Endpoint:                    viper.GetString("Peer.endpoint"),
				PersistentKeepaliveInterval: viper.GetInt("Peer.keepalive"),
				AllowedIPs:                  strings.Split(viper.GetString("Peer.allowed"), ","),
			},
		},
		Addresses: []string{viper.GetString("Interface.ipv4"), viper.GetString("Interface.ipv6")},
	}

	config, err := peer.GetConfig(configArgs)
	check("failed to make configuration", err)

	// Print public key for easier configuration.
	fmt.Println()
	fmt.Println("If needed, add this peer to your WireGuard configuration.")
	fmt.Println()
	fmt.Println(strings.Repeat("─", 32))
	fmt.Print(config.AsShareableFile())
	fmt.Println(strings.Repeat("─", 32))
	fmt.Println()

	// Create virtual interface with this address and MTU.
	ipv4Prefix, err := netip.ParsePrefix(viper.GetString("Interface.ipv4"))
	check("failed to parse ipv4 address", err)
	ipv4Addr := ipv4Prefix.Addr()

	ipv6Prefix, err := netip.ParsePrefix(viper.GetString("Interface.ipv6"))
	check("failed to parse ipv6 address", err)
	ipv6Addr := ipv6Prefix.Addr()

	apiPrefix, err := netip.ParsePrefix(viper.GetString("Interface.api"))
	check("failed to parse API address", err)
	apiAddr := apiPrefix.Addr()

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{ipv4Addr, ipv6Addr, apiAddr},
		[]netip.Addr{},
		viper.GetInt("Interface.mtu"),
	)
	check("failed to create TUN", err)

	// Make new device.
	var logger int
	if c.debug {
		logger = device.LogLevelVerbose
	} else if c.quiet {
		logger = device.LogLevelSilent
	} else {
		logger = device.LogLevelError
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logger, ""))

	// Configure wireguard.
	fmt.Println(config.AsIPC())
	err = dev.IpcSet(config.AsIPC())
	check("failed to configure wireguard device", err)

	err = dev.Up()
	check("failed to bring up device", err)

	// Start transport layer handlers.
	wg.Add(1)
	lock.Lock()
	go func() {
		tcp.Handle(tnet, ipv4Addr, ipv6Addr, 1337, &lock)
		wg.Done()
	}()

	lock.Lock()
	wg.Add(1)
	go func() {
		udp.Handle(tnet, ipv4Addr, ipv6Addr, 1337, &lock)
		wg.Done()
	}()

	lock.Lock()
	wg.Add(1)
	go func() {
		icmp.Handle(tnet, &lock)
		wg.Done()
	}()

	// Start API handler. Starting last because firewall rule needs to be first.
	lock.Lock()
	wg.Add(1)
	go func() {
		api.Handle(tnet, dev, &config, apiAddr, uint16(ApiPort), &lock)
		wg.Done()
	}()

	wg.Wait()
}
