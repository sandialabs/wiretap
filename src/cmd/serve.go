package cmd

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/cobra"
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
	privateKey string
	publicKey  string
	endpoint   string
	port       int
	quiet      bool
	debug      bool
	allowedIPs []string
	addr4      string
	addr6      string
	apiAddr    string
	keepalive  int
	mtu        int
	logging    bool
	logFile    string
}

// Defaults for serve command.
var serveCmd = serveCmdConfig{
	configFile: "",
	privateKey: "",
	publicKey:  "",
	endpoint:   Endpoint,
	port:       Port,
	quiet:      false,
	debug:      false,
	allowedIPs: []string{Subnet4.Addr().Next().Next().String() + "/32", Subnet6.Addr().Next().Next().String() + "/128"},
	addr4:      Subnet4.Addr().Next().String() + "/32",
	addr6:      Subnet6.Addr().Next().String() + "/128",
	apiAddr:    ApiAddr.String(),
	mtu:        1420,
	keepalive:  Keepalive,
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
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return serveCmd.PreRun()
		},
		Run: func(cmd *cobra.Command, args []string) {
			serveCmd.Run()
		},
	}

	rootCmd.AddCommand(cmd)

	cmd.Flags().StringVarP(&serveCmd.configFile, "config-file", "f", serveCmd.configFile, "wireguard config file to read from")
	cmd.Flags().StringVarP(&serveCmd.privateKey, "private", "", serveCmd.privateKey, "wireguard private key")
	cmd.Flags().StringVarP(&serveCmd.publicKey, "public", "", serveCmd.publicKey, "wireguard public key of remote peer")
	cmd.Flags().StringVarP(&serveCmd.endpoint, "endpoint", "e", serveCmd.endpoint, "socket address of remote peer that server will connect to (example \"1.2.3.4:51820\")")
	cmd.Flags().IntVarP(&serveCmd.port, "port", "p", serveCmd.port, "wireguard listener port")
	cmd.Flags().BoolVarP(&serveCmd.quiet, "quiet", "q", serveCmd.quiet, "silence wiretap log messages")
	cmd.Flags().BoolVarP(&serveCmd.debug, "debug", "d", serveCmd.debug, "enable wireguard log messages")

	cmd.Flags().StringSliceVarP(&serveCmd.allowedIPs, "allowed", "a", serveCmd.allowedIPs, "comma-separated list of CIDR IP ranges to associate with peer")
	cmd.Flags().StringVarP(&serveCmd.addr4, "ipv4", "4", serveCmd.addr4, "virtual ipv4 address of wireguard interface")
	cmd.Flags().StringVarP(&serveCmd.addr6, "ipv6", "6", serveCmd.addr6, "virtual ipv6 address of wireguard interface")
	cmd.Flags().StringVarP(&serveCmd.apiAddr, "api", "0", serveCmd.apiAddr, "address of API service")
	cmd.Flags().IntVarP(&serveCmd.keepalive, "keepalive", "k", serveCmd.keepalive, "tunnel keepalive in seconds")
	cmd.Flags().IntVarP(&serveCmd.mtu, "mtu", "m", serveCmd.mtu, "tunnel MTU")
	cmd.Flags().BoolVarP(&serveCmd.logging, "log", "l", serveCmd.logging, "enable logging to file")
	cmd.Flags().StringVarP(&serveCmd.logFile, "log-file", "o", serveCmd.logFile, "write log to this filename")

	// Quiet and debug flags must be used independently.
	cmd.MarkFlagsMutuallyExclusive("debug", "quiet")

	cmd.Flags().SortFlags = false

	helpFunc := cmd.HelpFunc()
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if !ShowHidden {
			for _, f := range []string{"allowed", "ipv4", "ipv6", "api", "keepalive", "mtu", "log", "log-file"} {
				err := cmd.Flags().MarkHidden(f)
				if err != nil {
					fmt.Printf("Failed to hide flag %v: %v\n", f, err)
				}
			}
		}
		helpFunc(cmd, args)
	})
}

// Checks for config file flag and reads config file if present.
func (c serveCmdConfig) PreRun() error {
	// Check for config file flag.
	if serveCmd.configFile == "" && serveCmd.publicKey == "" {
		return errors.New("Either --config-file or --public must be specified")
	}

	if serveCmd.configFile != "" {
		fmt.Println("Reading config file, ignoring other flags")

		// Read config file to string.
		config, err := ioutil.ReadFile(serveCmd.configFile)
		if err != nil {
			return errors.New("Failed to read config file")
		}

		// Parse config file.
		lines := strings.Split(string(config), "\n")
		parserState := 0
		sawPublic := false
		sawPeer  := false
		sawInterface := false

		for _, line := range lines {
			line, _, _ = strings.Cut(line, "#")
			line = strings.TrimSpace(line)
			lineLower := strings.ToLower(line)
			if len(line) == 0 {
				continue
			}
			if lineLower == "[interface]" {
				if sawInterface {
					return errors.New("Multiple interfaces are not supported")
				}
				sawInterface = true
				parserState = 1
				continue
			}
			if lineLower == "[peer]" {
				if sawPeer {
					return errors.New("Multiple peers are not supported")
				}
				sawPeer = true
				parserState = 2
				continue
			}
			if parserState == 0 {
				return errors.New("Line must occur in a section")
			}
			equals := strings.IndexByte(line, '=')
			if equals < 0 {
				return errors.New("Config key is missing an equals separator")
			}
			key, val := strings.TrimSpace(lineLower[:equals]), strings.TrimSpace(line[equals+1:])
			if len(val) == 0 {
				return errors.New("Key must have a value")
			}
			if parserState == 1 {
				switch key {
				case "private":
					serveCmd.privateKey = val
				case "port":
					port, err := strconv.Atoi(val)
					if err != nil {
						return errors.New("Failed to parse listen port")
					}
					serveCmd.port = port
				case "ipv4":
					serveCmd.addr4 = val
				case "ipv6":
					serveCmd.addr6 = val
				case "api":
					serveCmd.apiAddr = val
				case "mtu":
					mtu, err := strconv.Atoi(val)
					if err != nil {
						return errors.New("Failed to parse MTU")
					}
					serveCmd.mtu = mtu
				default:
					return errors.New("Unknown key in [interface] section")
				}
			}
			if parserState == 2 {
				switch key {
				case "public":
					serveCmd.publicKey = val
					sawPublic = true
				case "endpoint":
					serveCmd.endpoint = val
				case "allowed":
					serveCmd.allowedIPs = strings.Split(val, ",")
				case "keepalive":
					keepalive, err := strconv.Atoi(val)
					if err != nil {
						return errors.New("Failed to parse keepalive")
					}
					serveCmd.keepalive = keepalive
				default:
					return errors.New("Unknown key in [peer] section")
				}
			}
		}
		if !sawPublic {
			return errors.New("Config file must contain a public key")
		}
	} else {
		// Config file flag is not set
		// Cannot serve without public key of at least one peer.
		if serveCmd.publicKey == "" {
			return errors.New("public key of peer must be specified")
		}
	}

	return nil
}


// Run parses/processes/validates args and then connects to peer,
// proxying traffic from peer into local network.
func (c serveCmdConfig) Run() {
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

	configArgs := peer.ConfigArgs{
		PrivateKey: c.privateKey,
		ListenPort: c.port,
		Peers: []peer.PeerConfigArgs{
			{
				PublicKey:                   c.publicKey,
				Endpoint:                    c.endpoint,
				PersistentKeepaliveInterval: c.keepalive,
				AllowedIPs:                  c.allowedIPs,
			},
		},
		Addresses: []string{c.addr4, c.addr6},
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
	ipv4Prefix, err := netip.ParsePrefix(c.addr4)
	check("failed to parse ipv4 address", err)
	ipv4Addr := ipv4Prefix.Addr()

	ipv6Prefix, err := netip.ParsePrefix(c.addr6)
	check("failed to parse ipv6 address", err)
	ipv6Addr := ipv6Prefix.Addr()

	apiPrefix, err := netip.ParsePrefix(c.apiAddr)
	check("failed to parse API address", err)
	apiAddr := apiPrefix.Addr()

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{ipv4Addr, ipv6Addr, apiAddr},
		[]netip.Addr{},
		c.mtu,
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
