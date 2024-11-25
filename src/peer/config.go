package peer

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Config struct {
	config      wgtypes.Config
	mtu         int
	peers       []PeerConfig
	addresses   []net.IPNet
	localhostIP string
}

type configJSON struct {
	Config      wgtypes.Config
	MTU         int
	Peers       []PeerConfig
	Addresses   []net.IPNet
	LocalhostIP string
}

type ConfigArgs struct {
	PrivateKey   string
	ListenPort   int
	FirewallMark int
	MTU          int
	ReplacePeers bool
	Peers        []PeerConfigArgs
	Addresses    []string
	LocalhostIP  string
}

type Shell uint

const (
	POSIX Shell = iota
	PowerShell
)

const CUSTOM_PREFIX = "#@"

func GetConfig(args ConfigArgs) (Config, error) {
	c, err := NewConfig()
	if err != nil {
		return Config{}, err
	}

	if len(args.PrivateKey) != 0 {
		err = c.SetPrivateKey(args.PrivateKey)
		if err != nil {
			return Config{}, err
		}
	}

	if args.ListenPort != 0 {
		err = c.SetPort(args.ListenPort)
		if err != nil {
			return Config{}, err
		}
	}

	if args.FirewallMark != 0 {
		err = c.SetFirewallMark(args.FirewallMark)
		if err != nil {
			return Config{}, err
		}
	}

	if args.MTU != 0 {
		err = c.SetMTU(args.MTU)
		if err != nil {
			return Config{}, err
		}
	}

	c.SetReplacePeers(args.ReplacePeers)

	for _, peer := range args.Peers {
		newPeer, err := GetPeerConfig(peer)
		if err != nil {
			return Config{}, err
		}

		c.AddPeer(newPeer)
	}

	if len(args.Addresses) != 0 {
		err = c.SetAddresses(args.Addresses)
		if err != nil {
			return Config{}, err
		}
	}

	if args.LocalhostIP != "" {
		err = c.SetLocalhostIP(args.LocalhostIP)
		if err != nil {
			return Config{}, err
		}
	}

	return c, nil
}

func NewConfig() (Config, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Config{}, err
	}

	return Config{
		config: wgtypes.Config{
			PrivateKey: &privateKey,
		},
	}, nil
}

func ParseConfig(filename string) (c Config, err error) {
	configBytes, err := os.ReadFile(filename)
	if err != nil {
		return c, err
	}

	for _, section := range strings.Split(string(configBytes), "\n\n") {
		lines := strings.Split(section, "\n")
		switch strings.ToLower(lines[0]) {
		case "[interface]":
			if c.config.PrivateKey != nil {
				return c, errors.New("cannot have more than one interface section")
			}
			for _, line := range lines[1:] {
				if len(line) == 0 || line[0] == '#' {
					continue
				}
				key, value, err := parseConfigLine(line)
				if err != nil {
					return c, err
				}
				switch key {
				case "privatekey":
					err = c.SetPrivateKey(value)
				case "address":
					err = c.AddAddress(value)
				case "listenport":
					port, e := strconv.Atoi(value)
					if e != nil {
						return c, e
					}
					err = c.SetPort(port)
				case "mtu":
					mtu, e := strconv.Atoi(value)
					if e != nil {
						return c, e
					}
					err = c.SetMTU(mtu)
				case "localhostip":
					err = c.SetLocalhostIP(value)
				}
				if err != nil {
					return c, err
				}
			}
		case "[peer]":
			newPeer := PeerConfig{}
			for _, line := range lines[1:] {
				if len(line) == 0 {
					continue
				}

				if strings.HasPrefix(line, CUSTOM_PREFIX) { //special wiretap-specific values
					line = line[len(CUSTOM_PREFIX):]
				} else if line[0] == '#' {
					continue
				}

				key, value, err := parseConfigLine(line)
				if err != nil {
					return c, err
				}
				switch key {
				case "endpoint":
					err = newPeer.SetEndpoint(value)
				case "allowedips":
					err = newPeer.SetAllowedIPs(strings.Split(value, ","))
				case "publickey":
					err = newPeer.SetPublicKey(value)
				case "persistentkeepalive":
					keepalive, e := strconv.Atoi(value)
					if e != nil {
						return c, e
					}
					err = newPeer.SetPersistentKeepaliveInterval(keepalive)
				case "nickname":
					err = newPeer.SetNickname(value)
				}
				if err != nil {
					return c, err
				}
			}
			if newPeer.GetPublicKey().String() != "" {
				c.AddPeer(newPeer)
			}
		default:
			return c, fmt.Errorf("unknown configuration section: %s", lines[0])
		}
	}

	return c, nil
}

func parseConfigLine(line string) (string, string, error) {
	key, val, found := strings.Cut(line, "=")
	if !found {
		return "", "", fmt.Errorf("failed to parse line: no = found: [%s]", line)
	}

	return strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(val), nil
}

func (c *Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(configJSON{
		c.config,
		c.mtu,
		c.peers,
		c.addresses,
		c.localhostIP,
	})
}

func (c *Config) UnmarshalJSON(b []byte) error {
	tmp := &configJSON{}

	err := json.Unmarshal(b, &tmp)
	if err != nil {
		return err
	}

	c.config = tmp.Config
	c.peers = tmp.Peers
	c.addresses = tmp.Addresses
	c.localhostIP = tmp.LocalhostIP

	return nil
}

func (c *Config) SetPrivateKey(privateKey string) error {
	key, err := parseKey(privateKey)
	if err != nil {
		return err
	}

	c.config.PrivateKey = key
	return nil
}

func (c *Config) GetPrivateKey() string {
	return c.config.PrivateKey.String()
}

func (c *Config) SetPort(port int) error {
	if port < 1 || port > 65535 {
		return errors.New("invalid port")
	}

	c.config.ListenPort = &port
	return nil
}

func (c *Config) ClearPort() {
	c.config.ListenPort = nil
}

func (c *Config) SetFirewallMark(mark int) error {
	if mark < 1 {
		return errors.New("invalid firewall mark")
	}

	c.config.FirewallMark = &mark
	return nil
}

func (c *Config) SetMTU(mtu int) error {
	if mtu < 1 {
		return errors.New("invalid mtu")
	}

	c.mtu = mtu
	return nil
}

func (c *Config) SetReplacePeers(replacePeers bool) {
	c.config.ReplacePeers = replacePeers
}

func (c *Config) AddPeer(p PeerConfig) {
	c.peers = append(c.peers, p)
}

func (c *Config) GetPeer(pub wgtypes.Key) *PeerConfig {
	for i, p := range c.peers {
		if p.config.PublicKey == pub {
			return &c.peers[i]
		}
	}

	return nil
}

func (c *Config) ClearPeers() {
	c.peers = []PeerConfig{}
}

func (c *Config) SetAddresses(addrs []string) error {
	c.addresses = []net.IPNet{}
	for _, a := range addrs {
		err := c.AddAddress(a)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) AddAddress(addr string) error {
	// Ignore empty strings.
	if len(addr) == 0 {
		return nil
	}

	_, ipnet, err := net.ParseCIDR(addr)
	if err != nil {
		return err
	}

	c.addresses = append(c.addresses, *ipnet)
	return nil
}

func (c *Config) GetAddresses() []net.IPNet {
	return c.addresses
}

func (c *Config) GetPublicKey() string {
	return c.config.PrivateKey.PublicKey().String()
}

func (c *Config) GetPeers() []PeerConfig {
	return c.peers
}

func (c *Config) GetPeerPrivateKey(i int) string {
	if len(c.peers) > i {
		if c.peers[i].privateKey != nil {
			return c.peers[i].privateKey.String()
		}
	}

	return ""
}

func (c *Config) GetPeerPublicKey(i int) string {
	if len(c.peers) > i {
		return c.peers[i].config.PublicKey.String()
	}

	return ""
}

func (c *Config) GetPeerEndpoint(i int) string {
	if len(c.peers) > i {
		endpoint := c.peers[i].config.Endpoint
		if endpoint != nil {
			return endpoint.String()
		}

		return ""
	}

	return ""
}

func (c *Config) GetLocalhostIP() string {
	return c.localhostIP
}

func (c *Config) SetLocalhostIP(ip string) error {
	c.localhostIP = ip
	return nil
}

// Convert config to peer config, only transfers keys.
func (c *Config) AsPeer() (p PeerConfig, err error) {
	p, err = NewPeerConfig()
	if err != nil {
		return p, err
	}

	err = p.SetPrivateKey(c.GetPrivateKey())

	return p, err
}

func (c *Config) AsFile() string {
	var s strings.Builder

	s.WriteString("[Interface]\n")
	s.WriteString(fmt.Sprintf("PrivateKey = %s\n", c.config.PrivateKey.String()))
	for _, a := range c.addresses {
		s.WriteString(fmt.Sprintf("Address = %s\n", a.String()))
	}
	if c.config.ListenPort != nil {
		s.WriteString(fmt.Sprintf("ListenPort = %d\n", *c.config.ListenPort))
	}
	if c.mtu != 0 {
		s.WriteString(fmt.Sprintf("MTU = %d\n", c.mtu))
	}
	if c.localhostIP != "" {
		s.WriteString(fmt.Sprintf("LocalhostIP = %s\n", c.localhostIP))
	}
	for _, p := range c.peers {
		s.WriteString(fmt.Sprintf("\n%s", p.AsFile()))
	}

	return s.String()
}

func (c *Config) AsShareableFile() string {
	var s strings.Builder

	s.WriteString("[Peer]\n")
	s.WriteString(fmt.Sprintf("PublicKey = %s\n", c.config.PrivateKey.PublicKey().String()))
	s.WriteString("AllowedIPs = 0.0.0.0/32\n")

	return s.String()
}

func (c *Config) AsIPC() string {
	var s strings.Builder

	s.WriteString(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(c.config.PrivateKey[:])))
	s.WriteString(fmt.Sprintf("listen_port=%d\n", *c.config.ListenPort))
	for _, p := range c.peers {
		s.WriteString(p.AsIPC())
	}

	return s.String()
}

func CreateServerCommand(relayConfig Config, e2eeConfig Config, shell Shell, simple bool, disableV6 bool) string {
	var s strings.Builder
	var keys []string
	var vals []string

	// Relay Interface.
	keys = append(keys, "WIRETAP_RELAY_INTERFACE_PRIVATEKEY")
	vals = append(vals, relayConfig.GetPrivateKey())

	if len(relayConfig.addresses) >= 1 {
		keys = append(keys, "WIRETAP_RELAY_INTERFACE_IPV4")
		vals = append(vals, relayConfig.addresses[0].IP.String())
	}
	if len(relayConfig.addresses) >= 2 {
		keys = append(keys, "WIRETAP_RELAY_INTERFACE_IPV6")
		vals = append(vals, relayConfig.addresses[1].IP.String())
	}

	if relayConfig.config.ListenPort != nil {
		keys = append(keys, "WIRETAP_RELAY_INTERFACE_PORT")
		vals = append(vals, fmt.Sprint(*relayConfig.config.ListenPort))
	}

	if relayConfig.mtu != 0 {
		keys = append(keys, "WIRETAP_RELAY_INTERFACE_MTU")
		vals = append(vals, fmt.Sprint(relayConfig.mtu))
	}

	// Relay Peer.
	keys = append(keys, "WIRETAP_RELAY_PEER_PUBLICKEY")
	vals = append(vals, relayConfig.GetPeerPublicKey(0))

	if len(relayConfig.peers) > 0 && len(relayConfig.peers[0].config.AllowedIPs) > 0 {
		keys = append(keys, "WIRETAP_RELAY_PEER_ALLOWED")
		vals = append(vals, func() string {
			allowed := []string{}
			for _, ip := range relayConfig.peers[0].config.AllowedIPs {
				allowed = append(allowed, ip.String())
			}
			return strings.Join(allowed, ",")
		}())
	}

	if len(relayConfig.GetPeerEndpoint(0)) > 0 {
		keys = append(keys, "WIRETAP_RELAY_PEER_ENDPOINT")
		vals = append(vals, relayConfig.GetPeerEndpoint(0))
	}

	if !simple {
		// E2EE Interface.
		keys = append(keys, "WIRETAP_E2EE_INTERFACE_PRIVATEKEY")
		vals = append(vals, e2eeConfig.GetPrivateKey())

		if len(e2eeConfig.addresses) == 1 {
			keys = append(keys, "WIRETAP_E2EE_INTERFACE_API")
			vals = append(vals, e2eeConfig.addresses[0].IP.String())
		}

		// E2EE Peer.
		keys = append(keys, "WIRETAP_E2EE_PEER_PUBLICKEY")
		vals = append(vals, e2eeConfig.GetPeerPublicKey(0))

		if len(e2eeConfig.GetPeerEndpoint(0)) > 0 {
			keys = append(keys, "WIRETAP_E2EE_PEER_ENDPOINT")
			vals = append(vals, e2eeConfig.GetPeerEndpoint(0))
		}
	} else {
		keys = append(keys, "WIRETAP_SIMPLE")
		vals = append(vals, "true")
	}

	if disableV6 {
		keys = append(keys, "WIRETAP_DISABLEIPV6")
		vals = append(vals, "true")
	}

	if len(relayConfig.GetLocalhostIP()) > 0 {
		keys = append(keys, "WIRETAP_RELAY_INTERFACE_LOCALHOSTIP")
		vals = append(vals, relayConfig.GetLocalhostIP())
	}

	switch shell {
	case POSIX:
		for i := 0; i < len(keys); i++ {
			s.WriteString(fmt.Sprintf("%s=%s ", keys[i], vals[i]))
		}
		s.WriteString("./wiretap serve")
	case PowerShell:
		for i := 0; i < len(keys); i++ {
			s.WriteString(fmt.Sprintf("$env:%s=\"%s\"; ", keys[i], vals[i]))
		}
		s.WriteString(".\\wiretap.exe serve")
	}

	return s.String()
}

func CreateServerFile(relayConfig Config, e2eeConfig Config) string {
	var s strings.Builder

	// Relay Interface.
	s.WriteString("[Relay.Interface]\n")
	s.WriteString(fmt.Sprintf("PrivateKey = %s\n", relayConfig.GetPrivateKey()))

	if len(relayConfig.addresses) >= 1 {
		s.WriteString(fmt.Sprintf("IPv4 = %s\n", relayConfig.addresses[0].IP.String()))
	}
	if len(relayConfig.addresses) >= 2 {
		s.WriteString(fmt.Sprintf("IPv6 = %s\n", relayConfig.addresses[1].IP.String()))
	}

	if relayConfig.config.ListenPort != nil {
		s.WriteString(fmt.Sprintf("Port = %d\n", *relayConfig.config.ListenPort))
	}

	if relayConfig.mtu != 0 {
		s.WriteString(fmt.Sprintf("MTU = %d\n", relayConfig.mtu))
	}

	if relayConfig.localhostIP != "" {
		s.WriteString(fmt.Sprintf("LocalhostIP = %s\n", relayConfig.GetLocalhostIP()))
	}

	// Relay Peer.
	s.WriteString("\n[Relay.Peer]\n")

	if len(relayConfig.peers) > 0 && len(relayConfig.peers[0].config.AllowedIPs) > 0 {
		allowed := []string{}
		for _, ip := range relayConfig.peers[0].config.AllowedIPs {
			allowed = append(allowed, ip.String())
		}
		s.WriteString(fmt.Sprintf("Allowed = %s\n", strings.Join(allowed, ",")))
	}

	s.WriteString(fmt.Sprintf("PublicKey = %s\n", relayConfig.GetPeerPublicKey(0)))
	if len(relayConfig.GetPeerEndpoint(0)) > 0 {
		s.WriteString(fmt.Sprintf("Endpoint = %s\n", relayConfig.GetPeerEndpoint(0)))
	}

	// E2EE Interface.
	s.WriteString("\n[E2EE.Interface]\n")
	s.WriteString(fmt.Sprintf("PrivateKey = %s\n", e2eeConfig.GetPrivateKey()))

	if len(e2eeConfig.addresses) == 1 {
		s.WriteString(fmt.Sprintf("Api = %s\n", e2eeConfig.addresses[0].IP.String()))
	}

	// E2EE Peer.
	s.WriteString("\n[E2EE.Peer]\n")
	s.WriteString(fmt.Sprintf("PublicKey = %s\n", e2eeConfig.GetPeerPublicKey(0)))
	if len(e2eeConfig.GetPeerEndpoint(0)) > 0 {
		s.WriteString(fmt.Sprintf("Endpoint = %s\n", e2eeConfig.GetPeerEndpoint(0)))
	}

	return s.String()
}
