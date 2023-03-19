package peer

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Config struct {
	config    wgtypes.Config
	peers     []PeerConfig
	addresses []net.IPNet
}

type configJSON struct {
	Config    wgtypes.Config
	Peers     []PeerConfig
	Addresses []net.IPNet
}

type ConfigArgs struct {
	PrivateKey   string
	ListenPort   int
	FirewallMark int
	ReplacePeers bool
	Peers        []PeerConfigArgs
	Addresses    []string
}

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

func (c *Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(configJSON{
		c.config,
		c.peers,
		c.addresses,
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

func (c *Config) SetFirewallMark(mark int) error {
	if mark < 1 {
		return errors.New("invalid firewall mark")
	}

	c.config.FirewallMark = &mark
	return nil
}

func (c *Config) SetReplacePeers(replacePeers bool) {
	c.config.ReplacePeers = replacePeers
}

func (c *Config) AddPeer(p PeerConfig) {
	c.peers = append(c.peers, p)
}

func (c *Config) SetAddresses(addrs []string) error {
	c.addresses = []net.IPNet{}
	for _, a := range addrs {
		// Ignore empty strings.
		if len(a) == 0 {
			continue
		}

		_, ipnet, err := net.ParseCIDR(a)
		if err != nil {
			return err
		}

		c.addresses = append(c.addresses, *ipnet)
	}

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

func (c *Config) AsFile() string {
	var s strings.Builder

	s.WriteString("[Interface]\n")
	s.WriteString(fmt.Sprintf("PrivateKey = %s\n", c.config.PrivateKey.String()))
	for _, a := range c.addresses {
		s.WriteString(fmt.Sprintf("Address = %s\n", a.String()))
	}
	s.WriteString(fmt.Sprintf("ListenPort = %d\n", *c.config.ListenPort))
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

func (c *Config) AsServerCommand() string {
	var s strings.Builder

	s.WriteString(fmt.Sprintf("WIRETAP_INTERFACE_PRIVATE=%s WIRETAP_PEER_PUBLIC=%s",
		c.GetPeerPrivateKey(0),
		c.GetPublicKey(),
	))

	if len(c.GetPeerEndpoint(0)) > 0 {
		s.WriteString(fmt.Sprintf(" WIRETAP_PEER_ENDPOINT=%s", c.GetPeerEndpoint(0)))
	}

	s.WriteString(fmt.Sprintf(" ./wiretap serve"))

	return s.String()
}

func (c *Config) AsServerFile() string {
	var s strings.Builder

	s.WriteString("[Interface]\n")
	s.WriteString(fmt.Sprintf("PrivateKey = %s\n", c.GetPeerPrivateKey(0)))
	s.WriteString("[Peer]\n")
	s.WriteString(fmt.Sprintf("PublicKey = %s\n", c.GetPublicKey()))
	if len(c.GetPeerEndpoint(0)) > 0 {
		s.WriteString(fmt.Sprintf("Endpoint = %s\n", c.GetPeerEndpoint(0)))
	}

	return s.String()
}
