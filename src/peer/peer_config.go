package peer

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type PeerConfig struct {
	config     wgtypes.PeerConfig
	privateKey *wgtypes.Key
	nickname   string
}

type peerConfigJSON struct {
	Config     wgtypes.PeerConfig
	PrivateKey *wgtypes.Key
	Nickname   string
}

type PeerConfigArgs struct {
	PublicKey                   string
	Remove                      bool
	UpdateOnly                  bool
	PresharedKey                string
	Endpoint                    string
	PersistentKeepaliveInterval int
	ReplaceAllowedIPs           bool
	AllowedIPs                  []string
	PrivateKey                  string
	Nickname                    string
}

func GetPeerConfig(args PeerConfigArgs) (PeerConfig, error) {
	c, err := NewPeerConfig()
	if err != nil {
		return PeerConfig{}, err
	}

	if len(args.PublicKey) != 0 {
		err = c.SetPublicKey(args.PublicKey)
		if err != nil {
			return PeerConfig{}, err
		}
	}

	c.SetRemove(args.Remove)
	c.SetUpdateOnly(args.UpdateOnly)

	if len(args.PresharedKey) != 0 {
		err = c.SetPresharedKey(args.PresharedKey)
		if err != nil {
			return PeerConfig{}, err
		}
	}

	if len(args.Endpoint) != 0 {
		err = c.SetEndpoint(args.Endpoint)
		if err != nil {
			return PeerConfig{}, err
		}
	}

	if args.PersistentKeepaliveInterval != 0 {
		err = c.SetPersistentKeepaliveInterval(args.PersistentKeepaliveInterval)
		if err != nil {
			return PeerConfig{}, err
		}
	}

	c.SetReplaceAllowedIPs(args.ReplaceAllowedIPs)

	err = c.SetAllowedIPs(args.AllowedIPs)
	if err != nil {
		return PeerConfig{}, err
	}

	if len(args.PrivateKey) != 0 {
		err = c.SetPrivateKey(args.PrivateKey)
		if err != nil {
			return PeerConfig{}, err
		}
	}
	
	if args.Nickname != "" {
		err = c.SetNickname(args.Nickname)
		if err != nil {
			return PeerConfig{}, err
		}
	}

	return c, nil
}

func NewPeerConfig() (PeerConfig, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return PeerConfig{}, err
	}

	return PeerConfig{
		config: wgtypes.PeerConfig{
			PublicKey: privateKey.PublicKey(),
		},
		privateKey: &privateKey,
		nickname: "",
	}, nil
}

func (p *PeerConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(peerConfigJSON{
		p.config,
		p.privateKey,
		p.nickname,
	})
}

func (p *PeerConfig) UnmarshalJSON(b []byte) error {
	tmp := &peerConfigJSON{}

	err := json.Unmarshal(b, &tmp)
	if err != nil {
		return err
	}

	p.config = tmp.Config
	p.privateKey = tmp.PrivateKey
	p.nickname = tmp.Nickname

	return nil
}

func (p *PeerConfig) SetPublicKey(publicKey string) error {
	key, err := parseKey(publicKey)
	if err != nil {
		return err
	}

	p.privateKey = nil
	p.config.PublicKey = *key
	return nil
}

func (p *PeerConfig) GetPublicKey() wgtypes.Key {
	return p.config.PublicKey
}

func (p *PeerConfig) SetRemove(remove bool) {
	p.config.Remove = remove
}

func (p *PeerConfig) SetUpdateOnly(updateOnly bool) {
	p.config.UpdateOnly = updateOnly
}

func (p *PeerConfig) SetPresharedKey(presharedKey string) error {
	key, err := parseKey(presharedKey)
	if err != nil {
		return err
	}

	p.config.PresharedKey = key
	return nil
}

func (p *PeerConfig) SetEndpoint(addr string) error {
	endpoint, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	p.config.Endpoint = endpoint
	return nil
}

func (p *PeerConfig) GetEndpoint() *net.UDPAddr {
	return p.config.Endpoint
}

func (p *PeerConfig) SetPersistentKeepaliveInterval(keepalive int) error {
	secs, err := time.ParseDuration(fmt.Sprintf("%ds", keepalive))
	if err != nil {
		return err
	}

	p.config.PersistentKeepaliveInterval = &secs
	return nil
}

func (p *PeerConfig) SetReplaceAllowedIPs(replaceAllowedIPs bool) {
	p.config.ReplaceAllowedIPs = replaceAllowedIPs
}

func (p *PeerConfig) SetAllowedIPs(allowedIPs []string) error {
	for _, a := range allowedIPs {
		err := p.AddAllowedIPs(a)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *PeerConfig) AddAllowedIPs(ip string) error {
	// Skip empty allowed IPs
	if len(ip) == 0 {
		return nil
	}

	_, ipnet, err := net.ParseCIDR(ip)
	if err != nil {
		return err
	}

	p.config.AllowedIPs = append(p.config.AllowedIPs, *ipnet)
	return nil
}

func (p *PeerConfig) GetAllowedIPs() []net.IPNet {
	return p.config.AllowedIPs
}

func (p *PeerConfig) GetApiAddr() netip.Addr {
	apiIP := p.config.AllowedIPs[len(p.config.AllowedIPs)-1]
	apiAddr, _ := netip.AddrFromSlice(apiIP.IP)
	return apiAddr
}

func (p *PeerConfig) SetPrivateKey(privateKey string) error {
	key, err := parseKey(privateKey)
	if err != nil {
		return err
	}

	p.privateKey = key
	p.config.PublicKey = key.PublicKey()
	return nil
}

func (p *PeerConfig) GetNickname() string {
	return p.nickname
}

func (p *PeerConfig) SetNickname(nickname string) error {
	if nickname != "" {
		p.nickname = nickname
	}
	return nil
}

func (p *PeerConfig) AsFile() string {
	var s strings.Builder
	s.WriteString("[Peer]\n")
	
	if p.nickname != "" {
		s.WriteString(fmt.Sprintf("%s Nickname = %s\n", CUSTOM_PREFIX, p.nickname))
	}
	
	s.WriteString(fmt.Sprintf("PublicKey = %s\n", p.config.PublicKey.String()))
	
	ips := []string{}
	for _, a := range p.config.AllowedIPs {
		ips = append(ips, a.String())
	}
	if len(ips) != 0 {
		s.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(ips, ",")))
	}
	if p.config.Endpoint != nil {
		s.WriteString(fmt.Sprintf("Endpoint = %s\n", p.config.Endpoint.String()))
	}
	if p.config.PersistentKeepaliveInterval != nil {
		s.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", *p.config.PersistentKeepaliveInterval/time.Second))
	}

	return s.String()
}

func (p *PeerConfig) AsIPC() string {
	var s strings.Builder

	s.WriteString(fmt.Sprintf("public_key=%s\n", hex.EncodeToString(p.config.PublicKey[:])))
	if p.config.Endpoint != nil {
		s.WriteString(fmt.Sprintf("endpoint=%s\n", p.config.Endpoint.String()))
	}
	for _, a := range p.config.AllowedIPs {
		s.WriteString(fmt.Sprintf("allowed_ip=%s\n", a.String()))
	}
	if p.config.PersistentKeepaliveInterval != nil {
		s.WriteString(fmt.Sprintf("persistent_keepalive_interval=%.0f\n", p.config.PersistentKeepaliveInterval.Seconds()))
	}

	return s.String()
}
