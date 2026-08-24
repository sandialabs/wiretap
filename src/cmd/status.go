package cmd

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/m1gwings/treedrawer/tree"
	"github.com/spf13/cobra"

	"wiretap/api"
	"wiretap/peer"
)

type statusCmdConfig struct {
	networkInfo     bool
	jsonOutput      bool
	configFileRelay string
	configFileE2EE  string
}

// Represents one Server or Client in tree
type Node struct {
	peerConfig      peer.PeerConfig
	relayConfig     peer.Config
	e2eeConfig      peer.Config
	children        []*Node
	interfaces      []api.HostInterface
	interfacesError string
	error           string
}

type statusJSONOutput struct {
	NetworkInfo bool              `json:"network_info"`
	Client      statusJSONClient  `json:"client"`
	Errors      []statusJSONError `json:"errors"`
}

type statusJSONClient struct {
	RelayPublicKey string             `json:"relay_public_key"`
	E2EEPublicKey  string             `json:"e2ee_public_key"`
	Children       []statusJSONServer `json:"children"`
}

type statusJSONServer struct {
	Nickname         string                `json:"nickname,omitempty"`
	RelayPublicKey   string                `json:"relay_public_key"`
	E2EEPublicKey    string                `json:"e2ee_public_key"`
	API              string                `json:"api"`
	Routes           []string              `json:"routes"`
	LocalhostIP      string                `json:"localhost_ip,omitempty"`
	Interfaces       []statusJSONInterface `json:"interfaces"`
	NetworkInfoError string                `json:"network_info_error,omitempty"`
	Children         []statusJSONServer    `json:"children"`
}

type statusJSONInterface struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

type statusJSONError struct {
	Nickname      string   `json:"nickname,omitempty"`
	E2EEPublicKey string   `json:"e2ee_public_key"`
	API           string   `json:"api"`
	Routes        []string `json:"routes"`
	Error         string   `json:"error"`
}

// Defaults for status command.
// See root command for shared defaults.
var statusCmd = statusCmdConfig{
	networkInfo:     false,
	jsonOutput:      false,
	configFileRelay: ConfigRelay,
	configFileE2EE:  ConfigE2EE,
}

// Add command and set flags.
func init() {
	// Usage info.
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show peer layout",
		Long:  `Show diagram of all deployed peers`,
		Run: func(cmd *cobra.Command, args []string) {
			statusCmd.Run()
		},
	}

	rootCmd.AddCommand(cmd)

	cmd.Flags().BoolVarP(&statusCmd.networkInfo, "network-info", "n", statusCmd.networkInfo, "Display network info for each online server node")
	cmd.Flags().BoolVar(&statusCmd.jsonOutput, "json", statusCmd.jsonOutput, "Display status as JSON")
	cmd.Flags().StringVarP(&statusCmd.configFileRelay, "relay", "1", statusCmd.configFileRelay, "wireguard relay config input filename")
	cmd.Flags().StringVarP(&statusCmd.configFileE2EE, "e2ee", "2", statusCmd.configFileE2EE, "wireguard E2EE config input filename")

	cmd.Flags().SortFlags = false
}

// Run attempts to parse config files into a network diagram.
func (cc statusCmdConfig) Run() {
	var err error

	// Parse the relay and e2ee config files
	clientConfigRelay, err := peer.ParseConfig(cc.configFileRelay)
	check("failed to parse relay config file", err)
	clientConfigE2EE, err := peer.ParseConfig(cc.configFileE2EE)
	check("failed to parse e2ee config file", err)

	client := Node{
		relayConfig: clientConfigRelay,
		e2eeConfig:  clientConfigE2EE,
	}

	// Get list of all nodes, then use list to build tree.
	// Get map of all nodes for building tree.
	// Key on public key of relay interfaces.
	nodes := make(map[string]Node)
	var errorNodes []Node
	e2ee_peer_list := client.e2eeConfig.GetPeers()
	nodeChannel := make(chan Node)
	for _, ep := range e2ee_peer_list {
		// Make all the API requests concurrently to speed things up
		go cc.makeAPIRequests(nodeChannel, ep)
	}

	// Don't need to do anything with values, just need to loop the same number of times
	for range e2ee_peer_list {
		responseNode := <-nodeChannel

		if responseNode.error == "" {
			nodes[responseNode.relayConfig.GetPublicKey()] = responseNode
		} else {
			errorNodes = append(errorNodes, responseNode)
		}
	}

	// Build tree by adding each relay node as a child.
	var findChildren func(currentNode *Node)
	findChildren = func(current *Node) {
	outer:
		for _, rp := range current.relayConfig.GetPeers() {
			// Skip client-facing peers.
			for _, ip := range rp.GetAllowedIPs() {
				if clientConfigRelay.GetAddresses()[0].Contains(ip.IP) {
					continue outer
				}
			}

			next, ok := nodes[rp.GetPublicKey().String()]
			// Not a peer we know about. Could be another client or an error.
			if !ok {
				continue
			}
			current.children = append(current.children, &next)
			findChildren(&next)
		}
	}
	findChildren(&client)

	if cc.jsonOutput {
		statusBytes, err := marshalStatusJSON(&client, errorNodes, cc.networkInfo)
		check("could not encode status as JSON", err)
		fmt.Println(string(statusBytes))
		return
	}

	t := tree.NewTree(tree.NodeString(" Wiretap Network Status "))

	// Use node tree to build diagram tree.
	t.AddChild(tree.NodeString(fmt.Sprintf(`client

  relay: %v... 
   e2ee: %v... 
`, client.relayConfig.GetPublicKey()[:8], client.e2eeConfig.GetPublicKey()[:8])))

	// Closest peers should be at the top
	var treeTraversal func(*Node, *tree.Tree)
	treeTraversal = func(node *Node, t *tree.Tree) {
		for i, c := range node.children {
			ips := []string{}
			var api string
			for j, a := range c.peerConfig.GetAllowedIPs() {
				if j == len(c.peerConfig.GetAllowedIPs())-1 {
					api = a.IP.String()
				} else {
					ips = append(ips, a.String())
				}
			}

			nodeString := fmt.Sprintf(
				`server
 nickname: %v 
    relay: %v... 
     e2ee: %v... 
   
      api: %v 
   routes: %v `,
				c.peerConfig.GetNickname(),
				c.relayConfig.GetPublicKey()[:8],
				c.e2eeConfig.GetPublicKey()[:8],
				api,
				strings.Join(ips, ","),
			)

			if c.relayConfig.GetLocalhostIP() != "" {
				nodeString += "\n lhost IP: " + c.relayConfig.GetLocalhostIP()
			}

			if cc.networkInfo {
				nodeString += `

Network Interfaces:
-------------------
`
				for _, ifx := range c.interfaces {
					nodeString += ifx.Name + "\n"
					for _, a := range ifx.Addrs {
						nodeString += strings.Repeat(" ", 2) + a.String() + "\n"
					}
				}
			}

			t.AddChild(tree.NodeString(nodeString))
			child, err := t.Child(0)
			check("could not build tree", err)
			treeTraversal(node.children[i], child)
		}
	}
	child, err := t.Child(0)
	check("could not build tree", err)
	treeTraversal(&client, child)

	fmt.Println()
	_, _ = fmt.Fprintln(color.Output, WhiteBold(t))
	fmt.Println()

	if len(errorNodes) > 0 {
		// Display known peers that we had issues connecting to
		_, _ = fmt.Fprintln(color.Output, WhiteBold("Peers with Errors:"))
		fmt.Println()

		for _, node := range errorNodes {
			ips := []string{}
			var api string
			for j, a := range node.peerConfig.GetAllowedIPs() {
				if j == len(node.peerConfig.GetAllowedIPs())-1 {
					api = a.IP.String()
				} else {
					ips = append(ips, a.String())
				}
			}

			nodeString := fmt.Sprintf(
				`server

 nickname: %v 
     e2ee: %v... 
      api: %v 
   routes: %v 
		   
 error: %v`,
				node.peerConfig.GetNickname(),
				node.peerConfig.GetPublicKey().String()[:8],
				api, strings.Join(ips, ","),
				errorWrap(node.error, 80),
			)

			t = tree.NewTree(tree.NodeString(nodeString))
			_, _ = fmt.Fprintln(color.Output, WhiteBold(t))
		}
	}
}

func (cc statusCmdConfig) makeAPIRequests(ch chan<- Node, ep peer.PeerConfig) {
	relayConfig, e2eeConfig, err := api.ServerInfo(netip.AddrPortFrom(ep.GetApiAddr(), uint16(ApiPort)))
	if err != nil {
		ch <- Node{
			peerConfig: ep,
			error:      err.Error(),
		}
		return

	} else {
		var interfaces []api.HostInterface
		var interfacesError string
		if cc.networkInfo {
			interfaces, err = api.ServerInterfaces(netip.AddrPortFrom(ep.GetApiAddr(), uint16(ApiPort)))
			if err != nil {
				interfacesError = err.Error()
				interfaces = append(interfaces, api.HostInterface{
					Name: "ERROR: " + err.Error(),
				})
			}
		}

		ch <- Node{
			peerConfig:      ep,
			relayConfig:     relayConfig,
			e2eeConfig:      e2eeConfig,
			interfaces:      interfaces,
			interfacesError: interfacesError,
		}
		return
	}
}

func marshalStatusJSON(client *Node, errorNodes []Node, networkInfo bool) ([]byte, error) {
	return json.MarshalIndent(buildStatusJSON(client, errorNodes, networkInfo), "", "  ")
}

func buildStatusJSON(client *Node, errorNodes []Node, networkInfo bool) statusJSONOutput {
	output := statusJSONOutput{
		NetworkInfo: networkInfo,
		Client: statusJSONClient{
			RelayPublicKey: client.relayConfig.GetPublicKey(),
			E2EEPublicKey:  client.e2eeConfig.GetPublicKey(),
			Children:       make([]statusJSONServer, 0, len(client.children)),
		},
		Errors: make([]statusJSONError, 0, len(errorNodes)),
	}

	for _, child := range client.children {
		output.Client.Children = append(output.Client.Children, buildStatusJSONServer(child))
	}

	for _, node := range errorNodes {
		apiAddr, routes := statusPeerDetails(node.peerConfig)
		output.Errors = append(output.Errors, statusJSONError{
			Nickname:      node.peerConfig.GetNickname(),
			E2EEPublicKey: node.peerConfig.GetPublicKey().String(),
			API:           apiAddr,
			Routes:        routes,
			Error:         node.error,
		})
	}

	// API requests are concurrent, so errorNodes arrive in nondeterministic order.
	sort.Slice(output.Errors, func(i, j int) bool {
		if output.Errors[i].API != output.Errors[j].API {
			return output.Errors[i].API < output.Errors[j].API
		}
		if output.Errors[i].Nickname != output.Errors[j].Nickname {
			return output.Errors[i].Nickname < output.Errors[j].Nickname
		}
		return output.Errors[i].E2EEPublicKey < output.Errors[j].E2EEPublicKey
	})

	return output
}

func buildStatusJSONServer(node *Node) statusJSONServer {
	apiAddr, routes := statusPeerDetails(node.peerConfig)
	interfaces := []statusJSONInterface{}
	if node.interfacesError == "" {
		interfaces = statusJSONInterfaces(node.interfaces)
	}

	server := statusJSONServer{
		Nickname:         node.peerConfig.GetNickname(),
		RelayPublicKey:   node.relayConfig.GetPublicKey(),
		E2EEPublicKey:    node.e2eeConfig.GetPublicKey(),
		API:              apiAddr,
		Routes:           routes,
		LocalhostIP:      node.relayConfig.GetLocalhostIP(),
		Interfaces:       interfaces,
		NetworkInfoError: node.interfacesError,
		Children:         make([]statusJSONServer, 0, len(node.children)),
	}

	for _, child := range node.children {
		server.Children = append(server.Children, buildStatusJSONServer(child))
	}

	return server
}

func statusPeerDetails(p peer.PeerConfig) (string, []string) {
	allowedIPs := p.GetAllowedIPs()
	routes := make([]string, 0, len(allowedIPs))
	if len(allowedIPs) == 0 {
		return "", routes
	}

	for i, addr := range allowedIPs {
		if i == len(allowedIPs)-1 {
			return addr.IP.String(), routes
		}
		routes = append(routes, addr.String())
	}

	return "", routes
}

func statusJSONInterfaces(interfaces []api.HostInterface) []statusJSONInterface {
	output := make([]statusJSONInterface, 0, len(interfaces))
	for _, ifx := range interfaces {
		addresses := make([]string, 0, len(ifx.Addrs))
		for _, addr := range ifx.Addrs {
			addresses = append(addresses, addr.String())
		}
		sort.Strings(addresses)
		output = append(output, statusJSONInterface{
			Name:      ifx.Name,
			Addresses: addresses,
		})
	}

	sort.Slice(output, func(i, j int) bool {
		return output[i].Name < output[j].Name
	})

	return output
}

func errorWrap(text string, lineWidth int) string {
	words := strings.Fields(strings.TrimSpace(text))
	if len(words) == 0 {
		return text
	}
	wrapped := words[0]
	spaceLeft := lineWidth - len(wrapped)
	indent := len(" error: ")
	for _, word := range words[1:] {
		if len(word)+1 > spaceLeft {
			wrapped += " \n" + strings.Repeat(" ", indent) + word
			spaceLeft = lineWidth - len(word)
		} else {
			wrapped += " " + word
			spaceLeft -= 1 + len(word)
		}
	}

	return wrapped
}
