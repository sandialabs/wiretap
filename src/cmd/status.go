package cmd

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/fatih/color"
	"github.com/m1gwings/treedrawer/tree"
	"github.com/spf13/cobra"

	"wiretap/api"
	"wiretap/peer"
)

type statusCmdConfig struct {
	configFileRelay string
	configFileE2EE  string
}

// Defaults for status command.
// See root command for shared defaults.
var statusCmd = statusCmdConfig{
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

	cmd.Flags().StringVarP(&statusCmd.configFileRelay, "relay", "1", statusCmd.configFileRelay, "wireguard relay config input filename")
	cmd.Flags().StringVarP(&statusCmd.configFileE2EE, "e2ee", "2", statusCmd.configFileE2EE, "wireguard E2EE config input filename")

	cmd.Flags().SortFlags = false
}

// Run attempts to parse config files into a network diagram.
func (c statusCmdConfig) Run() {
	// Start building tree.
	type Node struct {
		peerConfig  peer.PeerConfig
		relayConfig peer.Config
		e2eeConfig  peer.Config
		children    []*Node
		error       string
	}

	var err error

	// Parse the relay and e2ee config files
	clientConfigRelay, err := peer.ParseConfig(c.configFileRelay)
	check("failed to parse relay config file", err)
	clientConfigE2EE, err := peer.ParseConfig(c.configFileE2EE)
	check("failed to parse e2ee config file", err)

	client := Node{
		relayConfig: clientConfigRelay,
		e2eeConfig:  clientConfigE2EE,
	}

	t := tree.NewTree(tree.NodeString(" Wiretap Network Status "))

	// Get list of all nodes, then use list to build tree.
	// Get map of all nodes for building tree.
	// Key on public key of relay interfaces.
	nodes := make(map[string]Node)
	var errorNodes []Node
	e2ee_peer_list := client.e2eeConfig.GetPeers()
	for _, ep := range e2ee_peer_list {
		relayConfig, e2eeConfig, err := api.ServerInfo(netip.AddrPortFrom(ep.GetApiAddr(), uint16(ApiPort)))
		if err != nil {
			errorNodes = append(errorNodes, Node{
				peerConfig:  ep,
				error:       err.Error(),
			})
			
		} else {
			nodes[relayConfig.GetPublicKey()] = Node{
				peerConfig:  ep,
				relayConfig: relayConfig,
				e2eeConfig:  e2eeConfig,
			}
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
				if j == len(c.peerConfig.GetAllowedIPs()) - 1 {
					api = a.IP.String()
				} else {
					ips = append(ips, a.String())
				}
			}
			t.AddChild(tree.NodeString(fmt.Sprintf(`server
  relay: %v... 
   e2ee: %v... 
   
    api: %v 
 routes: %v `, c.relayConfig.GetPublicKey()[:8], c.e2eeConfig.GetPublicKey()[:8], api, strings.Join(ips, ","))))
			child, err := t.Child(0)
			check("could not build tree", err)
			treeTraversal(node.children[i], child)
		}
	}
	child, err := t.Child(0)
	check("could not build tree", err)
	treeTraversal(&client, child)

	fmt.Println()
	fmt.Fprintln(color.Output, WhiteBold(t))
	fmt.Println()
	
	if len(errorNodes) > 0 {
		// Display known peers that we had issues connecting to
		fmt.Fprintln(color.Output, WhiteBold("Peers with Errors:"))
		fmt.Println()
		
		for _, node := range errorNodes {
			ips := []string{}
			var api string
			for j, a := range node.peerConfig.GetAllowedIPs() {
				if j == len(node.peerConfig.GetAllowedIPs()) - 1 {
					api = a.IP.String()
				} else {
					ips = append(ips, a.String())
				}
			}
			
			t = tree.NewTree(tree.NodeString(fmt.Sprintf(`server

     e2ee: %v... 
      api: %v 
   routes: %v 

 error: %v`, node.peerConfig.GetPublicKey().String()[:8], api, strings.Join(ips, ","), error_wrap(node.error, 80))))
			fmt.Fprintln(color.Output, WhiteBold(t))
		}
	}
}

func error_wrap(text string, lineWidth int) string {
	words := strings.Fields(strings.TrimSpace(text))
	if len(words) == 0 {
		return text
	}
	wrapped := words[0]
	spaceLeft := lineWidth - len(wrapped)
	for _, word := range words[1:] {
		if len(word)+1 > spaceLeft {
			wrapped += " \n        " + word
			spaceLeft = lineWidth - len(word)
		} else {
			wrapped += " " + word
			spaceLeft -= 1 + len(word)
		}
	}

	return wrapped
}
