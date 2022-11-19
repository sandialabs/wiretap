// Package icmp handles ICMPv4 and ICMPv6 messages.
package icmp

import (
	"log"
	"net"
	"net/netip"
	"sync"

	neticmp "golang.org/x/net/icmp"
	netipv4 "golang.org/x/net/ipv4"
	netipv6 "golang.org/x/net/ipv6"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"

	"wiretap/transport"
)

// preroutingMatch matches packets in the prerouting stage and clones:
// packet into channel for processing.
type preroutingMatch struct {
	pktChan chan *stack.PacketBuffer
}

var pinger Ping = nil

// When a new ICMP message hits the prerouting stage, the packet is cloned
// to the ICMP handler and dropped here.
func (m preroutingMatch) Match(hook stack.Hook, packet *stack.PacketBuffer, inputInterfaceName, outputInterfaceName string) (matches bool, hotdrop bool) {
	if hook == stack.Prerouting {
		m.pktChan <- packet.Clone()
		return false, true
	}

	return false, false
}

// handleICMP proxies ICMP messages using whatever means it can with the permissions this binary
// has on the system.
func Handle(tnet *netstack.Net, lock *sync.Mutex) {
	s := tnet.Stack()

	// create iptables rule that drops icmp, but clones packet and sends it to this handler.
	headerFilter4 := stack.IPHeaderFilter{
		Protocol:      icmp.ProtocolNumber4,
		CheckProtocol: true,
	}

	headerFilter6 := stack.IPHeaderFilter{
		Protocol:      icmp.ProtocolNumber6,
		CheckProtocol: true,
	}

	match := preroutingMatch{
		pktChan: make(chan *stack.PacketBuffer),
	}

	rule4 := stack.Rule{
		Filter:   headerFilter4,
		Matchers: []stack.Matcher{match},
		Target: &stack.DropTarget{
			NetworkProtocol: ipv4.ProtocolNumber,
		},
	}

	rule6 := stack.Rule{
		Filter:   headerFilter6,
		Matchers: []stack.Matcher{match},
		Target: &stack.DropTarget{
			NetworkProtocol: ipv6.ProtocolNumber,
		},
	}

	tid := stack.NATID
	transport.PushRule(s, rule4, tid, false)
	transport.PushRule(s, rule6, tid, true)
	lock.Unlock()

	log.Println("Transport: ICMP listener up")
	for {
		clonedPacket := <-match.pktChan
		go func() {
			handleMessage(s, clonedPacket)
			clonedPacket.DecRef()
		}()
	}
}

// handleICMPMessage parses ICMP packets and proxies them if possible.
func handleMessage(s *stack.Stack, packet *stack.PacketBuffer) {
	// Parse ICMP packet type.
	netHeader := packet.Network()
	log.Printf("(client %v) - Transport: ICMP -> %v", netHeader.SourceAddress(), netHeader.DestinationAddress())

	isIpv6 := !netip.MustParseAddr(netHeader.SourceAddress().String()).Is4()
	if isIpv6 {
		transHeader := header.ICMPv6(netHeader.Payload())
		switch transHeader.Type() {
		case header.ICMPv6EchoRequest:
			handleEcho(s, packet)
		default:
			log.Println("ICMPv6 type not implemented:", transHeader.Type())
		}
	} else {
		transHeader := header.ICMPv4(netHeader.Payload())
		switch transHeader.Type() {
		case header.ICMPv4Echo:
			handleEcho(s, packet)
		default:
			log.Println("ICMPv4 type not implemented:", transHeader.Type())
		}
	}

}

// handleICMPEcho tries to send ICMP echo requests to the true destination however it can.
// If successful, it sends an echo response to the peer.
func handleEcho(s *stack.Stack, packet *stack.PacketBuffer) {
	var success bool
	var err error

	// Parse network header for destination address.
	dest := packet.Network().DestinationAddress().String()

	if pinger == nil {
		pinger, success, err = getPing(dest)
	} else {
		success, err = pinger.ping(dest)
	}

	if err == nil {
		if success {
			sendEchoResponse(s, packet)
		}

		return
	}

	log.Printf("ping failed: %v", err)
}

// sendICMPEchoResponse sends an echo response to the peer with a spoofed source address.
func sendEchoResponse(s *stack.Stack, packet *stack.PacketBuffer) {
	var response []byte
	var ipHeader []byte
	var err error

	netHeader := packet.Network()

	isIpv6 := netHeader.DestinationAddress().To4() == ""

	netProto := ipv4.ProtocolNumber
	if isIpv6 {
		netProto = ipv6.ProtocolNumber
		transHeader := header.ICMPv6(netHeader.Payload())
		// Create ICMP response and marshal it.
		response, err = (&neticmp.Message{
			Type: netipv6.ICMPTypeEchoReply,
			Code: 0,
			Body: &neticmp.Echo{
				ID:   int(transHeader.Ident()),
				Seq:  int(transHeader.Sequence()),
				Data: transHeader.Payload(),
			},
		}).Marshal(neticmp.IPv6PseudoHeader(net.ParseIP(netHeader.DestinationAddress().String()), net.ParseIP(netHeader.SourceAddress().String())))
		if err != nil {
			log.Println("Failed to marshal response:", err)
			return
		}

		// Assert type to get network header bytes.
		ipv6Header, ok := netHeader.(header.IPv6)
		if !ok {
			log.Println("Could not assert network header as IPv6 header")
			return
		}
		// Swap source and destination addresses from original request.
		tmp := ipv6Header.DestinationAddress()
		ipv6Header.SetDestinationAddress(ipv6Header.SourceAddress())
		ipv6Header.SetSourceAddress(tmp)
		ipHeader = ipv6Header
	} else {
		transHeader := header.ICMPv4(netHeader.Payload())
		// Create ICMP response and marshal it.
		response, err = (&neticmp.Message{
			Type: netipv4.ICMPTypeEchoReply,
			Code: 0,
			Body: &neticmp.Echo{
				ID:   int(transHeader.Ident()),
				Seq:  int(transHeader.Sequence()),
				Data: transHeader.Payload(),
			},
		}).Marshal(nil)
		if err != nil {
			log.Println("Failed to marshal response:", err)
			return
		}

		// Assert type to get network header bytes.
		ipv4Header, ok := netHeader.(header.IPv4)
		if !ok {
			log.Println("Could not assert network header as IPv4 header")
			return
		}
		// Swap source and destination addresses from original request.
		tmp := ipv4Header.DestinationAddress()
		ipv4Header.SetDestinationAddress(ipv4Header.SourceAddress())
		ipv4Header.SetSourceAddress(tmp)
		ipHeader = ipv4Header
	}

	tcpipErr := transport.SendPacket(s, append(ipHeader, response...), &tcpip.FullAddress{NIC: 1, Addr: netHeader.SourceAddress()}, netProto)
	if tcpipErr != nil {
		log.Println("Failed to write:", tcpipErr)
		return
	}
}
