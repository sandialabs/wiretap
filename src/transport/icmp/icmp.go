// Package icmp handles ICMPv4 and ICMPv6 messages.
package icmp

import (
	"bytes"
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
	"gvisor.dev/gvisor/pkg/waiter"

	"wiretap/transport"
)

var pinger Ping = nil

func Handle(tnet *netstack.Net, lock *sync.Mutex) {
	handler := func(t tcpip.TransportProtocolNumber, n tcpip.NetworkProtocolNumber) {
		var wq waiter.Queue
		lock.Lock()
		ep, err := tnet.Stack().NewRawEndpoint(t, n, &wq, true)
		lock.Unlock()
		if err != nil {
			log.Panic("icmp handler error:", err)
		}

		// Need this to get destination address.
		ep.SocketOptions().SetIPv6ReceivePacketInfo(true)

		waitEntry, notifyChan := waiter.NewChannelEntry(waiter.ReadableEvents)
		wq.EventRegister(&waitEntry)
		defer wq.EventUnregister(&waitEntry)

		for {
			var buf bytes.Buffer
			res, err := ep.Read(&buf, tcpip.ReadOptions{NeedRemoteAddr: true})
			if err != nil {
				if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
					log.Panic("icmp handler error:", err)
				}
			} else {
				var netHeader header.Network
				if n == ipv4.ProtocolNumber {
					netHeader = header.IPv4(buf.Bytes())
				} else {
					// TODO: Come up with a better way to do this than manually building ipv6 header.
					version := 6     //IPv6
					nextHeader := 58 // ICMPv6
					payloadLength := len(buf.Bytes())
					hopLimit := 64 // TTL
					src := netip.MustParseAddr(res.RemoteAddr.Addr.String()).AsSlice()
					dst := netip.MustParseAddr(res.ControlMessages.IPv6PacketInfo.Addr.String()).AsSlice()

					ipv6Header := []byte{
						uint8(version << 4), // Version / Traffic Class
						0, 0, 0,             // Traffic Class / Flow Label
						uint8((payloadLength >> 8) & 0xFF), // Payload Length MSN
						uint8(payloadLength & 0xFF),        // Payload Length LSN
						uint8(nextHeader),
						uint8(hopLimit),
					}

					ipv6Header = append(ipv6Header, src...)
					ipv6Header = append(ipv6Header, dst...)
					packet := append(ipv6Header, buf.Bytes()...)
					netHeader = header.IPv6(packet)
				}

				go func() {
					handleMessage(tnet.Stack(), netHeader)
				}()

				continue
			}

			<-notifyChan
		}

	}

	// Start handler for ipv4 and ipv6.
	go handler(icmp.ProtocolNumber4, ipv4.ProtocolNumber)
	handler(icmp.ProtocolNumber6, ipv6.ProtocolNumber)
}

// handleICMPMessage parses ICMP packets and proxies them if possible.
func handleMessage(s *stack.Stack, pkt header.Network) {
	// Parse ICMP packet type.
	log.Printf("(client %v) - Transport: ICMP -> %v", pkt.SourceAddress(), pkt.DestinationAddress())

	isIpv6 := !netip.MustParseAddr(pkt.SourceAddress().String()).Is4()
	if isIpv6 {
		transHeader := header.ICMPv6(pkt.Payload())
		switch transHeader.Type() {
		case header.ICMPv6EchoRequest:
			handleEcho(s, pkt)
		default:
			log.Println("ICMPv6 type not implemented:", transHeader.Type())
		}
	} else {
		transHeader := header.ICMPv4(pkt.Payload())
		switch transHeader.Type() {
		case header.ICMPv4Echo:
			handleEcho(s, pkt)
		default:
			log.Println("ICMPv4 type not implemented:", transHeader.Type())
		}
	}

}

// handleICMPEcho tries to send ICMP echo requests to the true destination however it can.
// If successful, it sends an echo response to the peer.
func handleEcho(s *stack.Stack, pkt header.Network) {
	var success bool
	var err error

	// Parse network header for destination address.
	dest := pkt.DestinationAddress().String()

	if pinger == nil {
		pinger, success, err = getPing(dest)
	} else {
		success, err = pinger.ping(dest)
	}

	if err == nil {
		if success {
			sendEchoResponse(s, pkt)
		}

		return
	}

	log.Printf("ping failed: %v", err)
}

// sendICMPEchoResponse sends an echo response to the peer with a spoofed source address.
func sendEchoResponse(s *stack.Stack, pkt header.Network) {
	var response []byte
	var ipHeader []byte
	var err error

	isIpv6 := pkt.DestinationAddress().To4() == tcpip.Address{}

	netProto := ipv4.ProtocolNumber
	if isIpv6 {
		netProto = ipv6.ProtocolNumber
		transHeader := header.ICMPv6(pkt.Payload())
		// Create ICMP response and marshal it.
		response, err = (&neticmp.Message{
			Type: netipv6.ICMPTypeEchoReply,
			Code: 0,
			Body: &neticmp.Echo{
				ID:   int(transHeader.Ident()),
				Seq:  int(transHeader.Sequence()),
				Data: transHeader.Payload(),
			},
		}).Marshal(neticmp.IPv6PseudoHeader(net.ParseIP(pkt.DestinationAddress().String()), net.ParseIP(pkt.SourceAddress().String())))
		if err != nil {
			log.Println("failed to marshal response:", err)
			return
		}

		// Assert type to get network header bytes.
		ipv6Header, ok := pkt.(header.IPv6)
		if !ok {
			log.Println("could not assert network header as IPv6 header")
			return
		}
		// Swap source and destination addresses from original request.
		tmp := ipv6Header.DestinationAddress()
		ipv6Header.SetDestinationAddress(ipv6Header.SourceAddress())
		ipv6Header.SetSourceAddress(tmp)
		ipHeader = ipv6Header[:40]
	} else {
		transHeader := header.ICMPv4(pkt.Payload())
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
			log.Println("failed to marshal response:", err)
			return
		}

		// Assert type to get network header bytes.
		ipv4Header, ok := pkt.(header.IPv4)
		if !ok {
			log.Println("could not assert network header as IPv4 header")
			return
		}
		// Swap source and destination addresses from original request.
		tmp := ipv4Header.DestinationAddress()
		ipv4Header.SetDestinationAddress(ipv4Header.SourceAddress())
		ipv4Header.SetSourceAddress(tmp)
		ipHeader = ipv4Header[:ipv4Header.HeaderLength()]
	}

	tcpipErr := transport.SendPacket(s, append(ipHeader, response...), &tcpip.FullAddress{NIC: 1, Addr: pkt.SourceAddress()}, netProto)
	if tcpipErr != nil {
		log.Println("failed to write:", tcpipErr)
		return
	}
}
