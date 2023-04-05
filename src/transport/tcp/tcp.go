// Package tcp proxies TCP connections between a WireGuard peer and a destination
// accessible by the machine where Wiretap is running.
package tcp

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"

	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"wiretap/transport"
)

// tcpConn tracks a connection, source and destination IP and Port.
type tcpConn struct {
	Source string
	Dest   string
}

// connTrack holds the net.Conn to a final destination
// and the status of that connection.
type connTrack struct {
	Connecting bool
	Conn       net.Conn
}

// Keep track of connections so we don't duplicate work.
var isOpen = make(map[tcpConn]connTrack)
var isOpenLock = sync.RWMutex{}

// preroutingMatch matches packets in the prerouting stage.
type preroutingMatch struct {
	pktChan  chan stack.PacketBufferPtr
	endpoint *channel.Endpoint
}

// Match looks for SYN packets (start of a tcp conn). Before proxying connection, we need to check
// if intendend destination is up. Drop the packet to prevent blocking, but start goroutine that
// connects to destination. If destination is up, reinject packet and allow it through.
func (m preroutingMatch) Match(hook stack.Hook, packet stack.PacketBufferPtr, inputInterfaceName, outputInterfaceName string) (matches bool, hotdrop bool) {
	if hook == stack.Prerouting {
		// If SYN flag set, see if connection possible.
		netHeader := packet.Network()
		transHeader := header.TCP(netHeader.Payload())

		flags := transHeader.Flags()
		if flags.Contains(header.TCPFlagSyn) && !flags.Contains(header.TCPFlagAck) {
			dest := net.JoinHostPort(netHeader.DestinationAddress().String(), fmt.Sprint(transHeader.DestinationPort()))
			source := net.JoinHostPort(netHeader.SourceAddress().String(), fmt.Sprint(transHeader.SourcePort()))
			c := tcpConn{source, dest}

			isOpenLock.RLock()
			ctrack, ok := isOpen[c]
			isOpenLock.RUnlock()

			// If not in conn map, drop this packet for now, but clone so it can
			// be reinjected if connections are successful.
			if !ok {
				isOpenLock.Lock()
				// In progress, but not ready to forward SYN packets yet.
				isOpen[c] = connTrack{
					Connecting: true,
				}
				isOpenLock.Unlock()

				packetClone := packet.Clone()
				go func() {
					checkIfOpen(c, m.pktChan, packetClone, m.endpoint)
					packetClone.DecRef()
				}()

				// Hotdrop because we're taking control of the packet.
				return false, true
				// Already checking if port is open. Do nothing.
			} else if ctrack.Connecting {
				return false, false
				// Connection is verified to be open. Allow this connection and reset conn map.
			} else {
				return true, false
			}
		}
		// ACK here means ACK without prior connection, drop.
		if transHeader.Flags() == header.TCPFlagAck {
			return false, false
		}
	}

	return false, false
}

// If destination is open, whitelist and reinject. Otherwise send reset.
func checkIfOpen(conn tcpConn, pktChan chan stack.PacketBufferPtr, packet stack.PacketBufferPtr, endpoint *channel.Endpoint) {
	log.Printf("(client %v) - Transport: TCP -> %v", conn.Source, conn.Dest)
	c, err := net.Dial("tcp", conn.Dest)
	if err != nil {
		//log.Printf("Error connecting to %s: %s\n", conn.Dest, err)

		// If connection refused, we can send a reset to let peer know.
		if oerr, ok := err.(*net.OpError); ok {
			if syserr, ok := oerr.Err.(*os.SyscallError); ok {
				if syserr.Err == syscall.ECONNREFUSED {
					//log.Println("Connection refused, sending reset")
					pktChan <- packet.Clone()
				}
			}
		}

		// Error, reset connection progress.
		isOpenLock.Lock()
		delete(isOpen, conn)
		isOpenLock.Unlock()
		return
	}

	// No error, mark successful and reinject packet.
	isOpenLock.Lock()
	isOpen[conn] = connTrack{
		Connecting: false,
		Conn:       c,
	}
	isOpenLock.Unlock()

	isIpv6 := !netip.MustParseAddrPort(c.RemoteAddr().String()).Addr().Is4()
	netProto := ipv4.ProtocolNumber
	if isIpv6 {
		netProto = ipv6.ProtocolNumber
	}
	new_packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: packet.ToBuffer(),
	})
	endpoint.InjectInbound(netProto, new_packet)
}

// Handle creates a DNAT rule that forwards destination packets to a tcp listener.
// Once a connection is accepted, it gets handed off to handleConn().
func Handle(tnet *netstack.Net, ipv4Addr netip.Addr, ipv6Addr netip.Addr, port uint16, lock *sync.Mutex) {
	s := tnet.Stack()

	// Create iptables rule.
	// iptables -t nat -A PREROUTING -p tcp -j DNAT --to-destination 192.168.0.1:80
	headerFilter := stack.IPHeaderFilter{Protocol: tcp.ProtocolNumber,
		CheckProtocol: true,
	}

	match := preroutingMatch{
		pktChan:  make(chan stack.PacketBufferPtr, 1),
		endpoint: tnet.Endpoint(),
	}

	rule4 := stack.Rule{
		Filter:   headerFilter,
		Matchers: []stack.Matcher{match},
		Target: &stack.DNATTarget{
			Addr:            tcpip.Address(ipv4Addr.AsSlice()),
			Port:            port,
			NetworkProtocol: ipv4.ProtocolNumber,
		},
	}

	rule6 := stack.Rule{
		Filter:   headerFilter,
		Matchers: []stack.Matcher{match},
		Target: &stack.DNATTarget{
			Addr:            tcpip.Address(ipv6Addr.AsSlice()),
			Port:            port,
			NetworkProtocol: ipv6.ProtocolNumber,
		},
	}

	tid := stack.NATID
	transport.PushRule(s, rule4, tid, false)
	transport.PushRule(s, rule6, tid, true)
	lock.Unlock()

	// RST handler
	go func() {
		for {
			packetClone := <-match.pktChan
			go func() {
				sendRST(s, packetClone)
				packetClone.DecRef()
			}()
		}
	}()

	go startListener(tnet, s.IPTables(), &net.TCPAddr{Port: int(port)}, ipv4Addr, ipv6Addr)
}

// startListener accepts connections from WireGuard peer.
func startListener(tnet *netstack.Net, tables *stack.IPTables, listenAddr *net.TCPAddr, localAddr4 netip.Addr, localAddr6 netip.Addr) {
	l, err := tnet.ListenTCP(listenAddr)
	if err != nil {
		log.Panic(err)
	}

	defer l.Close()

	log.Println("Transport: TCP listener up")
	for {
		// Every TCP connection gets accepted here.
		c, err := l.Accept()
		if err != nil {
			log.Println("Failed to accept connection:", err)
			continue
		}

		// Remote Address isn't populated yet.
		// TODO: Figure out why and get rid of this silly busy loop.
		go func() {
			for {
				if c.RemoteAddr() != nil {
					break
				}
			}

			isIpv6 := !netip.MustParseAddrPort(c.RemoteAddr().String()).Addr().Is4()
			netProto := ipv4.ProtocolNumber
			localAddr := localAddr4
			if isIpv6 {
				netProto = ipv6.ProtocolNumber
				localAddr = localAddr6
			}

			handleConn(c, localAddr, netProto, tables)
		}()
	}

}

// handleConn finds the intended target of a peer's connection,
// connects to that target, then copies data between the two.
func handleConn(c net.Conn, ipAddr netip.Addr, netProto tcpip.NetworkProtocolNumber, tables *stack.IPTables) {
	var wg sync.WaitGroup
	defer c.Close()

	// Lookup original destination of this connection.
	remoteAddr := c.RemoteAddr()

	if remoteAddr == nil {
		log.Println("Could not read remote address of connection")
		return
	}
	addr, port, tcpipErr := tables.OriginalDst(stack.TransportEndpointID{
		LocalPort:    1337,
		LocalAddress: tcpip.Address(ipAddr.AsSlice()), RemotePort: netip.MustParseAddrPort(remoteAddr.String()).Port(),
		RemoteAddress: tcpip.Address(netip.MustParseAddrPort(remoteAddr.String()).Addr().AsSlice()),
	}, netProto, tcp.ProtocolNumber)
	if tcpipErr != nil {
		log.Println("Error reading original destination:", tcpipErr)
		return
	}

	dest := net.JoinHostPort(addr.String(), fmt.Sprint(port))
	source := remoteAddr.String()
	cString := tcpConn{source, dest}

	// Original destination should be dialed already for when we checked if it was open:
	isOpenLock.Lock()
	ctrack, ok := isOpen[cString]
	isOpenLock.Unlock()
	if !ok {
		log.Printf("Error looking up conn to destination: %v\n", net.JoinHostPort(addr.String(), fmt.Sprint(port)))
		return
	}

	// Delete original destination from map so it can be remade.
	newConn := ctrack.Conn
	isOpenLock.Lock()
	delete(isOpen, cString)
	isOpenLock.Unlock()

	// Copy from new connection to peer
	wg.Add(1)
	go func() {
		_, err := io.Copy(c, newConn)
		if err != nil {
			log.Printf("Error copying between connections: %v\n", err)
		}
		wg.Done()
		c.Close()
	}()

	// Copy from peer to new connection.
	_, err := io.Copy(newConn, c)
	if err != nil {
		log.Printf("Error copying between connections: %v\n", err)
	}
	newConn.Close()

	// Wait for both copies to finish.
	wg.Wait()
}

// sendICMPEchoResponse sends an echo response to the peer with a spoofed source address.
func sendRST(s *stack.Stack, packet stack.PacketBufferPtr) {
	var err error
	var ipv4Layer *layers.IPv4
	var ipv6Layer *layers.IPv6

	netHeader := packet.Network()
	transHeader := header.TCP(netHeader.Payload())

	isIpv6 := netHeader.DestinationAddress().To4() == ""

	if isIpv6 {
		ipv6Layer = &layers.IPv6{}
		ipv6Layer, err = transport.GetNetworkLayer[header.IPv6](netHeader, ipv6Layer)
		ipv6Layer.SrcIP, ipv6Layer.DstIP = ipv6Layer.DstIP, ipv6Layer.SrcIP
	} else {
		ipv4Layer = &layers.IPv4{}
		ipv4Layer, err = transport.GetNetworkLayer[header.IPv4](netHeader, ipv4Layer)
		ipv4Layer.SrcIP, ipv4Layer.DstIP = ipv4Layer.DstIP, ipv4Layer.SrcIP
	}

	if err != nil {
		log.Println("Could not decode Network header:", err)
		return
	}

	// Create transport layer and swap ports, fix flags.
	tcpLayer := &layers.TCP{}
	err = tcpLayer.DecodeFromBytes(transHeader, gopacket.NilDecodeFeedback)
	if err != nil {
		log.Println("Could not decode TCP header:", err)
		return
	}

	tcpLayer.SrcPort, tcpLayer.DstPort = tcpLayer.DstPort, tcpLayer.SrcPort
	tcpLayer.Ack = tcpLayer.Seq + 1
	tcpLayer.Seq = 0
	tcpLayer.DataOffset = 5
	tcpLayer.SYN = false
	tcpLayer.RST = true
	tcpLayer.ACK = true
	tcpLayer.Window = 0
	tcpLayer.Options = nil
	tcpLayer.Padding = nil

	if isIpv6 {
		err = tcpLayer.SetNetworkLayerForChecksum(ipv6Layer)
	} else {
		err = tcpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	}

	if err != nil {
		log.Println("Could not set layer for checksum:", err)
		return
	}

	buf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if isIpv6 {
		err = gopacket.SerializeLayers(buf, options,
			ipv6Layer,
			tcpLayer,
		)
	} else {
		err = gopacket.SerializeLayers(buf, options,
			ipv4Layer,
			tcpLayer,
		)
	}
	if err != nil {
		log.Println("Failed to serialize layers:", err)
		return
	}

	response := buf.Bytes()

	// Create network layer endpoint for spoofing source address.
	proto := ipv4.ProtocolNumber
	if isIpv6 {
		proto = ipv6.ProtocolNumber
	}

	tcpipErr := transport.SendPacket(s, response, &tcpip.FullAddress{NIC: 1, Addr: netHeader.SourceAddress()}, proto)
	if tcpipErr != nil {
		log.Println("Failed to send reset:", tcpipErr)
		return
	}
}
