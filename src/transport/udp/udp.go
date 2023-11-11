// Package udp proxies UDP messages between a WireGuard peer and a destination accessible
// by the machine where Wiretap is running.
package udp

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	reuse "github.com/libp2p/go-reuseport"
	neticmp "golang.org/x/net/icmp"
	netipv4 "golang.org/x/net/ipv4"
	netipv6 "golang.org/x/net/ipv6"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"wiretap/transport"
)

// udpConn holds socket addresses for source and destination.
type udpConn struct {
	Source netip.AddrPort
	Dest   netip.AddrPort
}

type dialerCount struct {
	Count int
	Port  int
}

// source address -> new bind port
var sourceMap = make(map[netip.AddrPort]dialerCount)
var sourceMapLock = sync.RWMutex{}

// source and destination -> dialer
var connMap = make(map[udpConn](chan stack.PacketBufferPtr))
var connMapLock = sync.RWMutex{}

type Config struct {
	Tnet      *netstack.Net
	StackLock *sync.Mutex
}

// Handler handles UDP packets. Returns function that returns true if packet is handled, or false if ICMP Destination Unreachable should be sent.
// TODO: Clean this up. Can't use UDPForwarder because it doesn't offer a way to return false, which is required to send Unreachables.
func Handler(c Config) func(stack.TransportEndpointID, stack.PacketBufferPtr) bool {
	return func(teid stack.TransportEndpointID, pkb stack.PacketBufferPtr) bool {
		log.Printf("(client %s) - Transport: UDP -> %s", net.JoinHostPort(teid.RemoteAddress.String(), fmt.Sprint(teid.RemotePort)), net.JoinHostPort(teid.LocalAddress.String(), fmt.Sprint(teid.LocalPort)))

		packetClone := pkb.Clone()
		go func() {
			newPacket(packetClone, c.Tnet.Stack())
			packetClone.DecRef()
		}()

		return true
	}
}

func sourceMapLookup(n netip.AddrPort) (dialerCount, bool) {
	sourceMapLock.RLock()
	dc, ok := sourceMap[n]
	sourceMapLock.RUnlock()

	return dc, ok
}

func sourceMapIncrement(n netip.AddrPort, port int) {
	sourceMapLock.Lock()
	dc, ok := sourceMap[n]
	if ok {
		dc.Count += 1
		sourceMap[n] = dc
	} else {
		sourceMap[n] = dialerCount{Count: 1, Port: port}
	}
	sourceMapLock.Unlock()
}

func sourceMapDecrement(n netip.AddrPort) {
	sourceMapLock.Lock()
	dc, ok := sourceMap[n]
	if ok {
		dc.Count -= 1
		if dc.Count <= 0 {
			delete(sourceMap, n)
		} else {
			sourceMap[n] = dc
		}
	}
	sourceMapLock.Unlock()
}

func connMapWrite(c udpConn, pktChan chan stack.PacketBufferPtr) {
	connMapLock.Lock()
	connMap[c] = pktChan
	connMapLock.Unlock()
}

func connMapDelete(c udpConn) {
	connMapLock.Lock()
	delete(connMap, c)
	connMapLock.Unlock()
}

func connMapLookup(c udpConn) (chan stack.PacketBufferPtr, bool) {
	connMapLock.RLock()
	pktChan, ok := connMap[c]
	connMapLock.RUnlock()

	return pktChan, ok
}

func getDataFromPacket(packet stack.PacketBufferPtr) []byte {
	netHeader := packet.Network()
	transHeader := header.UDP(netHeader.Payload())
	return transHeader.Payload()
}

// NewPacket handles every new packet and sending it to the proper UDP dialer.
func newPacket(packet stack.PacketBufferPtr, s *stack.Stack) {
	netHeader := packet.Network()
	transHeader := header.UDP(netHeader.Payload())

	source := netip.MustParseAddrPort(net.JoinHostPort(netHeader.SourceAddress().String(), fmt.Sprint(transHeader.SourcePort())))
	dest := netip.MustParseAddrPort(net.JoinHostPort(netHeader.DestinationAddress().String(), fmt.Sprint(transHeader.DestinationPort())))

	var pktChan chan stack.PacketBufferPtr
	var ok bool

	conn := udpConn{Source: source, Dest: dest}
	pktChan, ok = connMapLookup(conn)
	if ok {
		// Dialer already exists, just forward packet.
		pktChan <- packet.Clone()
		return
	}

	// Dialer doesn't exist, check if source address has been seen before.
	dc, ok := sourceMapLookup(source)
	port := dc.Port
	if !ok {
		// Source address never seen, choose new ephemeral port.
		port = 0
	}

	// New packet channel and dialer need to be created.
	pktChan = make(chan stack.PacketBufferPtr, 1)
	connMapWrite(conn, pktChan)

	go handleConn(conn, port, s)

	pktChan <- packet.Clone()
}

// handleConn proxies traffic between a source and destination.
func handleConn(conn udpConn, port int, s *stack.Stack) {
	defer func() {
		connMapDelete(conn)
	}()

	var mostRecentPacket stack.PacketBufferPtr

	// New dialer from source to destination.
	laddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Println("failed to parse laddr", err)
		return
	}
	raddr, err := net.ResolveUDPAddr("udp", conn.Dest.String())
	if err != nil {
		log.Println("failed to parse raddr", err)
		return
	}

	// Reusing port so we can get the ICMP unreachable message back.
	// Would like to use ListenUDP, but we don't get ICMP unreachable.
	newConn, err := reuse.Dial("udp", laddr.String(), raddr.String())
	if err != nil {
		log.Println("failed new UDP bind", err)
		return
	}
	defer newConn.Close()

	// No other dialer with same source address has a port set, so we get to be the first!
	tmp_addr, _ := net.ResolveUDPAddr("udp", newConn.LocalAddr().String())
	sourceMapIncrement(conn.Source, tmp_addr.Port)

	defer func() {
		sourceMapDecrement(conn.Source)
	}()

	err = newConn.SetDeadline(time.Now().Add(30 * time.Second))
	if err != nil {
		log.Println("failed to set deadline", err)
	}

	// Sends packet from peer to destination.
	go func() {
		for {
			pktChan, _ := connMapLookup(conn)
			pkt := <-pktChan
			// Exit if packet is empty, other goroutine wants us to close.
			if pkt == nil {
				return
			}

			// Update most recent packet for unreachable.
			mostRecentPacket = pkt.Clone()
			data := getDataFromPacket(pkt)

			_, err := newConn.Write(data)
			pkt.DecRef()
			if err != nil {
				log.Println("error sending packet:", err)
				newConn.Close()
				return
			}

			// Reset timer, we got a packet.
			err = newConn.SetDeadline(time.Now().Add(30 * time.Second))
			if err != nil {
				log.Println("failed to set deadline:", err)
			}
		}
	}()

	// Return packet from destination to peer.
	newBuf := make([]byte, 4096)
	for {
		n, err := newConn.Read(newBuf)
		if err != nil {
			// Failed to read from conn, if connection refused send unreachable to peer.
			if oerr, ok := err.(*net.OpError); ok {
				if syserr, ok := oerr.Err.(*os.SyscallError); ok {
					if syserr.Err == syscall.ECONNREFUSED {
						go sendUnreachable(mostRecentPacket, s)
					}
				}
			}

			// Force closing of goroutine by injecting nil pointer
			newConn.Close()
			pktChan, ok := connMapLookup(conn)
			if ok {
				pktChan <- nil
			}
			return
		}

		// Reset timer, we got a packet.
		err = newConn.SetDeadline(time.Now().Add(30 * time.Second))
		if err != nil {
			log.Println("failed to set deadline:", err)
		}

		// Write packet back to peer.
		sendResponse(conn, newBuf[:n], s)
	}
}

// sendResponse builds a UDP packet to return to the peer.
// TCP doesn't need this because the NATing works fine, but with UDP the OriginalDst function fails.
func sendResponse(conn udpConn, data []byte, s *stack.Stack) {
	var err error
	var ipv4Layer *layers.IPv4
	var ipv6Layer *layers.IPv6

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(conn.Dest.Port()),
		DstPort: layers.UDPPort(conn.Source.Port()),
	}

	isIpv6 := conn.Dest.Addr().Is6()
	if isIpv6 {
		ipv6Layer = &layers.IPv6{
			Version:    6,
			SrcIP:      conn.Dest.Addr().AsSlice(),
			DstIP:      conn.Source.Addr().AsSlice(),
			NextHeader: layers.IPProtocolUDP,
			HopLimit:   64,
		}
		err = udpLayer.SetNetworkLayerForChecksum(ipv6Layer)
	} else {
		ipv4Layer = &layers.IPv4{
			Version: 4,
			//IHL: 5,
			SrcIP:    conn.Dest.Addr().AsSlice(),
			DstIP:    conn.Source.Addr().AsSlice(),
			Protocol: layers.IPProtocolUDP,
			TTL:      64,
		}
		err = udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	}
	if err != nil {
		log.Println("failed to marshal response:", err)
		return
	}

	buf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	proto := ipv4.ProtocolNumber
	if isIpv6 {
		proto = ipv6.ProtocolNumber
		err = gopacket.SerializeLayers(buf, options,
			ipv6Layer,
			udpLayer,
			gopacket.Payload(data),
		)
	} else {
		err = gopacket.SerializeLayers(buf, options,
			ipv4Layer,
			udpLayer,
			gopacket.Payload(data),
		)
	}

	if err != nil {
		log.Println("failed to serialize layers:", err)
		return
	}

	tcpipErr := transport.SendPacket(s, buf.Bytes(), &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(conn.Source.Addr().AsSlice())}, proto)
	if tcpipErr != nil {
		log.Println("failed to write:", tcpipErr)
		return
	}
}

// sendUnreachable sends an ICMP Port Unreachable packet to peer as if from
// the original destination of the packet.
func sendUnreachable(packet stack.PacketBufferPtr, s *stack.Stack) {
	var err error
	var ipv4Layer *layers.IPv4
	var ipv6Layer *layers.IPv6
	var icmpLayer []byte

	defer packet.DecRef()
	netHeader := packet.Network()
	transHeader := header.UDP(netHeader.Payload())
	transHeader.SetChecksum(0)
	transHeaderPayload := transHeader.Payload()

	isIpv6 := netHeader.DestinationAddress().To4() == tcpip.Address{}

	if isIpv6 {
		ipv6Layer = &layers.IPv6{}
		ipv6Layer, err = transport.GetNetworkLayer[header.IPv6](netHeader, ipv6Layer)
		if err != nil {
			log.Println("could not decode Network header:", err)
			return
		}
		ipv6Layer = &layers.IPv6{
			Version:    6,
			SrcIP:      ipv6Layer.DstIP,
			DstIP:      ipv6Layer.SrcIP,
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   64,
		}
		ipv6Header, ok := netHeader.(header.IPv6)
		if !ok {
			log.Println("could not type assert IPv6 Network Header")
			return
		}
		icmpLayer, err = (&neticmp.Message{
			Type: netipv6.ICMPTypeDestinationUnreachable,
			Code: layers.ICMPv6CodePortUnreachable,
			Body: &neticmp.DstUnreach{
				Data: append(ipv6Header, transHeader[:len(transHeader)-len(transHeaderPayload)]...),
			},
		}).Marshal(nil)
		ipv6Layer.Length = uint16(len(icmpLayer))
	} else {
		ipv4Layer = &layers.IPv4{}
		ipv4Layer, err = transport.GetNetworkLayer[header.IPv4](netHeader, ipv4Layer)
		if err != nil {
			log.Println("could not decode Network header:", err)
			return
		}
		ipv4Layer = &layers.IPv4{
			Version:  4,
			IHL:      5,
			SrcIP:    ipv4Layer.DstIP,
			DstIP:    ipv4Layer.SrcIP,
			Protocol: layers.IPProtocolICMPv4,
			TTL:      64,
		}
		ipv4Header, ok := netHeader.(header.IPv4)
		if !ok {
			log.Println("could not type assert IPv6 Network Header")
			return
		}
		icmpLayer, err = (&neticmp.Message{
			Type: netipv4.ICMPTypeDestinationUnreachable,
			Code: layers.ICMPv4CodePort,
			Body: &neticmp.DstUnreach{
				Data: append(ipv4Header, transHeader[:len(transHeader)-len(transHeaderPayload)]...),
			},
		}).Marshal(nil)
		ipv4Layer.Length = uint16((int(ipv4Layer.IHL) * 4) + len(icmpLayer))
	}
	if err != nil {
		log.Println("failed to marshal response:", err)
		return
	}

	buf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}

	proto := ipv4.ProtocolNumber
	if isIpv6 {
		proto = ipv6.ProtocolNumber
		err = gopacket.SerializeLayers(buf, options,
			ipv6Layer,
		)
	} else {
		err = gopacket.SerializeLayers(buf, options,
			ipv4Layer,
		)
	}
	if err != nil {
		log.Println("failed to serialize layers:", err)
		return
	}

	response := append(buf.Bytes(), icmpLayer...)

	tcpipErr := transport.SendPacket(s, response, &tcpip.FullAddress{NIC: 1, Addr: netHeader.SourceAddress()}, proto)
	if tcpipErr != nil {
		log.Println("failed to write:", tcpipErr)
		return
	}
}
