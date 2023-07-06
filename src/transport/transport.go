// Package transport provides utility functions needed by all transport methods.
package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"

	"github.com/google/gopacket"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// IPHeader is a type interface used by GetNetworkLayer.
type IPHeader interface {
	header.IPv4 | header.IPv6
}

// IPLayer must have DecodeFromBytes function.
type IPLayer interface {
	DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error
}

type ConnCounts struct {
	counts map[netip.Addr]int
	lock   sync.Mutex
}

var connCounts ConnCounts

func init() {
	connCounts.counts = make(map[netip.Addr]int)
}

func GetConnCounts() *ConnCounts {
	return &connCounts
}

func (c *ConnCounts) AddAddress(addr netip.Addr, s *stack.Stack, stackLock *sync.Mutex) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.counts[addr]++

	if c.counts[addr] > 1 {
		return nil
	}

	var protoNumber tcpip.NetworkProtocolNumber
	if addr.Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else if addr.Is6() {
		protoNumber = ipv6.ProtocolNumber
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          protoNumber,
		AddressWithPrefix: tcpip.Address(addr.AsSlice()).WithPrefix(),
	}

	stackLock.Lock()
	err := s.AddProtocolAddress(1, protoAddr, stack.AddressProperties{})
	stackLock.Unlock()
	if err != nil {
		return errors.New(err.String())
	}
	return nil
}

// GetNetworkLayer parses a network header, then converts it to bytes.
func GetNetworkLayer[H IPHeader, L IPLayer](netHeader header.Network, ipLayer L) (L, error) {
	h, ok := netHeader.(H)
	if !ok {
		return ipLayer, errors.New("could not assert network header as provided type")
	}
	err := ipLayer.DecodeFromBytes(h, gopacket.NilDecodeFeedback)
	if err != nil {
		return ipLayer, err
	}

	return ipLayer, nil
}

// RemoveAddress removes an address from the stack once it is no longer needed.
func (c *ConnCounts) RemoveAddress(addr netip.Addr, s *stack.Stack, stackLock *sync.Mutex) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.counts[addr]--

	if c.counts[addr] > 0 {
		return nil
	}

	delete(c.counts, addr)

	stackLock.Lock()
	err := s.RemoveAddress(1, tcpip.Address(addr.AsSlice()))
	stackLock.Unlock()

	if err != nil {
		return errors.New(err.String())
	}
	return nil
}

// SendPacket sends a network-layer packet.
func SendPacket(s *stack.Stack, packet []byte, addr *tcpip.FullAddress, netProto tcpip.NetworkProtocolNumber) tcpip.Error {
	// Create network layer endpoint for spoofing source address.
	var wq waiter.Queue

	ep, tcpipErr := s.NewPacketEndpoint(true, netProto, &wq)
	if tcpipErr != nil {
		return tcpipErr
	}
	defer ep.Close()

	// Send packet.
	buf := bytes.NewReader(packet)
	_, tcpipErr = ep.Write(buf, tcpip.WriteOptions{
		To: addr,
	})
	if tcpipErr != nil {
		return tcpipErr
	}

	return nil
}

func Proxy(src net.Conn, dst net.Conn) {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		_, err := io.Copy(src, dst)
		if err != nil {
			log.Printf("error copying between connections: %v\n", err)
		}
		src.Close()
		wg.Done()
	}()

	// Copy from peer to new connection.
	_, nerr := io.Copy(dst, src)
	if nerr != nil {
		log.Printf("error copying between connections: %v\n", nerr)
	}
	dst.Close()

	// Wait for both copies to finish.
	wg.Wait()
}

// ForwardTcpPort proxies TCP connections by accepting connections and proxying them back to the client.
func ForwardTcpPort(s *stack.Stack, l net.Listener, localAddr tcpip.FullAddress, remoteAddr tcpip.FullAddress, np tcpip.NetworkProtocolNumber) {
	ctx, cancel := context.WithCancel(context.Background())
	for {
		conn, err := l.Accept()
		if err != nil {
			cancel()
			return
		}

		// Proxy between conns.
		go func() {
			var nc net.Conn
			nc, err = gonet.DialTCPWithBind(
				ctx,
				s,
				localAddr,
				remoteAddr,
				np,
			)
			if err != nil {
				log.Println("failed to proxy conn:", err)
				conn.Close()
				return
			}

			Proxy(conn, nc)
		}()
	}
}

// ForwardUdpPort proxies UDP datagrams by forwarding datagrams to a peer, and then returns responses to the last remote address to talk to this endpoint.
// No connection tracking is in place at this time.
func ForwardUdpPort(s *stack.Stack, conn *net.UDPConn, localAddr tcpip.FullAddress, remoteAddr tcpip.FullAddress, np tcpip.NetworkProtocolNumber) {
	var wg sync.WaitGroup
	var clientAddr *netip.AddrPort
	var lock sync.Mutex

	const bufSize = 65535

	// Connect to forwarded port.
	nc, err := gonet.DialUDP(
		s,
		&localAddr,
		&remoteAddr,
		np,
	)
	if err != nil {
		log.Println("failed to proxy conn:", err)
		conn.Close()
		return
	}

	// Accept packets and forward to peer.
	wg.Add(1)
	go func() {
		buf := make([]byte, bufSize)
		for {
			n, addr, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				nc.Close()
				log.Println("conn closed:", err)
				break
			}
			lock.Lock()
			clientAddr = &addr
			lock.Unlock()
			_, err = nc.Write(buf[:n])
			if err != nil {
				log.Println("failed to send:", err)
				continue
			}
		}
		wg.Done()
	}()

	for {
		buf := make([]byte, bufSize)
		n, err := nc.Read(buf)
		if err != nil {
			log.Println("conn closed:", err)
			conn.Close()
			break
		}
		lock.Lock()
		if clientAddr == nil {
			lock.Unlock()
			continue
		}
		addr := *clientAddr
		lock.Unlock()
		_, err = conn.WriteToUDPAddrPort(buf[:n], addr)
		if err != nil {
			log.Println("failed to send:", err)
			continue
		}
	}

	wg.Wait()
}
