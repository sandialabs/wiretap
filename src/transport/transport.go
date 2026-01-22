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
	"strconv"
	"sync"
	"time"

	"github.com/armon/go-socks5"
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
const UDP_TIMEOUT = 60 * time.Second

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
		AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
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
	err := s.RemoveAddress(1, tcpip.AddrFromSlice(addr.AsSlice()))
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
	defer src.Close()
	defer dst.Close()
	var wg sync.WaitGroup

	//log.Printf("Proxying between %v <-> %v and %v <-> %v\n", src.LocalAddr(), src.RemoteAddr(), dst.LocalAddr(), dst.RemoteAddr())

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(src, dst)
		if err != nil {
			log.Printf("error copying between connections: %v\n", err)
		}
	}()

	// Copy from peer to new connection.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, nerr := io.Copy(dst, src)
		if nerr != nil {
			log.Printf("error copying between connections: %v\n", nerr)
		}
	}()

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

		log.Printf("(client [%v]:%v) <- Expose: TCP <- %v", remoteAddr.Addr, remoteAddr.Port, conn.RemoteAddr().String())

		// Proxy between conns.
		go func() {
			var nc net.Conn
			// since the localAddr has a port value of 0 it should auto-select a random available source port
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
// DEPRECATED. Use ForwardUdpPortWithTracking instead.
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
			log.Println("UDP client addr null, cannot forward response")
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

// ForwardUdpPortWithTracking proxies UDP datagrams by forwarding datagrams to and from a peer. All connections are tracked so that the client responses can be sent to the correct sender
//
// "conn" is the listening socket on the "real" network (the port being forwarded). 
// "LocalAddr" should be the API listener for this server inside Wiretap's network (src), but port 0 (so a random ephemeral port is assigned).
// "remoteAddr" is the Client's IP(v6) address and port in Wiretap's network (dst)
func ForwardUdpPortWithTracking(s *stack.Stack, conn *net.UDPConn, localAddr tcpip.FullAddress, remoteAddr tcpip.FullAddress, np tcpip.NetworkProtocolNumber) {
	var wg sync.WaitGroup
	const bufSize = 65535
	type trackedConn struct {
		udpConn    *gonet.UDPConn
		lastActive time.Time
	}
	var connTrack = make(map[netip.AddrPort]*trackedConn)

	var ctLock sync.Mutex
	var newConn = make(chan netip.AddrPort)

	// Sanity check that we can create a connection to the target client port
	_, err := gonet.DialUDP(s, &localAddr, &remoteAddr, np)
	if err != nil {
		log.Println("failed to proxy UDP conn:", err)
		conn.Close()
		return
	}

	
	// Watchdog: periodically check for idle connections
	var stopWatchdog = make(chan bool)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				expire := time.Now().Add(-1 * UDP_TIMEOUT)
				ctLock.Lock()
				for addr, clientConn := range connTrack {
					if clientConn.lastActive.Before(expire) {
						log.Printf("Closing idle UDP forward: (client %v) <- Expose: UDP <- %v", clientConn.udpConn.RemoteAddr().String(), addr.String())
						clientConn.udpConn.Close()
						delete(connTrack, addr)
					}
				}
				ctLock.Unlock()
			case <-stopWatchdog:
				return
			}
		}
	}()

	// Process incoming packets (new or existing “connections”)
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, bufSize)

		for {
			n, addr, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				// This "listener" gets closed when the forward is removed via API
				log.Println("conn closed:", err)
				close(newConn) //signal the other goroutines to shut down
				stopWatchdog <-true

				ctLock.Lock()
				for _, t := range connTrack {
					t.udpConn.Close()
				}
				ctLock.Unlock()
				
				return
			}

			ctLock.Lock()
			clientConn, exists := connTrack[addr]
			ctLock.Unlock()
			if !exists {
				// If this connection is not already being tracked, set it up
				udpConn, err := gonet.DialUDP(s, &localAddr, &remoteAddr, np)
				if err != nil {
					log.Println("failed to establish new proxy conn:", err)
					continue
				}
				clientConn = &trackedConn{udpConn: udpConn, lastActive: time.Now()}
				ctLock.Lock()
				connTrack[addr] = clientConn
				ctLock.Unlock()

				// This blocks until it gets picked up by the response handler routine below
				newConn <- addr

			} else {
				clientConn.lastActive = time.Now()
			}

			// Forward payload to the client
			// We currently have no way to capture Dest Unreachable ICMP here, so the first Write() will never fail due to that. 
			// But the network stack will remember them, so the second Write() will fail and trigger the cleanup. 
			_, err = clientConn.udpConn.Write(buf[:n])
			if err != nil {
				log.Println("failed to forward UDP packet to client:", err)
				clientConn.udpConn.Close()
				continue
			}
		}
	}()

	// Process new connections – set up routines that handle return (outgoing) packets
	for {
		ncAddr, ok := <-newConn
		if !ok {
			break
		}

		ctLock.Lock()
		clientConn, exists := connTrack[ncAddr]
		ctLock.Unlock()
		if !exists {
			log.Printf("new UDP forward connection %v marked for processing but not found\n", ncAddr)
			continue
		}

		clientRemoteAddr := clientConn.udpConn.RemoteAddr().String()
		log.Printf("(client %v) <- Expose: UDP <- %v", clientRemoteAddr, ncAddr.String())

		// Spawn routine to forward responses back to the original sender
		wg.Add(1)
		go func(targetAddr netip.AddrPort) {
			defer wg.Done()
			buf := make([]byte, bufSize)

			for {
				n, err := clientConn.udpConn.Read(buf)
				if err != nil {
					log.Printf("response conn closed: (client %v) <- Expose: UDP <- %v : %s", clientRemoteAddr, targetAddr.String(), err)
					clientConn.udpConn.Close()

					ctLock.Lock()
					delete(connTrack, targetAddr)
					ctLock.Unlock()
					break
				}

				ctLock.Lock()
				if t, ok := connTrack[targetAddr]; ok {
					t.lastActive = time.Now()
				}
				ctLock.Unlock()

				_, err = conn.WriteToUDPAddrPort(buf[:n], targetAddr)
				if err != nil {
					log.Println("failed to send client UDP response:", err)
					continue
				}
			}
		}(ncAddr)
	}


	wg.Wait()
	log.Printf("All routines for UDP forward %v successfully shut down\n", conn.LocalAddr().String())
}

// ForwardTcpPort proxies TCP connections by accepting connections and proxying them back to the client.
func ForwardDynamic(s *stack.Stack, l *net.Listener, localAddr tcpip.FullAddress, remoteAddr tcpip.FullAddress, np tcpip.NetworkProtocolNumber) {
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		dport, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, err
		}

		return gonet.DialTCPWithBind(
			ctx,
			s,
			localAddr,
			tcpip.FullAddress{NIC: remoteAddr.NIC, Addr: remoteAddr.Addr, Port: uint16(dport)},
			np,
		)
	}

	conf := &socks5.Config{Dial: dialer}
	server, err := socks5.New(conf)
	if err != nil {
		log.Println("failed to make socks server:", err)
		return
	}

	if err := server.Serve(*l); err != nil {
		log.Println("socks server stopped:", err)
	}
}
