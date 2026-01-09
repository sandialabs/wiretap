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
	//"time"

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
	log.Printf("TCP Forwarder. Local %v; Remote %v", localAddr, remoteAddr)
	// wiretap expose -l 6666 -p tcp
	// TCP Forwarder. Local {1 ::2 0 }; Remote {1 fd:19::1 6666 }
	

	for {
		conn, err := l.Accept()
		if err != nil {
			cancel()
			return
		}

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
func ForwardUdpPort(s *stack.Stack, conn *net.UDPConn, localAddr tcpip.FullAddress, remoteAddr tcpip.FullAddress, np tcpip.NetworkProtocolNumber) {
	var wg sync.WaitGroup
	var clientAddr *netip.AddrPort
	var lock sync.Mutex

	const bufSize = 65535

	log.Printf("UDP Forwarder. Local %v; Remote %v", localAddr, remoteAddr)
	// wiretap expose -l 6666 -p tcp
	// UDP Forwarder. Local {1 ::2 0 }; Remote {1 fd:19::1 6666 }

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

// ForwardUdpPortWithTracking proxies UDP datagrams by forwarding datagrams to a peer. All connections are tracked so that the client responses are sent to the correct sender, if the exposed service supports doing that. 
// Services that don't support that (like 'ncat -lvnup') will only receive and respond to the first endpoint they get a packet from, and must be restarted to talk to a different endpoint. 
// Currently there is no mechanism for timing out tracked connections, they will remain tracked in memory until the forward is removed
// BUG: The first packet sent by an endpoint is never received by the client. 
func ForwardUdpPortWithTracking(s *stack.Stack, conn *net.UDPConn, localAddr tcpip.FullAddress, remoteAddr tcpip.FullAddress, np tcpip.NetworkProtocolNumber) {
	//Connection tracking has been tested to ensure that basic use cases work, and that all traffic forwards immediately stop once the Wiretap forward is stopped via 'expose remove'
	// There are likely other edge cases that are not handled perfectly

	// "LocalAddr" is the API listener for this server in Wiretap's network (src), but port 0; "remoteAddr" is the Client's IP(v6) in Wiretap's network (dst)
	// conn is the listening socket on the "real" network

	var wg sync.WaitGroup
	const bufSize = 65535
	
	var connTrack = make(map[netip.AddrPort]*gonet.UDPConn)
	var ctLock sync.Mutex
	var newConn = make(chan netip.AddrPort)
	var stop = false //trigger to shut down all goroutines

	// Sanity check that we can create a connection to the target client port
	_, err := gonet.DialUDP(
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

	// Process incoming packets (new or existing "connections")
	wg.Add(1)
	go func() {
		buf := make([]byte, bufSize)
		for {
			if stop {
				log.Printf("Stop received in UDP Listener routine\n")
				conn.Close()
				close(newConn)
				break
			}

			n, addr, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				// This conn gets closed to signal that the forwarder is being stopped
				log.Println("conn closed:", err)
				stop = true
				close(newConn)
				break
			}
			log.Printf("Read %d bytes from UDP listener\n", n)
			
			ctLock.Lock()
			clientConn, exists := connTrack[addr]
			ctLock.Unlock()
			if !exists { 
				// New connection to forwarded port (with random/unique source port)
				log.Printf("New UDP connection detected\n")
				clientConn, err = gonet.DialUDP(
					s,
					&localAddr,
					&remoteAddr,
					np,
				)
				if err != nil {
					log.Println("failed to establish new proxy conn:", err)
					//conn.Close()
					//break
					continue
				}

				ctLock.Lock()
				connTrack[addr] = clientConn
				ctLock.Unlock()

				// This blocks until it gets picked up by the next code block
				newConn <- addr
			}

			log.Printf("Forwarding %d UDP bytes from %v to %v\n", n, addr, clientConn.RemoteAddr())
			_, err = clientConn.Write(buf[:n])
			if err != nil {
				log.Println("failed to forward UDP packet to client:", err)
				continue
			}

		}
		wg.Done()
	}()

	// Process new connections to handle return (outgoing) packets
	var stoppers []chan int
	for {
		ncAddr, ok := <- newConn
		if stop || !ok {
			log.Printf("Stop received in new connection handler\n")
			log.Printf("Sending stop signals to %d routines\n", len(stoppers))
			// Send stop signals to all return packet routines
			for _, s := range stoppers {
				s <- 1
			}
			break
		}

		ctLock.Lock()
		clientConn, exists := connTrack[ncAddr]
		ctLock.Unlock()
		if ! exists {
			log.Printf("new UDP forward connection %v marked for processing but not found\n", ncAddr)
			continue
		}

		stopper := make(chan int, 1) // Buffered so it doesn't block on send
		stoppers = append(stoppers, stopper)

		// Spawn new routine to handle return packets (from client)
		wg.Add(1)
		go func() {
			for {
				buf := make([]byte, bufSize)

				// Turn the blocking Read() call into a channel that we can switch on
				// That way we can immediately exit the routine even when it's blocking
				readChan := make(chan any)
				var n int
				go func() {
					numBytes, err := clientConn.Read(buf)
					if err == nil {
						readChan <- numBytes
					} else {
						readChan <- err
					}
				}()

				// Stopper or Read() result will both be handled without one blocking the other
				select {
				case <-stopper:
					log.Printf("Stop received in goroutine for %v\n", clientConn.RemoteAddr())
					wg.Done()
					return

				case result := <- readChan:
					// Since it can return error or int, need to handle both
					switch result.(type) {
					case error:
						log.Println("client response conn closed:", result)
						clientConn.Close()

						ctLock.Lock()
						delete(connTrack, ncAddr)
						ctLock.Unlock()

						wg.Done()
						return
					}

					n = result.(int)
				}
				log.Printf("Read %d bytes from UDP client\n", n)

				// Find the target address associated with this response
				var targetAddr netip.AddrPort
				var found = false
				for k, v := range connTrack {
					if v == clientConn {
						targetAddr = k
						found = true
						break
					}
				}
				
				if !found {
					log.Println("mapping for UDP response to remote target not found, closing connection")
					clientConn.Close()

					ctLock.Lock()
					delete(connTrack, ncAddr)
					ctLock.Unlock()
					break
				}
				
				log.Printf("Forwarding %d UDP bytes from %v to %v\n", n, clientConn.RemoteAddr(), targetAddr)
				_, err := conn.WriteToUDPAddrPort(buf[:n], targetAddr)
				if err != nil {
					log.Println("failed to send client UDP response:", err)
					continue
				}

			}
			wg.Done()
		}()
	}

	wg.Wait()
	log.Println("Forward successfully shut down")
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
