// Package tcp proxies TCP connections between a WireGuard peer and a destination
// accessible by the machine where Wiretap is running.
//
// Adapted from https://github.com/tailscale/tailscale/blob/2cf6e127907641bdb9eb5cd8e8cf14e968b571d7/wgengine/netstack/netstack.go
// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package tcp

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"net/netip"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Configure TCP handler.
type TcpConfig struct {
	Ipv4Addr          netip.Addr
	Ipv6Addr          netip.Addr
	CatchTimeout      time.Duration
	ConnTimeout       time.Duration
	KeepaliveIdle     time.Duration
	KeepaliveInterval time.Duration
	KeepaliveCount    int
	Tnet              *netstack.Net
	StackLock         *sync.Mutex
	ConfigLock        *sync.Mutex
	ConnCounts        map[netip.Addr]int
}

// Handler manages a single TCP flow.
func Handler(c TcpConfig) func(*tcp.ForwarderRequest) {
	return func(req *tcp.ForwarderRequest) {
		var wg sync.WaitGroup

		// Received TCP flow, add address so we can work with it.
		s := req.ID()
		log.Printf("(client %v:%v) - Transport: TCP -> %v:%v", s.RemoteAddress, s.RemotePort, s.LocalAddress, s.LocalPort)

		// Add address to stack.
		addr, _ := netip.AddrFromSlice(net.IP(s.LocalAddress))
		addAddress(&c, addr)
		defer removeAddress(&c, addr)

		// Address is added, now test if remote endpoint is available.
		dstConn, caughtChan, rst := checkDst(&c, s)
		if dstConn == nil {
			req.Complete(rst)
			return
		}

		srcConn, err := accept(&c, req)
		if err != nil {
			log.Println("Failed to create endpoint:", err)
			return
		}

		// Tell checker that this connection was caught, timer can shutdown.
		caughtChan <- true

		// Copy from new connection to peer
		wg.Add(1)
		go func() {
			_, err := io.Copy(srcConn, dstConn)
			if err != nil {
				log.Printf("Error copying between connections: %v\n", err)
			}
			wg.Done()
			srcConn.Close()
		}()

		// Copy from peer to new connection.
		_, nerr := io.Copy(dstConn, srcConn)
		if nerr != nil {
			log.Printf("Error copying between connections: %v\n", err)
		}
		dstConn.Close()

		// Wait for both copies to finish.
		wg.Wait()
	}
}

// addAddress adds an address to the stack if it doesn't already exist.
func addAddress(c *TcpConfig, addr netip.Addr) error {
	c.StackLock.Lock()
	c.ConfigLock.Lock()

	c.ConnCounts[addr]++

	if c.ConnCounts[addr] > 1 {
		c.ConfigLock.Unlock()
		c.StackLock.Unlock()
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

	err := c.Tnet.Stack().AddProtocolAddress(1, protoAddr, stack.AddressProperties{})
	c.ConfigLock.Unlock()
	c.StackLock.Unlock()
	if err != nil {
		return errors.New(err.String())
	}
	return nil
}

// removeAddress removes an address from the stack once it is no longer needed.
func removeAddress(c *TcpConfig, addr netip.Addr) error {
	c.StackLock.Lock()
	c.ConfigLock.Lock()

	c.ConnCounts[addr]--

	if c.ConnCounts[addr] > 0 {
		c.ConfigLock.Unlock()
		c.StackLock.Unlock()
		return nil
	}

	delete(c.ConnCounts, addr)
	err := c.Tnet.Stack().RemoveAddress(1, tcpip.Address(addr.AsSlice()))

	c.ConfigLock.Unlock()
	c.StackLock.Unlock()
	if err != nil {
		return errors.New(err.String())
	}
	return nil
}

// checkDst determines if a tcp connection can be made to a destination.
// Returns the connection on success,
// a channel for the caller to populate when the connection is used,
// and whether or not to send RST to source.
func checkDst(config *TcpConfig, s stack.TransportEndpointID) (net.Conn, chan bool, bool) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", s.LocalAddress, s.LocalPort), config.ConnTimeout)
	if err != nil {
		// If connection refused, we can send a reset to let peer know.
		if oerr, ok := err.(*net.OpError); ok {
			if syserr, ok := oerr.Err.(*os.SyscallError); ok {
				if syserr.Err == syscall.ECONNREFUSED {
					return nil, nil, true
				}
			}
		}

		// Different error, don't send reset.
		return nil, nil, false
	}

	// Start "catch" timer to make sure connection is actually used.
	caughtChan := make(chan bool)
	go func() {
		select {
		case <-time.After(config.CatchTimeout):
			c.Close()
		case <-caughtChan:
		}
	}()

	return c, caughtChan, false
}

// Accept converts a forwarder request to an endpoint, sets sockopts, then converts to conn.
func accept(c *TcpConfig, req *tcp.ForwarderRequest) (net.Conn, error) {
	// We want to accept this flow, setup endpoint to complete handshake.
	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		return nil, errors.New(err.String())
	}

	// Enable keepalive and set defaults so that after (idle + (count * interval)) connection will be dropped if unresponsive.
	ep.SocketOptions().SetKeepAlive(true)
	keepaliveIdle := tcpip.KeepaliveIdleOption(c.KeepaliveIdle)
	err = ep.SetSockOpt(&keepaliveIdle)
	if err != nil {
		return nil, errors.New(err.String())
	}
	keepaliveInterval := tcpip.KeepaliveIntervalOption(c.KeepaliveInterval)
	err = ep.SetSockOpt(&keepaliveInterval)
	if err != nil {
		return nil, errors.New(err.String())
	}
	err = ep.SetSockOptInt(tcpip.KeepaliveCountOption, c.KeepaliveCount)
	if err != nil {
		return nil, errors.New(err.String())
	}

	return gonet.NewTCPConn(&wq, ep), nil
}
