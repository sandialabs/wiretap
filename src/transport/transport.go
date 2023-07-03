// Package transport provides utility functions needed by all transport methods.
package transport

import (
	"bytes"
	"errors"
	"net/netip"
	"sync"

	"github.com/google/gopacket"
	"gvisor.dev/gvisor/pkg/tcpip"
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
