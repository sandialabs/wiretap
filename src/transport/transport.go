// Package transport provides utility functions needed by all transport methods.
package transport

import (
	"bytes"
	"errors"

	"github.com/google/gopacket"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// PushRule pushes a rule onto a firewall table.
func PushRule(s *stack.Stack, rule stack.Rule, tableId stack.TableID, ipv6 bool) {
	table := s.IPTables().GetTable(tableId, ipv6)
	table.Rules = append([]stack.Rule{rule}, table.Rules...)
	s.IPTables().ReplaceTable(tableId, table, ipv6)
}

// IPHeader is a type interface used by GetNetworkLayer.
type IPHeader interface {
	header.IPv4 | header.IPv6
}

// IPLayer must have DecodeFromBytes function.
type IPLayer interface {
	DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error
}

// GetNetworkLayer parses a network header, then converts it to bytes.
func GetNetworkLayer[H IPHeader, L IPLayer](netHeader header.Network, ipLayer L) (L, error) {
	h, ok := netHeader.(H)
	if !ok {
		return ipLayer, errors.New("Could not assert network header as provided type")
	}

	err := ipLayer.DecodeFromBytes(h, gopacket.NilDecodeFeedback)
	if err != nil {
		return ipLayer, err
	}

	return ipLayer, nil
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
