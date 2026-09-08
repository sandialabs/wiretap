package userspace

import (
	"errors"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestUserspaceSocketBindDualStackLifecycle(t *testing.T) {
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{
			netip.MustParseAddr("10.77.0.1"),
			netip.MustParseAddr("fd77::1"),
		},
		nil,
		1420,
	)
	if err != nil {
		t.Fatalf("create netstack TUN: %v", err)
	}
	defer func() { _ = tun.Close() }()

	bind := NewBind(tnet).(*UserspaceSocketBind)
	receivers, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if port == 0 {
		t.Fatal("Open returned port 0")
	}
	if len(receivers) != 2 {
		t.Fatalf("Open returned %d receive functions, want 2", len(receivers))
	}
	if bind.ipv4 == nil {
		t.Fatal("IPv4 userspace UDP socket was not opened")
	}
	if bind.ipv6 == nil {
		t.Fatal("IPv6 userspace UDP socket was not opened")
	}
	if bind.ipv4 == bind.ipv6 {
		t.Fatal("IPv4 and IPv6 userspace sockets must be distinct")
	}

	if _, _, err := bind.Open(port); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatalf("second Open error = %v, want ErrBindAlreadyOpen", err)
	}

	ipv4 := bind.ipv4
	bind.ipv4 = nil
	if err := bind.Send(nil, asEndpoint(netip.MustParseAddrPort("[fd77::2]:51820"))); err != nil {
		t.Fatalf("IPv6 Send selected the wrong socket: %v", err)
	}
	bind.ipv4 = ipv4

	if err := bind.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if bind.ipv4 != nil || bind.ipv6 != nil {
		t.Fatalf("Close left sockets behind: ipv4=%v ipv6=%v", bind.ipv4 != nil, bind.ipv6 != nil)
	}
}
