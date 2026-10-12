package api

import (
	"net/netip"
	"testing"
)

func TestMakeUrl(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"192.0.2.2:80", "http://192.0.2.2:80/ping?a=1&b=2"},
		// The default API address is IPv6 (::2); it must be bracketed in a URL.
		{"[::2]:80", "http://[::2]:80/ping?a=1&b=2"},
	}
	for _, tt := range tests {
		got := makeUrl(netip.MustParseAddrPort(tt.addr), "ping", []string{"a=1", "b=2"})
		if got != tt.want {
			t.Errorf("makeUrl(%s) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}
