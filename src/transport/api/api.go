// Package API handles the internal API running on the server.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"wiretap/peer"
	"wiretap/transport"
)

// Handle adds rule to top of firewall rules that accepts direct connections to API.
func Handle(tnet *netstack.Net, dev *device.Device, config *peer.Config, addr netip.Addr, port uint16, lock *sync.Mutex) {
	s := tnet.Stack()

	headerFilter := stack.IPHeaderFilter{
		Protocol:      tcp.ProtocolNumber,
		CheckProtocol: true,
		Dst:           tcpip.Address(addr.AsSlice()),
		DstMask:       tcpip.Address(bytes.Repeat([]byte("\xff"), addr.BitLen()/8)),
	}

	rule := stack.Rule{
		Filter: headerFilter,
		Target: &stack.AcceptTarget{
			NetworkProtocol: func() tcpip.NetworkProtocolNumber {
				if addr.Is4() {
					return ipv4.ProtocolNumber
				}
				return ipv6.ProtocolNumber
			}(),
		},
	}

	tid := stack.NATID
	transport.PushRule(s, rule, tid, addr.Is6())
	lock.Unlock()

	// Stand up API server.
	listener, err := tnet.ListenTCP(&net.TCPAddr{IP: addr.AsSlice(), Port: int(port)})
	if err != nil {
		log.Panic(err)
	}

	http.HandleFunc("/ping", wrapApi(handlePing()))
	http.HandleFunc("/serverinfo", wrapApi(handleServerInfo(config)))
	http.HandleFunc("/peers/add", wrapApi(handlePeerAdd(dev, config)))

	log.Println("API: API listener up")
	err = http.Serve(listener, nil)
	if err != nil {
		log.Panic(err)
	}
}

// wrapAPI logs all API requests.
func wrapApi(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("(client %s) - API: %s", r.RemoteAddr, r.RequestURI)
		f(w, r)
	}
}

func writeErr(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	_, err = io.WriteString(w, err.Error())
	if err != nil {
		log.Printf("API Error: %v", err)
	}
}

func handlePing() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := io.WriteString(w, "pong")
		if err != nil {
			log.Printf("API Error: %v", err)
		}
	}
}

func handleServerInfo(config *peer.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := json.Marshal(config)
		if err != nil {
			writeErr(w, err)
			return
		}

		_, err = w.Write(body)
		if err != nil {
			log.Printf("API Error: %v", err)
		}
	}
}

func handlePeerAdd(dev *device.Device, config *peer.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var p peer.PeerConfig
		err := json.NewDecoder(r.Body).Decode(&p)
		if err != nil {
			writeErr(w, err)
			return
		}

		// If addresses not assigned, choose new address dynamically.
		var newAddrs []string
		peerAddrs := p.GetAllowedIPs()
		serverAddrs := config.GetAddresses()
		if len(peerAddrs) == 0 {
			if len(config.GetAddresses()) < 2 {
				writeErr(w, errors.New("unable to dynamically assign addresses"))
			}

			prefix4, err := netip.ParsePrefix(serverAddrs[0].String())
			if err != nil {
				writeErr(w, err)
				return
			}

			prefix6, err := netip.ParsePrefix(serverAddrs[1].String())
			if err != nil {
				writeErr(w, err)
				return
			}

			zeroAddr := netip.Addr{}
			availableAddr4 := findAvailableAddr(config, prefix4.Addr())
			if availableAddr4 != zeroAddr {
				prefix4, _ = availableAddr4.Prefix(availableAddr4.BitLen())
				newAddrs = append(newAddrs, prefix4.String())
			}
			availableAddr6 := findAvailableAddr(config, prefix6.Addr())
			if availableAddr6 != zeroAddr {
				prefix6, _ = availableAddr6.Prefix(availableAddr6.BitLen())
				newAddrs = append(newAddrs, prefix6.String())
			}

			err = p.SetAllowedIPs(newAddrs)
			if err != nil {
				writeErr(w, err)
				return
			}
		}

		if len(p.GetAllowedIPs()) == 0 {
			writeErr(w, errors.New("no addresses"))
			return
		}

		fmt.Println()
		fmt.Println(p.AsIPC())

		err = dev.IpcSet(p.AsIPC())
		if err != nil {
			writeErr(w, err)
			return
		}

		log.Printf("API: Peer Added: %s", p.GetPublicKey().String())

		body, err := json.Marshal(&p)
		if err != nil {
			writeErr(w, err)
			return
		}

		config.AddPeer(p)

		_, err = w.Write(body)
		if err != nil {
			log.Printf("API Error: %v", err)
		}
	}
}

func findAvailableAddr(config *peer.Config, baseAddr netip.Addr) netip.Addr {
	zeroAddr := netip.Addr{}
	candidate := baseAddr.Next()
	// Loop until address is found or zero address hit.
CandidateLoop:
	for candidate != zeroAddr {
		for _, peer := range config.GetPeers() {
			for _, aip := range peer.GetAllowedIPs() {
				// Already in use.
				if netip.MustParsePrefix(aip.String()).Addr() == candidate {
					candidate = candidate.Next()
					continue CandidateLoop
				}
			}
		}

		return candidate
	}

	return zeroAddr
}
