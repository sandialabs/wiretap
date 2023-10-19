// Package API handles the internal API running on all servers.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"wiretap/peer"
	"wiretap/transport"
)

var nsLock sync.Mutex
var devLock sync.Mutex
var addressLock sync.Mutex
var indexLock sync.Mutex

var clientIndex uint64 = 0
var serverIndex uint64 = 0

type ServerConfigs struct {
	RelayConfig *peer.Config
	E2EEConfig  *peer.Config
}

type InterfaceType int

const (
	Relay InterfaceType = iota
	E2EE
)

type NetworkState struct {
	NextClientRelayAddr4 netip.Addr
	NextClientRelayAddr6 netip.Addr
	NextServerRelayAddr4 netip.Addr
	NextServerRelayAddr6 netip.Addr
	NextClientE2EEAddr4  netip.Addr
	NextClientE2EEAddr6  netip.Addr
	NextServerE2EEAddr4  netip.Addr
	NextServerE2EEAddr6  netip.Addr
	ApiAddr              netip.Addr
	ServerRelaySubnet4   netip.Addr
	ServerRelaySubnet6   netip.Addr
}

type AddAllowedIPsRequest struct {
	PublicKey  wgtypes.Key
	AllowedIPs []net.IPNet
}

type ExposeTuple struct {
	RemoteAddr netip.Addr
	LocalPort  uint
	RemotePort uint
	Protocol   string
}
type ExposeAction int

const (
	ExposeActionExpose ExposeAction = iota
	ExposeActionList
	ExposeActionDelete
)

type ExposeRequest struct {
	Action     ExposeAction
	LocalPort  uint
	RemotePort uint
	Protocol   string
	Dynamic    bool
}

type ExposeConn struct {
	TcpListener *net.Listener
	UdpConn     *net.UDPConn
}

var clientAddresses map[uint64]NetworkState
var serverAddresses map[uint64]NetworkState

// Handle adds rule to top of firewall rules that accepts direct connections to API.
func Handle(tnet *netstack.Net, devRelay *device.Device, devE2EE *device.Device, relayConfig *peer.Config, e2eeConfig *peer.Config, addr netip.Addr, port uint16, lock *sync.Mutex, ns *NetworkState) {
	configs := ServerConfigs{
		RelayConfig: relayConfig,
		E2EEConfig:  e2eeConfig,
	}

	exposeMap := make(map[ExposeTuple]ExposeConn)
	var exposeLock sync.RWMutex

	serverAddresses = make(map[uint64]NetworkState)
	clientAddresses = make(map[uint64]NetworkState)

	serverAddresses[serverIndex] = *ns
	ns.NextServerRelayAddr4 = ns.NextServerRelayAddr4.Next()
	ns.NextServerRelayAddr6 = ns.NextServerRelayAddr6.Next()
	ns.NextClientE2EEAddr4 = ns.NextClientE2EEAddr4.Next()
	ns.NextClientE2EEAddr6 = ns.NextClientE2EEAddr6.Next()
	ns.NextServerE2EEAddr4 = ns.NextServerE2EEAddr4.Next()
	ns.NextServerE2EEAddr6 = ns.NextServerE2EEAddr6.Next()
	ns.ApiAddr = ns.ApiAddr.Next()
	serverIndex += 1

	// Stand up API server.
	listener, err := tnet.ListenTCP(&net.TCPAddr{IP: addr.AsSlice(), Port: int(port)})
	if err != nil {
		log.Panic(err)
	}

	localAddr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(addr.AsSlice()),
	}

	http.HandleFunc("/ping", wrapApi(handlePing()))
	http.HandleFunc("/serverinfo", wrapApi(handleServerInfo(configs)))
	http.HandleFunc("/addpeer", wrapApi(handleAddPeer(devRelay, devE2EE, configs)))
	http.HandleFunc("/allocate", wrapApi(handleAllocate(ns)))
	http.HandleFunc("/addallowedips", wrapApi(handleAddAllowedIPs(devRelay, configs)))
	http.HandleFunc("/expose", wrapApi(handleExpose(tnet, &exposeMap, &exposeLock, localAddr)))

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

// writeErr sets status to 500, logs error, and writes error in response.
func writeErr(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	_, err = io.WriteString(w, err.Error())
	if err != nil {
		log.Printf("API Error: %v", err)
	}
}

// handlePing responds with pong message.
func handlePing() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := io.WriteString(w, "pong")
		if err != nil {
			log.Printf("API Error: %v", err)
		}
	}
}

// handleServerInfo responds with the configs for this server.
func handleServerInfo(configs ServerConfigs) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		body, err := json.Marshal(configs)
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

// handleAddPeer adds a peer to either this server's relay or e2ee device.
func handleAddPeer(devRelay *device.Device, devE2EE *device.Device, config ServerConfigs) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		interfaceParam, err := strconv.Atoi(r.URL.Query().Get("interface"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		interfaceType := InterfaceType(interfaceParam)

		if interfaceType != Relay && interfaceType != E2EE {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var p peer.PeerConfig
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeErr(w, err)
			return
		}

		err = p.UnmarshalJSON(body)
		if err != nil {
			writeErr(w, err)
			return
		}

		// If addresses not assigned, error out, should have been determined from a previous API call.
		peerAddrs := p.GetAllowedIPs()
		if len(peerAddrs) == 0 {
			writeErr(w, errors.New("no addresses"))
			return
		}

		fmt.Println()
		fmt.Println(p.AsIPC())

		var dev *device.Device
		var c *peer.Config
		switch interfaceType {
		case Relay:
			dev = devRelay
			c = config.RelayConfig
		case E2EE:
			dev = devE2EE
			c = config.E2EEConfig
		}

		devLock.Lock()
		defer devLock.Unlock()
		err = dev.IpcSet(p.AsIPC())
		if err != nil {
			writeErr(w, err)
			return
		}

		c.AddPeer(p)

		log.Printf("API: Peer Added: %s", p.GetPublicKey().String())
		w.WriteHeader(http.StatusOK)
	}
}

// handleAllocate reserves address space for a new client or server peer to be integrated into the network.
func handleAllocate(ns *NetworkState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		typeParam, err := strconv.Atoi(r.URL.Query().Get("type"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		peerType := peer.PeerType(typeParam)

		if peerType != peer.Client && peerType != peer.Server {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		nsLock.Lock()
		defer nsLock.Unlock()

		body, err := json.Marshal(ns)
		if err != nil {
			writeErr(w, err)
			return
		}

		_, err = w.Write(body)
		if err != nil {
			log.Printf("API Error: %v", err)
		}

		indexLock.Lock()
		addressLock.Lock()
		defer indexLock.Unlock()
		defer addressLock.Unlock()

		switch peer.PeerType(peerType) {
		// Clients use Client Relay addresses and E2EE addresses.
		case peer.Client:
			clientAddresses[clientIndex] = *ns
			clientIndex += 1

			ns.NextClientRelayAddr4 = ns.NextClientRelayAddr4.Next()
			ns.NextClientRelayAddr6 = ns.NextClientRelayAddr6.Next()
			ns.NextClientE2EEAddr4 = ns.NextClientE2EEAddr4.Next()
			ns.NextClientE2EEAddr6 = ns.NextClientE2EEAddr6.Next()
		// IndirectServers use Server Relay addresses, E2EE addresses, and API addresses.
		case peer.Server:
			serverAddresses[serverIndex] = *ns
			serverIndex += 1

			ns.NextServerRelayAddr4 = ns.NextServerRelayAddr4.Next()
			ns.NextServerRelayAddr6 = ns.NextServerRelayAddr6.Next()
			ns.NextServerE2EEAddr4 = ns.NextServerE2EEAddr4.Next()
			ns.NextServerE2EEAddr6 = ns.NextServerE2EEAddr6.Next()
			ns.ApiAddr = ns.ApiAddr.Next()
		}
	}
}

// handleAddAllowedIPs adds new route to a specfied peer.
func handleAddAllowedIPs(devRelay *device.Device, config ServerConfigs) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Parse query parameters.
		decoder := json.NewDecoder(r.Body)
		var requestArgs AddAllowedIPsRequest
		err := decoder.Decode(&requestArgs)
		if err != nil {
			writeErr(w, err)
			return
		}

		// Verify peer exists.
		p := config.RelayConfig.GetPeer(requestArgs.PublicKey)
		if p == nil {
			writeErr(w, errors.New("peer not found"))
			return
		}

		for _, ip := range requestArgs.AllowedIPs {
			err = p.AddAllowedIPs(ip.String())
			if err != nil {
				writeErr(w, err)
				return
			}
		}

		devLock.Lock()
		defer devLock.Unlock()
		err = devRelay.IpcSet(p.AsIPC())
		if err != nil {
			writeErr(w, err)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func handleExpose(tnet *netstack.Net, exposeMap *map[ExposeTuple]ExposeConn, exposeLock *sync.RWMutex, localAddr tcpip.FullAddress) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Parse query parameters.
		decoder := json.NewDecoder(r.Body)
		var requestArgs ExposeRequest
		err := decoder.Decode(&requestArgs)
		if err != nil {
			writeErr(w, err)
			return
		}

		remoteAddr, _, _ := net.SplitHostPort(r.RemoteAddr)

		et := ExposeTuple{
			netip.MustParseAddr(remoteAddr),
			requestArgs.LocalPort,
			requestArgs.RemotePort,
			requestArgs.Protocol,
		}

		switch requestArgs.Action {
		// Return list of all exposed ports.
		case ExposeActionList:
			exposeLock.RLock()
			defer exposeLock.RUnlock()

			ett := []ExposeTuple{}

			for k := range *exposeMap {
				ett = append(ett, k)
			}

			body, err := json.Marshal(ett)
			if err != nil {
				writeErr(w, err)
				return
			}

			_, err = w.Write(body)
			if err != nil {
				log.Printf("API Error: %v", err)
			}
			return
		// Start exposing port if not already done.
		case ExposeActionExpose:
			exposeLock.Lock()
			defer exposeLock.Unlock()

			_, ok := (*exposeMap)[et]
			if ok {
				// Already exists, cancel.
				writeErr(w, errors.New("port already exposed"))
				return
			}

			proto := ipv4.ProtocolNumber
			if et.RemoteAddr.Is6() {
				proto = ipv6.ProtocolNumber
			}

			if requestArgs.Dynamic {
				// Handle Dynamic.
				l, err := net.Listen("tcp", fmt.Sprintf(":%d", requestArgs.RemotePort))
				if err != nil {
					writeErr(w, err)
					return
				}

				// Bind successful, perform dynamic forwarding.
				go transport.ForwardDynamic(
					tnet.Stack(),
					&l,
					localAddr,
					tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(et.RemoteAddr.AsSlice())},
					proto,
				)

				(*exposeMap)[et] = ExposeConn{TcpListener: &l}
			} else if requestArgs.Protocol == "tcp" {
				// Handle TCP.
				l, err := net.Listen(requestArgs.Protocol, fmt.Sprintf(":%d", requestArgs.RemotePort))
				if err != nil {
					writeErr(w, err)
					return
				}

				// Bind successful, expose port.
				go transport.ForwardTcpPort(
					tnet.Stack(),
					l,
					localAddr,
					tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(et.RemoteAddr.AsSlice()), Port: uint16(et.LocalPort)},
					proto,
				)

				(*exposeMap)[et] = ExposeConn{TcpListener: &l}
			} else {
				// Handle UDP.
				addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", requestArgs.RemotePort))
				if err != nil {
					writeErr(w, err)
					return
				}
				c, err := net.ListenUDP("udp", addr)
				if err != nil {
					writeErr(w, err)
					return
				}

				// Bind successful, expose port.
				go transport.ForwardUdpPort(
					tnet.Stack(),
					c,
					localAddr,
					tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(et.RemoteAddr.AsSlice()), Port: uint16(et.LocalPort)},
					proto,
				)

				(*exposeMap)[et] = ExposeConn{UdpConn: c}
			}

		// Stop listener and delete from map.
		case ExposeActionDelete:
			exposeLock.Lock()
			defer exposeLock.Unlock()

			c, ok := (*exposeMap)[et]
			if ok {
				if et.Protocol == "tcp" && c.TcpListener != nil {
					(*c.TcpListener).Close()
				} else if c.UdpConn != nil {
					c.UdpConn.Close()
				}
				delete(*exposeMap, et)
			} else {
				writeErr(w, errors.New("not found"))
				return
			}
		}

		w.WriteHeader(http.StatusOK)
	}
}
