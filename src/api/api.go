// Package api handles client-side API requests.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"wiretap/peer"
	serverapi "wiretap/transport/api"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Request packages a URL, method, and request body.
type request struct {
	URL    string
	Method string
	Body   []byte
}

// Re-export the server api struct so files importing this package can access it
type HostInterface serverapi.HostInterface

// MakeRequest attempts to send an API query to the Wiretap server.
func makeRequest(req request) ([]byte, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	reqBody := bytes.NewBuffer(req.Body)

	r, err := http.NewRequest(req.Method, req.URL, reqBody)
	if err != nil {
		return []byte{}, err
	}

	if len(req.Body) != 0 {
		r.Header.Add("Content-Type", "application/json")
	}

	resp, err := client.Do(r)
	if err != nil {
		return []byte{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return []byte{}, errors.New(string(body))
	}

	return body, nil
}

func makeUrl(apiAddr netip.AddrPort, route string, query []string) string {
	return fmt.Sprintf("http://%v:%d/%s?%s", apiAddr.Addr(), apiAddr.Port(), route, strings.Join(query, "&"))
}

func Ping(apiAddr netip.AddrPort) (string, error) {
	body, err := makeRequest(request{
		URL:    makeUrl(apiAddr, "ping", []string{}),
		Method: "GET",
	})

	return string(body), err
}

func ServerInfo(apiAddr netip.AddrPort) (peer.Config, peer.Config, error) {
	body, err := makeRequest(request{
		URL:    makeUrl(apiAddr, "serverinfo", []string{}),
		Method: "GET",
	})
	if err != nil {
		return peer.Config{}, peer.Config{}, err
	}

	var configs serverapi.ServerConfigs
	err = json.Unmarshal(body, &configs)
	if err != nil {
		return peer.Config{}, peer.Config{}, err
	}

	return *configs.RelayConfig, *configs.E2EEConfig, nil
}

func ServerInterfaces(apiAddr netip.AddrPort) ([]HostInterface, error) {
	body, err := makeRequest(request{
		URL:    makeUrl(apiAddr, "serverinterfaces", []string{}),
		Method: "GET",
	})
	if err != nil {
		return nil, err
	}

	var interfaces []HostInterface
	err = json.Unmarshal(body, &interfaces)
	if err != nil {
		return nil, err
	}

	return interfaces, nil
}

func AllocateNode(apiAddr netip.AddrPort, peerType peer.PeerType) (serverapi.NetworkState, error) {
	body, err := makeRequest(request{
		URL:    makeUrl(apiAddr, "allocate", []string{fmt.Sprintf("type=%d", peerType)}),
		Method: "GET",
	})
	if err != nil {
		return serverapi.NetworkState{}, err
	}

	var addresses serverapi.NetworkState
	err = json.Unmarshal(body, &addresses)
	if err != nil {
		return serverapi.NetworkState{}, err
	}

	return addresses, nil
}

func AllocateServerNode(apiAddr netip.AddrPort) (serverapi.NetworkState, error) {
	return AllocateNode(apiAddr, peer.Server)
}

func AllocateClientNode(apiAddr netip.AddrPort) (serverapi.NetworkState, error) {
	return AllocateNode(apiAddr, peer.Client)
}

func AddPeer(apiAddr netip.AddrPort, ifaceType serverapi.InterfaceType, config peer.PeerConfig) error {
	body, err := config.MarshalJSON()
	if err != nil {
		return err
	}
	_, err = makeRequest(request{
		URL:    makeUrl(apiAddr, "addpeer", []string{fmt.Sprintf("interface=%d", ifaceType)}),
		Method: "POST",
		Body:   body,
	})

	return err
}

func AddRelayPeer(apiAddr netip.AddrPort, config peer.PeerConfig) error {
	return AddPeer(apiAddr, serverapi.Relay, config)
}

func AddE2EEPeer(apiAddr netip.AddrPort, config peer.PeerConfig) error {
	return AddPeer(apiAddr, serverapi.E2EE, config)
}

func AddAllowedIPs(apiAddr netip.AddrPort, pubKey wgtypes.Key, allowedIPs []net.IPNet) error {
	req := serverapi.AddAllowedIPsRequest{
		PublicKey:  pubKey,
		AllowedIPs: allowedIPs,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	_, err = makeRequest(request{
		URL:    makeUrl(apiAddr, "addallowedips", []string{}),
		Method: "POST",
		Body:   body,
	})

	return err
}

func Expose(apiAddr netip.AddrPort, localPort uint, remotePort uint, protocol string, dynamic bool) error {
	req := serverapi.ExposeRequest{
		Action:     serverapi.ExposeActionExpose,
		LocalPort:  localPort,
		RemotePort: remotePort,
		Protocol:   protocol,
		Dynamic:    dynamic,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	_, err = makeRequest(request{
		URL:    makeUrl(apiAddr, "expose", []string{}),
		Method: "POST",
		Body:   body,
	})

	return err
}

func ExposeList(apiAddr netip.AddrPort) ([]serverapi.ExposeTuple, error) {
	req := serverapi.ExposeRequest{
		Action: serverapi.ExposeActionList,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	body, err = makeRequest(request{
		URL:    makeUrl(apiAddr, "expose", []string{}),
		Method: "POST",
		Body:   body,
	})
	if err != nil {
		return nil, err
	}

	var tuples []serverapi.ExposeTuple
	err = json.Unmarshal(body, &tuples)

	return tuples, err
}

func ExposeDelete(apiAddr netip.AddrPort, localPort uint, remotePort uint, protocol string, dynamic bool) error {
	req := serverapi.ExposeRequest{
		Action:     serverapi.ExposeActionDelete,
		LocalPort:  localPort,
		RemotePort: remotePort,
		Protocol:   protocol,
		Dynamic:    dynamic,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	_, err = makeRequest(request{
		URL:    makeUrl(apiAddr, "expose", []string{}),
		Method: "POST",
		Body:   body,
	})

	return err
}
