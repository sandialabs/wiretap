package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wiretap/api"
	"wiretap/peer"
)

func TestStatusRunJSONMinimalState(t *testing.T) {
	relayConfig := mustNewConfig(t)
	e2eeConfig := mustNewConfig(t)

	dir := t.TempDir()
	relayPath := filepath.Join(dir, "wiretap_relay.conf")
	e2eePath := filepath.Join(dir, "wiretap.conf")
	writeConfig(t, relayPath, relayConfig)
	writeConfig(t, e2eePath, e2eeConfig)

	output := captureStdout(t, func() {
		statusCmdConfig{
			jsonOutput:      true,
			configFileRelay: relayPath,
			configFileE2EE:  e2eePath,
		}.Run()
	})

	if !json.Valid([]byte(output)) {
		t.Fatalf("status output is not valid JSON: %q", output)
	}

	var status statusJSONOutput
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		t.Fatalf("unmarshal status JSON: %v", err)
	}
	if status.NetworkInfo {
		t.Fatal("network_info = true, want false")
	}
	if status.Client.RelayPublicKey != relayConfig.GetPublicKey() {
		t.Fatalf("relay public key = %q, want %q", status.Client.RelayPublicKey, relayConfig.GetPublicKey())
	}
	if status.Client.E2EEPublicKey != e2eeConfig.GetPublicKey() {
		t.Fatalf("e2ee public key = %q, want %q", status.Client.E2EEPublicKey, e2eeConfig.GetPublicKey())
	}
	if len(status.Client.Children) != 0 {
		t.Fatalf("children = %d, want 0", len(status.Client.Children))
	}
	if len(status.Errors) != 0 {
		t.Fatalf("errors = %d, want 0", len(status.Errors))
	}
}

func TestMarshalStatusJSONDeterministic(t *testing.T) {
	client := &Node{
		relayConfig: mustNewConfig(t),
		e2eeConfig:  mustNewConfig(t),
	}

	first := Node{
		peerConfig: mustPeerConfig(t, "zeta", []string{"10.2.0.0/16", "::3/128"}),
		error:      "timeout",
	}
	second := Node{
		peerConfig: mustPeerConfig(t, "alpha", []string{"10.1.0.0/16", "::2/128"}),
		error:      "connection refused",
	}

	one, err := marshalStatusJSON(client, []Node{first, second}, false)
	if err != nil {
		t.Fatalf("marshal first status: %v", err)
	}
	two, err := marshalStatusJSON(client, []Node{second, first}, false)
	if err != nil {
		t.Fatalf("marshal second status: %v", err)
	}

	if !bytes.Equal(one, two) {
		t.Fatalf("JSON changed with concurrent error arrival order:\nfirst:\n%s\nsecond:\n%s", one, two)
	}
}

func TestMarshalStatusJSONDoesNotExposePrivateKeys(t *testing.T) {
	clientRelay := mustNewConfig(t)
	clientE2EE := mustNewConfig(t)
	serverRelay := mustNewConfig(t)
	serverE2EE := mustNewConfig(t)

	client := &Node{
		relayConfig: clientRelay,
		e2eeConfig:  clientE2EE,
		children: []*Node{{
			peerConfig:  mustPeerConfig(t, "edge", []string{"10.0.0.0/24", "::2/128"}),
			relayConfig: serverRelay,
			e2eeConfig:  serverE2EE,
		}},
	}

	output, err := marshalStatusJSON(client, nil, false)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}

	for name, secret := range map[string]string{
		"client relay": clientRelay.GetPrivateKey(),
		"client e2ee":  clientE2EE.GetPrivateKey(),
		"server relay": serverRelay.GetPrivateKey(),
		"server e2ee":  serverE2EE.GetPrivateKey(),
	} {
		if strings.Contains(string(output), secret) {
			t.Fatalf("JSON exposed %s private key", name)
		}
	}
	if strings.Contains(string(output), "PrivateKey") || strings.Contains(string(output), "PresharedKey") {
		t.Fatalf("JSON exposed secret-bearing config fields: %s", output)
	}

	for name, publicKey := range map[string]string{
		"client relay": clientRelay.GetPublicKey(),
		"client e2ee":  clientE2EE.GetPublicKey(),
		"server relay": serverRelay.GetPublicKey(),
		"server e2ee":  serverE2EE.GetPublicKey(),
	} {
		if !strings.Contains(string(output), publicKey) {
			t.Fatalf("JSON missing %s public key", name)
		}
	}
}

func TestStatusJSONNetworkInfoErrorIsStructured(t *testing.T) {
	client := &Node{
		relayConfig: mustNewConfig(t),
		e2eeConfig:  mustNewConfig(t),
		children: []*Node{{
			peerConfig:      mustPeerConfig(t, "edge", []string{"10.0.0.0/24", "::2/128"}),
			relayConfig:     mustNewConfig(t),
			e2eeConfig:      mustNewConfig(t),
			interfaces:      []api.HostInterface{{Name: "ERROR: interface query failed"}},
			interfacesError: "interface query failed",
		}},
	}

	status := buildStatusJSON(client, nil, true)
	if !status.NetworkInfo {
		t.Fatal("network_info = false, want true")
	}
	server := status.Client.Children[0]
	if server.NetworkInfoError != "interface query failed" {
		t.Fatalf("network_info_error = %q, want %q", server.NetworkInfoError, "interface query failed")
	}
	if len(server.Interfaces) != 0 {
		t.Fatalf("interfaces = %#v, want empty when interface query fails", server.Interfaces)
	}
}

func TestStatusJSONMalformedConfigExitsNonZero(t *testing.T) {
	if os.Getenv("WIRETAP_STATUS_JSON_HELPER") == "1" {
		statusCmdConfig{
			jsonOutput:      true,
			configFileRelay: os.Getenv("WIRETAP_STATUS_RELAY"),
			configFileE2EE:  os.Getenv("WIRETAP_STATUS_E2EE"),
		}.Run()
		return
	}

	dir := t.TempDir()
	relayPath := filepath.Join(dir, "bad-relay.conf")
	e2eePath := filepath.Join(dir, "wiretap.conf")
	if err := os.WriteFile(relayPath, []byte("not a wireguard config\n"), 0o600); err != nil {
		t.Fatalf("write malformed relay config: %v", err)
	}
	writeConfig(t, e2eePath, mustNewConfig(t))

	cmd := exec.Command(os.Args[0], "-test.run=^TestStatusJSONMalformedConfigExitsNonZero$")
	cmd.Env = append(os.Environ(),
		"WIRETAP_STATUS_JSON_HELPER=1",
		"WIRETAP_STATUS_RELAY="+relayPath,
		"WIRETAP_STATUS_E2EE="+e2eePath,
	)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	if err == nil {
		t.Fatal("malformed config exited successfully, want non-zero status")
	}
	if _, ok := err.(*exec.ExitError); !ok {
		t.Fatalf("run helper: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty on malformed config", stdout.String())
	}
	if !strings.Contains(stderr.String(), "failed to parse relay config file") {
		t.Fatalf("stderr = %q, want relay parse diagnostic", stderr.String())
	}
}

func mustNewConfig(t *testing.T) peer.Config {
	t.Helper()
	config, err := peer.NewConfig()
	if err != nil {
		t.Fatalf("new config: %v", err)
	}
	return config
}

func mustPeerConfig(t *testing.T, nickname string, allowedIPs []string) peer.PeerConfig {
	t.Helper()
	config, err := peer.GetPeerConfig(peer.PeerConfigArgs{
		Nickname:   nickname,
		AllowedIPs: allowedIPs,
	})
	if err != nil {
		t.Fatalf("new peer config: %v", err)
	}
	return config
}

func writeConfig(t *testing.T, path string, config peer.Config) {
	t.Helper()
	if err := os.WriteFile(path, []byte(config.AsFile()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = original }()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close stdout reader: %v", err)
	}
	return string(output)
}
