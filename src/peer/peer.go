// Package peer contains functions to perform configuration and validation operations on devices and peers.
package peer

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type PeerType int

const (
	Client PeerType = iota
	Server
)

func parseKey(key string) (*wgtypes.Key, error) {
	var parsedKey wgtypes.Key
	var err error

	// Attempt to parse key.
	parsedKey, err = wgtypes.ParseKey(key)
	if err != nil {
		// Attempt to parse as hex.
		parseErr := err
		keyBytes, err := hex.DecodeString(key)
		if err != nil {
			return nil, parseErr
		}

		encodedKey := base64.StdEncoding.EncodeToString(keyBytes)
		parsedKey, err = wgtypes.ParseKey(encodedKey)
		if err != nil {
			return nil, err
		}
	}

	return &parsedKey, nil
}

func GetNextPrefix(prefix netip.Prefix) netip.Prefix {
	bits := prefix.Bits()
	if bits == 0 {
		return prefix
	}

	baseBytes := prefix.Masked().Addr().AsSlice()
	i := (bits - 1) / 8

	baseBytes[i] += (1 << (8 - (((bits - 1) % 8) + 1)))

	newAddr, _ := netip.AddrFromSlice(baseBytes)
	return netip.PrefixFrom(newAddr, bits)
}

// Iterate over all peers, use index of AllowedIPs to find next prefix of each.
func GetNextPrefixesForPeers(peers []PeerConfig) []netip.Prefix {
	if len(peers) == 0 {
		return []netip.Prefix{}
	}

	prefixes := []netip.Prefix{}
	// Get number of prefixes we'll be looking for.
	for i := 0; i < len(peers[0].GetAllowedIPs()); i++ {
		basePrefix := netip.MustParsePrefix(peers[0].GetAllowedIPs()[i].String()).Masked()
		for _, p := range peers {
			testPrefix := netip.MustParsePrefix(p.GetAllowedIPs()[i].String()).Masked()
			if basePrefix.Addr().Less(testPrefix.Addr()) {
				basePrefix = testPrefix
			}
		}
		prefixes = append(prefixes, GetNextPrefix(basePrefix))
	}

	return prefixes
}

// Add number to filename if it already exists.
func FindAvailableFilename(f string) string {
	count := 1
	ext := filepath.Ext(f)
	basename := strings.TrimSuffix(f, ext)
	for {
		_, err := os.Stat(f)
		if os.IsNotExist(err) {
			break
		}
		f = fmt.Sprintf("%s_%d%s", basename, count, ext)
		count += 1
	}

	return f
}
