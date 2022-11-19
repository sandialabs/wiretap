// Package peer contains functions to perform configuration and validation operations on devices and peers.
package peer

import (
	"encoding/base64"
	"encoding/hex"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
