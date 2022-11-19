// Package api handles client-side API requests.
package api

import (
	"bytes"
	"errors"
	"io"
	"net/http"
)

// Request packages a URL, method, and request body.
type Request struct {
	URL    string
	Method string
	Body   []byte
}

// MakeRequest attempts to send an API query to the Wiretap server.
func MakeRequest(req Request) ([]byte, error) {
	client := &http.Client{}
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
