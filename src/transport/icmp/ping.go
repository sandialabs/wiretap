package icmp

import (
	"log"
	"os/exec"
	"runtime"
	"time"

	"github.com/go-ping/ping"
)

// Ping type is an interface for the different methods of performing an unpriveleged ICMP echo request.
type Ping interface {
	ping(string) (bool, error)
}

type socketPing struct{}
type execPing struct{}
type noPing struct{}

func getPing(addr string) (pinger Ping, success bool, err error) {
	pingers := []Ping{socketPing{}, execPing{}, noPing{}}

	for _, p := range pingers {
		s, err := p.ping(addr)
		if err != nil {
			log.Printf("ping method failed: %v", err)
			continue
		}

		return p, s, err
	}

	return noPing{}, false, nil
}

// socketPing attempts to ping destination address via socket. Only some systems
// will allow an unprivileged user to do this.
func (socketPing) ping(addr string) (success bool, err error) {
	pinger, err := ping.NewPinger(addr)
	if err != nil {
		return false, err
	}

	pinger.RecordRtts = false
	pinger.Timeout = 1 * time.Second
	pinger.Count = 1
	err = pinger.Run()
	if err != nil {
		return false, err
	}

	if pinger.PacketsRecv > 0 {
		return true, nil
	} else {
		return false, nil
	}
}

// execPing attempts to ping destination address via ping binary on the local machine.
// This is a last resort used if unable to open ICMP echo socket.
func (execPing) ping(addr string) (success bool, err error) {
	pingPath, err := exec.LookPath("ping")
	if err != nil {
		return false, err
	}

	// ping -count 1 -timeout 1000ms
	// Use platform-specific args.
	var args []string
	switch runtime.GOOS {
	case "windows":
		args = []string{pingPath, "-n", "1", "-w", "1000", addr}
	default:
		args = []string{pingPath, "-c", "1", "-t", "1", addr}
	}

	cmd := &exec.Cmd{
		Path: pingPath,
		Args: args,
	}

	err = cmd.Run()
	if err != nil {
		return false, err
	}

	return true, nil
}

// noPing is a placeholder for when no supported ping method exists on the remote machine.
func (noPing) ping(addr string) (success bool, err error) {
	return false, nil
}
