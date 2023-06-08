// Copy of gvisor gonet TCPListener so we can implement new method that gets correct remote address even after connection has closed.
// Modifications have been made to the original file.
// TODO: Raise issue with gvisor about RemoteAddress() behavior so this can be removed.
package tcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

//  Address conversion adapted from https://git.zx2c4.com/wireguard-go/tree/tun/netstack/tun.go.
/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

// Reimplementation of the private function netstack.convertToFullAddr.
func convertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.Address(endpoint.Addr().AsSlice()),
		Port: endpoint.Port(),
	}, protoNumber
}

// Reimplementation of netstack.Net.ListenTCP to call custom ListenTCP.
func listenTCP(s *stack.Stack, laddr *net.TCPAddr) (*TCPListener, error) {
	ip, _ := netip.AddrFromSlice(laddr.IP)
	addrPort := netip.AddrPortFrom(ip, uint16(laddr.Port))
	addr, network := convertToFullAddr(addrPort)
	return ListenTCP(s, addr, network)
}

// netstack Net adapation ends here.

// Adaptation of gonet TCP adapter from https://github.com/google/gvisor/blob/df1f4cbd9fcbf56fbfc6fab82c4f3930f0343026/pkg/tcpip/adapters/gonet/gonet.go.

// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
var (
	errCanceled = errors.New("operation canceled")
)

// timeoutError is how the net package reports timeouts.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// A TCPListener is a wrapper around a TCP tcpip.Endpoint that implements
// net.Listener.
type TCPListener struct {
	stack      *stack.Stack
	ep         tcpip.Endpoint
	wq         *waiter.Queue
	cancelOnce sync.Once
	cancel     chan struct{}
}

// NewTCPListener creates a new TCPListener from a listening tcpip.Endpoint.
func NewTCPListener(s *stack.Stack, wq *waiter.Queue, ep tcpip.Endpoint) *TCPListener {
	return &TCPListener{
		stack:  s,
		ep:     ep,
		wq:     wq,
		cancel: make(chan struct{}),
	}
}

// maxListenBacklog is set to be reasonably high for most uses of gonet. Go net
// package uses the value in /proc/sys/net/core/somaxconn file in Linux as the
// default listen backlog. The value below matches the default in common linux
// distros.
//
// See: https://cs.opensource.google/go/go/+/refs/tags/go1.18.1:src/net/sock_linux.go;drc=refs%2Ftags%2Fgo1.18.1;l=66
const maxListenBacklog = 4096

// ListenTCP creates a new TCPListener.
func ListenTCP(s *stack.Stack, addr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*TCPListener, error) {
	// Create a TCP endpoint, bind it, then start listening.
	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, errors.New(err.String())
	}

	if err := ep.Bind(addr); err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "bind",
			Net:  "tcp",
			Addr: fullToTCPAddr(addr),
			Err:  errors.New(err.String()),
		}
	}

	if err := ep.Listen(maxListenBacklog); err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "listen",
			Net:  "tcp",
			Addr: fullToTCPAddr(addr),
			Err:  errors.New(err.String()),
		}
	}

	return NewTCPListener(s, &wq, ep), nil
}

// Close implements net.Listener.Close.
func (l *TCPListener) Close() error {
	l.ep.Close()
	return nil
}

// Shutdown stops the HTTP server.
func (l *TCPListener) Shutdown() {
	l.ep.Shutdown(tcpip.ShutdownWrite | tcpip.ShutdownRead)
	l.cancelOnce.Do(func() {
		close(l.cancel) // broadcast cancellation
	})
}

// Addr implements net.Listener.Addr.
func (l *TCPListener) Addr() net.Addr {
	a, err := l.ep.GetLocalAddress()
	if err != nil {
		return nil
	}
	return fullToTCPAddr(a)
}

type deadlineTimer struct {
	// mu protects the fields below.
	mu sync.Mutex

	readTimer     *time.Timer
	readCancelCh  chan struct{}
	writeTimer    *time.Timer
	writeCancelCh chan struct{}
}

func (d *deadlineTimer) init() {
	d.readCancelCh = make(chan struct{})
	d.writeCancelCh = make(chan struct{})
}

func (d *deadlineTimer) readCancel() <-chan struct{} {
	d.mu.Lock()
	c := d.readCancelCh
	d.mu.Unlock()
	return c
}
func (d *deadlineTimer) writeCancel() <-chan struct{} {
	d.mu.Lock()
	c := d.writeCancelCh
	d.mu.Unlock()
	return c
}

// setDeadline contains the shared logic for setting a deadline.
//
// cancelCh and timer must be pointers to deadlineTimer.readCancelCh and
// deadlineTimer.readTimer or deadlineTimer.writeCancelCh and
// deadlineTimer.writeTimer.
//
// setDeadline must only be called while holding d.mu.
func (d *deadlineTimer) setDeadline(cancelCh *chan struct{}, timer **time.Timer, t time.Time) {
	if *timer != nil && !(*timer).Stop() {
		*cancelCh = make(chan struct{})
	}

	// Create a new channel if we already closed it due to setting an already
	// expired time. We won't race with the timer because we already handled
	// that above.
	select {
	case <-*cancelCh:
		*cancelCh = make(chan struct{})
	default:
	}

	// "A zero value for t means I/O operations will not time out."
	// - net.Conn.SetDeadline
	if t.IsZero() {
		return
	}

	timeout := time.Until(t)
	if timeout <= 0 {
		close(*cancelCh)
		return
	}

	// Timer.Stop returns whether or not the AfterFunc has started, but
	// does not indicate whether or not it has completed. Make a copy of
	// the cancel channel to prevent this code from racing with the next
	// call of setDeadline replacing *cancelCh.
	ch := *cancelCh
	*timer = time.AfterFunc(timeout, func() {
		close(ch)
	})
}

// SetReadDeadline implements net.Conn.SetReadDeadline and
// net.PacketConn.SetReadDeadline.
func (d *deadlineTimer) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.readCancelCh, &d.readTimer, t)
	d.mu.Unlock()
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline and
// net.PacketConn.SetWriteDeadline.
func (d *deadlineTimer) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.writeCancelCh, &d.writeTimer, t)
	d.mu.Unlock()
	return nil
}

// SetDeadline implements net.Conn.SetDeadline and net.PacketConn.SetDeadline.
func (d *deadlineTimer) SetDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.readCancelCh, &d.readTimer, t)
	d.setDeadline(&d.writeCancelCh, &d.writeTimer, t)
	d.mu.Unlock()
	return nil
}

// A TCPConn is a wrapper around a TCP tcpip.Endpoint that implements the net.Conn
// interface.
type TCPConn struct {
	deadlineTimer

	wq *waiter.Queue
	ep tcpip.Endpoint

	// readMu serializes reads and implicitly protects read.
	//
	// Lock ordering:
	// If both readMu and deadlineTimer.mu are to be used in a single
	// request, readMu must be acquired before deadlineTimer.mu.
	readMu sync.Mutex
}

// NewTCPConn creates a new TCPConn.
func NewTCPConn(wq *waiter.Queue, ep tcpip.Endpoint) *TCPConn {
	c := &TCPConn{
		wq: wq,
		ep: ep,
	}
	c.deadlineTimer.init()
	return c
}

// Changed from original:
// AcceptFrom is identical to Accept except that it also returns the Remote Address as seen by the endpoint.
func (l *TCPListener) AcceptFrom(c *TcpConfig) (net.Conn, net.Addr, error) {
	remoteAddr := tcpip.FullAddress{}
	n, wq, err := l.ep.Accept(&remoteAddr)

	if _, ok := err.(*tcpip.ErrWouldBlock); ok {
		// Create wait queue entry that notifies a channel.
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		l.wq.EventRegister(&waitEntry)
		defer l.wq.EventUnregister(&waitEntry)

		for {
			n, wq, err = l.ep.Accept(&remoteAddr)

			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				break
			}

			select {
			case <-l.cancel:
				return nil, nil, errCanceled
			case <-notifyCh:
			}
		}
	}

	if err != nil {
		return nil, nil, &net.OpError{
			Op:   "accept",
			Net:  "tcp",
			Addr: l.Addr(),
			Err:  errors.New(err.String()),
		}
	}

	// Enable keepalive and set defaults so that after (idle + (count * interval)) connection will be dropped if unresponsive.
	n.SocketOptions().SetKeepAlive(true)
	keepaliveIdle := tcpip.KeepaliveIdleOption(c.KeepaliveIdle)
	err = n.SetSockOpt(&keepaliveIdle)
	if err != nil {
		return nil, nil, &net.OpError{
			Op:   "accept",
			Net:  "tcp",
			Addr: l.Addr(),
			Err:  errors.New(err.String()),
		}
	}
	keepaliveInterval := tcpip.KeepaliveIntervalOption(c.KeepaliveInterval)
	err = n.SetSockOpt(&keepaliveInterval)
	if err != nil {
		return nil, nil, &net.OpError{
			Op:   "accept",
			Net:  "tcp",
			Addr: l.Addr(),
			Err:  errors.New(err.String()),
		}
	}
	err = n.SetSockOptInt(tcpip.KeepaliveCountOption, c.KeepaliveCount)
	if err != nil {
		return nil, nil, &net.OpError{
			Op:   "accept",
			Net:  "tcp",
			Addr: l.Addr(),
			Err:  errors.New(err.String()),
		}
	}

	return NewTCPConn(wq, n), fullToTCPAddr(remoteAddr), nil
}

// Accept implements net.Conn.Accept.
func (l *TCPListener) Accept() (net.Conn, error) {
	remoteAddr := tcpip.FullAddress{}
	n, wq, err := l.ep.Accept(&remoteAddr)

	if _, ok := err.(*tcpip.ErrWouldBlock); ok {
		// Create wait queue entry that notifies a channel.
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		l.wq.EventRegister(&waitEntry)
		defer l.wq.EventUnregister(&waitEntry)

		for {
			n, wq, err = l.ep.Accept(&remoteAddr)

			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				break
			}

			select {
			case <-l.cancel:
				return nil, errCanceled
			case <-notifyCh:
			}
		}
	}

	if err != nil {
		return nil, &net.OpError{
			Op:   "accept",
			Net:  "tcp",
			Addr: l.Addr(),
			Err:  errors.New(err.String()),
		}
	}

	return NewTCPConn(wq, n), nil
}

type opErrorer interface {
	newOpError(op string, err error) *net.OpError
}

// commonRead implements the common logic between net.Conn.Read and
// net.PacketConn.ReadFrom.
func commonRead(b []byte, ep tcpip.Endpoint, wq *waiter.Queue, deadline <-chan struct{}, addr *tcpip.FullAddress, errorer opErrorer) (int, error) {
	select {
	case <-deadline:
		return 0, errorer.newOpError("read", &timeoutError{})
	default:
	}

	w := tcpip.SliceWriter(b)
	opts := tcpip.ReadOptions{NeedRemoteAddr: addr != nil}
	res, err := ep.Read(&w, opts)

	if _, ok := err.(*tcpip.ErrWouldBlock); ok {
		// Create wait queue entry that notifies a channel.
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
		wq.EventRegister(&waitEntry)
		defer wq.EventUnregister(&waitEntry)
		for {
			res, err = ep.Read(&w, opts)
			if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
				break
			}
			select {
			case <-deadline:
				return 0, errorer.newOpError("read", &timeoutError{})
			case <-notifyCh:
			}
		}
	}

	if _, ok := err.(*tcpip.ErrClosedForReceive); ok {
		return 0, io.EOF
	}

	if err != nil {
		return 0, errorer.newOpError("read", errors.New(err.String()))
	}

	if addr != nil {
		*addr = res.RemoteAddr
	}
	return res.Count, nil
}

// Read implements net.Conn.Read.
func (c *TCPConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	deadline := c.readCancel()

	n, err := commonRead(b, c.ep, c.wq, deadline, nil, c)
	if n != 0 {
		c.ep.ModerateRecvBuf(n)
	}
	return n, err
}

// Write implements net.Conn.Write.
func (c *TCPConn) Write(b []byte) (int, error) {
	deadline := c.writeCancel()

	// Check if deadlineTimer has already expired.
	select {
	case <-deadline:
		return 0, c.newOpError("write", &timeoutError{})
	default:
	}

	// We must handle two soft failure conditions simultaneously:
	//  1. Write may write nothing and return *tcpip.ErrWouldBlock.
	//     If this happens, we need to register for notifications if we have
	//     not already and wait to try again.
	//  2. Write may write fewer than the full number of bytes and return
	//     without error. In this case we need to try writing the remaining
	//     bytes again. I do not need to register for notifications.
	//
	// What is more, these two soft failure conditions can be interspersed.
	// There is no guarantee that all of the condition #1s will occur before
	// all of the condition #2s or visa-versa.
	var (
		r      bytes.Reader
		nbytes int
		entry  waiter.Entry
		ch     <-chan struct{}
	)
	for nbytes != len(b) {
		r.Reset(b[nbytes:])
		n, err := c.ep.Write(&r, tcpip.WriteOptions{})
		nbytes += int(n)
		switch err.(type) {
		case nil:
		case *tcpip.ErrWouldBlock:
			if ch == nil {
				entry, ch = waiter.NewChannelEntry(waiter.WritableEvents)
				c.wq.EventRegister(&entry)
				defer c.wq.EventUnregister(&entry)
			} else {
				// Don't wait immediately after registration in case more data
				// became available between when we last checked and when we setup
				// the notification.
				select {
				case <-deadline:
					return nbytes, c.newOpError("write", &timeoutError{})
				case <-ch:
					continue
				}
			}
		default:
			return nbytes, c.newOpError("write", errors.New(err.String()))
		}
	}
	return nbytes, nil
}

// Close implements net.Conn.Close.
func (c *TCPConn) Close() error {
	c.ep.Close()
	return nil
}

// CloseRead shuts down the reading side of the TCP connection. Most callers
// should just use Close.
//
// A TCP Half-Close is performed the same as CloseRead for *net.TCPConn.
func (c *TCPConn) CloseRead() error {
	if terr := c.ep.Shutdown(tcpip.ShutdownRead); terr != nil {
		return c.newOpError("close", errors.New(terr.String()))
	}
	return nil
}

// CloseWrite shuts down the writing side of the TCP connection. Most callers
// should just use Close.
//
// A TCP Half-Close is performed the same as CloseWrite for *net.TCPConn.
func (c *TCPConn) CloseWrite() error {
	if terr := c.ep.Shutdown(tcpip.ShutdownWrite); terr != nil {
		return c.newOpError("close", errors.New(terr.String()))
	}
	return nil
}

// LocalAddr implements net.Conn.LocalAddr.
func (c *TCPConn) LocalAddr() net.Addr {
	a, err := c.ep.GetLocalAddress()
	if err != nil {
		return nil
	}
	return fullToTCPAddr(a)
}

// RemoteAddr implements net.Conn.RemoteAddr.
func (c *TCPConn) RemoteAddr() net.Addr {
	a, err := c.ep.GetRemoteAddress()
	if err != nil {
		return nil
	}
	return fullToTCPAddr(a)
}

func (c *TCPConn) newOpError(op string, err error) *net.OpError {
	return &net.OpError{
		Op:     op,
		Net:    "tcp",
		Source: c.LocalAddr(),
		Addr:   c.RemoteAddr(),
		Err:    err,
	}
}

func fullToTCPAddr(addr tcpip.FullAddress) *net.TCPAddr {
	return &net.TCPAddr{IP: net.IP(addr.Addr), Port: int(addr.Port)}
}

// DialTCP creates a new TCPConn connected to the specified address.
func DialTCP(s *stack.Stack, addr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*TCPConn, error) {
	return DialContextTCP(context.Background(), s, addr, network)
}

// DialTCPWithBind creates a new TCPConn connected to the specified
// remoteAddress with its local address bound to localAddr.
func DialTCPWithBind(ctx context.Context, s *stack.Stack, localAddr, remoteAddr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*TCPConn, error) {
	// Create TCP endpoint, then connect.
	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, errors.New(err.String())
	}

	// Create wait queue entry that notifies a channel.
	//
	// We do this unconditionally as Connect will always return an error.
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Bind before connect if requested.
	if localAddr != (tcpip.FullAddress{}) {
		if err = ep.Bind(localAddr); err != nil {
			return nil, fmt.Errorf("ep.Bind(%+v) = %s", localAddr, err)
		}
	}

	err = ep.Connect(remoteAddr)
	if _, ok := err.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-ctx.Done():
			ep.Close()
			return nil, ctx.Err()
		case <-notifyCh:
		}

		err = ep.LastError()
	}
	if err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "connect",
			Net:  "tcp",
			Addr: fullToTCPAddr(remoteAddr),
			Err:  errors.New(err.String()),
		}
	}

	return NewTCPConn(&wq, ep), nil
}

// DialContextTCP creates a new TCPConn connected to the specified address
// with the option of adding cancellation and timeouts.
func DialContextTCP(ctx context.Context, s *stack.Stack, addr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*TCPConn, error) {
	return DialTCPWithBind(ctx, s, tcpip.FullAddress{} /* localAddr */, addr /* remoteAddr */, network)
}

// gonet adaptation ends here.
