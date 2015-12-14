/*
Package detour provides a net.Conn interface which detects blockage
of a site automatically and access it through alternative connection.

Basically, if a site is not whitelisted, following steps will be taken:
1. Dial proxied connection (detour) a small delay after dialed directly
2. Return to caller when any connection is established
3. Read/write through all open connections in parallel
4. Check for blockage on direct connection and closes it if it happens
5. If possible, replay operations on detour connection. [1]
6. After sucessfully read from a connection, stick with it and close others.
7. Add those sites failed on direct connection but succeeded on detour ones
   to proxied list, so above steps can be skipped next time. The list can be
   exported and persisted if required.

Blockage can happen at several stages of a connection, what detour can detect are:
1. Connection attempt is blocked (IP blocking / DNS hijack).
   Symptoms can be connection time out / TCP RST / connection refused.
2. Connection made but real data get blocked (DPI).
3. Successfully exchanged a few packets, while follow up packets are blocked. [2]
4. Connection made but get fake response or HTTP redirect to a fixed URL.

[1] Detour will not replay nonidempotent plain HTTP requests, but will add it to
    proxied list to be detoured next time.
[2] Detour can only handle exact 1 successful read followed by failed read,
    which covers most cases in reality.
*/
package detour

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/golog"
)

// If no any connection made after this period, stop dialing and fail
var TimeoutToConnect = 30 * time.Second

// To avoid unnecessarily proxy not-blocked url, detour will dial detour connection
// after this small delay. Set to zero to dial in parallel to not introducing any delay.
var DelayBeforeDetour = 0 * time.Millisecond

// If DirectAddrCh is set, when a direct connection is closed without any error,
// the connection's remote address (in host:port format) will be send to it
var DirectAddrCh = make(chan string)

var (
	log = golog.LoggerFor("detour")
)

// Conn implements an net.Conn interface by utilizing underlie direct and
// detour connections.
type Conn struct {
	// Keeps track of the total bytes read from this connection, atomic
	// Due to https://golang.org/pkg/sync/atomic/#pkg-note-BUG it requires
	// manual alignment. For this, it is best to keep it as the first field
	readBytes uint64

	// The chan to notify dialer to dial detour immediately
	chDialDetourNow chan bool
	chConnToIOLoop  chan conn
	chClose         chan struct{}
	chGetAddr       chan getAddrRequest
	chReadRequest   chan ioRequest
	chWriteRequest  chan ioRequest

	addr string

	muWriteBuffer sync.RWMutex
	// Keeps written bytes through direct connection to replay it if required.
	writeBuffer *bytes.Buffer
	// Is it a plain HTTP request or not, atomic
	nonidempotentHTTPRequest uint32
}

// The data structure to pass result of io operation back from underlie connection
type ioResult struct {
	buf []byte
	// Number of bytes read/wrote
	n int
	// IO error, if any
	err error
}

type ioRequest struct {
	buf      []byte
	chResult chan ioResult
}

type getAddrRequest struct {
	isLocal  bool
	chResult chan net.Addr
}

type connType int

const (
	connTypeDirect connType = iota
	connTypeDetour connType = iota
)

var connTypeDesc = []string{"direct", "detour"}

func (c connType) String() string {
	return connTypeDesc[c]
}

type conn interface {
	Type() connType
	Read(b []byte, isFirst bool) (int, error)
	Write(b []byte) (int, error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type dialFunc func(network, addr string) (net.Conn, error)

// Dialer returns a function with same signature of net.Dialer.Dial().
func Dialer(detourDialer dialFunc) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		dc := &Conn{
			addr:            addr,
			writeBuffer:     new(bytes.Buffer),
			chConnToIOLoop:  make(chan conn),
			chClose:         make(chan struct{}),
			chReadRequest:   make(chan ioRequest),
			chWriteRequest:  make(chan ioRequest),
			chDialDetourNow: make(chan bool),
			chGetAddr:       make(chan getAddrRequest),
		}

		type dialResult struct {
			c   conn
			err error
		}
		ch := make(chan dialResult)
		numDial := 1
		if !whitelisted(addr) {
			numDial = 2
		}
		go func() {
			if numDial == 2 {
				go func() {
					c, err := dialDirect(network, addr)
					ch <- dialResult{c, err}
				}()
				dt := time.NewTimer(DelayBeforeDetour)
				defer dt.Stop()
				select {
				case <-dt.C:
				case <-dc.chDialDetourNow:
				}
				if dc.anyDataReceived() {
					return
				}
			}
			go func() {
				c, err := dialDetour(network, addr, detourDialer)
				ch <- dialResult{c, err}
			}()
		}()

		chLastError := make(chan error, 2)
		go func() {
			var res dialResult
			for i := 0; i < numDial; i++ {
				res = <-ch
				if res.err == nil {
					dc.chConnToIOLoop <- res.c
					chLastError <- nil
				}
			}
			chLastError <- res.err
		}()

		go dc.ioLoop()
		t := time.NewTimer(TimeoutToConnect)
		defer t.Stop()
		select {
		case lastError := <-chLastError:
			if lastError != nil {
				return nil, lastError
			}
			return dc, nil
		case <-t.C:
			return nil, fmt.Errorf("Timeout dialing any connection to %s", addr)
		}
	}
}

// ioLoop waits for connections and handles read/write requests
func (dc *Conn) ioLoop() {
	// Use buffered channel in same goroutine so we can easily add / remove
	// connections. Should switch to container/ring if performace matters.
	chConns := make(chan conn, 2)
	chRemoveConn := make(chan conn, 2)
	var firstReadReq *ioRequest
	for {
		select {
		case c := <-dc.chConnToIOLoop:
			log.Tracef("I/O loop got %s connection to %s", c.Type(), dc.addr)
			if dc.anyDataReceived() {
				log.Debugf("%s connection to %s available after data received, closing", c.Type(), dc.addr)
				closeConn(c)
				continue
			}
			chConns <- c
			if firstReadReq != nil {
				if !dc.replay(c) {
					continue
				}
				go func() {
					n, err := c.Read(firstReadReq.buf, true)
					if err != nil {
						log.Debugf("Read from %s connection to %s failed: %s", c.Type(), dc.addr, err)
					} else {
						log.Tracef("Read %d bytes from %s connection to %s", n, c.Type(), dc.addr)
					}
					firstReadReq.chResult <- ioResult{firstReadReq.buf, n, err}
				}()
			}
		case r := <-chRemoveConn:
			tries := len(chConns)
			for i := 0; i < tries; i++ {
				c := <-chConns
				if c != r {
					chConns <- c
				}
			}
		case req := <-dc.chReadRequest:
			tries := len(chConns)
			chs := make(chan ioResult, tries)
			first := !dc.anyDataReceived()
			if first {
				firstReadReq = &ioRequest{make([]byte, len(req.buf)), chs}
			}
			for i := 0; i < tries; i++ {
				c := <-chConns
				chConns <- c
				buf := make([]byte, len(req.buf))
				go func() {
					log.Tracef("Read via %s connection to %s, first: %v", c.Type(), dc.addr, first)
					n, err := c.Read(buf, first)
					if err != nil && err != io.EOF {
						log.Tracef("Read from %s connection to %s failed, closing: %s", c.Type(), dc.addr, err)
						closeConn(c)
						chRemoveConn <- c
						switch c.Type() {
						case connTypeDirect:
							// if we haven't dial detour yet, do so now
							dc.chDialDetourNow <- true
							return
						case connTypeDetour:
							log.Tracef("Detour connection to %s failed, removing from whitelist", dc.addr)
							RemoveFromWl(dc.addr)
						}
					} else {
						log.Tracef("Read %d bytes from %s connection to %s", n, c.Type(), dc.addr)
						dc.incReadBytes(n)
					}
					chs <- ioResult{buf, n, err}
				}()
			}
			go func() {
				for i := 0; i < tries; i++ {
					result := <-chs
					if result.err != nil && i < tries-1 {
						log.Debugf("Error read from %s, skip", dc.addr)
						continue
					}
					n := copy(req.buf, result.buf[:result.n])
					req.chResult <- ioResult{req.buf, n, result.err}
				}
			}()
		case req := <-dc.chWriteRequest:
			if !dc.anyDataReceived() {
				if isNonidempotentHTTPRequest(req.buf) {
					atomic.StoreUint32(&dc.nonidempotentHTTPRequest, 1)
				} else {
					dc.muWriteBuffer.Lock()
					_, _ = dc.writeBuffer.Write(req.buf)
					dc.muWriteBuffer.Unlock()
				}
			}
			var lastN int
			tries := len(chConns)
			for i := 0; i < tries; i++ {
				c := <-chConns
				if n, err := c.Write(req.buf); err != nil {
					log.Debugf("Error write to %s connection to %s", c.Type(), dc.addr)
					closeConn(c)
				} else {
					log.Tracef("Wrote %v bytes to %s connection to %s", n, c.Type(), dc.addr)
					lastN = n
					chConns <- c
				}
			}
			if lastN > 0 {
				req.chResult <- ioResult{req.buf, lastN, nil}
			} else {
				req.chResult <- ioResult{req.buf, 0, errors.New("fail to write to any connection")}
			}
		case req := <-dc.chGetAddr:
			if len(chConns) == 0 {
				panic("should have at least one valid connection")
			}
			c := <-chConns
			chConns <- c
			if req.isLocal {
				req.chResult <- c.LocalAddr()
			} else {
				req.chResult <- c.RemoteAddr()
			}
		case <-dc.chClose:
			tries := len(chConns)
			for i := 0; i < tries; i++ {
				closeConn(<-chConns)
			}
			return
		}
	}
}

func (dc *Conn) replay(c conn) bool {
	if atomic.LoadUint32(&dc.nonidempotentHTTPRequest) == 1 {
		log.Tracef("Not replay nonidempotent request to %s, only add to whitelist", dc.addr)
		AddToWl(dc.addr, false)
		closeConn(c)
		return false
	}
	dc.muWriteBuffer.RLock()
	defer dc.muWriteBuffer.RUnlock()
	numBytes := dc.writeBuffer.Len()
	if numBytes > 0 {
		log.Tracef("Replay %d previous bytes to %s connection to %s", numBytes, c.Type(), dc.addr)
		if _, err := c.Write(dc.writeBuffer.Bytes()); err != nil {
			log.Debugf("Fail to replay %s bytes to %s", numBytes, dc.addr)
		}
	}
	return true
}

func (dc *Conn) anyDataReceived() bool {
	return atomic.LoadUint64(&dc.readBytes) > 0
}

func (dc *Conn) incReadBytes(n int) {
	atomic.AddUint64(&dc.readBytes, uint64(n))
}

// Read() implements the function from net.Conn
func (dc *Conn) Read(b []byte) (n int, err error) {
	chResult := make(chan ioResult)
	dc.chReadRequest <- ioRequest{b, chResult}
	result := <-chResult
	log.Tracef("Read %d bytes from %s", result.n, dc.addr)
	return result.n, result.err
}

// Write() implements the function from net.Conn
func (dc *Conn) Write(b []byte) (n int, err error) {
	chResult := make(chan ioResult)
	dc.chWriteRequest <- ioRequest{b, chResult}
	result := <-chResult
	if n, err = result.n, result.err; err != nil {
		log.Tracef("Error writing to %s: %s", dc.addr, err)
		return
	}
	log.Tracef("Wrote %d bytes to %s", n, dc.addr)
	return
}

// Close implements the function from net.Conn
func (dc *Conn) Close() error {
	close(dc.chClose)
	return nil
}

// LocalAddr implements the function from net.Conn
func (dc *Conn) LocalAddr() (addr net.Addr) {
	chResult := make(chan net.Addr)
	dc.chGetAddr <- getAddrRequest{true, chResult}
	return <-chResult
}

// RemoteAddr implements the function from net.Conn
func (dc *Conn) RemoteAddr() (addr net.Addr) {
	chResult := make(chan net.Addr)
	dc.chGetAddr <- getAddrRequest{false, chResult}
	return <-chResult
}

// SetDeadline implements the function from net.Conn
func (dc *Conn) SetDeadline(t time.Time) error {
	return fmt.Errorf("SetDeadline not implemented")
}

// SetReadDeadline implements the function from net.Conn
func (dc *Conn) SetReadDeadline(t time.Time) error {
	return fmt.Errorf("SetReadDeadline not implemented")
}

// SetWriteDeadline implements the function from net.Conn
func (dc *Conn) SetWriteDeadline(t time.Time) error {
	return fmt.Errorf("SetWriteDeadline not implemented")
}

func closeConn(c conn) {
	if err := c.Close(); err != nil {
		log.Tracef("Error close %s connection to %s: %s", c.Type(), c.RemoteAddr().String(), err)
	}
}

var nonidempotentMethods = [][]byte{
	[]byte("PUT "),
	[]byte("POST "),
	[]byte("PATCH "),
}

// Ref section 9.1.2 of https://www.ietf.org/rfc/rfc2616.txt.
// We consider the https handshake phase to be idemponent.
func isNonidempotentHTTPRequest(b []byte) bool {
	if len(b) > 4 {
		for _, m := range nonidempotentMethods {
			if bytes.HasPrefix(b, m) {
				return true
			}
		}
	}
	return false
}
