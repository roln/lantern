/*
Package detour provides a net.Conn interface which detects blockage of a
site automatically and access it through alternative connection.

Basically, if a site is not whitelisted, following steps will be taken:

1. Dial proxied connection (detour) a small delay after dialed directly.

2. Return to caller when any connection is established.

3. Read/write through all open connections in parallel.

4. Check for blockage on direct connection and closes it if it happens.

5. If possible, replay operations on detour connection[1].

6. After sucessfully read from a connection, stick with it and close others.

7. Add those sites failed on direct connection but succeeded on detour ones to
proxied list, so above steps can be skipped next time. The list can be exported
and persisted if required.

8. Caller can optionally provide a channel to receive the sites which can be
accessed directly without any error.

Blockage can happen at several stages of a connection, what detour can detect
are:

1. Connection attempt is blocked (IP blocking / DNS hijack). Symptoms can be
connection time out / connection refused / TCP RST.

2. Connection made but not able to transfer any data (DPI).

3. Successfully sent a few packets, but failed to receive any data[2].

4. Connection made but get fake response or HTTP redirect to a fixed URL.

[1] Detour will not replay nonidempotent plain HTTP requests, but will add it
to proxied list to be detoured next time.
*/
package detour

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/golog"
)

// If no any connection made after this period, stop dialing and fail
var TimeoutToConnect = 30 * time.Second

// To avoid unnecessarily proxy not-blocked url, detour will dial detour
// connection after this small delay. Set to zero will dial in parallel, hence not
// introducing any delay.
var DelayBeforeDetour = 0 * time.Millisecond

// If DirectAddrCh is set, when a direct connection is closed without any error,
// the connection's remote address (in host:port format) will be send to it.
var DirectAddrCh = make(chan string)

// Conn implements an net.Conn interface by utilizing underlie direct and
// detour connections.
type Conn struct {
	// Keeps track of the total bytes read from this connection, atomic
	// Due to https://golang.org/pkg/sync/atomic/#pkg-note-BUG it requires
	// manual alignment. For this, it is best to keep it as the first field
	readBytes uint64

	// The chan to notify dialer to dial detour immediately
	chDialDetourNow chan bool
	// chan to pass connections to I/O loop
	chConnToIOLoop chan conn
	// a signal to close connections
	chClose chan struct{}
	closed  uint32
	// signal I/O loop to get local or remote addr
	chGetAddr chan getAddrRequest
	// signal I/O loop to read
	chReadRequest chan readRequest
	// signal I/O loop to write
	chWriteRequest chan writeRequest

	// the target address to visit
	addr string

	muWriteBuffer sync.RWMutex
	// Keeps written bytes through direct connection to replay it if required.
	writeBuffer bytes.Buffer
	// Is it a plain HTTP request or not, atomic
	nonidempotentHTTPRequest uint32
}

// to pass result of read operation back from underlie connection
type readResult struct {
	// buffer to hold the received data, it's not necessarily the same buffer as readRequest.
	buf []byte
	// IO error, if any
	err error
}

type readRequest struct {
	buf      []byte
	chResult chan readResult
}

// to pass result of write operation back from underlie connection
type writeResult struct {
	// bytes written
	n int
	// IO error, if any
	err error
}

type writeRequest struct {
	buf      []byte
	chResult chan writeResult
}

type getAddrRequest struct {
	isLocal  bool
	chResult chan net.Addr
}

type conn interface {
	Type() connType
	Read(b []byte, isFirst bool) (int, error)
	Write(b []byte) (int, error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type connType int

const (
	connTypeDirect connType = iota
	connTypeDetour connType = iota
)

var connTypeDesc = []string{"direct", "detour"}

func (c connType) String() string { return connTypeDesc[c] }

var log = golog.LoggerFor("detour")

type dialFunc func(network, addr string) (net.Conn, error)

// Dialer returns a function with same signature of net.Dialer.Dial().
func Dialer(detourDialer dialFunc) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		dc := &Conn{
			addr:            addr,
			chConnToIOLoop:  make(chan conn),
			chClose:         make(chan struct{}),
			chReadRequest:   make(chan readRequest),
			chWriteRequest:  make(chan writeRequest),
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
		// Dialing logic
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
		// Merge dialing results. Run until all dialing attempts return
		// to avoid leaking connections.
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
		// Wait for first available connection and return, or fail if none available.
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

// ioLoop is the core of detour. It waits for connections and handles read/write requests
func (dc *Conn) ioLoop() {
	// Use buffered channel in same goroutine so we can easily add / remove
	// connections. Should switch to container/ring if performace matters.
	chConns := make(chan conn, 2)
	// Requests ioLoop to remove already closed connections.
	chRemoveConn := make(chan conn)
	// Hold the read request so we can re-read after replay.
	var firstReadReq *readRequest
	for {
		select {
		case c := <-dc.chConnToIOLoop:
			log.Tracef("***I/O loop got %s connection to %s", c.Type(), dc.addr)
			if dc.anyDataReceived() {
				log.Debugf("%s connection to %s available after data received, closing", c.Type(), dc.addr)
				closeConn(c)
				continue
			}
			var reRead bool
			if firstReadReq != nil {
				if !dc.replay(c) {
					closeConn(c)
					continue
				}
				reRead = true
			}
			chConns <- c
			// spawn goroutine after above statement so channel operations is in determined order
			if reRead {
				go func() {
					buf := make([]byte, len(firstReadReq.buf))
					n, err := c.Read(buf, true)
					if err != nil {
						log.Debugf("Read from %s connection to %s failed: %s", c.Type(), dc.addr, err)
						closeConn(c)
						// select on dc.chClose to avoid blocking on a channel with no receiver.
						// same hereafter.
						select {
						case <-dc.chClose:
						case chRemoveConn <- c:
						}
					} else {
						log.Tracef("Re-read %d bytes from %s connection to %s", n, c.Type(), dc.addr)
					}
					firstReadReq.chResult <- readResult{buf[:n], err}
				}()
			}
		case r := <-chRemoveConn:
			log.Trace("***I/O loop got remove connection request")
			tries := len(chConns)
			for i := 0; i < tries; i++ {
				c := <-chConns
				if c != r {
					chConns <- c
				}
			}
		case req := <-dc.chReadRequest:
			log.Trace("***I/O loop got read request")
			chMergeReads := make(chan readResult)
			first := !dc.anyDataReceived()
			if first {
				firstReadReq = &readRequest{req.buf, chMergeReads}
			}
			tries := len(chConns)
			// read from all valid connections, typically only one
			for i := 0; i < tries; i++ {
				c := <-chConns
				chConns <- c
				buf := make([]byte, len(req.buf))
				go func() {
					log.Tracef("Read via %s connection to %s, first: %v", c.Type(), dc.addr, first)
					n, err := c.Read(buf, first)
					if err != nil {
						log.Tracef("Read from %s connection to %s failed, closing: %s", c.Type(), dc.addr, err)
						closeConn(c)
						select {
						case <-dc.chClose:
						case chRemoveConn <- c:
						}
						switch c.Type() {
						case connTypeDirect:
							// if we haven't dial detour yet, do so now
							// just a hint, skip if no receiver
							select {
							case dc.chDialDetourNow <- true:
							default:
							}
						case connTypeDetour:
							log.Tracef("Detour connection to %s failed, removing from whitelist", dc.addr)
							RemoveFromWl(dc.addr)
						}
					} else {
						log.Tracef("Read %d bytes from %s connection to %s", n, c.Type(), dc.addr)
					}
					chMergeReads <- readResult{buf[:n], err}
				}()
			}
			// Merge read responses, return first succeeded one to caller and ignore later, or return the last error if both failed.
			// Fixed to 2 because the response of re-read request also goes here.
			go func() {
				var got bool
				for i := 0; i < 2; i++ {
					result := <-chMergeReads
					if result.err != nil && i == 0 {
						log.Debugf("Error read from %s, ignore: %s", dc.addr, result.err)
						continue
					}
					if got {
						log.Tracef("Ignore late copy of response from %s", dc.addr)
						continue
					}
					n := len(result.buf)
					if n > 0 {
						_ = copy(req.buf, result.buf)
					}
					req.chResult <- readResult{req.buf[:n], result.err}
					got = true
				}
			}()
		case req := <-dc.chWriteRequest:
			log.Trace("***I/O loop got write request")
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
				req.chResult <- writeResult{lastN, nil}
			} else {
				req.chResult <- writeResult{0, errors.New("fail to write to any connection")}
			}
		case req := <-dc.chGetAddr:
			log.Trace("***I/O loop got GetAddr request")
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
			log.Trace("***I/O loop got close request")
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
		return false
	}
	dc.muWriteBuffer.RLock()
	defer dc.muWriteBuffer.RUnlock()
	numBytes := dc.writeBuffer.Len()
	if numBytes == 0 {
		return false
	}
	log.Tracef("Replay %d previous bytes to %s connection to %s", numBytes, c.Type(), dc.addr)
	if _, err := c.Write(dc.writeBuffer.Bytes()); err != nil {
		log.Debugf("Fail to replay %s bytes to %s: %s", numBytes, dc.addr, err)
		return false
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
	ch := make(chan readResult)
	select {
	case <-dc.chClose:
		return 0, errors.New("read after closed")
	case dc.chReadRequest <- readRequest{b, ch}:
	}
	result := <-ch
	n, err = len(result.buf), result.err
	dc.incReadBytes(n)
	return

}

// Write() implements the function from net.Conn
func (dc *Conn) Write(b []byte) (n int, err error) {
	ch := make(chan writeResult)
	select {
	case <-dc.chClose:
		return 0, errors.New("read after closed")
	case dc.chWriteRequest <- writeRequest{b, ch}:
	}
	result := <-ch
	return result.n, result.err
}

// Close implements the function from net.Conn
func (dc *Conn) Close() error {
	// prevent multiple call of Close() from panicking
	if atomic.LoadUint32(&dc.closed) == 0 {
		close(dc.chClose)
		atomic.StoreUint32(&dc.closed, 1)
	}
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

// close with trace
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

// Ref https://tools.ietf.org/html/rfc2616#section-9.1.2
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
