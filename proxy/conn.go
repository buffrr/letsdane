package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"time"
)

// Conn represents a proxy connection
type Conn struct {
	wh func(int)
	net.Conn
}

// WriteHeader writes an HTTP status header
// to the proxy client. It must be called before
// any writes to ProxyConn otherwise http.StatusOK is written.
func (pc *Conn) WriteHeader(code int) {
	pc.wh(code)
}

// PeekClientHello attempts to read TLS ClientHello from the connection
// without consuming the TLS handshake.
func (pc *Conn) PeekClientHello() (*tls.ClientHelloInfo, error) {
	if err := pc.Conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}

	hello, conn, err := peekClientHello(pc.Conn)
	pc.Conn = conn

	if err := pc.Conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return hello, err
}

// Copy bidirectional copy with dst connection
func (pc *Conn) Copy(dst net.Conn) {
	defer pc.Close()
	defer dst.Close()

	done := make(chan struct{})
	copyFunc := func(dst, src io.ReadWriteCloser) {
		io.Copy(src, dst)
		done <- struct{}{}
	}

	go copyFunc(pc, dst)
	go copyFunc(dst, pc)

	<-done
}

// used if ResponseWriter doesn't implement http.Hijacker
type hijackConn struct {
	io.Writer
	io.ReadCloser
	localAddr, remoteAddr net.Addr
	flush                 func()
}

func (c *hijackConn) Write(b []byte) (n int, err error) {
	n, err = c.Writer.Write(b)
	if c.flush != nil {
		c.flush()
	}
	return
}

func (c *hijackConn) LocalAddr() net.Addr { return c.localAddr }

func (c *hijackConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *hijackConn) SetDeadline(t time.Time) error { return nil }

func (c *hijackConn) SetReadDeadline(t time.Time) error { return nil }

func (c *hijackConn) SetWriteDeadline(t time.Time) error { return nil }

// reads client hello from the given connection without consuming the tls handshake
// returns a newConn that must be used for future operations
func peekClientHello(conn net.Conn) (hello *tls.ClientHelloInfo, newConn net.Conn, err error) {
	p := &peekConn{
		peek: new(bytes.Buffer),
		r:    conn,
	}

	err = tls.Server(p, &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = info
			return nil, nil
		},
	}).Handshake()

	if hello != nil {
		err = nil
	}

	newConn = readerConn{io.MultiReader(p.peek, conn), conn}
	return
}

// a connection that uses the reader r for read ops
type readerConn struct {
	r io.Reader
	net.Conn
}

func (c readerConn) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

// peekConn reads into a buffer, returns io.EOF on writes and fails
// in other operations
type peekConn struct {
	peek *bytes.Buffer
	r    io.Reader
	net.Conn
}

func (c peekConn) Read(p []byte) (n int, err error) {
	n, err = c.r.Read(p)
	if n > 0 {
		if n, err := c.peek.Write(p[:n]); err != nil {
			return n, err
		}
	}
	return
}

func (c peekConn) Write(p []byte) (int, error) { return 0, io.EOF }
