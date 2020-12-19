package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
)

// Tunneler is an interface representing the ability to handle a
// single HTTP CONNECT request by opening a tunnel for a given Request.
type Tunneler interface {
	// Tunnel opens a tunnel for a given request
	// between clientConn and the target addr
	Tunnel(ctx context.Context, clientConn *Conn, network, addr string)
}

// A Handler implements http.Handler for running a proxy.
type Handler struct {
	// Tunneler specifies the mechanism for handling HTTP CONNECT
	// tunnels.
	Tunneler Tunneler

	// NonConnect is used for all other HTTP requests where HTTP method != CONNECT
	NonConnect http.Handler
}

type netAddr struct {
	network, value string
}

func (p netAddr) Network() string {
	return p.network
}

func (p netAddr) String() string {
	return p.value
}

// The TunnelerFunc type is an adapter to allow the use of
// an ordinary function as a tunneler.
type TunnelerFunc func(ctx context.Context, clientConn *Conn, network, addr string)

func (t TunnelerFunc) Tunnel(ctx context.Context, clientConn *Conn, network, addr string) {
	t(ctx, clientConn, network, addr)
}

func (p *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodConnect {
		p.NonConnect.ServeHTTP(w, req)
		return
	}

	conn, writeHeader := hijacker(w, req)
	pc := Conn{
		wh:   writeHeader,
		Conn: conn,
	}

	addr := req.URL.Host
	if addr == "" {
		pc.WriteHeader(http.StatusBadRequest)
		pc.Close()
		return
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		pc.WriteHeader(http.StatusBadRequest)
		pc.Close()
		return
	}

	network := "tcp"
	if pc.LocalAddr() != nil {
		network = pc.LocalAddr().Network()
	}

	p.Tunneler.Tunnel(context.Background(), &pc, network, addr)
}

// hijacker takes over the connection used by http.ResponseWriter
// if the response writer does not implement http.Hijacker it will attempt
// to read from the request body and use http.Flusher if available
func hijacker(w http.ResponseWriter, req *http.Request) (c net.Conn, writeHeader func(int)) {
	var err error
	var hijacked bool

	if h, ok := w.(http.Hijacker); ok {
		c, _, err = h.Hijack()
		if err != nil {
			panic("hijacking failed")
		}
		hijacked = true
	}

	writeHeader = func(code int) {
		fmt.Fprintf(c, "HTTP/1.1 %d %s\r\n\r\n", code, http.StatusText(code))
	}

	var localAddr, remoteAddr net.Addr
	if addr, ok := req.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		localAddr = addr
		remoteAddr = netAddr{addr.Network(), req.RemoteAddr}
	}

	if !hijacked {
		rwc := &hijackConn{
			Writer:     w,
			ReadCloser: req.Body,
			localAddr:  localAddr,
			remoteAddr: remoteAddr,
		}
		if f, ok := rwc.Writer.(http.Flusher); ok {
			rwc.flush = func() {
				f.Flush()
			}
		}

		writeHeader = func(code int) {
			w.WriteHeader(code)
			rwc.flush()
		}

		c = rwc
	}

	return
}
