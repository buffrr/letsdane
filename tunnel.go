package letsdane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/buffrr/letsdane/proxy"
	"github.com/buffrr/letsdane/resolver"
	"github.com/miekg/dns"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

const (
	Version   = "0.5"
	statusErr = "err"
)

type Config struct {
	Certificate    *x509.Certificate
	PrivateKey     interface{}
	Validity       time.Duration
	Resolver       resolver.Resolver
	Constraints    bool
	SkipNameChecks bool
	Verbose        bool
}

type tunneler struct {
	mitm        *mitmConfig
	dialer      *dialer
	nameChecks  bool
	constraints bool
	logger
}

func (h *tunneler) Tunnel(ctx context.Context, clientConn *proxy.Conn, network, addr string) {
	defer clientConn.Close()

	addrs, tlsa, err := h.dialer.resolveDANE(network, addr, h.constraints)
	if err == errBadHost {
		h.warnf("bad host", http.StatusBadRequest, addr)
		clientConn.WriteHeader(http.StatusBadRequest)
		return
	}
	if err != nil {
		h.warnf("%v", http.StatusBadGateway, addr, err)
		clientConn.WriteHeader(http.StatusBadGateway)
		return
	}
	if len(addrs.IPs) == 0 {
		h.warnf("no such host", http.StatusBadGateway, addr)
		clientConn.WriteHeader(http.StatusBadGateway)
		return
	}
	if !tlsaSupported(tlsa) {
		tlsa = []*dns.TLSA{}
	}

	if len(tlsa) == 0 {
		remote, err := h.dialer.dialAddrList(ctx, network, addrs)
		if err != nil {
			h.warnf("dial remote host failed: %v", http.StatusBadGateway, addr, err)
			clientConn.WriteHeader(http.StatusBadGateway)
			return
		}

		h.logf("tunnel established %s", http.StatusOK, addr, remote.RemoteAddr().String())
		clientConn.WriteHeader(http.StatusOK)
		clientConn.Copy(remote)
		return
	}

	// we must establish the tunnel to read client hello
	clientConn.WriteHeader(http.StatusOK)
	hello, err := clientConn.PeekClientHello()
	if err != nil {
		h.warnf("read client hello: %v", statusErr, addr, err)
		return
	}

	tlsaDomain := addrs.Host
	if tlsaDomain != hello.ServerName {
		h.warnf("client sni `%s` does not match tlsa domain `%s`", statusErr, addr, hello.ServerName, tlsaDomain)
		return
	}

	alpn := false
	daneConfig := newTLSConfig(tlsaDomain, tlsa, h.nameChecks)
	if len(hello.SupportedProtos) > 0 {
		daneConfig.NextProtos = hello.SupportedProtos
		alpn = true
	}

	remote, err := h.dialer.dialTLSContext(ctx, network, addrs, daneConfig)
	if _, ok := err.(*tlsError); ok {
		terminateTLSHandshake(clientConn)
	}
	if err != nil {
		h.warnf("dial remote host failed: %v", statusErr, addr, err)
		return
	}
	defer remote.Close()

	// create certificate & negotiate the same protocol
	// used by the remote server
	clientTLSConfig := h.mitm.configForTLSADomain(tlsaDomain)
	if alpn {
		clientTLSConfig.NextProtos = []string{remote.ConnectionState().NegotiatedProtocol}
	}

	clientTLS := tls.Server(clientConn, clientTLSConfig)
	if err := clientTLS.Handshake(); err != nil {
		h.warnf("client handshake failed: %v", statusErr, addr, err)
		return
	}

	h.logf("dane tunnel established %s", http.StatusOK, addr, remote.RemoteAddr().String())
	copyConn(clientTLS, remote)
}

func (c *Config) NewHandler() (*proxy.Handler, error) {
	p := &proxy.Handler{}

	mitm, err := newMITMConfig(c.Certificate, c.PrivateKey, c.Validity, "DNSSEC")
	if err != nil {
		return nil, err
	}

	dialer := newDialer()
	dialer.resolver = c.Resolver

	p.Tunneler = &tunneler{
		mitm:       mitm,
		dialer:     dialer,
		nameChecks: !c.SkipNameChecks,
		logger: logger{
			prefix:  "tunnel: %v CONNECT %s ",
			verbose: c.Verbose,
		},
		constraints: c.Constraints,
	}

	httpProxy := &httputil.ReverseProxy{
		Director:  func(req *http.Request) {},
		Transport: httpOnlyRoundTripper(dialer),
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			httpError(w, err.Error(), http.StatusBadGateway)
			if rws, ok := w.(*rwStatusReader); ok {
				rws.err = err
			}
		},
	}

	p.NonConnect = http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rws := &rwStatusReader{ResponseWriter: rw}
		defer func() {
			if rws.err != nil {
				log.Printf("[WARN] http: %s %s %s://%s%s: %v", statusErr, req.Method,
					req.URL.Scheme, req.URL.Host, req.URL.Path, rws.err)
				return
			}
			if c.Verbose {
				log.Printf("[INFO] http: %d %s %s://%s%s", rws.status, req.Method,
					req.URL.Scheme, req.URL.Host, req.URL.Path)
			}
		}()

		if !req.URL.IsAbs() {
			httpError(rws, "Invalid URL", http.StatusBadRequest)
			return
		}
		if req.URL.Scheme == "" {
			httpError(rws, "Missing protocol scheme", http.StatusBadRequest)
			return
		}
		if req.URL.Scheme != "http" {
			httpError(rws, "Unsupported scheme", http.StatusNotImplemented)
			return
		}

		httpProxy.ServeHTTP(rws, req)
	})

	return p, nil
}

func httpError(w http.ResponseWriter, error string, code int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	fmt.Fprintf(w, "<h1>%d %s</h1><p>%s</p><hr>letsdane/v%s",
		code, http.StatusText(code), html.EscapeString(error), Version)
}

type rwStatusReader struct {
	http.ResponseWriter
	status int
	err    error
}

func (rw *rwStatusReader) WriteHeader(statusCode int) {
	rw.ResponseWriter.WriteHeader(statusCode)
	rw.status = statusCode
}

func (c *Config) Run(addr string) error {
	h, err := c.NewHandler()
	if err != nil {
		return err
	}

	return http.ListenAndServe(addr, h)
}

func copyConn(dst net.Conn, src net.Conn) {
	defer src.Close()
	defer dst.Close()

	done := make(chan struct{})
	copyFunc := func(dst, src io.ReadWriteCloser) {
		io.Copy(src, dst)
		done <- struct{}{}
	}

	go copyFunc(src, dst)
	go copyFunc(dst, src)

	<-done
}

// inConstraints checks if a domain is in nameConstraints
func inConstraints(domain string) bool {
	l := len(domain)

	if l != 0 && domain[l-1] == '.' {
		l--
		domain = domain[0:l]
	}
	for i := l - 1; i >= 0; i-- {
		if domain[i] == '.' {
			domain = domain[i+1:]
			break
		}
	}

	_, ok := nameConstraints[domain]
	return ok
}

type logger struct {
	prefix  string
	verbose bool
}

func (l logger) logf(format string, args ...interface{}) {
	if l.verbose {
		log.Printf("[INFO] "+l.prefix+format, args...)
	}
}

func (l logger) warnf(format string, args ...interface{}) {
	log.Printf("[WARN] "+l.prefix+format, args...)
}
