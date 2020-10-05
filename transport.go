package letsdane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/buffrr/letsdane/resolver"
	"github.com/miekg/dns"
	"net"
	"net/http"
	"time"
)

// Timeouts used in the dialer and http transport.
const (
	Timeout               = 30 * time.Second
	KeepAlive             = 30 * time.Second
	TLSHandshakeTimeout   = 10 * time.Second
	ExpectContinueTimeout = time.Second
)

var dialer = net.Dialer{
	Timeout:   Timeout,
	KeepAlive: KeepAlive,
}

type tlsError struct {
	err string
}

func (t *tlsError) Error() string {
	return t.err
}

// roundTripper creates a round tripper capable of performing DANE/TLSA
// verification. Uses the given resolver for dns lookups.
func roundTripper(rs resolver.Resolver) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
			return dialContextResolver(ctx, network, addr, rs)
		},
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if res, ok := ctx.Value("dialConfig").(*tlsDialConfig); ok {
				if res.Fail != nil {
					return nil, fmt.Errorf("transport: %v", res.Fail)
				}
				if network != res.Network {
					return nil, fmt.Errorf("transport: specified network %s does not match network %s in tlsa record", network, res.Network)
				}

				res.Config = newDANEConfig(res.Host, res.TLSA)
				return dialTLSContext(ctx, res)
			}
			return nil, fmt.Errorf("transport: no dial config available for %s", address)
		},
		TLSHandshakeTimeout:   TLSHandshakeTimeout,
		ExpectContinueTimeout: ExpectContinueTimeout,
	}
}

// newDANEConfig creates a new tls configuration capable of validating DANE.
func newDANEConfig(host string, rrs []*dns.TLSA) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection:   verifyConnection(rrs),
		ServerName:         host,
	}
}

// verifyConnection returns a function that verifies the given tls connection state using the tlsa rrs
func verifyConnection(rrs []*dns.TLSA) func(cs tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		// DANE-EE verification
		// https://tools.ietf.org/html/rfc7671
		// https://tools.ietf.org/html/rfc6698
		// 1) validate the supplied chain is correct
		// there is nothing to trust here yet
		// what's important is the leaf certificate
		opts := x509.VerifyOptions{
			Roots:         x509.NewCertPool(),
			Intermediates: x509.NewCertPool(),
			// ignore leaf certificate name checking for DANE-EE
			DNSName: "",
			// the expiration date of the server certificate MUST be ignored as well.
			// https://tools.ietf.org/html/rfc7671#section-5.1
			CurrentTime: cs.PeerCertificates[0].NotBefore,
		}
		opts.Roots.AddCert(cs.PeerCertificates[len(cs.PeerCertificates)-1])
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
			return &tlsError{err: fmt.Sprintf("transport: verify chain failed: %s", err)}
		}

		// 2) Verify the leaf certificate against the TLSA rrs
		for _, t := range rrs {
			if t.Usage != 3 {
				continue
			}
			if err := t.Verify(cs.PeerCertificates[0]); err == nil {
				return nil
			}
		}
		return &tlsError{err: "transport: dane verification failed"}
	}
}

// dialTLSContext connects to the network using the dst configuration and initiates a TLS handshake.
func dialTLSContext(ctx context.Context, dst *tlsDialConfig) (*tls.Conn, error) {
	tlsDialer := &tls.Dialer{
		NetDialer: &dialer,
		Config:    dst.Config,
	}

	// TODO: use async dialing
	for _, ip := range dst.IPs {
		ipaddr := net.JoinHostPort(ip.String(), dst.Port)
		conn, err := tlsDialer.DialContext(ctx, dst.Network, ipaddr)
		if err != nil {
			if err, ok := err.(*tlsError); ok {
				return nil, err
			}
			continue
		}
		return conn.(*tls.Conn), nil
	}

	return nil, fmt.Errorf("transport: could not reach %s", dst.Host)
}

// dialFunc returns a dial function that uses the given resolver.
func dialFunc(rs resolver.Resolver) func(network string, addr string) (net.Conn, error) {
	return func(network string, addr string) (net.Conn, error) {
		return dialContextResolver(context.Background(), network, addr, rs)
	}
}

// dialContextResolver connects to the address on the named network using the provided context and resolver.
func dialContextResolver(ctx context.Context, network, addr string, rs resolver.Resolver) (net.Conn, error) {
	_, port, ips, err := resolveAddr(addr, rs)
	if err != nil {
		return nil, err
	}

	// TODO: use async dialing
	for _, ip := range ips {
		ipaddr := net.JoinHostPort(ip.String(), port)
		conn, err := dialer.DialContext(ctx, network, ipaddr)
		if err != nil {
			continue
		}
		return conn, nil
	}

	return nil, fmt.Errorf("transport: could not reach %s", addr)
}

func resolveAddr(addr string, rs resolver.Resolver) (host, port string, ips []net.IP, err error) {
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return
	}
	ips, err = rs.LookupIP(host, false)
	if err != nil {
		return
	}
	if len(ips) == 0 {
		err = fmt.Errorf("transport: lookup %s no such host", addr)
		return
	}

	return
}

// tlsaSupported checks if there is a supported DANE usage
// from the given TLSA records. currently checks for usage EE(3).
func tlsaSupported(rrs []*dns.TLSA) bool {
	for _, rr := range rrs {
		if rr.Usage == 3 {
			return true
		}
	}
	return false
}
