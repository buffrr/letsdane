package letsdane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/buffrr/letsdane/resolver"
	"github.com/elazarl/goproxy"
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

var daneErr = errors.New("transport: DANE verification failed")

// RoundTripper returns a round tripper capable of performing DANE/TLSA
// verification. Uses the given resolver for dns lookups.
func RoundTripper(rs resolver.Resolver, gContext *goproxy.ProxyCtx) http.RoundTripper {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
			return dialContext(ctx, network, addr, rs)
		},
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if gContext == nil {
				return nil, fmt.Errorf("transport: no validation data in ctx")
			}
			if cdata, ok := gContext.UserData.(*TLSAResult); ok {
				if cdata.Fail != nil {
					return nil, fmt.Errorf("transport: %v", cdata.Fail)
				}
				tlsConfig := newTLSVerifyConfig(cdata.TLSA)
				return dialTLS(network, address, tlsConfig, cdata, gContext)
			}
			return nil, fmt.Errorf("transport: address %s not reachable", address)
		},
		TLSHandshakeTimeout:   TLSHandshakeTimeout,
		ExpectContinueTimeout: ExpectContinueTimeout,
	}

}

// TLSASupported checks if there is a supported DANE usage
// from the given TLSA records. currently checks for usage EE(3).
func TLSASupported(rrs []*dns.TLSA) bool {
	for _, rr := range rrs {
		if rr.Usage == 3 {
			return true
		}
	}
	return false
}

func newTLSVerifyConfig(rrs []*dns.TLSA) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: getTLSAValidator(rrs),
	}
}

func getTLSAValidator(rrs []*dns.TLSA) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, asn1Data := range rawCerts {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				return errors.New("transport: failed to parse certificate from server: " + err.Error())
			}
			certs[i] = cert
		}

		// TLSA verification.
		// Currently, supports DANE-EE(3). We only need to check the leaf certificate.
		// https://tools.ietf.org/html/rfc7671#section-5.1
		// https://tools.ietf.org/html/rfc6698
		for _, t := range rrs {
			if t.Usage != 3 {
				continue
			}

			if err := t.Verify(certs[0]); err == nil {
				return nil
			}
		}

		return daneErr
	}
}

// GetDialFunc returns a dial function that uses the given resolver.
func GetDialFunc(rs resolver.Resolver) func(network string, addr string) (net.Conn, error) {
	return func(network string, addr string) (net.Conn, error) {
		return dialContext(context.Background(), network, addr, rs)
	}
}

func dialContext(ctx context.Context, network, addr string, rs resolver.Resolver) (net.Conn, error) {
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

func dialTLS(network, addr string, config *tls.Config, cdata *TLSAResult, ctx *goproxy.ProxyCtx) (*tls.Conn, error) {
	config.ServerName = cdata.Host
	// TODO: use async dialing
	for _, ip := range cdata.IPs {
		ipaddr := net.JoinHostPort(ip.String(), cdata.Port)
		conn, err := tls.Dial(network, ipaddr, config)
		if err != nil {
			if err == daneErr {
				return nil, err
			}

			ctx.Logf("transport: dialing %s for host %s failed: %v", ipaddr, addr, err)
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
