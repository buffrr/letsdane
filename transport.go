package godane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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

// RoundTripper returns a round tripper capable of performing DANE/TLSA
// verification. Uses the given resolver for dns lookups.
func RoundTripper(rs Resolver) http.RoundTripper {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
			return dialContext(ctx, network, addr, rs)
		},
		DialTLS: func(network, address string) (net.Conn, error) {
			tlsa := GetTLSAPrefix(address)
			if ans, err := rs.LookupTLSA(tlsa); err == nil && TLSASupported(ans) {
				tlsConfig := newTLSVerifyConfig(ans)
				return dialTLS(network, address, tlsConfig, rs)
			}

			return dialTLS(network, address, &tls.Config{InsecureSkipVerify: false}, rs)
		},
		TLSHandshakeTimeout:   TLSHandshakeTimeout,
		ExpectContinueTimeout: ExpectContinueTimeout,
	}

}

// TLSASupported checks if DANE usage is supported
// for the given TLSA records. currently checks for usage EE(3).
func TLSASupported(rrs []dns.TLSA) bool {
	for _, rr := range rrs {
		if rr.Usage == 3 {
			return true
		}
	}
	return false
}

func newTLSVerifyConfig(rrs []dns.TLSA) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: getTLSAValidator(rrs),
	}
}

func getTLSAValidator(rrs []dns.TLSA) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, asn1Data := range rawCerts {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				return errors.New("tls: failed to parse certificate from server: " + err.Error())
			}
			certs[i] = cert
		}

		// TLSA verification.
		// Currently, supports DANE-EE(3). We only need to check the leaf certificate.
		// https://tools.ietf.org/id/draft-ietf-dane-ops-02.html#type3
		// https://tools.ietf.org/html/rfc6698
		for _, t := range rrs {
			if t.Usage != 3 {
				continue
			}

			if err := t.Verify(certs[0]); err == nil {
				return nil
			}
		}

		return errors.New("tls: DANE verification failed")
	}
}

// GetDialFunc returns a dial function that uses the given resolver.
func GetDialFunc(rs Resolver) func(network string, addr string) (net.Conn, error) {
	return func(network string, addr string) (net.Conn, error) {
		_, port, ips, err := readAddr(addr, rs)
		if err != nil {
			return nil, err
		}

		for _, ip := range ips {
			ipaddr := net.JoinHostPort(ip.String(), port)
			conn, err := dialer.Dial(network, ipaddr)
			if err != nil {
				continue
			}
			return conn, nil
		}
		return nil, fmt.Errorf("dial: could not reach %s", addr)
	}
}

func dialContext(ctx context.Context, network, addr string, rs Resolver) (net.Conn, error) {
	_, port, ips, err := readAddr(addr, rs)
	if err != nil {
		return nil, err
	}

	for _, ip := range ips {
		ipaddr := net.JoinHostPort(ip.String(), port)
		conn, err := dialer.DialContext(ctx, network, ipaddr)
		if err != nil {
			continue
		}
		return conn, nil
	}

	return nil, fmt.Errorf("dial ctx: could not reach %s", addr)

}

func dialTLS(network, addr string, config *tls.Config, rs Resolver) (*tls.Conn, error) {
	host, port, ips, err := readAddr(addr, rs)
	if err != nil {
		return nil, err
	}

	config.ServerName = host

	for _, ip := range ips {
		ipaddr := net.JoinHostPort(ip.String(), port)
		conn, err := tls.Dial(network, ipaddr, config)
		if err != nil {
			continue
		}
		return conn, nil
	}

	return nil, fmt.Errorf("dial tls: could not reach %s", addr)

}

func readAddr(addr string, rs Resolver) (host, port string, ips []net.IP, err error) {
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return
	}

	ips, err = rs.LookupIP(host)
	if err != nil {
		err = fmt.Errorf("dial: %v", err)
		return
	}

	if len(ips) == 0 {
		err = fmt.Errorf("dial: lookup %s no such host", addr)
		return
	}

	return
}
