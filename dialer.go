package letsdane

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/buffrr/letsdane/resolver"
	"github.com/miekg/dns"
	"net"
	"net/http"
	"time"
)

type dialer struct {
	net      net.Dialer
	resolver resolver.Resolver
}

var errBadHost = errors.New("bad host")

type addrList struct {
	Host string
	Port string
	IPs  []net.IP
}

func newDialer() *dialer {
	return &dialer{
		net: net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}
}

// dialTLSContext attempts to connect to one of the dst addresses and initiates a TLS
// handshake, returning the resulting TLS connection.
func (d *dialer) dialTLSContext(ctx context.Context, network string, dst *addrList, config *tls.Config) (*tls.Conn, error) {
	tlsDialer := &tls.Dialer{
		NetDialer: &d.net,
		Config:    config,
	}

	for _, ip := range dst.IPs {
		ipaddr := net.JoinHostPort(ip.String(), dst.Port)
		conn, err := tlsDialer.DialContext(ctx, network, ipaddr)
		if err != nil {
			if err, ok := err.(*tlsError); ok {
				return nil, err
			}
			continue
		}
		return conn.(*tls.Conn), nil
	}

	return nil, fmt.Errorf("could not reach any of %v", dst.IPs)
}

// dialContext attempts to connect to the given named address.
func (d *dialer) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	addrs, err := d.resolveAddr(ctx, addr)
	if err != nil {
		return nil, err
	}

	return d.dialAddrList(ctx, network, addrs)
}

// dialAddrList attempts to connect to one of the dst addresses
func (d *dialer) dialAddrList(ctx context.Context, network string, dst *addrList) (net.Conn, error) {
	for _, ip := range dst.IPs {
		ipaddr := net.JoinHostPort(ip.String(), dst.Port)
		conn, err := d.net.DialContext(ctx, network, ipaddr)
		if err != nil {
			continue
		}
		return conn, nil
	}

	return nil, fmt.Errorf("could not reach any of %v", dst.IPs)
}

// resolveAddr resolves the named address by performing a dns lookup returning a list
// of ipv4 and ipv6 addresses
func (d *dialer) resolveAddr(ctx context.Context, addr string) (addrs *addrList, err error) {
	addrs = &addrList{}
	addrs.Host, addrs.Port, err = net.SplitHostPort(addr)
	if err != nil {
		return
	}
	addrs.IPs, _, err = d.resolver.LookupIP(ctx, "ip", addrs.Host)
	if err != nil {
		return
	}
	if len(addrs.IPs) == 0 {
		err = fmt.Errorf("%s no such host", addr)
		return
	}

	return
}

// resolveDANE resolves the given host by performing a dns lookup returning
// an address list of ipv4 and ipv6 addresses and TLSA resource records.
func (d *dialer) resolveDANE(ctx context.Context, network, host string, constraints map[string]struct{}) (addrs *addrList, tlsa []*dns.TLSA, err error) {
	addrs = &addrList{}
	tlsa = []*dns.TLSA{}
	addrs.Host, addrs.Port, err = net.SplitHostPort(host)
	if err != nil || addrs.Host == "" || addrs.Port == "" {
		return nil, nil, errBadHost
	}
	if ip := net.ParseIP(addrs.Host); ip != nil {
		addrs.IPs = []net.IP{ip}
		return
	}

	done := make(chan struct{})
	var tlsaErr, ipErr error

	go func() {
		addrs.IPs, _, ipErr = d.resolver.LookupIP(ctx, "ip", addrs.Host)
		done <- struct{}{}
	}()

	if constraints == nil || !inConstraints(constraints, addrs.Host) {
		var secure bool
		tlsa, secure, tlsaErr = d.resolver.LookupTLSA(ctx, addrs.Port, network, addrs.Host)
		if !secure {
			tlsa = []*dns.TLSA{}
		}
	}
	<-done

	if ipErr != nil {
		err = ipErr
		return
	}

	err = tlsaErr
	return
}

// httpOnlyRoundTripper creates a round tripper used for http requests (fails on https requests)
func httpOnlyRoundTripper(d *dialer) http.RoundTripper {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
			return d.dialContext(ctx, network, addr)
		},
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("dial tls for host %s not supported", address)
		},
	}
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
