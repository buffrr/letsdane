package resolver

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"net"
)

// Resolver is an interface for representing
// a security-aware DNS resolver.
type Resolver interface {
	// LookupIP looks up host for the given networks.
	// It returns a slice of that host's IP addresses of the type specified by
	// networks, and whether the lookup was secure
	// networks must be one of "ip", "ip4" or "ip6".
	LookupIP(ctx context.Context, network, host string) ([]net.IP, bool, error)

	// LookupTLSA looks up TLSA records for the given service, protocol and name.
	// It returns a slice of that name's TLSA records and
	// whether the lookup was secure.
	LookupTLSA(ctx context.Context, service, proto, name string) ([]*dns.TLSA, bool, error)
}

var ErrUnboundNotAvail = errors.New("unbound not available")
var ErrServFail = errors.New("dns lookup failed (rcode: servfail)")

type DNSResult struct {
	Records []dns.RR
	Secure  bool
	Err     error
}

type DefaultResolver struct {
	Query func(ctx context.Context, name string, qtype uint16) *DNSResult
}

// LookupIP looks up host for the given networks.
// It returns a slice of that host's IP addresses of the type specified by
// networks, and whether the lookup was secure
// networks must be one of "ip", "ip4" or "ip6".
func (r *DefaultResolver) LookupIP(ctx context.Context, network, host string) (ips []net.IP, secure bool, err error) {
	if ip := parseIP(host); ip != nil {
		return []net.IP{ip}, false, nil
	}

	lane := make(chan *DNSResult, 1)
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
	switch network {
	case "ip4":
		qtypes = []uint16{dns.TypeA}
	case "ip6":
		qtypes = []uint16{dns.TypeAAAA}
	}

	queryFn := func(qtype uint16) {
		lane <- r.Query(ctx, host, qtype)
	}

	for _, qtype := range qtypes {
		go queryFn(qtype)
	}

	secure = true
	for range qtypes {
		result := <-lane
		// should only be set if all lookups
		// are secure. If one lookup fails
		// assume insecure
		secure = secure && result.Secure

		if result.Err != nil {
			err = result.Err
			continue
		}

		err = nil
		for _, rr := range result.Records {
			switch t := rr.(type) {
			case *dns.A:
				ips = append(ips, t.A)
			case *dns.AAAA:
				ips = append(ips, t.AAAA)
			}
		}
	}

	return
}

// LookupTLSA looks up TLSA records for the given service, protocol and name.
// It returns a slice of that name's TLSA records and
// whether the lookup was secure.
func (r *DefaultResolver) LookupTLSA(ctx context.Context, service, proto, name string) ([]*dns.TLSA, bool, error) {
	if parseIP(name) != nil {
		return []*dns.TLSA{}, false, nil
	}

	tlsaName, err := dns.TLSAName(dns.Fqdn(name), service, proto)
	if err != nil {
		return nil, false, err
	}

	result := r.Query(ctx, tlsaName, dns.TypeTLSA)
	if result.Err != nil {
		return nil, false, result.Err
	}

	var rrs []*dns.TLSA
	for _, rr := range result.Records {
		switch t := rr.(type) {
		case *dns.TLSA:
			rrs = append(rrs, t)
		}
	}

	return rrs, result.Secure, nil
}

func parseIP(name string) net.IP {
	if name == "" {
		return nil
	}
	if name[len(name)-1] == '.' {
		return net.ParseIP(name[:len(name)-1])
	}

	return net.ParseIP(name)
}
