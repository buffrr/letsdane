// +build unbound

package resolver

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/miekg/unbound"
	"net"
)

type Unbound struct {
	ub          *unbound.Unbound
	resolvAsync func(name string, rrtype, rrclass uint16, c chan *unbound.ResultError)
	resolv      func(name string, rrtype, rrclass uint16) (*unbound.Result, error)
}

func NewUnbound() (u *Unbound, err error) {
	u = &Unbound{ub: unbound.New()}

	u.resolvAsync = func(name string, rrtype, rrclass uint16, c chan *unbound.ResultError) {
		u.ub.ResolveAsync(name, rrtype, rrclass, c)
	}

	u.resolv = func(name string, rrtype, rrclass uint16) (*unbound.Result, error) {
		return u.ub.Resolve(name, rrtype, rrclass)
	}

	return u, nil
}

func (u *Unbound) AddTA(ta string) error {
	return u.ub.AddTa(ta)
}

func (u *Unbound) AddTAFile(file string) error {
	return u.ub.AddTaFile(file)
}

func (u *Unbound) SetFwd(addr string) error {
	return u.ub.SetFwd(addr)
}

func (u *Unbound) ResolvConf(name string) error {
	return u.ub.ResolvConf(name)
}

func (u *Unbound) LookupIP(host string) (addrs []net.IP, err error) {
	// taken from miekg/unbound added check for bogus
	c := make(chan *unbound.ResultError)
	u.ub.ResolveAsync(host, dns.TypeA, dns.ClassINET, c)
	u.ub.ResolveAsync(host, dns.TypeAAAA, dns.ClassINET, c)
	seen := 0
Wait:
	for {
		select {
		case r := <-c:
			if r.Bogus {
				err = fmt.Errorf("unbound: bogus: %s: %w", r.WhyBogus, errServFail)
				return
			}

			for _, rr := range r.Rr {
				if x, ok := rr.(*dns.A); ok {
					addrs = append(addrs, x.A)
				}
				if x, ok := rr.(*dns.AAAA); ok {
					addrs = append(addrs, x.AAAA)
				}
			}
			seen++
			if seen == 2 {
				break Wait
			}
		}
	}
	return
}

func (u *Unbound) LookupTLSA(service, proto, name string) (tlsa []*dns.TLSA, err error) {
	if net.ParseIP(name) != nil || !shouldResolve(name) {
		return []*dns.TLSA{}, nil
	}

	tlsaname, err := dns.TLSAName(dns.Fqdn(name), service, proto)
	if err != nil {
		return nil, err
	}

	r, err := u.resolv(tlsaname, dns.TypeTLSA, dns.ClassINET)
	if err != nil {
		return nil, err
	}

	if r.Bogus {
		return nil, fmt.Errorf("unbound: bogus: %s: %w", r.WhyBogus, errServFail)
	}

	// even if the response is not bugs servfail does not indicate
	// that the server responded properly
	if r.Rcode == dns.RcodeServerFailure {
		return nil, fmt.Errorf("unbound: servfail: %d: %w", r.Rcode, errServFail)
	}

	if !r.Secure {
		return []*dns.TLSA{}, nil
	}
	for _, rr := range r.Rr {
		tlsa = append(tlsa, rr.(*dns.TLSA))
	}
	return tlsa, nil
}

func (u *Unbound) Destroy() {
	u.ub.Destroy()
}
