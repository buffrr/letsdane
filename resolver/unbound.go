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
	defer func() {
		if err != nil {
			err = fmt.Errorf("unbound: %v", err)
			u.Destroy()
		}
	}()

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

func (u *Unbound) LookupIP(host string, secure bool) (addrs []net.IP, err error) {
	// this method is the body of LookupIP in github.com/miekg/unbound
	//modified here to check for bogus & secure
	ip := net.ParseIP(host)
	if ip != nil {
		if secure {
			return []net.IP{}, nil
		}
		return []net.IP{ip}, nil
	}

	if !shouldResolve(host) {
		if secure {
			return []net.IP{}, nil
		}
		ips, err := net.LookupIP(host)
		return ips, err
	}

	c := make(chan *unbound.ResultError)
	host = dns.Fqdn(host)
	u.resolvAsync(host, dns.TypeA, dns.ClassINET, c)
	u.resolvAsync(host, dns.TypeAAAA, dns.ClassINET, c)
	seen := 0
Wait:
	for {
		select {
		case r := <-c:
			if r.Bogus {
				err = fmt.Errorf("unbound: bogus: %s: %w", r.WhyBogus, ErrServFail)
			}

			if !secure || r.Secure {
				for _, rr := range r.Rr {
					if x, ok := rr.(*dns.A); ok {
						addrs = append(addrs, x.A)
					}
					if x, ok := rr.(*dns.AAAA); ok {
						addrs = append(addrs, x.AAAA)
					}
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

func (u *Unbound) LookupTLSA(service, proto, name string, secure bool) (tlsa []*dns.TLSA, err error) {
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
		return nil, fmt.Errorf("unbound: bogus: %s: %w", r.WhyBogus, ErrServFail)
	}

	if !r.Secure && secure {
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
