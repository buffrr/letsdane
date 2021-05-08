// +build unbound

package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"github.com/miekg/unbound"
)

// Recursive is a DNSSEC validating recursive resolver
// implementing the Resolver interface
type Recursive struct {
	ub     *unbound.Unbound
	resolv func(name string, rrtype, rrclass uint16) (*unbound.Result, error)
	resolver
}

func NewRecursive() (r *Recursive, err error) {
	r = &Recursive{ub: unbound.New()}

	r.resolv = func(name string, rrtype, rrclass uint16) (*unbound.Result, error) {
		return r.ub.Resolve(name, rrtype, rrclass)
	}
	r.resolver = resolver{
		lookup: r.lookup,
	}

	return r, nil
}

func (r *Recursive) AddTA(ta string) error {
	return r.ub.AddTa(ta)
}

func (r *Recursive) AddTAFile(file string) error {
	return r.ub.AddTaFile(file)
}

func (r *Recursive) SetFwd(addr string) error {
	return r.ub.SetFwd(addr)
}

func (r *Recursive) ResolvConf(name string) error {
	return r.ub.ResolvConf(name)
}

func (r *Recursive) lookup(ctx context.Context, name string, qtype uint16) *dnsResult {
	result := make(chan dnsResult, 1)
	go r.cgoLookup(name, qtype, result)

	select {
	case r := <-result:
		return &r
	case <-ctx.Done():
		return &dnsResult{nil, false, fmt.Errorf("unbound: context error: %w", ctx.Err())}
	}
}

func (r *Recursive) cgoLookup(name string, qtype uint16, result chan<- dnsResult) {
	res, err := r.resolv(name, qtype, dns.ClassINET)
	if err != nil {
		result <- dnsResult{err: err}
		return
	}

	if res.Bogus {
		result <- dnsResult{err: fmt.Errorf("unbound: bogus: %s: %w", res.WhyBogus, errServFail)}
		return
	}

	if res.Rcode != dns.RcodeSuccess && res.Rcode != dns.RcodeNameError {
		result <- dnsResult{
			err: fmt.Errorf("unbound: received rcode %s",
				dns.RcodeToString[res.Rcode]),
		}
		return
	}

	result <- dnsResult{
		secure: res.Secure,
		rrs:    res.Rr,
	}
}

func (r *Recursive) Destroy() {
	r.ub.Destroy()
}
