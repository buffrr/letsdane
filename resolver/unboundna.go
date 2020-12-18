// +build !unbound

package resolver

import (
	"github.com/miekg/dns"
	"net"
)

type Unbound struct {
}

func NewUnbound() (u *Unbound, err error) {
	return nil, ErrUnboundNotAvail
}

func (u *Unbound) SetFwd(addr string) error {
	return ErrUnboundNotAvail
}

func (u *Unbound) ResolvConf(name string) error {
	return ErrUnboundNotAvail
}

func (u *Unbound) AddTA(ta string) error {
	return ErrUnboundNotAvail
}

func (u *Unbound) AddTAFile(file string) error {
	return ErrUnboundNotAvail
}

func (u *Unbound) LookupIP(host string) (addrs []net.IP, err error) {
	return nil, ErrUnboundNotAvail
}

func (u *Unbound) LookupTLSA(service, proto, name string) (tlsa []*dns.TLSA, err error) {
	return nil, ErrUnboundNotAvail
}

func (u *Unbound) Destroy() {
}
