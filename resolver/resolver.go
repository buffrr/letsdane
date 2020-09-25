package resolver

import (
	"errors"
	"github.com/miekg/dns"
	"net"
)

// Resolver used for dns lookups
type Resolver interface {
	LookupIP(host string, secure bool) ([]net.IP, error)
	LookupTLSA(service, proto, name string, secure bool) ([]*dns.TLSA, error)
}

var ErrUnboundNotAvail = errors.New("resolver: unbound not available")
var ErrServFail = errors.New("resolver: server failure")
