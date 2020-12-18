package resolver

import (
	"errors"
	"github.com/miekg/dns"
	"net"
)

// Resolver used for dns lookups
type Resolver interface {
	LookupIP(host string) ([]net.IP, error)
	LookupTLSA(service, proto, name string) ([]*dns.TLSA, error)
}

var ErrUnboundNotAvail = errors.New("unbound not available")
var errServFail = errors.New("server failure")
