// +build unbound

package resolver

import (
	"github.com/miekg/dns"
	"github.com/miekg/unbound"
	"net"
	"testing"
)

func fakeUnboundResp(question string, qtype, rrclass uint16) *unbound.Result {
	reply := testData[qtype][question]

	return &unbound.Result{
		Qname:        question,
		Qtype:        qtype,
		Qclass:       rrclass,
		Rr:           reply.Answer,
		CanonName:    "",
		Rcode:        reply.Rcode,
		AnswerPacket: nil,
		HaveData:     true,
		NxDomain:     reply.Rcode == dns.RcodeNameError,
		Secure:       reply.AuthenticatedData,
		Bogus:        reply.Rcode == dns.RcodeServerFailure,
		WhyBogus:     "",
		Ttl:          0,
		Rtt:          0,
	}
}

func TestUnbound_LookupTLSA(t *testing.T) {
	rs := &Unbound{
		ub: nil,
		resolv: func(name string, rrtype, rrclass uint16) (*unbound.Result, error) {
			return fakeUnboundResp(name, rrtype, rrclass), nil
		},
	}

	ans, err := rs.LookupTLSA("443", "tcp", "example.com")
	if err != nil {
		t.Fatal(err)
	}

	if len(ans) != 1 {
		t.Fatalf("got %d, want 1", len(ans))
	}

	ans, err = rs.LookupTLSA("443", "tcp", "no-ad.example.com")
	if err != nil {
		t.Fatal(err)
	}

	if len(ans) != 0 {
		t.Fatalf("got %d, want no results", len(ans))
	}

	if _, err := rs.LookupTLSA("443", "tcp", "dnssec-failed.org"); err == nil {
		t.Fatal("want error servfail")
	}

	if _, err := rs.LookupTLSA("443", "tcp", "dnssec-failed.org"); err == nil {
		t.Fatal("want error servfail")
	}

	ans, _ = rs.LookupTLSA("443", "tcp", "localhost")
	if len(ans) != 0 {
		t.Fatal("want no answers")
	}

	ans, _ = rs.LookupTLSA("443", "tcp", "1.1.1.1")
	if len(ans) != 0 {
		t.Fatal("want no answers")
	}
}

func TestUnbound_LookupIP(t *testing.T) {
	rs := &Unbound{
		ub: nil,
		resolvAsync: func(name string, rrtype, rrclass uint16, c chan *unbound.ResultError) {
			go func() {
				c <- &unbound.ResultError{
					Result: fakeUnboundResp(name, rrtype, rrclass),
					Error:  nil,
				}
			}()
		},
	}

	if _, err := rs.LookupIP("dnssec-failed.org"); err == nil {
		t.Fatal("want error servfail")
	}

	if _, err := rs.LookupIP("dnssec-failed.org"); err == nil {
		t.Fatal("want error servfail")
	}

	ips, err := rs.LookupIP("example.com")
	if err != nil {
		t.Fatal(err)
	}

	if len(ips) != 1 {
		t.Fatalf("got %d, want 1 ip address", len(ips))
	}

	ips, err = rs.LookupIP("ad.example.com")
	if err != nil {
		t.Fatal(err)
	}

	if len(ips) != 1 {
		t.Fatalf("got %d, want 1 ip address", len(ips))
	}

	ips, err = rs.LookupIP("localhost")
	if err != nil {
		t.Fatal(err)
	}

	if len(ips) == 1 && ips[0].Equal(net.ParseIP("1.1.1.1")) {
		t.Fatal("resolver shouldn't attempt to resolve localhost")
	}

	ips, err = rs.LookupIP("1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}

	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("1.1.1.1")) {
		t.Fatal("resolver shouldn't attempt to resolve ip addresses")
	}
}
