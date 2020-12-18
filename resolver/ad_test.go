package resolver

import (
	"errors"
	"github.com/miekg/dns"
	"net"
	"testing"
	"time"
)

func TestAD_LookupTLSA(t *testing.T) {
	rs, _ := NewAD("0.0.0.0")
	rs.exchangeFunc = func(req *dns.Msg, addr string, client *dns.Client) (r *dns.Msg, rtt time.Duration, err error) {
		qm := testData[req.Question[0].Qtype]
		reply := qm[req.Question[0].Name]

		return reply, 0, nil
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

func TestAD_LookupIP(t *testing.T) {
	rs, _ := NewAD("0.0.0.0")
	rs.exchangeFunc = func(req *dns.Msg, addr string, client *dns.Client) (r *dns.Msg, rtt time.Duration, err error) {
		qm := testData[req.Question[0].Qtype]
		reply := qm[req.Question[0].Name]

		return reply, 0, nil
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

	if len(ips) != 2 {
		t.Fatalf("got %d, want 2 ip address", len(ips))
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

func TestAD_Verify(t *testing.T) {
	rs, _ := NewAD("0.0.0.0")
	rs.exchangeFunc = func(req *dns.Msg, addr string, client *dns.Client) (r *dns.Msg, rtt time.Duration, err error) {
		qm := testData[req.Question[0].Qtype]
		reply := qm[req.Question[0].Name]

		return reply, 0, nil
	}
	rs.Verify = func(m *dns.Msg) error {
		if m.Answer[0].Header().Name == "ad.example.com." {
			return errors.New("sig failed")
		}
		return nil
	}

	if _, err := rs.LookupIP("ad.example.com"); err == nil {
		t.Fatal("want query to fail")
	}
	if _, err := rs.LookupIP("example.com"); err != nil {
		t.Fatal(err)
	}

	rs.Verify = nil
	if _, err := rs.LookupIP("ad.example.com"); err != nil {
		t.Fatal("want no error")
	}
}

func testRR(rr string) dns.RR {
	r, err := dns.NewRR(rr)
	if err != nil {
		panic(err)
	}

	return r
}
