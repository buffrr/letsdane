package resolver

import (
	"errors"
	"github.com/miekg/dns"
	"net"
	"sync"
	"testing"
	"time"
)

func TestAD_LookupTLSA(t *testing.T) {
	rs, _ := NewAD("0.0.0.0")
	rs.exchangeFunc = func(req *dns.Msg, client *DNSClient) (r *dns.Msg, rtt time.Duration, err error) {
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
	rs.exchangeFunc = func(req *dns.Msg, client *DNSClient) (r *dns.Msg, rtt time.Duration, err error) {
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
	rs.exchangeFunc = func(req *dns.Msg, client *DNSClient) (r *dns.Msg, rtt time.Duration, err error) {
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

func TestAD_NewAD(t *testing.T) {
	ad, err := NewAD("https://cloudflare.com")
	if err != nil {
		t.Fatal(err)
	}

	if ad.client.addr != "https://cloudflare.com" {
		t.Fatalf("want %s, got %s", "https://cloudflare.com", ad.client.addr)
	}

	if ad.client.d.Net != "https" {
		t.Fatalf("want https, got %s", ad.client.d.Net)
	}

	ad, err = NewAD("1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}

	if ad.client.addr != "1.1.1.1:53" {
		t.Fatalf("want 1.1.1.1, got %s", ad.client.addr)
	}
}

func TestAD_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// quickly go through every supported transport
	// to make sure they are functional
	// TODO: create a dummy resolver to test this instead
	var wg sync.WaitGroup
	protos := []string{"", "udp://", "tcp://", "tls://", "https://"}
	wg.Add(len(protos))
	for _, p := range protos {
		go func(proto string) {
			defer wg.Done()

			rs, err := NewAD(proto + "1.1.1.1")
			if err != nil {
				t.Fatal(err)
			}

			if _, err := rs.LookupIP("dnssec-failed.org") ; err == nil {
				t.Fatal("dnssec-failed.org returned a valid response")
			}

			ips, err := rs.LookupIP("example.com")
			if err != nil {
				t.Fatal(err)
			}

			if len(ips) == 0 {
				t.Fatalf("got no ips")
			}

			rrs, err := rs.LookupTLSA("443", "tcp","freebsd.org")
			if err != nil {
				t.Fatal(err)
			}

			if len(rrs) == 0 {
				t.Fatalf("got no tlsa records from freebsd.org")
			}
		}(p)
	}

	wg.Wait()
}

func testRR(rr string) dns.RR {
	r, err := dns.NewRR(rr)
	if err != nil {
		panic(err)
	}

	return r
}
