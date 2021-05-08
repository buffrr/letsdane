package resolver

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"sync"
	"testing"
	"time"
)

func TestStub_Verify(t *testing.T) {
	rs, _ := NewStub("0.0.0.0")
	rs.exchangeFunc = func(ctx context.Context, req *dns.Msg, client *client) (r *dns.Msg, rtt time.Duration, err error) {
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

	ctx := context.Background()
	if _, _, err := rs.LookupIP(ctx, "ip", "ad.example.com"); err == nil {
		t.Fatal("want query to fail")
	}
	if _, _, err := rs.LookupIP(ctx, "ip", "example.com"); err != nil {
		t.Fatal(err)
	}

	rs.Verify = nil
	if _, _, err := rs.LookupIP(ctx, "ip", "ad.example.com"); err != nil {
		t.Fatal("want no error")
	}
}

func TestStub_NewStub(t *testing.T) {
	ad, err := NewStub("https://cloudflare.com")
	if err != nil {
		t.Fatal(err)
	}

	if ad.client.addr != "https://cloudflare.com" {
		t.Fatalf("want %s, got %s", "https://cloudflare.com", ad.client.addr)
	}

	if ad.client.d.Net != "https" {
		t.Fatalf("want https, got %s", ad.client.d.Net)
	}

	ad, err = NewStub("1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}

	if ad.client.addr != "1.1.1.1:53" {
		t.Fatalf("want 1.1.1.1, got %s", ad.client.addr)
	}
}

func TestStub_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// go through every supported transport
	// to make sure they are functional
	// TODO: create a dummy resolver to test this instead
	var wg sync.WaitGroup
	protos := []string{"", "udp://", "tcp://", "tls://", "https://"}
	wg.Add(len(protos))
	for _, p := range protos {
		go func(proto string) {
			defer wg.Done()

			rs, err := NewStub(proto + "1.1.1.1")
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			if _, _, err := rs.LookupIP(ctx, "ip", "dnssec-failed.org"); err == nil {
				t.Fatal("dnssec-failed.org returned a valid response")
			}

			ips, _, err := rs.LookupIP(ctx, "ip", "example.com")
			if err != nil {
				t.Fatal(err)
			}

			if len(ips) == 0 {
				t.Fatalf("got no ips")
			}

			rrs, _, err := rs.LookupTLSA(ctx, "443", "tcp", "freebsd.org")
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
