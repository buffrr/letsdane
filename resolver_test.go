package godane

import (
	"github.com/miekg/dns"
	"reflect"
	"sync"
	"testing"
)

func TestNewResolver(t *testing.T) {
	t.Parallel()
	var wg sync.WaitGroup
	protos := []string{"udp", "tcp", "tls", "https"}
	wg.Add(len(protos))
	for _, p := range protos {
		go func(proto string) {
			defer wg.Done()

			rs, err := NewResolver(proto + "://1.1.1.1")
			if err != nil {
				t.Fatal(err)
			}

			ips, err := rs.lookupIPv4("example.com", true)
			if err != nil {
				t.Fatal(err)
			}

			if len(ips) == 0 {
				t.Fatalf("got no ips")
			}
		}(p)
	}

	wg.Wait()

	_, err := NewResolver("udp://:53")
	if err != nil {
		t.Fatal(err)
	}
}

func TestDNS_LookupIP(t *testing.T) {
	t.Parallel()
	rs, err := NewResolver("udp://8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}

	ips, err := rs.LookupIP("example.com", true)
	if err != nil {
		t.Fatal(err)
	}

	if len(ips) != 2 {
		t.Fatalf("want 2 ips, got %d ips", len(ips))
	}

	_, err = rs.LookupIP("no-thanks.invalid", false)
	if err == nil {
		t.Fatal("want error, got nil")
	}

	rs, err = NewResolver("udp://a.iana-servers.net")
	if err != nil {
		t.Fatal(err)
	}

	// authoritative answers are not authenticated
	ips, err = rs.LookupIP("example.com", true)
	if err != nil {
		t.Fatal(err)
	}

	if len(ips) != 0 {
		t.Fatalf("want no ips, got %d", len(ips))
	}

	ips, err = rs.LookupIP("example.com", false)
	if err != nil {
		t.Fatal(err)
	}

	if len(ips) != 2 {
		t.Fatalf("want 2 ips, got %d", len(ips))
	}
}

var tlsaRRs = []dns.TLSA{
	{
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Certificate:  "781c71783fcd0d2c4b4b82ae7636fef5d0de94f99ce6192afdf2640357835e0b",
	},
}

func TestDNS_LookupTLSA(t *testing.T) {
	t.Parallel()

	rs, _ := NewResolver("tls://9.9.9.9")
	ans, err := rs.LookupTLSA("tlsa.godane.buffrr.dev")
	if err != nil {
		t.Fatal(err)
	}

	if len(ans) != 1 {
		t.Fatalf("want 1, got %d", len(ans))
	}

	ans[0].Hdr = tlsaRRs[0].Hdr

	if !reflect.DeepEqual(ans[0], tlsaRRs[0]) {
		t.Fatalf("want %v, got %v", tlsaRRs[0], ans[0])
	}

	rs, _ = NewResolver("udp://aiden.ns.cloudflare.com")
	ans, err = rs.LookupTLSA("tlsa.godane.buffrr.dev")
	if err == nil {
		t.Fatal("want error, got nil")
	}

}
