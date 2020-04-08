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

			ips, err := rs.lookupIPv4("ip.godane.buffrr.dev")
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

	ips, err := rs.LookupIP("ip.godane.buffrr.dev")
	if err != nil {
		t.Fatal(err)
	}

	if len(ips) != 4 {
		t.Fatalf("want 4 ips, got %d ips", len(ips))
	}

	_, err = rs.LookupIP("ip.godane.invalid")
	if err == nil {
		t.Fatal("want error, got nil")
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
	d, _ := NewResolver("tls://9.9.9.9")
	r, _ := d.LookupTLSA("tlsa.godane.buffrr.dev")

	if len(r) != 1 {
		t.Fatalf("want 1, got %d", len(r))
	}

	r[0].Hdr = tlsaRRs[0].Hdr

	if !reflect.DeepEqual(r[0], tlsaRRs[0]) {
		t.Fatalf("want %v, got %v", tlsaRRs[0], r[0])
	}

}
