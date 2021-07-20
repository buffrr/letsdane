package resolver

import (
	"bytes"
	"context"
	"github.com/miekg/dns"
	"net"
	"sort"
	"testing"
)

var (
	testHdr = dns.MsgHdr{
		AuthenticatedData: false,
	}
	testHdrAD = dns.MsgHdr{
		AuthenticatedData: true,
	}
	testHdrServfail = dns.MsgHdr{
		Rcode: dns.RcodeServerFailure,
	}
)

type tlsaOut struct {
	rrs    []*dns.TLSA
	secure bool
	err    error
}

type ipOut struct {
	ips    []net.IP
	secure bool
	err    error
}

var testData = map[uint16]map[string]*dns.Msg{
	dns.TypeTLSA: {
		"_443._tcp.example.com.": &dns.Msg{
			MsgHdr: testHdrAD,
			Answer: testRRs("_443._tcp.example.com. IN TLSA 3 1 1 31EF2A4D6E285CC29A636C5171F7DA0AC69CC44CEBAF5CD039DA8CC8 1187482A"),
		},
		"_587._smtp.no-ad.example.com.": &dns.Msg{
			MsgHdr: testHdr,
			Answer: testRRs("_587._smtp.no-ad.example.com. IN TLSA 3 1 1 31EF2A4D6E285CC29A636C5171F7DA0AC69CC44CEBAF5CD039DA8CC8 1187482A"),
		},
		"_443._tcp.dnssec-failed.org.": &dns.Msg{
			MsgHdr: testHdrServfail,
		},
		"_443._tcp.www.isc.org.": &dns.Msg{
			MsgHdr: testHdrAD,
			Answer: []dns.RR{
				testRR("_443._tcp.www.isc.org. 7200 IN CNAME _tlsa.isc.org."),
				testRR("_tlsa.isc.org. 7200 IN TLSA 3 0 1 7C31F5B6D577A06448C67BAE690E1A3905CA34146BDA86C664EB2690 710D085C"),
				testRR("_tlsa.isc.org. 7200 IN TLSA 3 0 1 813D4AD03FB4B2E01081AAACF109A10ADA02182A48AD977D0F42B01A CA859B39"),
			},
		},
		// weird lookup shouldn't resolve
		"_443._tcp.1.1.1.1.": &dns.Msg{
			MsgHdr: testHdr,
			Answer: testRRs("_443._tcp.1.1.1.1. IN TLSA 3 1 1 31EF2A4D6E285CC29A636C5171F7DA0AC69CC44CEBAF5CD039DA8CC8 1187482A"),
		},
	},
	dns.TypeA: {
		"example.com.": &dns.Msg{
			MsgHdr: testHdr,
			Answer: testRRs("example.com. IN A 127.0.0.1"),
		},
		"ad.example.com.": &dns.Msg{
			MsgHdr: testHdrAD,
			Answer: testRRs("ad.example.com. IN A 127.0.0.1"),
		},
		"ip4.ad.example.com.": &dns.Msg{
			MsgHdr: testHdrAD,
			Answer: testRRs("ad.example.com. IN A 127.0.0.1"),
		},
		"dnssec-failed.org.": &dns.Msg{
			MsgHdr: testHdrServfail,
		},
		// should not attempt to resolve
		// ip addresses
		"1.1.1.1.": &dns.Msg{
			MsgHdr: testHdrAD,
			Answer: testRRs("1.1.1.1. IN A 127.0.0.1"),
		},
		"unsigned-ip6.example.com.": &dns.Msg{
			MsgHdr: testHdrAD,
			Answer: testRRs("unsigned-ip6.example.com. IN A 127.0.0.1"),
		},
		"servfail-ip6.example.com.": &dns.Msg{
			MsgHdr: testHdrAD,
			Answer: testRRs("servfail-ip6.example.com. IN A 127.0.0.1"),
		},
	},
	dns.TypeAAAA: {
		"example.com.": &dns.Msg{
			MsgHdr: testHdr,
			Answer: testRRs("example.com. IN AAAA 2606:2800:220:1:248:1893:25c8:1946"),
		},
		"ad.example.com.": &dns.Msg{
			MsgHdr: testHdrAD,
			Answer: testRRs("ad.example.com. IN AAAA 2606:2800:220:1:248:1893:25c8:1946"),
		},
		"dnssec-failed.org.": &dns.Msg{
			MsgHdr: testHdrServfail,
		},
		"unsigned-ip6.example.com.": &dns.Msg{
			MsgHdr: testHdr,
			Answer: testRRs("unsigned-ip6.example.com. IN AAAA 2606:2800:220:1:248:1893:25c8:1946"),
		},
		"servfail-ip6.example.com.": &dns.Msg{
			MsgHdr: testHdrServfail,
		},
	},
}

var tlsaTestCases = []struct {
	test    string
	service string
	proto   string
	name    string
	out     *tlsaOut
}{
	{
		test:    "signed",
		service: "443",
		proto:   "tcp",
		name:    "example.com.",
		out: &tlsaOut{
			rrs: tlsaRRs(
				testRRs("_443._tcp.example.com. IN TLSA 3 1 1 31EF2A4D6E285CC29A636C5171F7DA0AC69CC44CEBAF5CD039DA8CC8 1187482A"),
			),
			secure: true,
		},
	},
	{
		test: "signed_w_cnames",
		// named service https = 443
		service: "https",
		proto:   "tcp",
		name:    "www.isc.org.",
		out: &tlsaOut{
			rrs: tlsaRRs([]dns.RR{
				testRR("_tlsa.isc.org. 7200 IN TLSA 3 0 1 7C31F5B6D577A06448C67BAE690E1A3905CA34146BDA86C664EB2690 710D085C"),
				testRR("_tlsa.isc.org. 7200 IN TLSA 3 0 1 813D4AD03FB4B2E01081AAACF109A10ADA02182A48AD977D0F42B01A CA859B39"),
			}),
			secure: true,
		},
	},
	{
		test:    "unsigned",
		service: "587",
		proto:   "smtp",
		name:    "no-ad.example.com.",
		out: &tlsaOut{
			rrs: tlsaRRs([]dns.RR{
				testRR("_587._smtp.no-ad.example.com. IN TLSA 3 1 1 31EF2A4D6E285CC29A636C5171F7DA0AC69CC44CEBAF5CD039DA8CC8 1187482A"),
			}),
		},
	},
	{
		test:    "servfail",
		service: "443",
		proto:   "tcp",
		name:    "dnssec-failed.org.",
		out: &tlsaOut{
			err: ErrServFail,
		},
	},
	{
		test:    "no_ip_addresses",
		service: "443",
		proto:   "tcp",
		name:    "1.1.1.1.",
		out: &tlsaOut{
			rrs: tlsaRRs([]dns.RR{}),
		},
	},
}

var ipTestCases = []struct {
	test     string
	name     string
	networks []string
	out      *ipOut
}{
	{
		test:     "unsigned",
		name:     "example.com.",
		networks: []string{"ip4", "ip6", "ip"},
		out: &ipOut{
			ips: []net.IP{
				net.ParseIP("127.0.0.1"),
				net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
			},
		},
	},
	{
		test:     "signed",
		name:     "ad.example.com.",
		networks: []string{"ip4", "ip6", "ip"},
		out: &ipOut{
			ips: []net.IP{
				net.ParseIP("127.0.0.1"),
				net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
			},
			secure: true,
		},
	},
	{
		test:     "servfail",
		name:     "dnssec-failed.org.",
		networks: []string{"ip4", "ip6", "ip"},
		out: &ipOut{
			err: ErrServFail,
		},
	},
	{
		test:     "signed_ip4_no_ip6",
		name:     "ip4.ad.example.com.",
		networks: []string{"ip"},
		out: &ipOut{
			ips: []net.IP{
				net.ParseIP("127.0.0.1"),
			},
			secure: true,
		},
	},
	{
		test:     "servfail_ip6",
		name:     "servfail-ip6.example.com.",
		networks: []string{"ip"},
		out: &ipOut{
			ips: []net.IP{
				net.ParseIP("127.0.0.1"),
			},
			secure: false,
		},
	},
	{
		test:     "signed_ip4_unsigned_ip6",
		name:     "unsigned-ip6.example.com.",
		networks: []string{"ip"},
		out: &ipOut{
			ips: []net.IP{
				net.ParseIP("127.0.0.1"),
				net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
			},
			secure: false,
		},
	},
}

func TestResolver_LookupTLSA(t *testing.T) {
	for _, tc := range tlsaTestCases {
		t.Run(tc.test, func(t *testing.T) {
			lookupFn := func(ctx context.Context, qname string, qtype uint16) *DNSResult {
				qname = dns.Fqdn(qname)
				if qtype != dns.TypeTLSA {
					t.Fatal("want qtype = TLSA")
				}
				name, _ := dns.TLSAName(tc.name, tc.service, tc.proto)
				if name != qname {
					t.Fatalf("got qname = %s, want %s", qname, name)
				}

				var data *dns.Msg
				var ok bool
				if data, ok = testData[qtype][name]; !ok {
					t.Fatalf("qname %s not found", qname)
				}

				var err error
				if data.Rcode == dns.RcodeServerFailure {
					err = ErrServFail
				}

				return &DNSResult{
					Records: data.Answer,
					Secure:  data.AuthenticatedData,
					Err:     err,
				}
			}

			r := DefaultResolver{lookupFn}
			got, secure, err := r.LookupTLSA(context.Background(), tc.service, tc.proto, tc.name)

			if err == nil && tc.out.err != nil {
				t.Fatal("got nil, want error")
			}
			if secure != tc.out.secure {
				t.Fatalf("got secure = %v, want %v", secure, tc.out.secure)
			}

			want := tc.out.rrs
			if !tlsaEq(want, got) {
				t.Fatalf("got answer = %v, want %v", got, want)
			}
		})
	}
}

func TestResolver_LookupIP(t *testing.T) {
	r := DefaultResolver{
		Query: func(ctx context.Context, qname string, qtype uint16) *DNSResult {
			qname = dns.Fqdn(qname)
			if qtype != dns.TypeA && qtype != dns.TypeAAAA {
				t.Fatalf("got qtype = %s, want qtype = A/AAAA", dns.TypeToString[qtype])
			}

			qm := testData[qtype]
			reply, ok := qm[qname]
			if !ok {
				reply = new(dns.Msg)
				reply.Rcode = dns.RcodeSuccess
				reply.AuthenticatedData = true
			}

			var err error
			if reply.Rcode == dns.RcodeServerFailure {
				err = ErrServFail
			}

			return &DNSResult{reply.Answer, reply.AuthenticatedData, err}
		},
	}

	ctx := context.Background()
	for _, tc := range ipTestCases {
		t.Run(tc.test, func(t *testing.T) {
			for _, network := range tc.networks {
				ips, secure, err := r.LookupIP(ctx, network, tc.name)

				if secure != tc.out.secure {
					t.Fatalf("got secure = %v, want %v", secure, tc.out.secure)
				}

				if err == nil && tc.out.err != nil {
					t.Fatal("got nil, want error")
				}

				want := filterNetwork(tc.out.ips, network)
				if !ipEq(want, ips) {
					t.Fatalf("got answer = %v, want %v", ips, want)
				}
			}
		})
	}
}

func testRRs(args ...string) []dns.RR {
	var out []dns.RR
	for _, arg := range args {
		out = append(out, testRR(arg))
	}
	return out
}

func tlsaRRs(rrs []dns.RR) []*dns.TLSA {
	var f []*dns.TLSA
	for _, rr := range rrs {
		switch rr.(type) {
		case *dns.TLSA:
			f = append(f, rr.(*dns.TLSA))
		}
	}
	return f
}

func tlsaEq(slice1, slice2 []*dns.TLSA) bool {
	if len(slice1) != len(slice2) {
		return false
	}
	for i, v := range slice1 {
		if v.String() != slice2[i].String() {
			return false
		}
	}
	return true
}

func ipEq(slice1, slice2 []net.IP) bool {
	if len(slice1) != len(slice2) {
		return false
	}

	sort.Slice(slice1, func(i, j int) bool {
		return bytes.Compare(slice1[i], slice1[j]) < 0
	})

	sort.Slice(slice2, func(i, j int) bool {
		return bytes.Compare(slice2[i], slice2[j]) < 0
	})

	for i, v := range slice1 {
		if !v.Equal(slice2[i]) {
			return false
		}
	}

	return true
}

func rrsEq(slice1, slice2 []dns.RR) bool {
	if len(slice1) != len(slice2) {
		return false
	}

	sort.Slice(slice1, func(i, j int) bool {
		return slice1[i].String() < slice1[j].String()
	})

	sort.Slice(slice2, func(i, j int) bool {
		return slice2[i].String() < slice2[j].String()
	})

	for i, v := range slice1 {
		if v.String() != slice2[i].String() {
			return false
		}
	}

	return true
}

func filterNetwork(ips []net.IP, network string) []net.IP {
	var out []net.IP
	if network == "ip" {
		return ips
	}

	net4 := network != "ip6"
	for _, ip := range ips {
		ip4 := ip.To4() != nil
		if ip4 && net4 {
			out = append(out, ip)
			continue
		}

		if !ip4 && !net4 {
			out = append(out, ip)
		}

	}

	return out
}
