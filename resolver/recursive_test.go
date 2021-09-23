//go:build unbound
// +build unbound

package resolver

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"github.com/miekg/unbound"
	"testing"
)

func fakeUnboundResp(question string, qtype, rrclass uint16) *unbound.Result {
	reply, ok := testData[qtype][question]
	if !ok {
		reply = new(dns.Msg)
		reply.Rcode = dns.RcodeServerFailure
	}

	res := &unbound.Result{
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
		WhyBogus:     "",
		Ttl:          0,
		Rtt:          0,
	}

	if question == "dnssec-failed.org." {
		res.Bogus = true
	}

	return res
}

func TestRecursive_Lookup(t *testing.T) {
	lookupErr := errors.New("some error")
	r := &Recursive{
		resolv: func(name string, rrtype, rrclass uint16) (*unbound.Result, error) {
			if name == "error.example.com." {
				return nil, lookupErr
			}

			res := fakeUnboundResp(name, rrtype, rrclass)
			if name == "badrcode.example.com." {
				res.Rcode = dns.RcodeFormatError
			}

			return res, nil
		},
	}
	r.DefaultResolver = DefaultResolver{
		Query: r.lookup,
	}

	tests := []struct {
		qname string
		qtype uint16
		out   DNSResult
	}{
		{
			qname: "example.com.",
			qtype: dns.TypeA,
			out: DNSResult{
				Records: testRRs("example.com. IN A 127.0.0.1"),
			},
		},
		{
			qname: "_443._tcp.example.com.",
			qtype: dns.TypeTLSA,
			out: DNSResult{
				Records: testRRs("_443._tcp.example.com. IN TLSA 3 1 1 31EF2A4D6E285CC29A636C5171F7DA0AC69CC44CEBAF5CD039DA8CC8 1187482A"),
				Secure:  true,
			},
		},
		{
			qname: "error.example.com.",
			qtype: dns.TypeA,
			out: DNSResult{
				Err: lookupErr,
			},
		},
		{
			qname: "dnssec-failed.org.",
			qtype: dns.TypeA,
			out: DNSResult{
				Err: ErrServFail,
			},
		},
		{
			qname: "badrcode.example.com.",
			qtype: dns.TypeA,
		},
		{
			qname: "bad.invalid.",
			qtype: dns.TypeA,
		},
	}

	ctx := context.Background()
	for _, test := range tests {
		tname := test.qname + "_" + dns.TypeToString[test.qtype]
		t.Run(tname, func(t *testing.T) {
			res := r.Query(ctx, test.qname, test.qtype)
			if test.out.Secure != res.Secure {
				t.Fatalf("got secure = %v, want %v", res.Secure, test.out.Secure)
			}

			if test.out.Err != nil && res.Err == nil {
				t.Fatalf("want error")
			}

			if !rrsEq(test.out.Records, res.Records) {
				t.Fatalf("got rrs = %v, want %v", res.Records, test.out.Records)
			}
		})
	}

	ctx, cancel := context.WithCancel(ctx)
	cancel()

	if out := r.Query(ctx, "example.com.", dns.TypeA); out.Err == nil {
		t.Fatalf("want error")
	}
}

func TestRecursive_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	r, err := NewRecursive()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Destroy()

	if err = r.SetFwd("1.1.1.1"); err != nil {
		t.Fatal(err)
	}

	if err = r.AddTA(`. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D`); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	ips, secure, err := r.LookupIP(ctx, "ip", "isc.org.")
	if err != nil {
		t.Fatal(err)
	}

	if !secure {
		t.Fatal("want secure")
	}

	if len(ips) == 0 {
		t.Fatal("want ip addresses")
	}
}
