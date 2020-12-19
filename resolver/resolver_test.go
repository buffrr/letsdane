package resolver

import "github.com/miekg/dns"

var testData = map[uint16]map[string]*dns.Msg{
	dns.TypeTLSA: {
		"_443._tcp.example.com.": &dns.Msg{
			MsgHdr: dns.MsgHdr{
				AuthenticatedData: true,
			},
			Answer: []dns.RR{
				testRR("_443._tcp.example.com.  3600    IN      TLSA    3 1 1 31EF2A4D6E285CC29A636C5171F7DA0AC69CC44CEBAF5CD039DA8CC8 1187482A"),
			},
		},
		"_443._tcp.no-ad.example.com.": &dns.Msg{
			MsgHdr: dns.MsgHdr{
				AuthenticatedData: false,
			},
			Answer: []dns.RR{
				testRR("_443._tcp.no-ad.example.com.  3600    IN      TLSA    3 1 1 31EF2A4D6E285CC29A636C5171F7DA0AC69CC44CEBAF5CD039DA8CC8 1187482A"),
			},
		},
		"_443._tcp.dnssec-failed.org.": &dns.Msg{
			MsgHdr: dns.MsgHdr{
				AuthenticatedData: false,
				Rcode:             dns.RcodeServerFailure,
			},
		},
		// bad lookups
		"_443._tcp.localhost.": &dns.Msg{
			MsgHdr: dns.MsgHdr{
				AuthenticatedData: true,
			},
			Answer: []dns.RR{
				testRR("_443._tcp.localhost.  3600    IN      TLSA    3 1 1 31EF2A4D6E285CC29A636C5171F7DA0AC69CC44CEBAF5CD039DA8CC8 1187482A"),
			},
		},
		"_443._tcp.1.1.1.1.": &dns.Msg{
			MsgHdr: dns.MsgHdr{
				AuthenticatedData: true,
			},
			Answer: []dns.RR{
				testRR("_443._tcp.1.1.1.1.  3600    IN      TLSA    3 1 1 31EF2A4D6E285CC29A636C5171F7DA0AC69CC44CEBAF5CD039DA8CC8 1187482A"),
			},
		},
	},
	dns.TypeA: {
		"example.com.": &dns.Msg{
			MsgHdr: dns.MsgHdr{
				AuthenticatedData: false,
			},
			Answer: []dns.RR{
				testRR("example.com.            86400   IN      A       93.184.216.34"),
			},
		},
		"ad.example.com.": &dns.Msg{
			MsgHdr: dns.MsgHdr{
				AuthenticatedData: true,
			},
			Answer: []dns.RR{
				testRR("ad.example.com.            86400   IN      A       93.184.216.34"),
			},
		},
		"dnssec-failed.org.": &dns.Msg{
			MsgHdr: dns.MsgHdr{
				AuthenticatedData: false,
				Rcode:             dns.RcodeServerFailure,
			},
		},
		// bad lookups
		"localhost.": &dns.Msg{
			MsgHdr: dns.MsgHdr{
				AuthenticatedData: false,
			},
			Answer: []dns.RR{
				testRR("localhost.            86400   IN      A       1.1.1.1"),
			},
		},
		"1.1.1.1.": &dns.Msg{
			MsgHdr: dns.MsgHdr{
				AuthenticatedData: false,
			},
			Answer: []dns.RR{
				testRR("1.1.1.1.            86400   IN      A      192.168.0.1"),
			},
		},
	},
	dns.TypeAAAA: {
		"example.com.": &dns.Msg{
			MsgHdr: dns.MsgHdr{
				AuthenticatedData: false,
			},
			Answer: []dns.RR{
				testRR("example.com.             3599    IN      SOA     av1.nstld.com. dnssupport.verisign-grs.com. 1600883622 28800 7200 1209600 86400"),
			},
		},
		"ad.example.com.": &dns.Msg{
			MsgHdr: dns.MsgHdr{
				AuthenticatedData: false,
			},
			Answer: []dns.RR{
				testRR("ad.example.com.            86400   IN      AAAA    2606:2800:220:1:248:1893:25c8:1946"),
			},
		},
		"dnssec-failed.org.": &dns.Msg{
			MsgHdr: dns.MsgHdr{
				AuthenticatedData: false,
				Rcode:             dns.RcodeServerFailure,
			},
		},
		"localhost.": &dns.Msg{
			MsgHdr: dns.MsgHdr{
				AuthenticatedData: false,
			},
			Answer: []dns.RR{
				testRR("localhost.            86400   IN      AAAA    2606:2800:220:1:248:1893:25c8:1946"),
			},
		},
	},
}
