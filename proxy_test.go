package letsdane

import (
	"bytes"
	"github.com/elazarl/goproxy"
	"github.com/miekg/dns"
	"log"
	"net"
	"net/http"
	"testing"
)

func TestProxyTLSAFilter(t *testing.T) {
	ctx := &goproxy.ProxyCtx{
		Proxy: &goproxy.ProxyHttpServer{
			Verbose: false,
			Logger:  nil,
		},
	}

	c := &Config{
		Resolver: &testResolver{
			domain:    "example.com",
			ip:        net.ParseIP("127.0.0.1"),
			tlsaPrefx: "_443._tcp.example.com.",
			tlsaRRs:   tlsaRRs,
			bogus:     true,
		},
		Verbose: true,
	}

	validateTLSA := tlsaFilterFunc(c)
	req, _ := http.NewRequest("GET", "https://example.com", bytes.NewReader([]byte("hello")))
	if validateTLSA(req, ctx) {
		log.Fatal("want port to be specified")
	}

	req, _ = http.NewRequest("GET", "https://example.com:443", bytes.NewReader([]byte("hello")))
	if !validateTLSA(req, ctx) {
		log.Fatal("want failed queries to be interrupted")
	}

	auth, ok := ctx.UserData.(*TLSAResult)
	if !ok {
		log.Fatal("want auth result")
	}

	if auth.Fail == nil {
		log.Fatal("want auth result with error")
	}

	c.Resolver.(*testResolver).bogus = false
	if validateTLSA(req, ctx) {
		log.Fatal("want non secure queries to skip")
	}

	c.Resolver.(*testResolver).secure = true
	if !validateTLSA(req, ctx) {
		log.Fatal("want secure queries to be sent for validation")
	}

	if ctx.UserData.(*TLSAResult).Fail != nil {
		t.Fatal("want no error")
	}

	// unsupported dane types should skip
	c.Resolver.(*testResolver).tlsaRRs = []*dns.TLSA{
		tlsaRRs[1],
	}

	if validateTLSA(req, ctx) {
		log.Fatal("want unsupported tlsa to skip")
	}

}
