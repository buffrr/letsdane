package godane

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/elazarl/goproxy"
	"github.com/miekg/dns"
	"net"
	"net/http"
	"time"
)

type authResult struct {
	Host string
	Port string
	IPs  []net.IP
	TLSA []dns.TLSA
}

type Config struct {
	Certificate *x509.Certificate
	PrivateKey  interface{}
	Validity    time.Duration
	Resolver    Resolver
	Verbose     bool
}

func (c *Config) setupMITM(p *goproxy.ProxyHttpServer) error {
	if c.Certificate != nil && c.PrivateKey != nil {
		mc, err := newMITMConfig(c.Certificate, c.PrivateKey, c.Validity, "DNSSEC")
		if err != nil {
			return err
		}

		tlsConfig := func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
			host, _, _ = net.SplitHostPort(host)
			return mc.tlsForHost(host, ctx), nil
		}

		goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: tlsConfig}
		goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsConfig}
		goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: tlsConfig}
		goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: tlsConfig}

		var checkMITM goproxy.ReqConditionFunc = func(req *http.Request, ctx *goproxy.ProxyCtx) bool {
			host, port, err := net.SplitHostPort(req.Host)
			if err != nil {
				ctx.Logf("invalid host %s", req.Host)
				return false
			}

			ips, err := c.Resolver.LookupIP(host, true)
			if err != nil {
				ctx.Logf("ip lookup for host %s failed %v", req.Host, err)
				return false
			}

			if len(ips) == 0 {
				ctx.Logf("no authenticated ip addresses were found skipping mitm")
				return false
			}

			prefix := GetTLSAPrefix(req.Host)
			ans, err := c.Resolver.LookupTLSA(prefix)

			if err == nil {
				if !TLSASupported(ans) {
					ctx.Logf("host %s has no supported tlsa records skipping mitm", req.Host)
					return false
				}

				res := &authResult{
					IPs:  ips,
					TLSA: ans,
					Host: host,
					Port: port,
				}
				ctx.UserData = res
				return true
			}

			ctx.Logf("tlsa lookup failed: %v, skipping mitm", err)
			return false
		}

		p.OnRequest(checkMITM).HandleConnect(goproxy.AlwaysMitm)
	}

	return nil
}

func (c *Config) Run(addr string) error {
	p := goproxy.NewProxyHttpServer()
	p.ConnectDial = GetDialFunc(c.Resolver)
	p.Verbose = c.Verbose
	if err := c.setupMITM(p) ; err != nil {
		return err
	}

	// do our own round tripping
	p.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (resp *http.Response, err error) {
			tr := RoundTripper(c.Resolver, ctx)
			resp, err = tr.RoundTrip(req)

			ctx.Logf("round trip completed for %s", req.Host)

			if err != nil {
				ctx.Warnf("host: %s: %v", req.Host, err)
				err = fmt.Errorf("unable to proxy %s: %v", req.Host, err)
			}

			return
		})
		return req, nil
	})

	return http.ListenAndServe(addr, p)
}
