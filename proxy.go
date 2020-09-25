package letsdane

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/buffrr/letsdane/resolver"
	"github.com/elazarl/goproxy"
	"github.com/miekg/dns"
	"net"
	"net/http"
	"time"
)

type authResult struct {
	Fail error
	Host string
	Port string
	IPs  []net.IP
	TLSA []*dns.TLSA
}

type Config struct {
	Certificate *x509.Certificate
	PrivateKey  interface{}
	Validity    time.Duration
	Resolver    resolver.Resolver
	Verbose     bool
}

func tlsaFilterFunc(c *Config) goproxy.ReqConditionFunc {
	return func(req *http.Request, ctx *goproxy.ProxyCtx) bool {
		host, port, err := net.SplitHostPort(req.Host)
		if err != nil {
			ctx.Logf("proxy: invalid host %s", req.Host)
			return false
		}

		var blockError error
		var ips []net.IP

		ans, err := c.Resolver.LookupTLSA(port, "tcp", host, true)
		if err != nil {
			blockError = err
			ctx.Logf("proxy: tlsa lookup for host %s failed: %v", host, err)
		} else {
			ips, blockError = c.Resolver.LookupIP(host, true)
			if blockError != nil {
				ctx.Logf("proxy: ip lookup for host %s failed: %v", host, err)
			}
		}

		if blockError == nil {
			if len(ips) == 0 {
				ctx.Logf("proxy: no such host %s: skipping mitm", host)
				return false
			}

			if !TLSASupported(ans) {
				ctx.Logf("proxy: host %s has no supported tlsa records skipping mitm", host)
				return false
			}
		}

		res := &authResult{
			Fail: blockError,
			IPs:  ips,
			TLSA: ans,
			Host: host,
			Port: port,
		}
		ctx.UserData = res

		return true
	}
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

		p.OnRequest(tlsaFilterFunc(c)).HandleConnect(goproxy.AlwaysMitm)
	}

	return nil
}

func (c *Config) Handler() (http.Handler, error) {
	p := goproxy.NewProxyHttpServer()
	// ConnectDial is only used for non mitm ed CONNECT requests
	// the configured resolver should still be used for all requests
	p.ConnectDial = GetDialFunc(c.Resolver)
	p.Verbose = c.Verbose
	if err := c.setupMITM(p); err != nil {
		return nil, err
	}

	p.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (resp *http.Response, err error) {
			// the custom round tripper expects an authResult in the ctx for DialTLSContext
			// it also uses the resolver for DialContext requests
			ctx.Logf("proxy: attempt round trip for %s", req.Host)
			tr := RoundTripper(c.Resolver, ctx)
			resp, err = tr.RoundTrip(req)
			if err != nil {
				err = fmt.Errorf("proxy: unable to round trip %s: %v", req.Host, err)
			}
			return
		})
		return req, nil
	})

	return p, nil
}

func (c *Config) Run(addr string) error {
	h, err := c.Handler()
	if err != nil {
		return err
	}

	return http.ListenAndServe(addr, h)
}
