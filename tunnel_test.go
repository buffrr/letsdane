package letsdane

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func newProxyTestConfig(t *testing.T) (*x509.Certificate, *Config) {
	ca, priv, err := NewAuthority("TEST", "TEST", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}

	return ca, &Config{
		Certificate: ca,
		PrivateKey:  priv,
		Validity:    time.Hour,
		Verbose:     true,
	}
}

func TestNonConnectHandler(t *testing.T) {
	wantHost := "example.com"
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !strings.HasPrefix(req.Host, wantHost) {
			t.Errorf("got %s, want host %s", req.Host, wantHost)
		}

		w.Write([]byte("foo"))
	}))
	defer targetSrv.Close()

	ip, port, _ := net.SplitHostPort(targetSrv.Listener.Addr().String())
	_, proxyConfig := newProxyTestConfig(t)

	proxyConfig.Resolver = &testResolver{
		lookupIP: func(ctx context.Context, network, host string) ([]net.IP, bool, error) {
			if host != wantHost {
				t.Errorf("got host %s, want %s", host, "example.com")
				return nil, false, errors.New("no such host")
			}
			return []net.IP{net.ParseIP(ip)}, true, nil
		},
	}

	proxyHandler, _ := proxyConfig.NewHandler()
	proxySrv := httptest.NewServer(proxyHandler)

	var tests = []struct {
		name       string
		wantCode   int
		shouldFail bool
		uri        string
		host       string
	}{
		{
			name:     "basic_request",
			wantCode: http.StatusOK,
			uri:      "http://example.com:" + port,
			host:     "example.com:" + port,
		},
		{
			name:     "abs_url",
			wantCode: http.StatusBadRequest,
			uri:      "/",
			host:     "example.com",
		},
		{
			name:     "unsupported_scheme",
			wantCode: http.StatusNotImplemented,
			uri:      "https://example.com",
			host:     "example.com",
		},
		{
			name:     "invalid_host",
			wantCode: http.StatusOK,
			uri:      "http://" + wantHost + ":" + port,
			host:     "foo.bar:" + port,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", proxySrv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			conn.Write([]byte(fmt.Sprintf("GET %s HTTP/1.1\nHost:%s\nConnection:close\n\r\n\r", test.uri, test.host)))
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}

			if resp.StatusCode != test.wantCode {
				t.Fatalf("status = %d, wanted %d", resp.StatusCode, test.wantCode)
			}

			if resp.StatusCode == http.StatusOK {
				b, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}

				c := string(b)
				if c != "foo" {
					t.Fatalf("body = %s, wanted %s", c, "foo")
				}
			}
		})
	}
}

func TestHandlerTLS(t *testing.T) {
	resolver := &testResolver{}
	targetSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {
		wr.Write([]byte("foo"))
	}))

	// server supports "my_proto" (used for ALPN test)
	targetSrv.TLS = &tls.Config{
		NextProtos: []string{"my_proto"},
	}
	targetSrv.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		"my_proto": func(server *http.Server, conn *tls.Conn, handler http.Handler) {
			conn.Write([]byte("ALPN TEST"))
		},
	}

	targetSrv.StartTLS()
	defer targetSrv.Close()

	targetIP, targetPort, _ := net.SplitHostPort(targetSrv.Listener.Addr().String())
	proxyCA, proxyConfig := newProxyTestConfig(t)
	proxyConfig.Resolver = resolver
	proxyHandler, _ := proxyConfig.NewHandler()

	// cert pool that only trusts the proxy CA.
	daneStore := x509.NewCertPool()
	daneStore.AddCert(proxyCA)

	// cert pool that trusts the target server CA
	webPKIStore := x509.NewCertPool()
	webPKIStore.AddCert(targetSrv.Certificate())

	proxySrv := httptest.NewServer(proxyHandler)
	proxyURL, _ := url.Parse(proxySrv.URL)

	var testRequests = []struct {
		name         string
		host         string
		port         string
		ip           []net.IP
		tlsa         []*dns.TLSA
		tlsaInsecure bool
		store        *x509.CertPool
		fail         bool // whether the request should fail
		constraints  bool
		nameCheck    bool
	}{
		{
			name:  "no_such_host_no_tlsa",
			host:  "example.com",
			port:  targetPort,
			ip:    []net.IP{},
			tlsa:  []*dns.TLSA{},
			store: webPKIStore,
			fail:  true,
		},
		{
			name:  "ip_no_tlsa",
			host:  targetIP,
			port:  targetPort,
			ip:    []net.IP{net.ParseIP(targetIP)},
			tlsa:  []*dns.TLSA{},
			store: webPKIStore,
			fail:  false,
		},
		{
			name:  "ip_tlsa",
			host:  targetIP,
			port:  targetPort,
			ip:    []net.IP{net.ParseIP(targetIP)},
			tlsa:  newTLSA(3, 1, 1, targetSrv.Certificate()),
			store: daneStore,
			fail:  true,
		},
		{
			name:  "no_tlsa",
			host:  "example.com",
			port:  targetPort,
			ip:    []net.IP{net.ParseIP(targetIP)},
			tlsa:  []*dns.TLSA{},
			store: webPKIStore,
			fail:  false,
		},
		{
			name:  "invalid_dane_usage",
			host:  "example.com",
			port:  targetPort,
			ip:    []net.IP{net.ParseIP(targetIP)},
			tlsa:  newTLSA(4, 1, 1, targetSrv.Certificate()),
			store: daneStore,
			fail:  true,
		},
		{
			name:  "tlsa_lookup_fail_no_downgrade",
			host:  "example.com",
			port:  targetPort,
			ip:    []net.IP{net.ParseIP(targetIP)},
			tlsa:  nil,
			store: webPKIStore,
			fail:  true,
		},
		{
			name:  "dane_ee_spki",
			host:  "example.com",
			port:  targetPort,
			ip:    []net.IP{net.ParseIP(targetIP)},
			tlsa:  newTLSA(3, 1, 1, targetSrv.Certificate()),
			store: daneStore,
			fail:  false,
		},
		{
			name:         "tlsa_insecure",
			host:         "example.com",
			port:         targetPort,
			ip:           []net.IP{net.ParseIP(targetIP)},
			tlsa:         newTLSA(3, 1, 1, targetSrv.Certificate()),
			tlsaInsecure: true,
			store:        daneStore,
			fail:         true,
		},
		{
			name:  "dane_ee_spki_no_namecheck",
			host:  "foo.bar",
			port:  targetPort,
			ip:    []net.IP{net.ParseIP(targetIP)},
			tlsa:  newTLSA(3, 1, 1, targetSrv.Certificate()),
			store: daneStore,
			fail:  false,
		},
		{
			name:  "dane_ee_full",
			host:  "example.com",
			port:  targetPort,
			ip:    []net.IP{net.ParseIP(targetIP)},
			tlsa:  newTLSA(3, 0, 1, targetSrv.Certificate()),
			store: daneStore,
			fail:  false,
		},
		{
			name: "valid_and_invalid_tlsa_rrs",
			host: "example.com",
			port: targetPort,
			ip:   []net.IP{net.ParseIP(targetIP)},
			tlsa: append(append(newTLSA(1, 0, 1, proxyCA),
				newTLSA(3, 0, 1, "bar")...),
				newTLSA(3, 1, 1, targetSrv.Certificate())...),
			store: daneStore,
			fail:  false,
		},
		{
			name:  "tlsa_no_match",
			host:  "example.com",
			port:  targetPort,
			ip:    []net.IP{net.ParseIP(targetIP)},
			tlsa:  newTLSA(3, 1, 1, "1599B2352EE910499C0DA1A104575935477C5765CCD10D81F43B50AC"),
			store: daneStore,
			fail:  true,
		},
		{
			name:      "good_name_check",
			host:      "example.com", // cert is issued for example.com
			port:      targetPort,
			ip:        []net.IP{net.ParseIP(targetIP)},
			tlsa:      newTLSA(3, 1, 1, targetSrv.Certificate()),
			store:     daneStore,
			fail:      false,
			nameCheck: true,
		},
		{
			name:      "bad_name_check",
			host:      "foo.bar", // cert is issued for example.com
			port:      targetPort,
			ip:        []net.IP{net.ParseIP(targetIP)},
			tlsa:      newTLSA(3, 1, 1, targetSrv.Certificate()),
			store:     daneStore,
			fail:      true,
			nameCheck: true,
		},
		{
			name:        "name_in_constraints",
			host:        "example.com",
			port:        targetPort,
			ip:          []net.IP{net.ParseIP(targetIP)},
			tlsa:        newTLSA(3, 1, 1, targetSrv.Certificate()),
			store:       webPKIStore,
			fail:        false, // should ignore tlsa
			constraints: true,
		},
		{
			name:        "name_not_in_constraints",
			host:        "bar.3b",
			port:        targetPort,
			ip:          []net.IP{net.ParseIP(targetIP)},
			tlsa:        newTLSA(3, 1, 1, targetSrv.Certificate()),
			store:       daneStore,
			fail:        false,
			constraints: true,
		},
	}

	for _, testReq := range testRequests {
		t.Run(testReq.name, func(t *testing.T) {
			proxyHandler.Tunneler.(*tunneler).nameChecks = testReq.nameCheck
			if testReq.constraints {
				proxyHandler.Tunneler.(*tunneler).constraints = constraintTest
			} else {
				proxyHandler.Tunneler.(*tunneler).constraints = nil
			}

			// create an http transport that acts as a client using the proxySrv server
			tr := &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{
					RootCAs: testReq.store,
				},
			}

			// setup resolver for this request
			resolver.lookupIP = func(ctx context.Context, network, host string) ([]net.IP, bool, error) {
				if testReq.ip != nil && host == testReq.host {
					return testReq.ip, true, nil
				}
				return nil, false, errors.New("no such host")
			}
			resolver.lookupTLSA = func(ctx context.Context, service, proto, name string) ([]*dns.TLSA, bool, error) {
				if testReq.tlsa != nil && name == testReq.host && service == testReq.port && proto == "tcp" {
					return testReq.tlsa, !testReq.tlsaInsecure, nil
				}
				return nil, false, errors.New("no tlsa record found")
			}

			req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s:%s", testReq.host, testReq.port), nil)
			resp, err := tr.RoundTrip(req)
			if testReq.fail {
				if err != nil {
					return
				}

				t.Fatal("got nil, wanted an error")
			}
			if err != nil {
				t.Fatal(err)
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			content := string(body)
			if content != "foo" {
				t.Fatalf("body = %s, wanted 'foo'", content)
			}
		})
	}

	t.Run("alpn", func(t *testing.T) {
		proxyHandler.Tunneler.(*tunneler).nameChecks = true
		proxyHandler.Tunneler.(*tunneler).constraints = nil

		// client supports "my_proto_2" and "my_proto"
		// server only supports "my_proto". letsdane should negotiate a mutually supported ALPN
		tr := &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				NextProtos: []string{"my_proto_2", "my_proto"},
				RootCAs:    daneStore,
			},
			TLSNextProto: map[string]func(authority string, c *tls.Conn) http.RoundTripper{
				"my_proto": func(authority string, c *tls.Conn) http.RoundTripper {
					return roundTripperTestFunc(func(req *http.Request) (*http.Response, error) {
						return &http.Response{
							Body: c,
						}, nil
					})
				},
				"my_proto_2": func(authority string, c *tls.Conn) http.RoundTripper {
					t.Fatal("my proto 2 not supported by server")
					return nil
				},
			},
		}
		resolver.lookupIP = func(ctx context.Context, network, host string) ([]net.IP, bool, error) {
			return []net.IP{net.ParseIP(targetIP)}, true, nil
		}
		resolver.lookupTLSA = func(ctx context.Context, service, proto, name string) ([]*dns.TLSA, bool, error) {
			return newTLSA(3, 0, 0, targetSrv.Certificate()), true, nil
		}

		req, _ := http.NewRequest("GET", "https://example.com:"+targetPort, nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		c := string(body)
		if c != "ALPN TEST" {
			t.Fatalf("body = %s, wanted 'ALPN TEST'", c)
		}

	})
}

func TestNameInConstraints(t *testing.T) {
	var tests = []struct {
		input  string
		result bool
	}{
		{".", false},
		{"", false},
		{"org", true},
		{"com.", true},
		{".com", true},
		{"example.com", true},
		{"test.domain.google.", true},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test #%d", i), func(t *testing.T) {
			if inConstraints(constraintTest, test.input) != test.result {
				t.Fatalf("input = `%s`: got %v, wanted %v", test.input, !test.result, test.result)
			}
		})
	}
}

type roundTripperTestFunc func(req *http.Request) (*http.Response, error)

// RoundTrip implements the RoundTripper interface.
func (rt roundTripperTestFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return rt(r)
}

type testResolver struct {
	lookupIP   func(ctx context.Context, network, host string) ([]net.IP, bool, error)
	lookupTLSA func(ctx context.Context, service, proto, name string) ([]*dns.TLSA, bool, error)
}

func (t testResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, bool, error) {
	return t.lookupIP(ctx, network, host)
}

func (t testResolver) LookupTLSA(ctx context.Context, service, proto, name string) ([]*dns.TLSA, bool, error) {
	return t.lookupTLSA(ctx, service, proto, name)
}
