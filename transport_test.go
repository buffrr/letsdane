package godane

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/google/martian/v3/mitm"
	"github.com/miekg/dns"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type TestResolver struct {
	domain    string
	ip        net.IP
	tlsaPrefx string
	tlsaRRs   []dns.TLSA
}

func (rs TestResolver) LookupIP(name string) ([]net.IP, error) {
	if name == rs.domain {
		return []net.IP{rs.ip}, nil
	}

	return nil, errors.New("no such host")
}

func (rs TestResolver) LookupTLSA(prefix string) ([]dns.TLSA, error) {
	if prefix == rs.tlsaPrefx {
		return rs.tlsaRRs, nil
	}

	return nil, errors.New("not found")
}

func TestRoundTripperTLS(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello")
	}))
	defer ts.Close()
	cert, _, goodTLSA := testCreateCertTLSAPair(3, 1, 1)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ts.StartTLS()

	// https://127.0.0.1:port => https://example.com:port
	url, _ := url.Parse(ts.URL)
	host, port, _ := net.SplitHostPort(url.Host)
	addr := net.JoinHostPort("example.com", port)
	requrl := "https://" + addr

	rs := TestResolver{
		domain: "example.com",
		ip:     net.ParseIP(host),
	}

	client := ts.Client()
	client.Transport = RoundTripper(rs)

	// no tlsa
	_, err := client.Get(requrl)
	if err == nil {
		t.Fatalf("want error, got nil")
	}

	// tlsa doesn't match server certificate
	rs.tlsaPrefx = GetTLSAPrefix(addr)
	_, _, tlsa2 := testCreateCertTLSAPair(3, 1, 1)
	rs.tlsaRRs = []dns.TLSA{tlsa2}

	client.Transport = RoundTripper(rs)
	_, err = client.Get(requrl)
	if err == nil {
		t.Fatalf("want error, got nil")
	}

	// good tlsa
	rs.tlsaRRs = []dns.TLSA{goodTLSA}
	client.Transport = RoundTripper(rs)
	res, err := client.Get(requrl)

	if err != nil {
		t.Fatal(err)
	}
	greeting, err := ioutil.ReadAll(res.Body)
	res.Body.Close()

	if err != nil {
		log.Fatal(err)
	}

	got := strings.TrimSpace(string(greeting))

	if got != "hello" {
		t.Fatalf("want `hello`, got `%s`", got)
	}

	// unsupported tlsa
	_, _, tlsa3 := testCreateCertTLSAPair(1, 0, 1)
	rs.tlsaRRs = []dns.TLSA{tlsa3}
	client.Transport = RoundTripper(rs)
	_, err = client.Get(requrl)

	if err == nil {
		t.Fatalf("want error, got nil")
	}
}

func TestRoundTripperNoTLS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello")
	})))
	defer ts.Close()

	// http://127.0.0.1:port => http://example.com:port
	url, _ := url.Parse(ts.URL)
	host, port, _ := net.SplitHostPort(url.Host)
	addr := net.JoinHostPort("example.com", port)
	requrl := "http://" + addr

	rs := TestResolver{
		domain: "example.com",
		ip:     net.ParseIP(host),
	}

	client := ts.Client()
	client.Transport = RoundTripper(rs)

	res, err := client.Get(requrl)
	if err != nil {
		t.Fatal(err)
	}

	greeting, err := ioutil.ReadAll(res.Body)
	res.Body.Close()

	if err != nil {
		log.Fatal(err)
	}

	got := strings.TrimSpace(string(greeting))

	if got != "hello" {
		t.Fatalf("want `hello`, got `%s`", got)
	}
}

// creates a test certificate and a TLSA record for it.
func testCreateCertTLSAPair(usage, selector, matching uint8) (tls.Certificate, *rsa.PrivateKey, dns.TLSA) {
	ca, priv, err := mitm.NewAuthority("DNSSEC", "DNSSEC", time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	m, err := mitm.NewConfig(ca, priv)
	if err != nil {
		log.Fatal(err)
	}
	mc := m.TLS()
	cert, err := mc.GetCertificate(&tls.ClientHelloInfo{
		ServerName: "example.com",
	})

	if err != nil {
		log.Fatal(err)
	}

	if cert == nil {
		log.Fatal("no cert")
	}

	certStr, err := dns.CertificateToDANE(selector, matching, cert.Leaf)
	if err != nil {
		log.Fatal(err)
	}

	tlsa := dns.TLSA{
		Usage:        usage,
		Selector:     selector,
		MatchingType: matching,
		Certificate:  certStr,
	}

	return *cert, priv, tlsa
}

func printCA(ca *x509.Certificate) {
	raw := bytes.NewBuffer(make([]byte, 8000))
	pem.Encode(raw, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Raw,
	})

	fmt.Println(raw.String())
}
