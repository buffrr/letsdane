package resolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
)

// Stub is an AD-bit aware stub resolver
// implementing the Resolver interface
type Stub struct {
	rrCache map[uint16]*cache
	client  *client

	exchangeFunc func(ctx context.Context, m *dns.Msg, client *client) (r *dns.Msg, rtt time.Duration, err error)
	Verify       func(m *dns.Msg) error
	DefaultResolver
}

type client struct {
	d    *dns.Client
	addr string
}

const (
	maxAttempts = 3
	minTTL      = 10 * time.Second
	maxTTL      = 3 * time.Hour
	// max cache len for each rr type
	maxCache      = 5000
	lookupTimeout = 10 * time.Second
)

func parseSimpleAddr(server string) (string, error) {
	_, _, err := net.SplitHostPort(server)
	if err == nil {
		return server, nil
	}

	return net.JoinHostPort(server, "53"), nil
}

func parseAddress(server string) (string, string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", "", fmt.Errorf("couldn't parse server address: %v", err)
	}

	var p, defaultPort string
	host := u.Host

	switch u.Scheme {
	case "udp":
		defaultPort = "53"
		p = ""
	case "tcp":
		p = u.Scheme
		defaultPort = "53"
	case "tls":
		p = "tcp-tls"
		defaultPort = "853"
	case "https":
		p = u.Scheme
		host = u.Scheme + "://" + u.Host
	default:
		return "", "", fmt.Errorf("unsupported scheme %s", u.Scheme)
	}

	_, _, err = net.SplitHostPort(u.Host)
	if err != nil && u.Scheme != "https" {
		return net.JoinHostPort(host, defaultPort), p, nil
	}

	return host, p, nil

}

// NewStub creates a new stub resolver
func NewStub(server string) (*Stub, error) {
	addr, proto, err := parseAddress(server)

	if err != nil {
		addr, err = parseSimpleAddr(server)

		if err != nil {
			return nil, err
		}
		proto = "udp"
	}
	c := &client{}
	c.addr = addr

	c.d = new(dns.Client)
	c.d.Net = proto
	c.d.Timeout = lookupTimeout

	rrCache := make(map[uint16]*cache)
	rrCache[dns.TypeA] = newCache(maxCache)
	rrCache[dns.TypeAAAA] = newCache(maxCache)
	rrCache[dns.TypeTLSA] = newCache(maxCache)

	stub := &Stub{
		rrCache:      rrCache,
		client:       c,
		exchangeFunc: exchange,
	}
	stub.DefaultResolver = DefaultResolver{
		Query: stub.lookup,
	}

	return stub, nil
}

func exchange(ctx context.Context, m *dns.Msg, client *client) (r *dns.Msg, rtt time.Duration, err error) {
	for i := 0; i < maxAttempts; i++ {
		if client.d.Net == "https" {
			return exchangeDOH(ctx, m, client.addr)
		}

		r, rtt, err = client.d.ExchangeContext(ctx, m, client.addr)
		if err == nil {
			return
		}
	}

	return
}

func exchangeDOH(ctx context.Context, m *dns.Msg, doh string) (r *dns.Msg, rtt time.Duration, err error) {
	buf, err := m.Pack()
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doh+"/dns-query", bytes.NewReader(buf))
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("content-type", "application/dns-message")
	req.Header.Set("accept", "application/dns-message")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("error fetching response %s", resp.Status)
	}

	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	ans := new(dns.Msg)
	err = ans.Unpack(b)

	return ans, 0, err
}

func (s *Stub) checkCache(key string, qtype uint16) (*entry, bool) {
	if ans, ok := s.rrCache[qtype].get(key); ok {
		if time.Now().Before(ans.ttl) {
			return ans, true
		}

		s.rrCache[qtype].remove(key)
	}

	return nil, false
}

func (s *Stub) lookup(ctx context.Context, name string, qtype uint16) *DNSResult {
	if ans, ok := s.checkCache(name, qtype); ok {
		return &DNSResult{ans.msg, ans.secure, nil}
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(4096, false)
	m.RecursionDesired = true
	m.AuthenticatedData = true

	r, _, err := s.exchangeFunc(ctx, m, s.client)
	if err != nil {
		return &DNSResult{nil, false, err}
	}

	if s.Verify != nil {
		if err := s.Verify(r); err != nil {
			return &DNSResult{nil, false, fmt.Errorf("verify error: %v", err)}
		}
	}

	if r.Truncated {
		return &DNSResult{nil, false, errors.New("response truncated")}
	}

	if r.Rcode == dns.RcodeServerFailure {
		return &DNSResult{nil, false, ErrServFail}
	}

	if r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError {
		e := &entry{
			msg:    r.Answer,
			secure: r.AuthenticatedData,
			ttl:    time.Now().Add(getMinTTL(r)),
		}

		s.rrCache[qtype].set(name, e)

		return &DNSResult{e.msg, e.secure, nil}
	}

	return &DNSResult{nil, false, fmt.Errorf("failed with rcode %d", r.Rcode)}
}

// getMinTTL get the ttl for dns msg
// borrowed from coredns: https://github.com/coredns/coredns/blob/master/plugin/pkg/dnsutil/ttl.go
func getMinTTL(m *dns.Msg) time.Duration {
	// No records or OPT is the only record, return a short ttl as a fail safe.
	if len(m.Answer)+len(m.Ns) == 0 &&
		(len(m.Extra) == 0 || (len(m.Extra) == 1 && m.Extra[0].Header().Rrtype == dns.TypeOPT)) {
		return minTTL
	}

	minTTL := maxTTL
	for _, r := range m.Answer {
		if r.Header().Ttl < uint32(minTTL.Seconds()) {
			minTTL = time.Duration(r.Header().Ttl) * time.Second
		}
	}
	for _, r := range m.Ns {
		if r.Header().Ttl < uint32(minTTL.Seconds()) {
			minTTL = time.Duration(r.Header().Ttl) * time.Second
		}
	}

	for _, r := range m.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
			// OPT records use TTL field for extended rcode and flags
			continue
		}
		if r.Header().Ttl < uint32(minTTL.Seconds()) {
			minTTL = time.Duration(r.Header().Ttl) * time.Second
		}
	}
	return minTTL
}
