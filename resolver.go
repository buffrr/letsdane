package godane

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Resolver looks up names
type Resolver interface {
	LookupIP(string) ([]net.IP, error)
	LookupTLSA(string) ([]dns.TLSA, error)
}

// ClientResolver implements Resolver and caches queries.
type ClientResolver struct {
	rrCache  map[uint16]*cache
	client   *dns.Client
	protocol string
	address  string
}

const (
	minTTL = 10 * time.Second
	maxTTL = 3 * time.Hour
	// max cache len for each rr type
	maxCache = 10000
)

// NewResolver creates a new resolver
// the server can be specified using udp://, tcp://, tls:// or https://
func NewResolver(server string) (*ClientResolver, error) {
	address, protocol, err := parseAddress(server)
	if err != nil {
		return nil, err
	}

	client := new(dns.Client)
	client.Net = protocol
	rrCache := make(map[uint16]*cache)
	rrCache[dns.TypeA] = newCache(maxCache)
	rrCache[dns.TypeAAAA] = newCache(maxCache)
	rrCache[dns.TypeTLSA] = newCache(maxCache)

	return &ClientResolver{
		rrCache:  rrCache,
		client:   client,
		protocol: protocol,
		address:  address,
	}, nil
}

func parseAddress(server string) (string, string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", "", fmt.Errorf("dns: couldn't parse server address: %v", err)
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
		return "", "", fmt.Errorf("dns: unsupported scheme %s", u.Scheme)
	}

	_, _, err = net.SplitHostPort(u.Host)
	if err != nil && u.Scheme != "https" {
		return net.JoinHostPort(host, defaultPort), p, nil
	}

	return host, p, nil

}

func (rs *ClientResolver) exchange(m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	if rs.protocol == "https" {
		return rs.exchangeDOH(m)
	}
	return rs.client.Exchange(m, rs.address)
}

func (rs *ClientResolver) exchangeDOH(m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	buf, err := m.Pack()
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequest(http.MethodPost, rs.address+"/dns-query", bytes.NewReader(buf))
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
		return nil, 0, fmt.Errorf("dns: %s", resp.Status)
	}

	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}

	ans := new(dns.Msg)
	err = ans.Unpack(b)

	return ans, 0, err
}

func (rs *ClientResolver) checkCache(key string, qtype uint16) (*entry, bool) {
	if ans, ok := rs.rrCache[qtype].get(key); ok {
		if time.Now().Before(ans.ttl) {
			return ans, true
		}

		rs.rrCache[qtype].remove(key)
	}

	return nil, false
}

// LookupIP looks up host using the specified resolver.
// It returns a slice of that host's IPv4 and IPv6 addresses.
func (rs *ClientResolver) LookupIP(hostname string) ([]net.IP, error) {
	ip := net.ParseIP(hostname)
	if ip != nil {
		return []net.IP{ip}, nil
	}

	if !shouldResolve(hostname) {
		return net.LookupIP(hostname)
	}

	var wg sync.WaitGroup
	var ipv4, ipv6 []net.IP
	var err1, err2 error

	wg.Add(2)
	go func() {
		ipv4, err1 = rs.lookupIPv4(hostname)
		wg.Done()
	}()

	go func() {
		ipv6, err2 = rs.lookupIPv6(hostname)
		wg.Done()
	}()

	wg.Wait()

	if err1 != nil {
		return nil, err1
	}

	if err2 != nil {
		return nil, err2
	}

	return append(ipv4, ipv6...), nil
}

func (rs *ClientResolver) lookupIPv4(hostname string) ([]net.IP, error) {
	rr, err := rs.lookup(hostname, dns.TypeA)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, r := range rr {
		switch t := r.(type) {
		case *dns.A:
			ips = append(ips, t.A)
		}
	}
	return ips, nil
}

func (rs *ClientResolver) lookupIPv6(hostname string) ([]net.IP, error) {
	rr, err := rs.lookup(hostname, dns.TypeAAAA)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, r := range rr {
		switch t := r.(type) {
		case *dns.AAAA:
			ips = append(ips, t.AAAA)
		}
	}
	return ips, nil
}

// LookupTLSA returns TLSA records for the given TLSA prefix.
func (rs *ClientResolver) LookupTLSA(prefix string) ([]dns.TLSA, error) {
	rr, err := rs.lookup(prefix, dns.TypeTLSA)
	if err != nil {
		return nil, err
	}

	var tr []dns.TLSA
	for _, r := range rr {
		switch t := r.(type) {
		case *dns.TLSA:
			tr = append(tr, *t)
		}
	}

	return tr, nil
}

func (rs *ClientResolver) lookup(name string, qtype uint16) ([]dns.RR, error) {
	if ans, ok := rs.checkCache(name, qtype); ok {
		return ans.msg, nil
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.AuthenticatedData = true

	r, _, err := rs.exchange(m)
	if err != nil {
		return nil, err
	}

	if r.Truncated {
		return nil, errors.New("dns: response truncated")
	}

	if qtype == dns.TypeTLSA && !r.AuthenticatedData {
		return nil, errors.New("dns: resolver didn't confirm msg (no ad flag)")
	}

	e := &entry{
		msg: r.Answer,
		ttl: time.Now().Add(getMinTTL(r)),
	}

	rs.rrCache[qtype].set(name, e)

	return r.Answer, nil
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

func shouldResolve(hostname string) bool {
	var tld string

	index := strings.LastIndex(hostname, ".")
	if index == -1 {
		tld = hostname
	} else {
		tld = hostname[index+1:]
	}

	return tld != "test" && tld != "example" && tld != "invalid" && tld != "localhost"
}

// GetTLSAPrefix returns the TLSA prefix for the given host:port
func GetTLSAPrefix(host string) string {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return fmt.Sprintf("_%s._tcp.%s", p, h)
}
