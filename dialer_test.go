package letsdane

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDialTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {
		wr.Write([]byte("foo"))
	}))

	var (
		addrs = &addrList{}
		ip    string
		d     = newDialer()
	)

	addr := strings.TrimPrefix(srv.URL, "https://")
	ip, addrs.Port, _ = net.SplitHostPort(addr)
	addrs.Host = "example.com"
	addrs.IPs = []net.IP{net.ParseIP("255.255.255.255"), net.ParseIP(ip)}

	tlsa := newTLSA(3, 1, 1, srv.Certificate())
	config := newTLSConfig("", tlsa, false)

	conn, err := d.dialTLSContext(context.Background(), "tcp", addrs, config)
	if err != nil {
		t.Fatal(err)
	}

	conn.Write([]byte("GET / HTTP/1.1\nHost:example.org\n\r\n\r"))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	c := string(body)
	if c != "foo" {
		t.Fatalf("body = '%s', wanted 'foo'", c)
	}
}
