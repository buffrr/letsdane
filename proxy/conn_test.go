package proxy

import (
	"crypto/tls"
	"net"
	"testing"
)

func TestConn_PeekClientHello(t *testing.T) {
	srv, c := net.Pipe()
	client := tls.Client(c, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"foo"},
	})
	p := &Conn{
		wh:   func(i int) {},
		Conn: srv,
	}

	go func() {
		client.Handshake()
	}()

	hello, err := p.PeekClientHello()
	if err != nil {
		t.Fatal(err)
	}
	if hello.ServerName != "example.com" || hello.SupportedProtos[0] != "foo" {
		t.Fatal("bad client hello")
	}

	var hello2 *tls.ClientHelloInfo
	tls.Server(p, &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			hello2 = info
			return nil, nil
		},
		InsecureSkipVerify: true,
	}).Handshake()

	if hello2 == nil {
		t.Fatal("got nil, want client hello 2")
	}
}
