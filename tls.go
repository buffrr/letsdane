package letsdane

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"time"
)

type tlsError struct {
	err string
}

func (t *tlsError) Error() string {
	return t.err
}

// newTLSConfig creates a new tls configuration capable of validating DANE.
func newTLSConfig(host string, rrs []*dns.TLSA, nameCheck bool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // lgtm[go/disabled-certificate-check]
		VerifyConnection:   verifyConnection(rrs, nameCheck),
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		// Supported TLS 1.2 cipher suites
		// Crypto package does automatic cipher suite ordering
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}
}

// verifyConnection returns a function that verifies the given tls connection state using the host and rrs
func verifyConnection(rrs []*dns.TLSA, nameCheck bool) func(cs tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		// the host can be ignored per RFC 7671. Not Before, Not After are ignored as well.
		// https://tools.ietf.org/html/rfc7671
		if nameCheck {
			if err := cs.PeerCertificates[0].VerifyHostname(cs.ServerName); err != nil {
				return &tlsError{err: fmt.Sprintf("tls: %v", err)}
			}
		}

		// Verify the leaf certificate against the TLSA rrs
		for _, t := range rrs {
			if t.Usage != 3 {
				continue
			}
			if err := t.Verify(cs.PeerCertificates[0]); err == nil {
				return nil
			}
		}
		return &tlsError{err: "tls: dane authentication failed"}
	}
}

// terminateTLSHandshake terminates the tls handshake with an internal error alert
// this is slightly more descriptive to indicate a validation failure instead of promptly closing the connection
func terminateTLSHandshake(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second * 3))

	c := &tls.Config{
		// returning an error in GetCertificate will send an internal error alert
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, errors.New("tls: no cert available for this name")
		},
	}

	clientTLS := tls.Server(conn, c)
	clientTLS.Handshake()
}
