package letsdane

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/miekg/dns"
	"testing"
)

func TestVerifyConnection(t *testing.T) {
	// cert for: example.com
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIBLzCB4qADAgECAhEA1pbSdxe5GXDT7C8Rgqen0DAFBgMrZXAwEjEQMA4GA1UE
ChMHQWNtZSBDbzAeFw0yMDExMjAyMjM3MjJaFw0yMTExMjAyMjM3MjJaMBIxEDAO
BgNVBAoTB0FjbWUgQ28wKjAFBgMrZXADIQDTy5hjVUYs2/fZ55U9kcYq0rMzM6GV
h0ohfe/vFvtVxKNNMEswDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUF
BwMBMAwGA1UdEwEB/wQCMAAwFgYDVR0RBA8wDYILZXhhbXBsZS5jb20wBQYDK2Vw
A0EA1wQgxtVuzgpd9kKDQhheJGQyaQzcZwAR7k215Fi/h0UTLb0jwOB+YUqd3eTn
6cGblo0fJHvovm8Fvs/DSgj/DA==
-----END CERTIFICATE-----`)

	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)
	peerCerts := []*x509.Certificate{cert}

	tests := []*struct {
		name      string
		rr        []*dns.TLSA
		valid     bool
		host      string
		nameCheck bool
	}{
		{"valid_dane_ee_spki",
			newTLSA(3, 1, 1, cert),
			true,
			"",
			false,
		},
		{
			"valid_dane_ee_full",
			newTLSA(3, 0, 1, cert),
			true,
			"",
			false,
		},
		{
			"unsupported_usage",
			newTLSA(1, 1, 1, cert),
			false,
			"",
			false,
		},
		{
			"tlsa_no_match",
			newTLSA(3, 1, 1, "1599B2352EE910499C0DA1A104575935477C5765CCD10D81F43B50AC"),
			false,
			"",
			false,
		},
		{
			"name_check",
			newTLSA(3, 1, 1, cert),
			false,
			"foo.bar",
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := newTLSConfig(test.host, test.rr, test.nameCheck)
			err := c.VerifyConnection(tls.ConnectionState{PeerCertificates: peerCerts})

			if err != nil && test.valid {
				t.Fatal(err)
			}
		})

	}
}

func newTLSA(usage, selector, matching uint8, cert interface{}) []*dns.TLSA {
	c, _ := cert.(string)
	if cert, ok := cert.(*x509.Certificate); ok {
		var err error

		c, err = dns.CertificateToDANE(selector, matching, cert)
		if err != nil {
			panic(err)
		}
	}

	return []*dns.TLSA{{
		Usage:        usage,
		Selector:     selector,
		MatchingType: matching,
		Certificate:  c,
	}}
}
