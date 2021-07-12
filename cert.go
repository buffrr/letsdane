package letsdane

// based on github.com/google/martian/mitm

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// maxSerialNumber is the upper boundary that is used to create unique serial
// numbers for the certificate. This can be any unsigned integer up to 20
// bytes (2^(8*20)-1).
var maxSerialNumber = big.NewInt(0).SetBytes(bytes.Repeat([]byte{255}, 20))

// mitmConfig is a set of configuration values that are used to build TLS configs
// capable of MITM.
type mitmConfig struct {
	ca             *x509.Certificate
	capriv         interface{}
	priv           *rsa.PrivateKey
	keyID          []byte
	validity       time.Duration
	org            string
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	roots          *x509.CertPool

	certmu sync.RWMutex
	certs  map[string]*tls.Certificate
}

// NewAuthority creates a new CA certificate and associated
// private key.
func NewAuthority(name, organization string, validity time.Duration, constraints map[string]struct{}) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	pub := priv.Public()

	// Subject Key Identifier support for end entity certificate.
	// https://www.ietf.org/rfc/rfc3280.txt (section 4.2.1.2)
	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	h := sha1.New()
	h.Write(pkixpub)
	keyID := h.Sum(nil)

	// TODO: keep a map of used serial numbers to avoid potentially reusing a
	// serial multiple times.
	serial, err := rand.Int(rand.Reader, maxSerialNumber)
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{organization},
		},
		SubjectKeyId:          keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-validity),
		NotAfter:              time.Now().Add(validity),
		DNSNames:              []string{name},
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	if constraints != nil {
		tmpl.PermittedDNSDomainsCritical = true
		_, ipv4, _ := net.ParseCIDR("0.0.0.0/0")
		_, ipv6, _ := net.ParseCIDR("::/0")
		tmpl.ExcludedIPRanges = []*net.IPNet{ipv4, ipv6}

		var names []string
		for name := range constraints {
			names = append(names, "."+name)
		}

		tmpl.ExcludedDNSDomains = names
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	// Parse certificate bytes so that we have a leaf certificate.
	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}

	return x509c, priv, nil
}

// newMITMConfig creates a MITM config using the CA certificate and
// private key to generate on-the-fly certificates.
func newMITMConfig(ca *x509.Certificate, privateKey interface{}, validity time.Duration, organization string) (*mitmConfig, error) {
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pub := priv.Public()

	// Subject Key Identifier support for end entity certificate.
	// https://www.ietf.org/rfc/rfc3280.txt (section 4.2.1.2)
	pkixpub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	h := sha1.New()
	h.Write(pkixpub)
	keyID := h.Sum(nil)

	return &mitmConfig{
		ca:       ca,
		capriv:   privateKey,
		priv:     priv,
		keyID:    keyID,
		validity: validity,
		org:      organization,
		certs:    make(map[string]*tls.Certificate),
		roots:    roots,
	}, nil
}

// configForTLSADomain returns a *tls.mitmConfig that will generate certificates on-the-fly
// using the provided hostname
func (c *mitmConfig) configForTLSADomain(tlsaDomain string) *tls.Config {
	return &tls.Config{
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if tlsaDomain != clientHello.ServerName {
				return nil, fmt.Errorf("tlsa domain `%s` does not match server name `%s`", tlsaDomain, clientHello.ServerName)
			}
			return c.cert(tlsaDomain)
		},
	}
}

func (c *mitmConfig) cert(hostname string) (*tls.Certificate, error) {
	// Remove the port if it exists.
	host, _, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	}

	c.certmu.RLock()
	tlsc, ok := c.certs[hostname]
	c.certmu.RUnlock()

	if ok {
		// Check validity of the certificate for hostname match, expiry, etc. In
		// particular, if the cached certificate has expired, create a new one.
		if _, err := tlsc.Leaf.Verify(x509.VerifyOptions{
			DNSName: hostname,
			Roots:   c.roots,
		}); err == nil {
			return tlsc, nil
		}

	}

	serial, err := rand.Int(rand.Reader, maxSerialNumber)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{c.org},
		},
		SubjectKeyId:          c.keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore: time.
			Now().Add(-c.validity),
		NotAfter: time.Now().Add(c.validity),
	}

	if ip := net.ParseIP(hostname); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{hostname}
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca, c.priv.Public(), c.capriv)
	if err != nil {
		return nil, err
	}

	// Parse certificate bytes so that we have a leaf certificate.
	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}

	tlsc = &tls.Certificate{
		Certificate: [][]byte{raw, c.ca.Raw},
		PrivateKey:  c.priv,
		Leaf:        x509c,
	}

	c.certmu.Lock()
	c.certs[hostname] = tlsc
	c.certmu.Unlock()

	return tlsc, nil
}
