package letsdane

// based on github.com/google/martian/mitm

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

var constraintTest = map[string]struct{}{
	"com":    {},
	"org":    {},
	"gov":    {},
	"google": {},
}

func TestConstraints(t *testing.T) {
	ca, _, err := NewAuthority("DNSSEC", "DNSSEC", 24*time.Hour, constraintTest)
	if err != nil {
		t.Fatalf("NewAuthority(): got %v, want no error", err)
	}

	if !ca.PermittedDNSDomainsCritical {
		t.Error("ca.PermittedDNSDomainsCritical: got false, want true")
	}

	testNames := []string{"google.com", "isc.org", "example.gov"}
	for _, name := range testNames {
		found := false
		for _, excluded := range ca.ExcludedDNSDomains {
			if strings.HasSuffix(name, excluded) {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("got name = %s permitted, want excluded", name)
		}
	}
}

func TestMITM(t *testing.T) {
	ca, priv, err := NewAuthority("DNSSEC", "DNSSEC", 24*time.Hour, nil)
	if err != nil {
		t.Fatalf("NewAuthority(): got %v, want no error", err)
	}

	c, err := newMITMConfig(ca, priv, 1*time.Hour, "dd")
	if err != nil {
		t.Fatalf("NewConfig(): got %v, want no error", err)
	}

	conf := c.configForTLSADomain("example.com")

	if conf.InsecureSkipVerify {
		t.Error("conf.InsecureSkipVerify: got true, want false")
	}

	// Simulate a TLS connection without SNI.
	clientHello := &tls.ClientHelloInfo{
		ServerName: "",
	}

	if _, err := conf.GetCertificate(clientHello); err == nil {
		t.Fatal("conf.GetCertificate(): got nil, want error")
	}

	// Simulate a TLS connection with SNI.
	clientHello.ServerName = "example.com"

	tlsc, err := conf.GetCertificate(clientHello)
	if err != nil {
		t.Fatalf("conf.GetCertificate(): got %v, want no error", err)
	}

	x509c := tlsc.Leaf
	if got, want := x509c.Subject.CommonName, "example.com"; got != want {
		t.Errorf("x509c.Subject.CommonName: got %q, want %q", got, want)
	}

	// SNI must match host since the host is used for the TLSA lookup
	clientHello.ServerName = "google.com"
	tlsc, err = conf.GetCertificate(clientHello)
	if err == nil {
		t.Fatalf("conf.GetCertificate(): got nil, want error")
	}

	// ServerName cannot be empty
	clientHello.ServerName = ""
	tlsc, err = conf.GetCertificate(clientHello)
	if err == nil {
		t.Fatalf("conf.GetCertificate(): got nil, want error")
	}
}

func TestCert(t *testing.T) {
	ca, priv, err := NewAuthority("DNSSEC", "DNSSEC", 24*time.Hour, nil)
	if err != nil {
		t.Fatalf("NewAuthority(): got %v, want no error", err)
	}

	c, err := newMITMConfig(ca, priv, time.Hour, "DNSSEC")
	if err != nil {
		t.Fatalf("NewConfig(): got %v, want no error", err)
	}

	tlsc, err := c.cert("example.com")
	if err != nil {
		t.Fatalf("c.cert(%q): got %v, want no error", "example.com:8080", err)
	}

	if tlsc.Certificate == nil {
		t.Error("tlsc.Certificate: got nil, want certificate bytes")
	}
	if tlsc.PrivateKey == nil {
		t.Error("tlsc.PrivateKey: got nil, want private key")
	}

	x509c := tlsc.Leaf
	if x509c == nil {
		t.Fatal("x509c: got nil, want *x509.Certificate")
	}

	if got := x509c.SerialNumber; got.Cmp(maxSerialNumber) >= 0 {
		t.Errorf("x509c.SerialNumber: got %v, want <= MaxSerialNumber", got)
	}
	if got, want := x509c.Subject.CommonName, "example.com"; got != want {
		t.Errorf("X509c.Subject.CommonName: got %q, want %q", got, want)
	}
	if err := x509c.VerifyHostname("example.com"); err != nil {
		t.Errorf("x509c.VerifyHostname(%q): got %v, want no error", "example.com", err)
	}

	if got, want := x509c.Subject.Organization, []string{"DNSSEC"}; !reflect.DeepEqual(got, want) {
		t.Errorf("x509c.Subject.Organization: got %v, want %v", got, want)
	}

	if got := x509c.SubjectKeyId; got == nil {
		t.Error("x509c.SubjectKeyId: got nothing, want key ID")
	}
	if !x509c.BasicConstraintsValid {
		t.Error("x509c.BasicConstraintsValid: got false, want true")
	}

	if got, want := x509c.KeyUsage, x509.KeyUsageKeyEncipherment; got&want == 0 {
		t.Error("x509c.KeyUsage: got nothing, want to include x509.KeyUsageKeyEncipherment")
	}
	if got, want := x509c.KeyUsage, x509.KeyUsageDigitalSignature; got&want == 0 {
		t.Error("x509c.KeyUsage: got nothing, want to include x509.KeyUsageDigitalSignature")
	}

	want := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if got := x509c.ExtKeyUsage; !reflect.DeepEqual(got, want) {
		t.Errorf("x509c.ExtKeyUsage: got %v, want %v", got, want)
	}

	if got, want := x509c.DNSNames, []string{"example.com"}; !reflect.DeepEqual(got, want) {
		t.Errorf("x509c.DNSNames: got %v, want %v", got, want)
	}

	before := time.Now().Add(-2 * time.Hour)
	if got := x509c.NotBefore; before.After(got) {
		t.Errorf("x509c.NotBefore: got %v, want after %v", got, before)
	}

	after := time.Now().Add(2 * time.Hour)
	if got := x509c.NotAfter; !after.After(got) {
		t.Errorf("x509c.NotAfter: got %v, want before %v", got, want)
	}

	// Retrieve cached certificate.
	tlsc2, err := c.cert("example.com")
	if err != nil {
		t.Fatalf("c.cert(%q): got %v, want no error", "example.com", err)
	}
	if tlsc != tlsc2 {
		t.Error("tlsc2: got new certificate, want cached certificate")
	}

	// TLS certificate for IP.
	tlsc, err = c.cert("10.0.0.1:8227")
	if err != nil {
		t.Fatalf("c.cert(%q): got %v, want no error", "10.0.0.1:8227", err)
	}
	x509c = tlsc.Leaf

	if got, want := len(x509c.IPAddresses), 1; got != want {
		t.Fatalf("len(x509c.IPAddresses): got %d, want %d", got, want)
	}

	if got, want := x509c.IPAddresses[0], net.ParseIP("10.0.0.1"); !got.Equal(want) {
		t.Fatalf("x509c.IPAddresses: got %v, want %v", got, want)
	}
}
