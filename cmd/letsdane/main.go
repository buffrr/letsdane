package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/buffrr/hsig0"
	"github.com/buffrr/letsdane"
	rs "github.com/buffrr/letsdane/resolver"
	"github.com/miekg/dns"
)

const KSK2017 = `. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D`

var (
	raddr          = flag.String("r", "", "dns resolvers to use (default: /etc/resolv.conf)")
	output         = flag.String("o", "", "path to export the public CA file")
	conf           = flag.String("conf", "", "dir path to store configuration (default: ~/.letsdane)")
	addr           = flag.String("addr", ":8080", "host:port of the proxy")
	certPath       = flag.String("cert", "", "filepath to custom CA")
	keyPath        = flag.String("key", "", "filepath to the CA's private key")
	pass           = flag.String("pass", "", "CA passphrase or use DANE_CA_PASS environment variable to decrypt CA file (if encrypted)")
	anchor         = flag.String("anchor", "", "path to trust anchor file (default: hardcoded 2017 KSK)")
	verbose        = flag.Bool("verbose", false, "verbose output for debugging")
	ad             = flag.Bool("skip-dnssec", false, "check ad flag only without dnssec validation")
	skipICANN      = flag.Bool("skip-icann", false, "skip TLSA lookups for ICANN tlds and include them in the CA name constraints extension")
	validity       = flag.Duration("validity", time.Hour, "window of time generated DANE certificates are valid")
	skipNameChecks = flag.Bool("skip-namechecks", false, "disable name checks when matching DANE-EE TLSA reocrds.")
	version        = flag.Bool("version", false, "Show version")
)

func getConfPath() string {
	if *conf != "" {
		return *conf
	}

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("failed to get home dir: %v", err)
	}

	p := path.Join(home, ".letsdane")

	if _, err := os.Stat(p); err != nil {
		if err := os.Mkdir(p, 0700); err != nil {
			log.Fatalf("failed to create conf dir: %v", err)
		}
	}

	return p
}

func getOrCreateCA() (string, string) {
	if *certPath != "" && *keyPath != "" {
		return *certPath, *keyPath
	}
	p := getConfPath()
	certPath := path.Join(p, "cert.crt")
	keyPath := path.Join(p, "cert.key")

	if _, err := os.Stat(certPath); err != nil {
		if _, err := os.Stat(keyPath); err != nil {
			ca, priv, err := letsdane.NewAuthority("DNSSEC", "DNSSEC", 365*24*time.Hour, nameConstraints)
			if err != nil {
				log.Fatalf("couldn't generate CA: %v", err)
			}

			certOut, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatalf("couldn't create CA file: %v", err)
			}
			defer certOut.Close()

			pem.Encode(certOut, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: ca.Raw,
			})

			privOut := bytes.NewBuffer([]byte{})
			pem.Encode(privOut, &pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(priv),
			})

			kOut, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				log.Fatalf("couldn't create CA private key file: %v", err)
			}
			defer kOut.Close()

			kOut.Write(privOut.Bytes())
			return certPath, keyPath
		}
	}
	return certPath, keyPath
}

func loadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	block, _ := pem.Decode(keyPEMBlock)
	var decryptedBlock []byte

	if x509.IsEncryptedPEMBlock(block) {
		if *pass == "" {
			*pass = os.Getenv("DANE_CA_PASS")
		}

		decryptedBlock, err = x509.DecryptPEMBlock(block, []byte(*pass))
		if err != nil {
			log.Fatalf("decryption failed: %v", err)
		}
	} else {
		decryptedBlock = keyPEMBlock
	}

	return tls.X509KeyPair(certPEMBlock, decryptedBlock)
}

func loadCA() (*x509.Certificate, interface{}) {
	var x509c *x509.Certificate
	var priv interface{}

	*certPath, *keyPath = getOrCreateCA()
	if *certPath != "" && *keyPath != "" {
		cert, err := loadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			log.Fatal(err)
		}

		priv = cert.PrivateKey
		x509c, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			log.Fatal(err)
		}

		return x509c, priv
	}

	return nil, nil
}

func isLoopback(r string) bool {
	var ip net.IP
	host, _, err := net.SplitHostPort(r)

	if err == nil {
		ip = net.ParseIP(host)
	} else {
		ip = net.ParseIP(r)
	}

	return ip != nil && ip.IsLoopback()
}

func exportCA() {
	b, err := os.ReadFile(*certPath)
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(*output, b, 0600); err != nil {
		log.Fatal(err)
	}
}

func setupUnbound() (u *rs.Recursive, err error) {
	u, err = rs.NewRecursive()
	if err == rs.ErrUnboundNotAvail {
		return nil, errors.New("letsdane has not been compiled with unbound. " +
			"if you have a local dnssec capable resolver, run with -skip-dnssec")
	}
	if err != nil {
		return
	}
	defer func() {
		if u != nil && err != nil {
			u.Destroy()
		}
	}()

	if *anchor != "" {
		if err := u.AddTAFile(*anchor); err != nil {
			return nil, err
		}
	} else {
		// add hardcoded ksk if no anchor is specified
		if err := u.AddTA(KSK2017); err != nil {
			return nil, err
		}
	}

	if *raddr != "" {
		addrs := strings.Split(*raddr, " ")
		for _, r := range addrs {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}

			ip, port, err := net.SplitHostPort(r)
			if err != nil {
				port = "53"
				ip = r
			}

			if err := u.SetFwd(ip + "@" + port); err != nil {
				return nil, err
			}
		}

		return
	}

	// falls back to root hints if no /etc/resolv.conf
	_ = u.ResolvConf("/etc/resolv.conf")
	return
}

var errNoKey = errors.New("no key found")

// parses hsd format: key@host:port
func splitHostPortKey(addr string) (hostport string, key *hsig0.PublicKey, err error) {
	s := strings.Split(strings.TrimSpace(addr), "@")
	if len(s) != 2 {
		return "", nil, errNoKey
	}

	hostport = s[1]
	key, err = hsig0.ParsePublicKey(s[0])
	return
}

func main() {
	flag.Parse()
	if *version {
		fmt.Printf("Version %s\n", letsdane.Version)
		return
	}

	if !*skipICANN {
		nameConstraints = nil
	}

	ca, priv := loadCA()
	if *output != "" {
		exportCA()
		return
	}

	var resolver rs.Resolver
	var sig0, secure bool

	hostport, key, err := splitHostPortKey(*raddr)
	switch err {
	case errNoKey:
		sig0 = false
		u, err := url.Parse(*raddr)
		if err == nil {
			secure = u.Scheme == "https" || u.Scheme == "tls"
		}
	case nil:
		sig0 = true
		*ad = true
		*raddr = hostport
	default:
		log.Fatal(err)
	}

	if *ad {
		if !sig0 && !secure && !isLoopback(*raddr) {
			log.Printf("You must have a local dnssec capable resolver to use letsdane securely")
			log.Printf("'%s' is not a loopback address (insecure)!", *raddr)
		}

		ad, err := rs.NewStub(*raddr)
		if err != nil {
			log.Fatal(err)
		}
		if sig0 {
			ad.Verify = func(m *dns.Msg) error {
				return hsig0.Verify(m, key)
			}
		}
		resolver = ad

	} else {
		u, err := setupUnbound()
		if err != nil {
			log.Fatalf("unbound: %v", err)
		}
		defer u.Destroy()

		resolver = u
	}

	c := &letsdane.Config{
		Certificate:    ca,
		PrivateKey:     priv,
		Validity:       *validity,
		Resolver:       resolver,
		Constraints:    nameConstraints,
		SkipNameChecks: *skipNameChecks,
		Verbose:        *verbose,
	}

	log.Printf("Listening on %s", *addr)
	log.Fatal(c.Run(*addr))
}
