package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/buffrr/letsdane"
	rs "github.com/buffrr/letsdane/resolver"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"time"
)

var (
	raddr    = flag.String("r", "", "dns resolvers to use (default: /etc/resolv.conf)")
	output   = flag.String("o", "", "path to export the public CA file")
	conf     = flag.String("conf", "", "dir path to store configuration (default: ~/.letsdane)")
	addr     = flag.String("addr", ":8080", "host:port of the proxy")
	certPath = flag.String("cert", "", "filepath to custom CA")
	keyPath  = flag.String("key", "", "filepath to the CA's private key")
	anchor   = flag.String("anchor", "", "path to trust anchor file (default: hardcoded 2017 KSK)")
	verbose  = flag.Bool("verbose", false, "verbose output for debugging")
	ad       = flag.Bool("skip-dnssec", false, "check ad flag only without dnssec validation")
	validity = flag.Duration("validity", time.Hour, "window of time generated DANE certificates are valid")
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

func readPassword(confirm bool) string {
	fmt.Print("enter passphrase: ")
	input, err := terminal.ReadPassword(0)
	fmt.Println()
	if err != nil {
		log.Fatal(err)
	}

	if !confirm {
		return string(input)
	}

	fmt.Print("confirm passphrase: ")
	verify, err := terminal.ReadPassword(0)
	fmt.Println()
	if err != nil {
		log.Fatal(err)
	}

	if string(input) != string(verify) {
		log.Fatal("passphrase didn't match")
	}

	return string(input)
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
			ca, priv, err := godane.NewAuthority("DNSSEC", "DNSSEC", 365*24*time.Hour)
			if err != nil {
				log.Fatalf("couldn't generate CA: %v", err)
			}

			certOut, err := os.Create(certPath)
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

			kOut, err := os.Create(keyPath)
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
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}

	block, _ := pem.Decode(keyPEMBlock)
	var decryptedBlock []byte

	if x509.IsEncryptedPEMBlock(block) {
		decryptedBlock, err = x509.DecryptPEMBlock(block, []byte(readPassword(false)))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		decryptedBlock = keyPEMBlock
	}

	return tls.X509KeyPair(certPEMBlock, decryptedBlock)
}

func parseCA() (*x509.Certificate, interface{}) {
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
	b, err := ioutil.ReadFile(*certPath)
	if err != nil {
		log.Fatal(err)
	}

	if err := ioutil.WriteFile(*output, b, 0600); err != nil {
		log.Fatal(err)
	}
}

func setupUnbound(u *rs.Unbound) error {
	if *anchor != "" {
		if err := u.AddTAFile(*anchor) ; err != nil {
			log.Fatalf("unbound: %v", err)
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

			if err := u.SetFwd(ip + "@" + port) ; err != nil {
				return err
			}
		}

		return nil
	}

	// falls back to root hints if no /etc/resolv.conf
	_ = u.ResolvConf("/etc/resolv.conf")

	return nil
}

func main() {
	flag.Parse()
	var resolver rs.Resolver

	if *ad {
		if !isLoopback(*raddr) {
			log.Printf("WARNING: you must have a local dnssec capable resolver to use Go DANE securely")
			log.Printf("WARNING: '%s' is not a loopback address!", *raddr)
		}

		ad, err := rs.NewAD(*raddr)
		if err != nil {
			log.Fatal(err)
		}
		resolver = ad

	} else {
		u, err := rs.NewUnbound()
		if err == rs.ErrUnboundNotAvail {
			log.Fatal("Go DANE has not been compiled with unbound. if you have a local dnssec capable resolver, run with -skip-dnssec")
		}
		if err != nil {
			log.Fatalf("unbound: %v", err)
		}

		if err := setupUnbound(u) ; err != nil {
			log.Fatalf("unbound: %v", err)
		}

		defer u.Destroy()
		resolver = u
	}

	ca, priv := parseCA()
	c := &godane.Config{
		Certificate: ca,
		PrivateKey:  priv,
		Validity:    *validity,
		Resolver:    resolver,
		Verbose:     *verbose,
	}

	if *output != "" {
		exportCA()
	}

	log.Println("starting proxy on ", *addr)
	log.Fatal(c.Run(*addr))
}
