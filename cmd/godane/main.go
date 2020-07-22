package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/buffrr/godane"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"os"
	"path"
	"time"
)

var (
	resolver = flag.String("dns", "tls://1.1.1.1", "resolver supports udp://, tcp://, tls:// or https://")
	conf     = flag.String("conf", "", "dir path to store configuration (default: ~/.godane)")
	addr     = flag.String("addr", ":8080", "host:port of the proxy")
	certPath = flag.String("cert", "", "filepath to custom CA")
	keyPath  = flag.String("key", "", "filepath to the CA's private key")
	pass     = flag.String("pass", "", "passphrase for the private key to avoid being prompted")
	verbose  = flag.Bool("verbose", false, "verbose output for debugging")
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

	p := path.Join(home, ".godane")

	if _, err := os.Stat(p); err != nil {
		if err := os.Mkdir(p, 0700); err != nil {
			log.Fatalf("failed to create conf dir: %v", err)
		}
	}

	return p
}

func readPassword(confirm bool) string {
	if *pass != "" {
		return *pass
	}

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

	*pass = string(input)
	return *pass
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

			password := readPassword(true)

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

			if password == "" {
				kOut.Write(privOut.Bytes())
				return certPath, keyPath
			}

			block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", privOut.Bytes(),
				[]byte(password), x509.PEMCipherAES256)

			if err != nil {
				log.Fatal(err)
			}

			pem.Encode(kOut, block)
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

func main() {
	flag.Parse()
	rs, err := godane.NewResolver(*resolver)
	if err != nil {
		log.Fatal(err)
	}

	ca, priv := parseCA()
	c := &godane.Config{
		Certificate: ca,
		PrivateKey:  priv,
		Validity:    *validity,
		Resolver:    rs,
		Verbose:     *verbose,
	}

	log.Println("starting proxy on ", *addr)
	log.Fatal(c.Run(*addr))
}
