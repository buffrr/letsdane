package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"github.com/google/martian/v3"
	mapi "github.com/google/martian/v3/api"
	"github.com/google/martian/v3/fifo"
	"github.com/google/martian/v3/httpspec"
	"github.com/google/martian/v3/martianhttp"
	"github.com/google/martian/v3/mitm"
	"github.com/google/martian/v3/servemux"
	"godane"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

var (
	resolver = flag.String("dns", "tls://1.1.1.1", "dns resolver udp://, tcp://, tls:// or https://")
	conf     = flag.String("dir", "", "dir path to store configuration (default: ~/.godane)")
	addr     = flag.String("addr", ":8080", "host:port of the proxy")
	apiAddr  = flag.String("api-addr", ":8181", "host:port of the configuration api")
	cert     = flag.String("cert", "", "filepath to the CA (leave empty to auto generate)")
	key      = flag.String("key", "", "filepath to the private key of the CA")
	validity = flag.Duration("validity", time.Hour, "window of time generated DANE certificates are valid")
)

var badGatewayTmpl = `
<!DOCTYPE html>
<html>
<head>
<style>
body {
    font-size: 16px;
    font-family: -apple-system,BlinkMacSystemFont,Segoe UI,PingFang SC,Hiragino Sans GB,Microsoft YaHei,Helvetica Neue,Helvetica,Arial,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol;
}
h1 {
    color:#481380;
}
</style>
</head>
<body>
<div style="margin: 0 auto; text-align: center; margin-top: 6em;">
<h1>HTTP 502 - Bad Gateway</h1><p>An error occurred while making this request: </p><br>
<pre>`

var daneSetupTmpl = `
<!DOCTYPE html>
<html>
<head>
<style>
body {
    font-size: 16px;
    font-family: -apple-system,BlinkMacSystemFont,Segoe UI,PingFang SC,Hiragino Sans GB,Microsoft YaHei,Helvetica Neue,Helvetica,Arial,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol;
}
h1 {
    color:#481380;
}
.c {
    max-width:600px;margin:0 auto;margin-top:6em;
}
.btn {
    background-color:#481380;color:#fff;
    border:none;
    border-radius:4px;
    padding:.8em;margin-left:.1em;
    text-decoration:none;
}
    </style>
</head>
<body>
	<div class="c">
		<h1>Go DANE Setup</h1>
        <h3>Install Certificate</h3>
		<p>The root CA has been generated and stored at <code>{{.CertPath}}</code>. <br>
         </p>
         <p>Add this certificate to your browser's trusted root certificates. It will be used to generate certificates for websites that use DANE.</p>
        <br><br><br>
        <a href="{{.CertURL}}" class="btn">Install Certificate</a>
    </div>
    </div>
  </body>
</html>
`

const certEndpoint = "/authority.cer"
const godaneHost = "godane.test"

var indexTmpl *template.Template

type indexTmplData struct {
	CertPath string
	CertURL  string
}

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

func generateCA() (string, string) {
	if *cert != "" && *key != "" {
		return *cert, *key
	}

	p := getConfPath()
	ca, priv, err := mitm.NewAuthority("DNSSEC", "DNSSEC", 365*24*time.Hour)
	if err != nil {
		log.Fatalf("couldn't generate CA: %v", err)
	}

	certPath := path.Join(p, "cert.crt")
	keyPath := path.Join(p, "cert.key")

	if _, err := os.Stat(certPath); err != nil {

		cOut, err := os.Create(certPath)
		if err != nil {
			log.Fatalf("couldn't create CA file: %v", err)
		}

		// pem encode
		pem.Encode(cOut, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ca.Raw,
		})

		if err := cOut.Close(); err != nil {
			log.Fatalf("couldn't close CA file: %v", err)
		}

		kOut, err := os.Create(keyPath)
		if err != nil {
			log.Fatalf("couldn't create CA key file: %v", err)
		}

		pem.Encode(kOut, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		})

		if err := kOut.Close(); err != nil {
			log.Fatalf("couldn't close CA key file: %v", err)
		}
	}

	return certPath, keyPath
}

func setupMITM(p *martian.Proxy, mux *http.ServeMux, rs godane.Resolver) {
	var x509c *x509.Certificate
	var priv interface{}

	*cert, *key = generateCA()
	if *cert != "" && *key != "" {
		tlsc, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			log.Fatal(err)
		}
		priv = tlsc.PrivateKey

		x509c, err = x509.ParseCertificate(tlsc.Certificate[0])
		if err != nil {
			log.Fatal(err)
		}
	}

	if x509c != nil && priv != nil {
		mc, err := mitm.NewConfig(x509c, priv)
		if err != nil {
			log.Fatal(err)
		}

		mc.SetValidity(*validity)
		mc.SetOrganization("DNSSEC")
		p.SetMITM(mc)
		p.SkipMITM(func(req *http.Request) bool {
			prefix := godane.GetTLSAPrefix(req.Host)
			if ans, err := rs.LookupTLSA(prefix); err == nil && godane.TLSASupported(ans) {
				return false
			}
			return true
		})

		// Expose certificate authority.
		ah := martianhttp.NewAuthorityHandler(x509c)
		configure(certEndpoint, ah, mux)
		configure("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			indexTmpl.Execute(w, indexTmplData{
				CertPath: *cert,
				CertURL:  "http://" + path.Join(godaneHost, certEndpoint),
			})
		}), mux)
	}
}

func main() {
	p := martian.NewProxy()
	defer p.Close()

	rs, err := godane.NewResolver(*resolver)
	if err != nil {
		log.Fatal(err)
	}

	tr := godane.RoundTripper(rs)
	p.SetRoundTripper(tr)
	p.SetDial(godane.GetDialFunc(rs))

	mux := http.NewServeMux()
	setupMITM(p, mux, rs)

	// Note: this part uses the same forwarding logic in the original martian proxy[0]
	//  to handle requests for http://godane.test
	// [0]: https://github.com/google/martian/blob/master/cmd/proxy/main.go

	stack, fg := httpspec.NewStack("martian")

	// wrap stack in a group so that we can forward API requests to the API port
	// before the httpspec modifiers which include the via modifier which will
	// trip loop detection
	topg := fifo.NewGroup()

	// Redirect API traffic to API server.
	if *apiAddr != "" {
		apip := strings.Replace(*apiAddr, ":", "", 1)
		port, err := strconv.Atoi(apip)
		if err != nil {
			log.Fatal(err)
		}

		// Forward traffic that pattern matches in http.DefaultServeMux
		apif := servemux.NewFilter(mux)
		apif.SetRequestModifier(mapi.NewForwarder("", port))
		topg.AddRequestModifier(apif)
	}
	topg.AddRequestModifier(stack)
	topg.AddResponseModifier(stack)
	topg.AddResponseModifier(martian.ResponseModifierFunc(func(res *http.Response) error {
		if res.StatusCode == 502 {
			// format:199 "martian" "error message" "date"
			w := strings.TrimSpace(res.Header.Get("Warning"))
			p := strings.Split(w, `"`)
			if len(p) != 7 {
				return nil
			}

			msg := p[3]
			raw := []byte(badGatewayTmpl + msg)
			res.ContentLength = int64(len(raw))
			res.Header.Set("Content-Length", strconv.Itoa(len(raw)))
			res.Body = ioutil.NopCloser(bytes.NewReader(raw))
		}

		return nil
	}))

	p.SetRequestModifier(topg)
	p.SetResponseModifier(topg)

	m := martianhttp.NewModifier()
	fg.AddRequestModifier(m)
	fg.AddResponseModifier(m)

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}

	lAPI, err := net.Listen("tcp", *apiAddr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("godane: starting proxy on %s and api on %s", l.Addr().String(), lAPI.Addr().String())

	go p.Serve(l)
	http.Serve(lAPI, mux)
}

func init() {
	var err error
	indexTmpl, err = template.New("index").Parse(daneSetupTmpl)
	if err != nil {
		log.Fatal(err)
	}

	martian.Init()
}

// configure installs a configuration handler at path.
func configure(pattern string, handler http.Handler, mux *http.ServeMux) {
	// register handler for godane.test
	mux.Handle(godaneHost+pattern, handler)

	// register handler for local server
	p := path.Join("localhost"+*apiAddr, pattern)
	mux.Handle(p, handler)
}
