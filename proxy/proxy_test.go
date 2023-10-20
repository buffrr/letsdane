package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestHijacker(t *testing.T) {
	dialer := &net.Dialer{}
	targetSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("hey"))
	}))
	targetSrv.EnableHTTP2 = true
	targetSrv.StartTLS()
	defer targetSrv.Close()

	tun := TunnelerFunc(func(ctx context.Context, clientConn *Conn, network, addr string) {
		targetConn, err := dialer.DialContext(ctx, network, addr)
		defer clientConn.Close()

		if err != nil {
			clientConn.WriteHeader(http.StatusBadGateway)
			return
		}

		clientConn.WriteHeader(http.StatusOK)
		clientConn.Copy(targetConn)
	})

	proxySrv := httptest.NewUnstartedServer(&Handler{
		Tunneler: tun,
	})
	proxySrv.EnableHTTP2 = true
	proxySrv.StartTLS()
	defer proxySrv.Close()

	proxyUrl, _ := url.Parse(proxySrv.URL)
	store := x509.NewCertPool()
	store.AddCert(proxySrv.Certificate())
	tr := &http.Transport{
		Proxy: http.ProxyURL(proxyUrl),
		TLSClientConfig: &tls.Config{
			RootCAs: store,
		},
	}

	req, _ := http.NewRequest("GET", targetSrv.URL, nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	c := string(body)
	if c != "hey" {
		t.Fatalf("body = %s, wanted 'hey'", c)
	}
}

func TestHandler_ServeHTTPTunnelerAddr(t *testing.T) {
	f := TunnelerFunc(func(ctx context.Context, clientConn *Conn, network, addr string) {
		if addr != "example.com:443" {
			t.Errorf("addr = %s, wanted %s", addr, "example.com:443")
		}
		clientConn.Write([]byte("bar"))
	})

	proxy := &Handler{Tunneler: f}

	req := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
	req.Host = "example.org:8080"
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	resp := w.Result()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "bar" {
		t.Errorf("body = %s, wanted %s", string(body), "bar")
	}

	// request must be a valid authority form host:port
	badReq := httptest.NewRequest(http.MethodConnect, "example.com", nil)
	w = httptest.NewRecorder()
	proxy.ServeHTTP(w, badReq)

	resp = w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, wanted %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestHandler_ServeHTTPNonConnect(t *testing.T) {
	h := &Handler{
		NonConnect: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusTeapot)
			w.Write([]byte("hello"))
		}),
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	h.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("status = %d, wanted %d", resp.StatusCode, http.StatusTeapot)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello" {
		t.Errorf("body = %s, wanted %s", string(b), "hello")
	}
}
