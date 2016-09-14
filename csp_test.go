package csp

import (
	"crypto/tls"
	"fmt"
	"github.com/justinas/alice"
	"github.com/pilu/xrequestid"
	"github.com/urfave/negroni"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerNoPolicy(t *testing.T) {
	csp := New(Config{})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	if header != "" {
		t.Log(header)
		t.Error("expected header to be empty")
	}
}

func TestHandlerDefaultPolicy(t *testing.T) {
	csp := New(Config{
		Default: None,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	if header != "default-src 'none';" {
		t.Log(header)
		t.Error("expected header to be default-src 'none'")
	}
}

func TestHandlerScriptPolicy(t *testing.T) {
	csp := New(Config{
		Script: Self,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	if header != " script-src 'self';" {
		t.Log(header)
		t.Error("expected script-src to be 'self'")
	}
}

func TestHandlerConnect(t *testing.T) {
	csp := New(Config{
		Connect: Self,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	if header != " connect-src 'self';" {
		t.Log(header)
		t.Error("expected connect-src to be 'self'")
	}
}

func TestHandlerConnectWebSocket(t *testing.T) {
	csp := New(Config{
		Connect:   Self,
		WebSocket: true,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get("Content-Security-Policy")
	if header != " connect-src 'self' ws://localhost:3000;" {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", "'self' ws://localhost:3000;")
	}
}

func TestHandlerConnectWebSocketDuplicateHeader(t *testing.T) {
	csp := New(Config{
		Connect:   Self,
		WebSocket: true,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	if header != " connect-src 'self' ws://localhost:3000;" {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", "'self' ws://localhost:3000;")
	}

	r = &http.Request{}
	r.Host = "localhost:3000"
	rw = httptest.NewRecorder()
	fn(rw, r)
	header = rw.Header().Get("Content-Security-Policy")
	if header != " connect-src 'self' ws://localhost:3000;" {
		t.Errorf("expected connect-src to be %q, got %q", "'self' ws://localhost:3000;", header)
	}
}

func TestHandlerConnectTLSWebSocket(t *testing.T) {
	csp := New(Config{
		Connect:   Self,
		WebSocket: true,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.TLS = &tls.ConnectionState{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	if header != " connect-src 'self' wss://localhost:3000;" {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", "'self' ws://localhost:3000;")
	}
}

func TestHandlerConnectWebSocketOnly(t *testing.T) {
	csp := New(Config{
		WebSocket: true,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	if header != " connect-src ws://localhost:3000;" {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", "ws://localhost:3000;")
	}
}

func TestHandlerImg(t *testing.T) {
	csp := New(Config{
		Img: Self,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	if header != " img-src 'self';" {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", "img-src 'self'")
	}
}

func TestHandlerStyle(t *testing.T) {
	csp := New(Config{
		Style: Self,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	if header != " style-src 'self';" {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", "style-src 'self'")
	}
}

func TestHandlerEverything(t *testing.T) {
	csp := New(Config{
		Default: None,
		Script:  Self,
		Connect: Self,
		Img:     Self,
		Style:   Self,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	expected := "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';"
	if header != expected {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", expected)
	}
}

func TestHandlerAny(t *testing.T) {
	csp := New(Config{
		Default: Any,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	r.Host = "localhost:3000"
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	expected := "default-src *;"
	if header != expected {
		t.Log(header)
		t.Errorf("expected connect-src to be %q", expected)
	}
}

func TestNegroniIntegration(t *testing.T) {
	csp := New(Config{
		Default: None,
		Script:  Self,
		Connect: Self,
		Img:     Self,
		Style:   Self,
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Hello World")
	})
	n := negroni.Classic()
	n.UseFunc(csp.NegroniHandlerFunc())
	n.UseHandler(mux)
	ts := httptest.NewServer(n)
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fail()
	}
	_, err = ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fail()
	}

	expected := "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';"
	policy := res.Header.Get(CSPHeader)
	if expected != policy {
		t.Errorf("Expected Policy %q, got %q", expected, policy)
	}
}

// Ensure Middleware Chain is being invoked
func TestHandlerNegroniMiddlewareChain(t *testing.T) {
	csp := New(Config{
		Connect: Self,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Hello World")
	})
	n := negroni.Classic()
	n.UseFunc(csp.NegroniHandlerFunc())
	n.Use(xrequestid.New(16))
	n.UseHandler(mux)
	ts := httptest.NewServer(n)
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fail()
	}
	_, err = ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fail()
	}
	cspHeader := res.Header.Get(CSPHeader)
	xRequestID := res.Header.Get("X-Request-Id")
	if cspHeader != "connect-src 'self';" || xRequestID == "" {
		t.Log(cspHeader, xRequestID)
		t.Error("expected connect-src to be 'self' + random request id")
	}
}

func TestAliceIntegration(t *testing.T) {
	csp := New(Config{
		Default: None,
		Script:  Self,
		Connect: Self,
		Img:     Self,
		Style:   Self,
	})
	stdChain := alice.New(csp.Middleware)
	mux := http.NewServeMux()
	mux.Handle("/", stdChain.ThenFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Hello World")
	}))
	n := negroni.Classic()
	n.UseHandler(mux)
	ts := httptest.NewServer(n)
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fail()
	}
	_, err = ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fail()
	}

	expected := "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';"
	policy := res.Header.Get(CSPHeader)
	if expected != policy {
		t.Errorf("Expected Policy %q, got %q", expected, policy)
	}
}

func TestPartialConfig(t *testing.T) {
	csp := New(Config{
		Script:  Self,
		Connect: Self,
	})
	stdChain := alice.New(csp.Middleware)
	mux := http.NewServeMux()
	mux.Handle("/", stdChain.ThenFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Hello World")
	}))
	n := negroni.Classic()
	n.UseHandler(mux)
	ts := httptest.NewServer(n)
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fail()
	}
	_, err = ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fail()
	}

	expected := "script-src 'self'; connect-src 'self';"
	policy := res.Header.Get(CSPHeader)
	if expected != policy {
		t.Errorf("Expected Policy %q, got %q", expected, policy)
	}
}

func TestHandlerReportUri(t *testing.T) {
	reportUri := "https://example.com/csp-reports"
	csp := New(Config{
		ReportUri: reportUri,
	})
	fn := csp.HandlerFunc()

	rw := httptest.NewRecorder()
	r := &http.Request{}
	fn(rw, r)
	header := rw.Header().Get(CSPHeader)
	if header != fmt.Sprintf(" report-uri %s;", reportUri) {
		t.Log(header)
		t.Errorf("expected report-uri to be %q", reportUri)
	}
}
