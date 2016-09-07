package csp

import (
	"fmt"
	"github.com/urfave/negroni"
	"net/http"
)

// Helpful constants for CSP values
const (
	Self       = "'self'"
	None       = "'none'"
	Any        = "*"
	CSPHeader  = "Content-Security-Policy"
	DefaultSrc = "default-src"
	ScriptSrc  = "script-src"
	ConnectSrc = "connect-src"
	ImgSrc     = "img-src"
	StyleSrc   = "style-src"
)

// Config is Content Security Policy Configuration. If you do not define a
// policy string it will not be included in the policy output
type Config struct {
	WebSocket bool   // enable dynamic websocket support in CSP
	Default   string // default-src CSP policy
	Script    string // script-src CSP policy
	Connect   string // connect-src CSP policy
	Img       string // img-src CSP policy
	Style     string // style-src CSP policy
}

// StarterConfig is a reasonable default set of policies.
//
// Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style: 'self';
func StarterConfig() Config {
	return Config{
		Default: None,
		Script:  Self,
		Connect: Self,
		Img:     Self,
		Style:   Self,
	}
}

// CSP is a http middleware that configures CSP in the response header of an http request
type CSP struct {
	*Config
	handler http.HandlerFunc
}

// New returns a new instance of CSP Middleware
func New(config Config) *CSP {
	instance := &CSP{Config: &config}
	instance.handler = instance.handlerFunc()
	return instance
}

// NegroniHandlerFunc returns a function with the negroni middleware interface
func (csp *CSP) NegroniHandlerFunc() negroni.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		csp.handler(rw, r)
		if next != nil {
			next(rw, r)
		}
	}
}

// Middleware returns a function with the http.Handler interface and provides
// github.com/justinas/alice integration
func (csp *CSP) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		csp.handler(rw, r)
		if next != nil {
			next.ServeHTTP(rw, r)
		}
	})
}

// HandlerFunc returns a function the http.HandlerFunc interface
func (csp *CSP) HandlerFunc() http.HandlerFunc {
	return csp.handler
}

// handlerFunc is the http.HandlerFunc interface
func (csp *CSP) handlerFunc() http.HandlerFunc {
	// Do as much work during construction as possible
	var defaultPolicy, scriptPolicy, connectPolicy, imgPolicy, stylePolicy, baseConnectPolicy string
	if csp.Default != "" {
		defaultPolicy = fmt.Sprintf("%s %s;", DefaultSrc, csp.Default)
	}
	if csp.Script != "" {
		scriptPolicy = fmt.Sprintf(" %s %s;", ScriptSrc, csp.Script)
	}
	if csp.Connect != "" {
		baseConnectPolicy = fmt.Sprintf(" %s %s", ConnectSrc, csp.Connect)
	}
	if csp.Img != "" {
		imgPolicy = fmt.Sprintf(" %s %s;", ImgSrc, csp.Img)
	}
	if csp.Style != "" {
		stylePolicy = fmt.Sprintf(" %s %s;", StyleSrc, csp.Style)
	}
	if csp.WebSocket && len(csp.Connect) == 0 {
		baseConnectPolicy = " " + ConnectSrc
	}
	preConnectPolicy := defaultPolicy + scriptPolicy
	postConnectPolicy := imgPolicy + stylePolicy
	return func(rw http.ResponseWriter, r *http.Request) {
		connectPolicy = baseConnectPolicy
		if csp.WebSocket {
			proto := "ws"
			if r.TLS != nil {
				proto = "wss"
			}
			connectPolicy = fmt.Sprintf("%s %s://%s", connectPolicy, proto, r.Host)
		}
		if len(connectPolicy) > 0 {
			connectPolicy += ";"
		}
		policy := fmt.Sprintf("%s%s%s", preConnectPolicy, connectPolicy, postConnectPolicy)
		if policy != "" {
			rw.Header().Add(CSPHeader, policy)
		}
	}
}
