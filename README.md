# Content Security Policy (CSP) Middleware

A simple middleware for configuring CSP headers with support for websockets.

This middleware was inspired by github.com/unrolled/secure which
provides a good way to apply security policy to your HTTP server
response headers to help mitigate some common web based XSS attacks.

Unfortunately the unrolled/secure CSP configuration is a static
string. Combining this with web sockets in dynamic environments
where the server may be running behind a reverse proxy or in a
Container, means that it is not possible to use the connect-src
policy if you also wish to use websockets.

This middleware provides just the CSP header, but also supports
reading the host value directly out of the HTTP request and configuring
the appropriate WS (HTTP) or WSS (TLS) protocol based on the request
configuration.

If you don't specify a specific CSP policy field, the middleware
will not configure a policy for it.

## Policy strings

csp has some commonly used constants defined

```go
const (
	Self      = "'self'"
	None      = "'none'"
	Any       = "*"
	CSPHeader = "Content-Security-Policy"
)
```

### Starter Config

csp has a starter config policy, with reasonable defaults, which
you can use as a basis for customizing your own.

```go
  csp := csp.New(csp.StarterConfig())

  ... use of csp middleware ...
```

### Dynamic WebSocket Support

If you specify WebSocket in the config, the middleware will dynamically
permit the Host specified in the Request.Host field to use Web Sockets.

TODO: consider adding a white-list feature to prevent weird attacks
against things like vhosts.

```go
	csp := csp.New(csp.Config{
		Default:   csp.None,
		Script:    csp.Self,
		Connect:   csp.Self,
		Img:       csp.Self,
		Style:     csp.Self,
		WebSocket: true,
	})
```

## Integration

### Negroni
```go
package main

import (
  "github.com/yanfali/csp"
  "github.com/urfave/negroni"
)

func main() {

    ... set up code for router ...

	n := negroni.Classic()

	csp := csp.New(csp.Config{
		Default: csp.None,
		Script:  csp.Self,
		Connect: csp.Self,
		Img:     csp.Self,
		Style:   csp.Self,
	})
	n.UseFunc(csp.NegroniHandlerFunc())

	... startup code for http server ...
}

```

### Alice
```go

	csp := csp.New(csp.Config{
		Default: csp.None,
		Script:  csp.Self,
		Connect: csp.Self,
		Img:     csp.Self,
		Style:   csp.Self,
	})
  	stdChain := alice.New(csp.Middleware)
	mux := http.NewServeMux()
	mux.Handle("/", stdChain.ThenFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "Hello World")

```

csp also supports anything that accepts a standard http.HandlerFunc
(csp.HandlerFunc()) or http.Handler (csp.Middleware).
