package http

// TODO: Create a list of warnings and errors
// TODO: Handle connection refused

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptrace"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/http2"

	h "net/http"
)

const DefaultUserAgent = "github.com/sfreiberg/probes"

// HTTPRequest is a HTTPRequest check
type HTTPRequest struct {
	// URL to check
	URL string

	// Specify the HTTP method (GET, POST, PUT, DELETE, etc...) Empty defaults to GET
	Method string

	// Used for POST and PUTS
	Body string

	// Check for the following Regex. An empty string means the regex check is ignored
	Regex string

	BasicAuthUsername string

	BasicAuthPassword string

	// UserAgent is used to set a custom UserAgent. If left unset it will
	// default to DefaultUserAgent.
	UserAgent string

	// ContentType specifies a specific content-type for the request.
	ContentType string

	// CustomHeader allows specifying arbitrary headers.
	CustomHeader h.Header
}

func (r *HTTPRequest) setBasicAuth() bool {
	return r.BasicAuthPassword != "" || r.BasicAuthUsername != ""
}

func HTTP(ctx context.Context, req *HTTPRequest) (*HTTPResponse, error) {
	if req.CustomHeader == nil {
		req.CustomHeader = h.Header{}
	}
	res := &HTTPResponse{}

	client, err := newClient()
	if err != nil {
		return res, err
	}
	defer client.CloseIdleConnections()

	var reqBody io.Reader

	if req.Body != "" {
		reqBody = strings.NewReader(req.Body)
	}

	trace := newClientTrace(res)

	ctx = httptrace.WithClientTrace(ctx, trace)

	r, err := h.NewRequestWithContext(ctx, req.Method, req.URL, reqBody)
	if err != nil {
		return res, err
	}
	r.Header = req.CustomHeader

	if req.setBasicAuth() {
		r.SetBasicAuth(req.BasicAuthUsername, req.BasicAuthPassword)
	}

	userAgent := DefaultUserAgent
	if req.UserAgent != "" {
		userAgent = req.UserAgent
	}
	r.Header.Set("User-Agent", userAgent)

	if req.ContentType != "" {
		r.Header.Set("Content-Type", req.ContentType)
	}

	res.Start = time.Now()
	resp, err := client.Do(r)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return res, err
	}

	res.End = time.Now()

	res.ContentLen = len(body)
	res.Compression = resp.Uncompressed
	res.StatusCode = resp.StatusCode
	res.Protocol = resp.Proto

	if req.Regex != "" {
		re, err := regexp.Compile(req.Regex)
		if err != nil {
			return res, err
		}

		res.RegexMatched = re.Match(body)
	}

	res.TLS = resp.TLS != nil
	if resp.TLS != nil {
		start := certNotBefore(resp.TLS.PeerCertificates)
		end := certNotAfter(resp.TLS.PeerCertificates)
		res.TLSCertStart = &start
		res.TLSCertEnd = &end

		res.TLSVersion = tlsVersion(resp)

		if resp.TLS.PeerCertificates[0].VerifyHostname(r.URL.Host) == nil {
			res.TLSValidHostname = true
		}
	}

	return res, nil
}

func newClient() (*http.Client, error) {
	// Setup the transport. We need to ignore TLS errors so we can still
	// ping sites with invalid certs.
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}

	// Because we create a custom TLSClientConfig, we have to opt-in to HTTP/2.
	// See https://github.com/golang/go/issues/14275
	err := http2.ConfigureTransport(tr)
	if err != nil {
		return nil, err
	}

	// Create a client with our custom transport and never follow redirects.
	// The thinking on redirects is that it makes quantification difficult
	// because you have multiple requests to keep track of.
	//
	// We also can't reuse the client because it will keep a connection
	// established for http2 and that messes up our numbers.
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return client, nil
}

func newClientTrace(res *HTTPResponse) *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			res.DNSStart = time.Now()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			res.DNSComplete = time.Now()
		},
		ConnectDone: func(string, string, error) {
			res.TCPConnComplete = time.Now()
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			res.TLSHandshakeComplete = time.Now()
		},
		GotFirstResponseByte: func() {
			res.FirstByte = time.Now()
		},
	}
}

func tlsVersion(resp *h.Response) string {
	switch resp.TLS.Version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

func certNotBefore(certs []*x509.Certificate) time.Time {
	if len(certs) == 0 {
		return time.Time{}
	} else if len(certs) == 1 {
		return certs[0].NotBefore
	}

	t := certs[0].NotBefore

	for i := range certs {
		if certs[i].NotBefore.After(t) {
			t = certs[i].NotBefore
		}
	}

	return t
}

func certNotAfter(certs []*x509.Certificate) time.Time {
	if len(certs) == 0 {
		return time.Time{}
	} else if len(certs) == 1 {
		return certs[0].NotAfter
	}

	t := certs[0].NotAfter

	for i := range certs {
		if certs[i].NotAfter.Before(t) {
			t = certs[i].NotAfter
		}
	}

	return t
}

// HTTPResponse contains the results of a HTTP check
type HTTPResponse struct {
	// Timings
	Start                time.Time
	DNSStart             time.Time
	DNSComplete          time.Time
	TCPConnComplete      time.Time
	TLSHandshakeComplete time.Time
	FirstByte            time.Time
	End                  time.Time

	// SSL
	TLS              bool
	TLSCertStart     *time.Time
	TLSCertEnd       *time.Time
	TLSVersion       string
	TLSValidHostname bool

	// Http
	Protocol    string
	ContentLen  int
	StatusCode  int
	Compression bool

	// Other
	RegexMatched bool
}

// TLSExpiration is how long before the cert expires
func (r *HTTPResponse) TLSExpiration() time.Duration {
	return r.TLSCertEnd.Sub(r.Start)
}

// TLSExpInDays is the number of days before the cert expires
func (r *HTTPResponse) TLSExpInDays() float64 {
	exp := r.TLSExpiration()

	return float64(exp) / float64(time.Hour) / 24
}
