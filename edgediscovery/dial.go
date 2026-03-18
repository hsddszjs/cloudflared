package edgediscovery

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/pkg/errors"
)

// DialEdge makes a TLS connection to a Cloudflare edge node
func DialEdge(
	ctx context.Context,
	timeout time.Duration,
	tlsConfig *tls.Config,
	edgeTCPAddr *net.TCPAddr,
	localIP net.IP,
) (net.Conn, error) {
	// Inherit from parent context so we can cancel (Ctrl-C) while dialing
	dialCtx, dialCancel := context.WithTimeout(ctx, timeout)
	defer dialCancel()

	dialer := net.Dialer{}
	if localIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: localIP, Port: 0}
	}

	edgeAddr := edgeTCPAddr.String()

	// Check if we should use an HTTP CONNECT proxy
	edgeConn, err := dialWithProxy(dialCtx, &dialer, edgeAddr)
	if err != nil {
		return nil, newDialError(err, "DialContext error")
	}

	tlsEdgeConn := tls.Client(edgeConn, tlsConfig)
	tlsEdgeConn.SetDeadline(time.Now().Add(timeout))

	if err = tlsEdgeConn.Handshake(); err != nil {
		return nil, newDialError(err, "TLS handshake with edge error")
	}
	// clear the deadline on the conn; http2 has its own timeouts
	tlsEdgeConn.SetDeadline(time.Time{})
	return tlsEdgeConn, nil
}

// dialWithProxy attempts to connect to the target address, using an HTTP CONNECT proxy if configured.
func dialWithProxy(ctx context.Context, dialer *net.Dialer, addr string) (net.Conn, error) {
	proxyURL := getProxyURL(addr)
	if proxyURL == nil {
		return dialer.DialContext(ctx, "tcp", addr)
	}

	// Connect to the proxy server
	proxyAddr := proxyURL.Host
	if proxyURL.Port() == "" {
		proxyAddr = net.JoinHostPort(proxyURL.Hostname(), "8080")
	}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %s: %w", proxyAddr, err)
	}

	// Send HTTP CONNECT request
	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}

	// Add proxy authentication if provided
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		connectReq.Header.Set("Proxy-Authorization",
			"Basic "+basicAuth(proxyURL.User.Username(), password))
	}

	if err := connectReq.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to write CONNECT request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), connectReq)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT returned %s", resp.Status)
	}

	return conn, nil
}

// getProxyURL returns the proxy URL from environment variables, or nil if no proxy is configured.
func getProxyURL(targetAddr string) *url.URL {
	// Use Go's standard proxy detection
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: targetAddr}}
	proxyURL, err := http.ProxyFromEnvironment(req)
	if err != nil || proxyURL == nil {
		return nil
	}
	return proxyURL
}

// basicAuth returns the Base64 encoding of an HTTP basic auth header.
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// Ensure NO_PROXY and no_proxy are checked for edge addresses
func init() {
	// Ensure the proxy env vars are available
	_ = os.Getenv("HTTPS_PROXY")
}

// DialError is an error returned from DialEdge
type DialError struct {
	cause error
}

func newDialError(err error, message string) error {
	return DialError{cause: errors.Wrap(err, message)}
}

func (e DialError) Error() string {
	return e.cause.Error()
}

func (e DialError) Cause() error {
	return e.cause
}
