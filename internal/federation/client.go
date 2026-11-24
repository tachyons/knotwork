package federation

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

const deliveryTimeout = 15 * time.Second

// blockedPrefixes are ranges that are not globally routable but are not
// covered by netip.Addr.IsPrivate. They are rejected for outbound federation
// requests so a peer cannot steer the server at internal services.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved
}

// NewDeliveryClient returns an HTTP client for outbound federation delivery.
// It refuses to connect to loopback, private, link-local, multicast, and
// otherwise reserved addresses at connect time, so DNS rebinding cannot bypass
// the check. Redirects are not followed because the Signature header is bound
// to the original request target and must not be forwarded.
func NewDeliveryClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("invalid outbound address %q: %w", address, err)
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("invalid outbound address %q: %w", address, err)
			}
			if isBlockedAddr(addr) {
				return fmt.Errorf("outbound connection to %s is not allowed", addr)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: deliveryTimeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ValidateOutboundURL rejects URLs that can never be a safe federation target.
// Hostnames are resolved by the dialer, which applies the same address checks
// after DNS resolution.
func ValidateOutboundURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("URL must use https")
	}
	if u.User != nil {
		return errors.New("URL must not contain userinfo")
	}
	if u.Fragment != "" {
		return errors.New("URL must not contain a fragment")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return errors.New("URL must contain a host")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if isBlockedAddr(addr) {
			return fmt.Errorf("host %s is not allowed", host)
		}
		return nil
	}
	switch host {
	case "localhost", "metadata", "metadata.google.internal":
		return fmt.Errorf("host %s is not allowed", host)
	}
	if strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("host %s is not allowed", host)
	}
	return nil
}

func isBlockedAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() ||
		addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return true
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
