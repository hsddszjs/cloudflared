// Package doh provides DNS-over-HTTPS resolution via Cloudflare's JSON API.
// All queries go through http.Client with Proxy: http.ProxyFromEnvironment,
// making them work behind HTTP/HTTPS proxies.
//
// This is essential for environments like China where local DNS is unreliable
// and all outbound traffic must go through a proxy.
package doh

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"time"

	"math/rand"
)

const (
	// Cloudflare DoH JSON API endpoint
	Endpoint = "https://cloudflare-dns.com/dns-query"
	Timeout  = 15 * time.Second
)

// DNS record type constants
const (
	TypeA   = 1
	TypeTXT = 16
	TypeSRV = 33
)

// Response represents the JSON response from Cloudflare's DoH API.
type Response struct {
	Status int      `json:"Status"`
	Answer []Answer `json:"Answer"`
}

// Answer represents a single DNS answer record.
type Answer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	Data string `json:"data"`
}

// HasProxy returns true if HTTPS_PROXY or HTTP_PROXY environment variables are set.
func HasProxy() bool {
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v := os.Getenv(key); v != "" {
			return true
		}
	}
	return false
}

func newClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
		Timeout: Timeout,
	}
}

func query(name string, qtype string) (*Response, error) {
	client := newClient()

	req, err := http.NewRequest("GET", Endpoint+"?name="+name+"&type="+qtype, nil)
	if err != nil {
		return nil, fmt.Errorf("doh: failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: unexpected status %d", resp.StatusCode)
	}

	var doh Response
	if err := json.NewDecoder(resp.Body).Decode(&doh); err != nil {
		return nil, fmt.Errorf("doh: failed to decode response: %w", err)
	}

	if doh.Status != 0 {
		return nil, fmt.Errorf("doh: DNS error status %d", doh.Status)
	}

	return &doh, nil
}

// LookupSRV resolves SRV records for _service._proto.name via DoH.
// Returns records sorted by priority and randomized by weight.
func LookupSRV(service, proto, name string) (string, []*net.SRV, error) {
	queryName := fmt.Sprintf("_%s._%s.%s", service, proto, name)

	doh, err := query(queryName, "SRV")
	if err != nil {
		return "", nil, err
	}

	var addrs []*net.SRV
	for _, ans := range doh.Answer {
		if ans.Type != TypeSRV {
			continue
		}
		srv, parseErr := parseSRVData(ans.Data)
		if parseErr != nil {
			continue
		}
		addrs = append(addrs, srv)
	}

	if len(addrs) == 0 {
		return "", nil, fmt.Errorf("doh: no SRV records found for %s", queryName)
	}

	sortSRVByPriority(addrs)
	return "", addrs, nil
}

// LookupIP resolves A records for a hostname via DoH.
func LookupIP(host string) ([]net.IP, error) {
	doh, err := query(host, "A")
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for _, ans := range doh.Answer {
		if ans.Type != TypeA {
			continue
		}
		ip := net.ParseIP(ans.Data)
		if ip != nil {
			ips = append(ips, ip)
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("doh: no A records found for %s", host)
	}
	return ips, nil
}

// LookupTXT resolves TXT records for a hostname via DoH.
func LookupTXT(host string) ([]string, error) {
	doh, err := query(host, "TXT")
	if err != nil {
		return nil, err
	}

	var records []string
	for _, ans := range doh.Answer {
		if ans.Type != TypeTXT {
			continue
		}
		// DoH JSON API returns TXT data as a JSON-encoded string with escaped quotes.
		// e.g. "\"{\\\"pq\\\":101}\"" -> {"pq":101}
		// Try to JSON-unquote it first, then strip outer quotes if still present.
		data := ans.Data
		var unquoted string
		if err := json.Unmarshal([]byte(data), &unquoted); err == nil {
			data = unquoted
		}
		records = append(records, data)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("doh: no TXT records found for %s", host)
	}
	return records, nil
}

// parseSRVData parses SRV record data in format "priority weight port target"
func parseSRVData(data string) (*net.SRV, error) {
	var priority, weight, port uint16
	var target string
	n, err := fmt.Sscanf(data, "%d %d %d %s", &priority, &weight, &port, &target)
	if err != nil || n != 4 {
		return nil, fmt.Errorf("invalid SRV data: %s", data)
	}
	// Remove trailing dot from target if present
	if len(target) > 0 && target[len(target)-1] == '.' {
		target = target[:len(target)-1]
	}
	return &net.SRV{
		Target:   target,
		Port:     port,
		Priority: priority,
		Weight:   weight,
	}, nil
}

// sortSRVByPriority sorts SRV records by priority and randomizes within same priority by weight.
func sortSRVByPriority(addrs []*net.SRV) {
	sort.SliceStable(addrs, func(i, j int) bool {
		if addrs[i].Priority != addrs[j].Priority {
			return addrs[i].Priority < addrs[j].Priority
		}
		return rand.Intn(int(addrs[i].Weight)+int(addrs[j].Weight)+2) < int(addrs[i].Weight)+1
	})
}
