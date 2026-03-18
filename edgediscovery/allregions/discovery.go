package allregions

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	"github.com/cloudflare/cloudflared/doh"
	"github.com/cloudflare/cloudflared/management"
)

const (
	// Used to discover HA origintunneld servers
	srvService = "v2-origintunneld"
	srvProto   = "tcp"
	srvName    = "argotunnel.com"

	// Used to fallback to DoT when we can't use the default resolver to
	// discover HA origintunneld servers (GitHub issue #75).
	dotServerName = "cloudflare-dns.com"
	dotServerAddr = "1.1.1.1:853"
	dotTimeout    = 15 * time.Second

	logFieldAddress = "address"
)

// Redeclare network functions so they can be overridden in tests.
var (
	netLookupSRV = net.LookupSRV
	netLookupIP  = net.LookupIP
)

// ConfigIPVersion is the selection of IP versions from config
type ConfigIPVersion int8

const (
	Auto     ConfigIPVersion = 2
	IPv4Only ConfigIPVersion = 4
	IPv6Only ConfigIPVersion = 6
)

func (c ConfigIPVersion) String() string {
	switch c {
	case Auto:
		return "auto"
	case IPv4Only:
		return "4"
	case IPv6Only:
		return "6"
	default:
		return ""
	}
}

// IPVersion is the IP version of an EdgeAddr
type EdgeIPVersion int8

const (
	V4 EdgeIPVersion = 4
	V6 EdgeIPVersion = 6
)

// String returns the enum's constant name.
func (c EdgeIPVersion) String() string {
	switch c {
	case V4:
		return "4"
	case V6:
		return "6"
	default:
		return ""
	}
}

// EdgeAddr is a representation of possible ways to refer an edge location.
type EdgeAddr struct {
	TCP       *net.TCPAddr
	UDP       *net.UDPAddr
	IPVersion EdgeIPVersion
}

var fallbackLookupSRV = lookupSRVWithDOT

var friendlyDNSErrorLines = []string{
	`Please try the following things to diagnose this issue:`,
	`  1. ensure that argotunnel.com is returning "origintunneld" service records.`,
	`     Run your system's equivalent of: dig srv _origintunneld._tcp.argotunnel.com`,
	`  2. ensure that your DNS resolver is not returning compressed SRV records.`,
	`     See GitHub issue https://github.com/golang/go/issues/27546`,
	`     For example, you could use Cloudflare's 1.1.1.1 as your resolver:`,
	`     https://developers.cloudflare.com/1.1.1.1/setting-up-1.1.1.1/`,
}

// EdgeDiscovery implements HA service discovery lookup.
func edgeDiscovery(log *zerolog.Logger, srvService string) ([][]*EdgeAddr, error) {
	logger := log.With().Int(management.EventTypeKey, int(management.Cloudflared)).Logger()
	logger.Debug().
		Int(management.EventTypeKey, int(management.Cloudflared)).
		Str("domain", "_"+srvService+"._"+srvProto+"."+srvName).
		Msg("edge discovery: looking up edge SRV record")

	var addrs []*net.SRV
	var err error

	// When HTTP proxy is configured, use DoH exclusively.
	// Local DNS and DoT are unreliable in proxy-required environments (e.g. China).
	if doh.HasProxy() {
		logger.Info().Msg("edge discovery: HTTPS_PROXY set, using DoH via proxy")
		_, addrs, err = doh.LookupSRV(srvService, srvProto, srvName)
		if err != nil {
			logger.Err(err).Msg("edge discovery: DoH SRV lookup failed")
			return nil, errors.Wrapf(err, "Could not lookup srv records via DoH on _%v._%v.%v", srvService, srvProto, srvName)
		}
	} else {
		_, addrs, err = netLookupSRV(srvService, srvProto, srvName)
		if err != nil {
			_, fallbackAddrs, fallbackErr := fallbackLookupSRV(srvService, srvProto, srvName)
			if fallbackErr != nil || len(fallbackAddrs) == 0 {
				logger.Err(err).Msg("edge discovery: error looking up Cloudflare edge IPs: the DNS query failed")
				for _, s := range friendlyDNSErrorLines {
					logger.Error().Msg(s)
				}
				return nil, errors.Wrapf(err, "Could not lookup srv records on _%v._%v.%v", srvService, srvProto, srvName)
			}
			addrs = fallbackAddrs
		}
	}

	var resolvedAddrPerCNAME [][]*EdgeAddr
	for _, addr := range addrs {
		edgeAddrs, err := resolveSRV(addr)
		if err != nil {
			return nil, err
		}
		logAddrs := make([]string, len(edgeAddrs))
		for i, e := range edgeAddrs {
			logAddrs[i] = e.UDP.IP.String()
		}
		logger.Debug().
			Strs("addresses", logAddrs).
			Msg("edge discovery: resolved edge addresses")
		resolvedAddrPerCNAME = append(resolvedAddrPerCNAME, edgeAddrs)
	}

	return resolvedAddrPerCNAME, nil
}

func lookupSRVWithDOT(srvService string, srvProto string, srvName string) (cname string, addrs []*net.SRV, err error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
			var dialer net.Dialer
			conn, err := dialer.DialContext(ctx, "tcp", dotServerAddr)
			if err != nil {
				return nil, err
			}
			tlsConfig := &tls.Config{ServerName: dotServerName}
			return tls.Client(conn, tlsConfig), nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), dotTimeout)
	defer cancel()
	return r.LookupSRV(ctx, srvService, srvProto, srvName)
}

func resolveSRV(srv *net.SRV) ([]*EdgeAddr, error) {
	var ips []net.IP
	var err error

	// When proxy is set, use DoH for IP resolution too
	if doh.HasProxy() {
		ips, err = doh.LookupIP(srv.Target)
	} else {
		ips, err = netLookupIP(srv.Target)
	}

	if err != nil {
		return nil, errors.Wrapf(err, "Couldn't resolve SRV record %v", srv)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("SRV record %v had no IPs", srv)
	}
	return ipsToEdgeAddrs(ips, srv.Port), nil
}

func ipsToEdgeAddrs(ips []net.IP, port uint16) []*EdgeAddr {
	addrs := make([]*EdgeAddr, len(ips))
	for i, ip := range ips {
		version := V6
		if ip.To4() != nil {
			version = V4
		}
		addrs[i] = &EdgeAddr{
			TCP:       &net.TCPAddr{IP: ip, Port: int(port)},
			UDP:       &net.UDPAddr{IP: ip, Port: int(port)},
			IPVersion: version,
		}
	}
	return addrs
}

// ResolveAddrs resolves TCP address given a list of addresses. Address can be a hostname, however, it will return at most one
// of the hostname's IP addresses.
func ResolveAddrs(addrs []string, log *zerolog.Logger) (resolved []*EdgeAddr) {
	for _, addr := range addrs {
		tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			log.Error().Int(management.EventTypeKey, int(management.Cloudflared)).
				Str(logFieldAddress, addr).Err(err).Msg("edge discovery: failed to resolve to TCP address")
			continue
		}

		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			log.Error().Int(management.EventTypeKey, int(management.Cloudflared)).
				Str(logFieldAddress, addr).Err(err).Msg("edge discovery: failed to resolve to UDP address")
			continue
		}
		version := V6
		if udpAddr.IP.To4() != nil {
			version = V4
		}
		resolved = append(resolved, &EdgeAddr{
			TCP:       tcpAddr,
			UDP:       udpAddr,
			IPVersion: version,
		})
	}
	return
}
