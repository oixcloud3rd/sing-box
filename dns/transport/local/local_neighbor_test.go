package local

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

type preferredDomainTestNeighborResolver struct{}

func (r *preferredDomainTestNeighborResolver) LookupMAC(address netip.Addr) (net.HardwareAddr, bool) {
	return nil, false
}

func (r *preferredDomainTestNeighborResolver) LookupHostname(address netip.Addr) (string, bool) {
	return "", false
}

func (r *preferredDomainTestNeighborResolver) LookupAddresses(hostname string) []netip.Addr {
	if hostname == "router" {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	}
	return nil
}

func (r *preferredDomainTestNeighborResolver) Start() error {
	return nil
}

func (r *preferredDomainTestNeighborResolver) Close() error {
	return nil
}

func TestPreferredDomainMatcher(t *testing.T) {
	t.Parallel()

	matcher, err := NewPreferredDomainMatcher(context.Background(), log.NewNOPFactory().Logger(), []string{".lan"})
	require.NoError(t, err)
	hostsPath := filepath.Join(t.TempDir(), "hosts")
	require.NoError(t, os.WriteFile(hostsPath, []byte("192.0.2.2 hosts-entry.example\n"), 0o600))
	matcher.hosts = hosts.NewFile(context.Background(), hostsPath)
	matcher.neighborResolver = new(preferredDomainTestNeighborResolver)

	require.True(t, matcher.PreferredDomain("HOSTS-ENTRY.EXAMPLE"))
	require.True(t, matcher.PreferredDomain("router.lan"))
	require.True(t, matcher.PreferredDomain("printer.local"))
	require.False(t, matcher.PreferredDomain("nested.router.lan"))
	require.False(t, matcher.PreferredDomain("example.org"))
}

func TestPreferredDomainMatcherRejectsInvalidNeighborDomain(t *testing.T) {
	t.Parallel()

	_, err := NewPreferredDomainMatcher(context.Background(), log.NewNOPFactory().Logger(), []string{"lan"})
	require.EqualError(t, err, "neighbor_domain entry must start with '.': lan")
}
