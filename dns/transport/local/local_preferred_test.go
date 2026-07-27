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

	mDNS "github.com/miekg/dns"
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

func TestPreferredDomainResolver(t *testing.T) {
	t.Parallel()

	rawResolver, err := NewPreferredDomainResolver(context.Background(), log.NewNOPFactory().Logger(), []string{".lan"})
	require.NoError(t, err)
	resolver := rawResolver.(*preferredDomainResolver)
	hostsPath := filepath.Join(t.TempDir(), "hosts")
	require.NoError(t, os.WriteFile(hostsPath, []byte("192.0.2.2 hosts-entry.example\n"), 0o600))
	resolver.hosts = hosts.NewFile(context.Background(), hostsPath)
	resolver.neighborResolver = new(preferredDomainTestNeighborResolver)

	require.True(t, resolver.PreferredDomain("HOSTS-ENTRY.EXAMPLE"))
	require.True(t, resolver.PreferredDomain("router.lan"))
	require.True(t, resolver.PreferredDomain("printer.local"))
	require.False(t, resolver.PreferredDomain("nested.router.lan"))
	require.False(t, resolver.PreferredDomain("example.org"))

	hostsRequest := new(mDNS.Msg)
	hostsRequest.SetQuestion("hosts-entry.example.", mDNS.TypeA)
	hostsResponse, resolved := resolver.TryResolve(hostsRequest)
	require.True(t, resolved)
	require.Len(t, hostsResponse.Answer, 1)
	require.IsType(t, new(mDNS.A), hostsResponse.Answer[0])
	require.Equal(t, "192.0.2.2", hostsResponse.Answer[0].(*mDNS.A).A.String())

	neighborRequest := new(mDNS.Msg)
	neighborRequest.SetQuestion("router.lan.", mDNS.TypeA)
	neighborResponse, resolved := resolver.TryResolve(neighborRequest)
	require.True(t, resolved)
	require.Len(t, neighborResponse.Answer, 1)
	require.IsType(t, new(mDNS.A), neighborResponse.Answer[0])
	require.Equal(t, "192.0.2.1", neighborResponse.Answer[0].(*mDNS.A).A.String())

	upstreamRequest := new(mDNS.Msg)
	upstreamRequest.SetQuestion("example.org.", mDNS.TypeA)
	upstreamResponse, resolved := resolver.TryResolve(upstreamRequest)
	require.False(t, resolved)
	require.Nil(t, upstreamResponse)
}
