package route

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type overrideAddressWithDomainTestDNSRouter struct {
	cachedAddresses []netip.Addr
	warmAddresses   []netip.Addr
	cacheCalls      atomic.Int32
	warmCalls       atomic.Int32
}

func (r *overrideAddressWithDomainTestDNSRouter) Start(stage adapter.StartStage) error { return nil }
func (r *overrideAddressWithDomainTestDNSRouter) Close() error                         { return nil }
func (r *overrideAddressWithDomainTestDNSRouter) Exchange(context.Context, *dns.Msg, adapter.DNSQueryOptions) (*dns.Msg, error) {
	return nil, nil
}

func (r *overrideAddressWithDomainTestDNSRouter) ExchangeAsync(context.Context, *dns.Msg, adapter.DNSQueryOptions, func(*dns.Msg, error)) {
}

func (r *overrideAddressWithDomainTestDNSRouter) Lookup(_ context.Context, _ string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	if options.CacheOnly {
		r.cacheCalls.Add(1)
		return r.cachedAddresses, nil
	}
	r.warmCalls.Add(1)
	return r.warmAddresses, nil
}

func (r *overrideAddressWithDomainTestDNSRouter) ClearCache() {}
func (r *overrideAddressWithDomainTestDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) {
	return "", false
}
func (r *overrideAddressWithDomainTestDNSRouter) ResetNetwork() {}

func newOverrideAddressWithDomainTestRouter(dnsRouter adapter.DNSRouter) *Router {
	return &Router{
		ctx:    context.Background(),
		logger: log.NewNOPFactory().Logger(),
		dns:    dnsRouter,
	}
}

func overrideAddressWithDomainAction(actionType string, mode string) option.RuleAction {
	options := option.RawRouteOptionsActionOptions{
		OverrideAddressWithDomain: option.RouteOverrideAddressWithDomainOptions{
			Condition: option.RouteOverrideAddressWithDomainCondition(mode),
		},
	}
	switch actionType {
	case C.RuleActionTypeRoute:
		return option.RuleAction{
			Action: actionType,
			RouteOptions: option.RouteActionOptions{
				Outbound:                     "direct",
				RawRouteOptionsActionOptions: options,
			},
		}
	case C.RuleActionTypeRouteOptions:
		return option.RuleAction{
			Action:              actionType,
			RouteOptionsOptions: option.RouteOptionsActionOptions(options),
		}
	case C.RuleActionTypeBypass:
		return option.RuleAction{
			Action: actionType,
			BypassOptions: option.RouteActionOptions{
				Outbound:                     "direct",
				RawRouteOptionsActionOptions: options,
			},
		}
	default:
		panic("unknown action type")
	}
}

func TestOverrideAddressWithDomainEvaluatorIsLazy(t *testing.T) {
	t.Parallel()

	dnsRouter := &overrideAddressWithDomainTestDNSRouter{}
	router := newOverrideAddressWithDomainTestRouter(dnsRouter)
	require.Nil(t, router.domainOverrideEvaluator)

	alwaysMetadata := overrideAddressWithDomainTestMetadata(C.ProtocolTLS, C.RouteOverrideAddressWithDomainAlways)
	router.applyOverrideAddressWithDomain(context.Background(), &alwaysMetadata)
	require.Nil(t, router.domainOverrideEvaluator)

	disabledMetadata := overrideAddressWithDomainTestMetadata(C.ProtocolTLS, C.RouteOverrideAddressWithDomainDisable)
	router.applyOverrideAddressWithDomain(context.Background(), &disabledMetadata)
	require.Nil(t, router.domainOverrideEvaluator)

	dnsMetadata := overrideAddressWithDomainTestMetadata(C.ProtocolDNS, C.RouteOverrideAddressWithDomainIfResolvable)
	router.applyOverrideAddressWithDomain(context.Background(), &dnsMetadata)
	require.Nil(t, router.domainOverrideEvaluator)

	resolvableMetadata := overrideAddressWithDomainTestMetadata(C.ProtocolTLS, C.RouteOverrideAddressWithDomainIfResolvable)
	router.applyOverrideAddressWithDomain(context.Background(), &resolvableMetadata)
	require.NotNil(t, router.domainOverrideEvaluator)
}

func overrideAddressWithDomainTestMetadata(protocol string, mode string) adapter.InboundContext {
	return adapter.InboundContext{
		Protocol:                       protocol,
		Domain:                         "www.example.org",
		RouteOverrideAddressWithDomain: mode,
		Destination: M.Socksaddr{
			Addr: netip.MustParseAddr("198.51.100.1"),
			Port: 443,
		},
	}
}

func TestOverrideAddressWithDomainAlwaysProtocolScope(t *testing.T) {
	t.Parallel()

	router := newOverrideAddressWithDomainTestRouter(&overrideAddressWithDomainTestDNSRouter{})
	for _, protocol := range []string{C.ProtocolHTTP, C.ProtocolTLS, C.ProtocolQUIC} {
		metadata := overrideAddressWithDomainTestMetadata(protocol, C.RouteOverrideAddressWithDomainAlways)
		router.applyOverrideAddressWithDomain(context.Background(), &metadata)
		require.Equal(t, "www.example.org", metadata.Destination.Fqdn, protocol)
	}
	for _, protocol := range []string{C.ProtocolDNS, C.ProtocolSTUN, C.ProtocolBitTorrent} {
		metadata := overrideAddressWithDomainTestMetadata(protocol, C.RouteOverrideAddressWithDomainAlways)
		router.applyOverrideAddressWithDomain(context.Background(), &metadata)
		require.True(t, metadata.Destination.IsIP(), protocol)
	}
}

func TestOverrideAddressWithDomainDomainScope(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{C.RouteOverrideAddressWithDomainAlways, C.RouteOverrideAddressWithDomainIfResolvable} {
		dnsRouter := &overrideAddressWithDomainTestDNSRouter{cachedAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.1")}}
		router := newOverrideAddressWithDomainTestRouter(dnsRouter)
		metadata := overrideAddressWithDomainTestMetadata(C.ProtocolTLS, mode)
		metadata.Destination = M.Socksaddr{Fqdn: "origin.example.org", Port: 443}
		metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("198.51.100.2")}
		metadata.DestinationAddressesRouteOnly = true
		router.applyOverrideAddressWithDomain(context.Background(), &metadata)
		require.Equal(t, "www.example.org", metadata.Destination.Fqdn, mode)
		require.Empty(t, metadata.DestinationAddresses, mode)
		require.False(t, metadata.DestinationAddressesRouteOnly, mode)
		if mode == C.RouteOverrideAddressWithDomainIfResolvable {
			require.Equal(t, int32(1), dnsRouter.cacheCalls.Load(), mode)
		} else {
			require.Zero(t, dnsRouter.cacheCalls.Load(), mode)
		}
		require.Zero(t, dnsRouter.warmCalls.Load(), mode)
	}

	domainScopeDisabled := false
	for _, mode := range []string{C.RouteOverrideAddressWithDomainAlways, C.RouteOverrideAddressWithDomainIfResolvable} {
		dnsRouter := &overrideAddressWithDomainTestDNSRouter{cachedAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.1")}}
		router := newOverrideAddressWithDomainTestRouter(dnsRouter)
		metadata := overrideAddressWithDomainTestMetadata(C.ProtocolTLS, mode)
		metadata.Destination = M.Socksaddr{Fqdn: "origin.example.org", Port: 443}
		metadata.RouteOverrideAddressWithDomainScopeDomain = &domainScopeDisabled
		router.applyOverrideAddressWithDomain(context.Background(), &metadata)
		require.Equal(t, "origin.example.org", metadata.Destination.Fqdn, mode)
		require.Zero(t, dnsRouter.cacheCalls.Load(), mode)
		require.Zero(t, dnsRouter.warmCalls.Load(), mode)
	}
}

func TestOverrideAddressWithDomainIPScope(t *testing.T) {
	t.Parallel()

	ipScopeDisabled := false
	for _, mode := range []string{C.RouteOverrideAddressWithDomainAlways, C.RouteOverrideAddressWithDomainIfResolvable} {
		dnsRouter := &overrideAddressWithDomainTestDNSRouter{cachedAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.1")}}
		router := newOverrideAddressWithDomainTestRouter(dnsRouter)
		metadata := overrideAddressWithDomainTestMetadata(C.ProtocolTLS, mode)
		metadata.RouteOverrideAddressWithDomainScopeIP = &ipScopeDisabled
		router.applyOverrideAddressWithDomain(context.Background(), &metadata)
		require.True(t, metadata.Destination.IsIP(), mode)
		require.Zero(t, dnsRouter.cacheCalls.Load(), mode)
		require.Zero(t, dnsRouter.warmCalls.Load(), mode)
	}
}

func TestOverrideAddressWithDomainClearsDestinationAddresses(t *testing.T) {
	t.Parallel()

	router := newOverrideAddressWithDomainTestRouter(&overrideAddressWithDomainTestDNSRouter{})
	metadata := overrideAddressWithDomainTestMetadata(C.ProtocolTLS, C.RouteOverrideAddressWithDomainAlways)
	metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("203.0.113.1")}
	metadata.DestinationAddressesRouteOnly = true
	router.applyOverrideAddressWithDomain(context.Background(), &metadata)
	require.Equal(t, "www.example.org", metadata.Destination.Fqdn)
	require.Empty(t, metadata.DestinationAddresses)
	require.False(t, metadata.DestinationAddressesRouteOnly)
}

func TestOverrideAddressWithDomainKeepsDestinationAddressesWhenUnchanged(t *testing.T) {
	t.Parallel()

	router := newOverrideAddressWithDomainTestRouter(&overrideAddressWithDomainTestDNSRouter{})
	metadata := overrideAddressWithDomainTestMetadata(C.ProtocolTLS, C.RouteOverrideAddressWithDomainAlways)
	metadata.Destination = M.Socksaddr{Fqdn: "www.example.org", Port: 443}
	metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("203.0.113.1")}
	metadata.DestinationAddressesRouteOnly = true
	router.applyOverrideAddressWithDomain(context.Background(), &metadata)
	require.Equal(t, "www.example.org", metadata.Destination.Fqdn)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.1")}, metadata.DestinationAddresses)
	require.True(t, metadata.DestinationAddressesRouteOnly)
}

func TestOverrideAddressWithDomainRouteOptions(t *testing.T) {
	t.Parallel()

	metadata := overrideAddressWithDomainTestMetadata(C.ProtocolTLS, C.RouteOverrideAddressWithDomainDefault)
	applyRouteOptionsOverride(&metadata, &R.RuleActionRouteOptions{
		OverrideAddressWithDomain: R.RuleActionOverrideAddressWithDomain{
			Condition: C.RouteOverrideAddressWithDomainIfResolvable,
		},
	})
	require.Equal(t, C.RouteOverrideAddressWithDomainIfResolvable, metadata.RouteOverrideAddressWithDomain)
	applyRouteOptionsOverride(&metadata, &R.RuleActionRouteOptions{})
	require.Equal(t, C.RouteOverrideAddressWithDomainIfResolvable, metadata.RouteOverrideAddressWithDomain)
	domainScopeDisabled := false
	ipScopeDisabled := false
	applyRouteOptionsOverride(&metadata, &R.RuleActionRouteOptions{
		OverrideAddressWithDomain: R.RuleActionOverrideAddressWithDomain{
			Condition:   C.RouteOverrideAddressWithDomainAlways,
			ScopeDomain: &domainScopeDisabled,
		},
	})
	require.Equal(t, C.RouteOverrideAddressWithDomainAlways, metadata.RouteOverrideAddressWithDomain)
	require.Equal(t, &domainScopeDisabled, metadata.RouteOverrideAddressWithDomainScopeDomain)
	require.Nil(t, metadata.RouteOverrideAddressWithDomainScopeIP)
	applyRouteOptionsOverride(&metadata, &R.RuleActionRouteOptions{
		OverrideAddressWithDomain: R.RuleActionOverrideAddressWithDomain{
			Condition: C.RouteOverrideAddressWithDomainDisable,
			ScopeIP:   &ipScopeDisabled,
		},
	})
	require.Equal(t, C.RouteOverrideAddressWithDomainDisable, metadata.RouteOverrideAddressWithDomain)
	require.Equal(t, &domainScopeDisabled, metadata.RouteOverrideAddressWithDomainScopeDomain)
	require.Equal(t, &ipScopeDisabled, metadata.RouteOverrideAddressWithDomainScopeIP)
	domainScopeEnabled := true
	applyRouteOptionsOverride(&metadata, &R.RuleActionRouteOptions{
		OverrideAddressWithDomain: R.RuleActionOverrideAddressWithDomain{
			ScopeDomain: &domainScopeEnabled,
		},
	})
	require.Equal(t, &domainScopeEnabled, metadata.RouteOverrideAddressWithDomainScopeDomain)
	require.Equal(t, &ipScopeDisabled, metadata.RouteOverrideAddressWithDomainScopeIP)
	newOverrideAddressWithDomainTestRouter(&overrideAddressWithDomainTestDNSRouter{}).applyOverrideAddressWithDomain(context.Background(), &metadata)
	require.True(t, metadata.Destination.IsIP())
}

func TestOverrideAddressTakesPriorityOverDomain(t *testing.T) {
	t.Parallel()

	router := newOverrideAddressWithDomainTestRouter(&overrideAddressWithDomainTestDNSRouter{})
	metadata := overrideAddressWithDomainTestMetadata(C.ProtocolTLS, C.RouteOverrideAddressWithDomainDefault)
	metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("198.51.100.2")}
	metadata.DestinationAddressesRouteOnly = true
	applyRouteOptionsOverride(&metadata, &R.RuleActionRouteOptions{
		OverrideAddress: M.Socksaddr{
			Addr: netip.MustParseAddr("203.0.113.1"),
		},
		OverridePort: 9443,
		OverrideAddressWithDomain: R.RuleActionOverrideAddressWithDomain{
			Condition: C.RouteOverrideAddressWithDomainAlways,
		},
	})
	router.applyOverrideAddressWithDomain(context.Background(), &metadata)
	require.Equal(t, netip.MustParseAddr("203.0.113.1"), metadata.Destination.Addr)
	require.Equal(t, uint16(9443), metadata.Destination.Port)
	require.Empty(t, metadata.DestinationAddresses)
	require.False(t, metadata.DestinationAddressesRouteOnly)
}

func TestOverrideAddressKeepsDestinationAddressesWhenAddressIsUnchanged(t *testing.T) {
	t.Parallel()

	metadata := overrideAddressWithDomainTestMetadata(C.ProtocolTLS, C.RouteOverrideAddressWithDomainAlways)
	metadata.DestinationAddresses = []netip.Addr{netip.MustParseAddr("198.51.100.2")}
	metadata.DestinationAddressesRouteOnly = true
	applyRouteOptionsOverride(&metadata, &R.RuleActionRouteOptions{
		OverrideAddress: M.Socksaddr{Addr: netip.MustParseAddr("198.51.100.1")},
		OverridePort:    9443,
	})
	require.Equal(t, netip.MustParseAddr("198.51.100.1"), metadata.Destination.Addr)
	require.Equal(t, uint16(9443), metadata.Destination.Port)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("198.51.100.2")}, metadata.DestinationAddresses)
	require.True(t, metadata.DestinationAddressesRouteOnly)
	require.True(t, metadata.RouteOverrideAddressSet)
}

func TestSniffDoesNotOverrideAddress(t *testing.T) {
	t.Parallel()

	router := newOverrideAddressWithDomainTestRouter(&overrideAddressWithDomainTestDNSRouter{})
	metadata := overrideAddressWithDomainTestMetadata(C.ProtocolTLS, C.RouteOverrideAddressWithDomainAlways)
	_, _, err := router.actionSniff(context.Background(), &metadata, &R.RuleActionSniff{}, nil, nil, nil, nil)
	require.NoError(t, err)
	require.True(t, metadata.Destination.IsIP())

	ipRule, err := R.NewRule(context.Background(), log.NewNOPFactory().Logger(), option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				IPCIDR: []string{"198.51.100.0/24"},
			},
			RuleAction: overrideAddressWithDomainAction(C.RuleActionTypeRoute, C.RouteOverrideAddressWithDomainAlways),
		},
	}, false)
	require.NoError(t, err)
	require.True(t, ipRule.Match(&metadata))
}

func TestOverrideAddressWithDomainIfResolvableRejectsDNSProtocol(t *testing.T) {
	t.Parallel()

	dnsRouter := &overrideAddressWithDomainTestDNSRouter{cachedAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.1")}}
	router := newOverrideAddressWithDomainTestRouter(dnsRouter)
	metadata := overrideAddressWithDomainTestMetadata(C.ProtocolDNS, C.RouteOverrideAddressWithDomainIfResolvable)
	router.applyOverrideAddressWithDomain(context.Background(), &metadata)
	require.True(t, metadata.Destination.IsIP())
	require.Zero(t, dnsRouter.cacheCalls.Load())
	require.Zero(t, dnsRouter.warmCalls.Load())
}

func TestOverrideAddressWithDomainIfResolvableCacheHit(t *testing.T) {
	t.Parallel()

	dnsRouter := &overrideAddressWithDomainTestDNSRouter{cachedAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.1")}}
	router := newOverrideAddressWithDomainTestRouter(dnsRouter)
	metadata := overrideAddressWithDomainTestMetadata(C.ProtocolTLS, C.RouteOverrideAddressWithDomainIfResolvable)
	router.applyOverrideAddressWithDomain(context.Background(), &metadata)
	require.Equal(t, "www.example.org", metadata.Destination.Fqdn)
	require.Equal(t, int32(1), dnsRouter.cacheCalls.Load())
	require.Zero(t, dnsRouter.warmCalls.Load())
}

func TestOverrideAddressWithDomainIfResolvableWarmsInBackground(t *testing.T) {
	t.Parallel()

	dnsRouter := &overrideAddressWithDomainTestDNSRouter{warmAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.2")}}
	router := newOverrideAddressWithDomainTestRouter(dnsRouter)
	metadata := overrideAddressWithDomainTestMetadata(C.ProtocolQUIC, C.RouteOverrideAddressWithDomainIfResolvable)
	router.applyOverrideAddressWithDomain(context.Background(), &metadata)
	require.True(t, metadata.Destination.IsIP())
	require.Eventually(t, func() bool {
		return dnsRouter.warmCalls.Load() == 1
	}, time.Second, time.Millisecond)
	require.Eventually(t, func() bool {
		secondMetadata := overrideAddressWithDomainTestMetadata(C.ProtocolQUIC, C.RouteOverrideAddressWithDomainIfResolvable)
		router.applyOverrideAddressWithDomain(context.Background(), &secondMetadata)
		return secondMetadata.Destination.IsDomain()
	}, time.Second, time.Millisecond)
}
