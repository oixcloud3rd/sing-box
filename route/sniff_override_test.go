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

type sniffOverrideTestDNSRouter struct {
	cachedAddresses []netip.Addr
	warmAddresses   []netip.Addr
	cacheCalls      atomic.Int32
	warmCalls       atomic.Int32
}

func (r *sniffOverrideTestDNSRouter) Start(stage adapter.StartStage) error { return nil }
func (r *sniffOverrideTestDNSRouter) Close() error                         { return nil }
func (r *sniffOverrideTestDNSRouter) Exchange(context.Context, *dns.Msg, adapter.DNSQueryOptions) (*dns.Msg, error) {
	return nil, nil
}

func (r *sniffOverrideTestDNSRouter) ExchangeAsync(context.Context, *dns.Msg, adapter.DNSQueryOptions, func(*dns.Msg, error)) {
}

func (r *sniffOverrideTestDNSRouter) Lookup(_ context.Context, _ string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	if options.CacheOnly {
		r.cacheCalls.Add(1)
		return r.cachedAddresses, nil
	}
	r.warmCalls.Add(1)
	return r.warmAddresses, nil
}
func (r *sniffOverrideTestDNSRouter) ClearCache() {}
func (r *sniffOverrideTestDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) {
	return "", false
}
func (r *sniffOverrideTestDNSRouter) ResetNetwork() {}

func newSniffOverrideTestRouter(dnsRouter adapter.DNSRouter) *Router {
	return &Router{
		ctx:           context.Background(),
		logger:        log.NewNOPFactory().Logger(),
		dns:           dnsRouter,
		sniffOverride: newSniffOverrideEvaluator(),
	}
}

func TestNewSniffOverrideEvaluatorIfNeeded(t *testing.T) {
	t.Parallel()

	dnsEvaluateAction := option.RuleAction{
		Action: C.RuleActionTypeSniff,
		SniffOptions: option.RouteActionSniff{
			OverrideDestination: C.SniffOverrideDestinationDNSEvaluate,
		},
	}
	testCases := []struct {
		name     string
		rules    []option.Rule
		expected bool
	}{
		{
			name: "empty",
		},
		{
			name: "always",
			rules: []option.Rule{{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{RuleAction: option.RuleAction{
					Action: C.RuleActionTypeSniff,
					SniffOptions: option.RouteActionSniff{
						OverrideDestination: C.SniffOverrideDestinationAlways,
					},
				}},
			}},
		},
		{
			name: "default rule",
			rules: []option.Rule{{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RuleAction: dnsEvaluateAction,
				},
			}},
			expected: true,
		},
		{
			name: "logical rule",
			rules: []option.Rule{{
				Type: C.RuleTypeLogical,
				LogicalOptions: option.LogicalRule{
					RuleAction: dnsEvaluateAction,
				},
			}},
			expected: true,
		},
		{
			name: "nested rule",
			rules: []option.Rule{{
				Type: C.RuleTypeLogical,
				LogicalOptions: option.LogicalRule{RawLogicalRule: option.RawLogicalRule{
					Rules: []option.Rule{{
						Type: C.RuleTypeDefault,
						DefaultOptions: option.DefaultRule{
							RuleAction: dnsEvaluateAction,
						},
					}},
				}},
			}},
			expected: true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			router := NewRouter(context.Background(), log.NewNOPFactory(), option.RouteOptions{Rules: testCase.rules}, option.DNSOptions{})
			if testCase.expected {
				require.NotNil(t, router.sniffOverride)
			} else {
				require.Nil(t, router.sniffOverride)
			}
		})
	}
}

func sniffOverrideTestMetadata(protocol string) adapter.InboundContext {
	return adapter.InboundContext{
		Protocol: protocol,
		Domain:   "www.example.org",
		Destination: M.Socksaddr{
			Addr: netip.MustParseAddr("198.51.100.1"),
			Port: 443,
		},
	}
}

func TestSniffOverrideAlwaysProtocolScope(t *testing.T) {
	t.Parallel()

	router := newSniffOverrideTestRouter(&sniffOverrideTestDNSRouter{})
	action := &R.RuleActionSniff{OverrideDestination: C.SniffOverrideDestinationAlways}
	for _, protocol := range []string{C.ProtocolHTTP, C.ProtocolTLS, C.ProtocolQUIC} {
		metadata := sniffOverrideTestMetadata(protocol)
		router.applySniffOverride(context.Background(), &metadata, action)
		require.Equal(t, "www.example.org", metadata.Destination.Fqdn, protocol)
	}
	for _, protocol := range []string{C.ProtocolDNS, C.ProtocolSTUN, C.ProtocolBitTorrent} {
		metadata := sniffOverrideTestMetadata(protocol)
		router.applySniffOverride(context.Background(), &metadata, action)
		require.True(t, metadata.Destination.IsIP(), protocol)
	}
}

func TestSniffOverrideDisabled(t *testing.T) {
	t.Parallel()

	router := newSniffOverrideTestRouter(&sniffOverrideTestDNSRouter{})
	for _, mode := range []string{C.SniffOverrideDestinationDefault, C.SniffOverrideDestinationDisabled} {
		metadata := sniffOverrideTestMetadata(C.ProtocolTLS)
		router.applySniffOverride(context.Background(), &metadata, &R.RuleActionSniff{OverrideDestination: mode})
		require.True(t, metadata.Destination.IsIP(), mode)
	}
}

func TestSniffOverrideDNSEvaluateRejectsDNSProtocol(t *testing.T) {
	t.Parallel()

	dnsRouter := &sniffOverrideTestDNSRouter{cachedAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.1")}}
	router := newSniffOverrideTestRouter(dnsRouter)
	metadata := sniffOverrideTestMetadata(C.ProtocolDNS)
	router.applySniffOverride(context.Background(), &metadata, &R.RuleActionSniff{OverrideDestination: C.SniffOverrideDestinationDNSEvaluate})
	require.True(t, metadata.Destination.IsIP())
	require.Zero(t, dnsRouter.cacheCalls.Load())
	require.Zero(t, dnsRouter.warmCalls.Load())
}

func TestSniffOverrideDNSEvaluateCacheHit(t *testing.T) {
	t.Parallel()

	dnsRouter := &sniffOverrideTestDNSRouter{cachedAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.1")}}
	router := newSniffOverrideTestRouter(dnsRouter)
	metadata := sniffOverrideTestMetadata(C.ProtocolTLS)
	router.applySniffOverride(context.Background(), &metadata, &R.RuleActionSniff{OverrideDestination: C.SniffOverrideDestinationDNSEvaluate})
	require.Equal(t, "www.example.org", metadata.Destination.Fqdn)
	require.Equal(t, int32(1), dnsRouter.cacheCalls.Load())
	require.Zero(t, dnsRouter.warmCalls.Load())
}

func TestSniffOverrideDNSEvaluateWarmsInBackground(t *testing.T) {
	t.Parallel()

	dnsRouter := &sniffOverrideTestDNSRouter{warmAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.2")}}
	router := newSniffOverrideTestRouter(dnsRouter)
	action := &R.RuleActionSniff{OverrideDestination: C.SniffOverrideDestinationDNSEvaluate}
	metadata := sniffOverrideTestMetadata(C.ProtocolQUIC)
	router.applySniffOverride(context.Background(), &metadata, action)
	require.True(t, metadata.Destination.IsIP())
	require.Eventually(t, func() bool {
		return dnsRouter.warmCalls.Load() == 1
	}, time.Second, time.Millisecond)
	require.Eventually(t, func() bool {
		secondMetadata := sniffOverrideTestMetadata(C.ProtocolQUIC)
		router.applySniffOverride(context.Background(), &secondMetadata, action)
		return secondMetadata.Destination.IsDomain()
	}, time.Second, time.Millisecond)
}
