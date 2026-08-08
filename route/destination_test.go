package route

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	boxDomainEvaluator "github.com/sagernet/sing-box/adapter/domain_evaluator"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type destinationTestDNSRouter struct {
	access          sync.Mutex
	cachedAddresses []netip.Addr
	warmAddresses   []netip.Addr
	cacheCalls      int
	warmCalls       int
	lastTransport   adapter.DNSTransport
}

func (r *destinationTestDNSRouter) Start(adapter.StartStage) error { return nil }
func (r *destinationTestDNSRouter) Close() error                   { return nil }
func (r *destinationTestDNSRouter) Exchange(context.Context, *mDNS.Msg, adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	return nil, errors.New("not implemented")
}
func (r *destinationTestDNSRouter) ExchangeAsync(context.Context, *mDNS.Msg, adapter.DNSQueryOptions, func(*mDNS.Msg, error)) {
}
func (r *destinationTestDNSRouter) Lookup(_ context.Context, _ string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.access.Lock()
	defer r.access.Unlock()
	r.lastTransport = options.Transport
	if options.CacheOnly {
		r.cacheCalls++
		if len(r.cachedAddresses) == 0 {
			return nil, errors.New("not cached")
		}
		return r.cachedAddresses, nil
	}
	r.warmCalls++
	if len(r.warmAddresses) == 0 {
		return nil, errors.New("unresolvable")
	}
	return r.warmAddresses, nil
}
func (r *destinationTestDNSRouter) ClearCache()                                    {}
func (r *destinationTestDNSRouter) LookupReverseMapping(netip.Addr) (string, bool) { return "", false }
func (r *destinationTestDNSRouter) ResetNetwork()                                  {}

func destinationTestMetadata() adapter.InboundContext {
	return adapter.InboundContext{
		Protocol: C.ProtocolTLS,
		Domain:   "WWW.Example.ORG.",
		Destination: M.Socksaddr{
			Addr: netip.MustParseAddr("198.51.100.1"),
			Port: 443,
		},
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.1")},
	}
}

func TestSelectDestinationStrategies(t *testing.T) {
	t.Parallel()

	manager := NewConnectionManager(context.Background(), log.NewNOPFactory().Logger())
	metadata := destinationTestMetadata()

	destination, addresses := manager.selectDestination(context.Background(), option.DestinationStrategy{}, &metadata)
	require.Equal(t, metadata.Destination, destination)
	require.Equal(t, metadata.DestinationAddresses, addresses)

	destination, addresses = manager.selectDestination(context.Background(), option.DestinationStrategy{
		Strategy: C.DestinationStrategyPreferDestination,
	}, &metadata)
	require.Equal(t, metadata.Destination, destination)
	require.Empty(t, addresses)

	overriddenMetadata := metadata
	overriddenMetadata.RouteOverrideAddressSet = true
	destination, addresses = manager.selectDestination(context.Background(), option.DestinationStrategy{
		Strategy: C.DestinationStrategyPreferDestination,
		OverrideWithDomain: &option.OverrideWithDomainOptions{
			Evaluator: "missing",
		},
	}, &overriddenMetadata)
	require.Equal(t, overriddenMetadata.Destination, destination)
	require.Empty(t, addresses)
}

func TestSelectDestinationDomainOverride(t *testing.T) {
	t.Parallel()

	dnsRouter := &destinationTestDNSRouter{
		cachedAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.2")},
	}
	evaluatorManager := boxDomainEvaluator.NewManager(
		context.Background(),
		log.NewNOPFactory().NewLogger("domain-evaluator"),
		dnsRouter,
		nil,
		[]option.DomainEvaluatorOptions{{Tag: "dns-check"}},
	)
	ctx := service.ContextWith[adapter.DomainEvaluatorManager](context.Background(), evaluatorManager)
	manager := NewConnectionManager(ctx, log.NewNOPFactory().Logger())
	strategy := option.DestinationStrategy{
		Strategy: C.DestinationStrategyPreferDestination,
		OverrideWithDomain: &option.OverrideWithDomainOptions{
			Evaluator: "dns-check",
		},
	}
	metadata := destinationTestMetadata()
	destination, addresses := manager.selectDestination(context.Background(), strategy, &metadata)
	require.Equal(t, "www.example.org", destination.Fqdn)
	require.Equal(t, uint16(443), destination.Port)
	require.Empty(t, addresses)
	require.True(t, metadata.Destination.IsIP())
	require.NotEmpty(t, metadata.DestinationAddresses)

	portOverrideMetadata := metadata
	portOverrideMetadata.Destination.Port = 9443
	destination, addresses = manager.selectDestination(context.Background(), strategy, &portOverrideMetadata)
	require.Equal(t, "www.example.org", destination.Fqdn)
	require.Equal(t, uint16(9443), destination.Port)
	require.Empty(t, addresses)

	domainMetadata := metadata
	domainMetadata.Destination = M.Socksaddr{Fqdn: "origin.example", Port: 8443}
	strategy = option.DestinationStrategy{
		Strategy: C.DestinationStrategyPreferDestination,
		OverrideWithDomain: &option.OverrideWithDomainOptions{
			Evaluator: "dns-check",
			IPOnly:    true,
		},
	}
	destination, addresses = manager.selectDestination(context.Background(), strategy, &domainMetadata)
	require.Equal(t, domainMetadata.Destination, destination)
	require.Empty(t, addresses)
}

func TestSelectDestinationWithoutOverrideDoesNotEvaluateDomain(t *testing.T) {
	t.Parallel()

	dnsRouter := &destinationTestDNSRouter{
		cachedAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.2")},
	}
	evaluatorManager := boxDomainEvaluator.NewManager(
		context.Background(),
		log.NewNOPFactory().NewLogger("domain-evaluator"),
		dnsRouter,
		nil,
		[]option.DomainEvaluatorOptions{{Tag: "dns-check"}},
	)
	ctx := service.ContextWith[adapter.DomainEvaluatorManager](context.Background(), evaluatorManager)
	manager := NewConnectionManager(ctx, log.NewNOPFactory().Logger())
	strategy := option.DestinationStrategy{
		Strategy: C.DestinationStrategyPreferDestination,
	}
	metadata := destinationTestMetadata()
	destination, addresses := manager.selectDestination(context.Background(), strategy, &metadata)
	require.Equal(t, metadata.Destination, destination)
	require.Empty(t, addresses)
	require.Zero(t, dnsRouter.cacheCalls)
	require.Zero(t, dnsRouter.warmCalls)
}

func TestSelectDestinationDomainEvaluatorWarmsInBackground(t *testing.T) {
	t.Parallel()

	dnsRouter := &destinationTestDNSRouter{
		warmAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.3")},
	}
	evaluatorManager := boxDomainEvaluator.NewManager(
		context.Background(),
		log.NewNOPFactory().NewLogger("domain-evaluator"),
		dnsRouter,
		nil,
		[]option.DomainEvaluatorOptions{{Tag: "dns-check"}},
	)
	ctx := service.ContextWith[adapter.DomainEvaluatorManager](context.Background(), evaluatorManager)
	manager := NewConnectionManager(ctx, log.NewNOPFactory().Logger())
	strategy := option.DestinationStrategy{
		Strategy: C.DestinationStrategyPreferDestination,
		OverrideWithDomain: &option.OverrideWithDomainOptions{
			Evaluator: "dns-check",
		},
	}
	metadata := destinationTestMetadata()
	destination, _ := manager.selectDestination(context.Background(), strategy, &metadata)
	require.Equal(t, metadata.Destination, destination)
	require.Eventually(t, func() bool {
		dnsRouter.access.Lock()
		defer dnsRouter.access.Unlock()
		return dnsRouter.warmCalls == 1
	}, 1_000_000_000, 1_000_000)
	require.Eventually(t, func() bool {
		destination, _ = manager.selectDestination(context.Background(), strategy, &metadata)
		return destination.Fqdn == "www.example.org"
	}, 1_000_000_000, 1_000_000)
}

type destinationTestDNSTransport struct {
	tag string
}

func (t *destinationTestDNSTransport) Start(adapter.StartStage) error { return nil }
func (t *destinationTestDNSTransport) Close() error                   { return nil }
func (t *destinationTestDNSTransport) Type() string                   { return "test" }
func (t *destinationTestDNSTransport) Tag() string                    { return t.tag }
func (t *destinationTestDNSTransport) Dependencies() []string         { return nil }
func (t *destinationTestDNSTransport) Reset()                         {}
func (t *destinationTestDNSTransport) Exchange(context.Context, *mDNS.Msg) (*mDNS.Msg, error) {
	return nil, errors.New("not implemented")
}
func (t *destinationTestDNSTransport) ExchangeAsync(_ context.Context, _ *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	callback(nil, errors.New("not implemented"))
}

type destinationTestDNSTransportManager struct {
	transport adapter.DNSTransport
}

func (m *destinationTestDNSTransportManager) Start(adapter.StartStage) error { return nil }
func (m *destinationTestDNSTransportManager) Close() error                   { return nil }
func (m *destinationTestDNSTransportManager) Transports() []adapter.DNSTransport {
	return []adapter.DNSTransport{m.transport}
}
func (m *destinationTestDNSTransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	return m.transport, m.transport != nil && m.transport.Tag() == tag
}
func (m *destinationTestDNSTransportManager) Default() adapter.DNSTransport   { return m.transport }
func (m *destinationTestDNSTransportManager) FakeIP() adapter.FakeIPTransport { return nil }
func (m *destinationTestDNSTransportManager) Remove(string) error             { return nil }
func (m *destinationTestDNSTransportManager) Create(context.Context, log.ContextLogger, string, string, any) error {
	return nil
}

func TestDomainEvaluatorUsesConfiguredDNSServer(t *testing.T) {
	t.Parallel()

	transport := &destinationTestDNSTransport{tag: "special"}
	dnsRouter := &destinationTestDNSRouter{cachedAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.4")}}
	evaluatorManager := boxDomainEvaluator.NewManager(
		context.Background(),
		log.NewNOPFactory().NewLogger("domain-evaluator"),
		dnsRouter,
		&destinationTestDNSTransportManager{transport: transport},
		[]option.DomainEvaluatorOptions{{Tag: "dns-check", Server: "special"}},
	)
	require.NoError(t, evaluatorManager.Start(adapter.StartStateStart))
	ctx := service.ContextWith[adapter.DomainEvaluatorManager](context.Background(), evaluatorManager)
	manager := NewConnectionManager(ctx, log.NewNOPFactory().Logger())
	strategy := option.DestinationStrategy{
		Strategy: C.DestinationStrategyPreferDestination,
		OverrideWithDomain: &option.OverrideWithDomainOptions{
			Evaluator: "dns-check",
		},
	}
	metadata := destinationTestMetadata()
	destination, _ := manager.selectDestination(context.Background(), strategy, &metadata)
	require.Equal(t, "www.example.org", destination.Fqdn)
	require.Same(t, transport, dnsRouter.lastTransport)
}

func TestDomainEvaluatorManagerRegisteredService(t *testing.T) {
	t.Parallel()

	manager := boxDomainEvaluator.NewManager(
		context.Background(),
		log.NewNOPFactory().NewLogger("domain-evaluator"),
		&destinationTestDNSRouter{},
		nil,
		[]option.DomainEvaluatorOptions{{Tag: "first"}, {Tag: "second"}},
	)
	ctx := service.ContextWith[adapter.DomainEvaluatorManager](context.Background(), manager)
	require.Same(t, manager, service.FromContext[adapter.DomainEvaluatorManager](ctx))
	require.Len(t, manager.DomainEvaluators(), 2)
	evaluator, loaded := manager.Get("second")
	require.True(t, loaded)
	require.Equal(t, "second", evaluator.Tag())
	_, loaded = manager.Get("missing")
	require.False(t, loaded)
}

func TestDomainEvaluatorManagerRejectsUnknownDNSServer(t *testing.T) {
	t.Parallel()

	manager := boxDomainEvaluator.NewManager(
		context.Background(),
		log.NewNOPFactory().NewLogger("domain-evaluator"),
		&destinationTestDNSRouter{},
		&destinationTestDNSTransportManager{},
		[]option.DomainEvaluatorOptions{{Tag: "dns-check", Server: "missing"}},
	)
	require.ErrorContains(t, manager.Start(adapter.StartStateStart), "domain evaluator[dns-check]")
}
