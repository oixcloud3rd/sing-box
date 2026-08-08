package route

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestResolveRouteOnly(t *testing.T) {
	t.Parallel()

	resolvedAddress := netip.MustParseAddr("203.0.113.1")
	router := newOverrideAddressWithDomainTestRouter(&overrideAddressWithDomainTestDNSRouter{
		warmAddresses: []netip.Addr{resolvedAddress},
	})
	metadata := adapter.InboundContext{
		Destination: M.Socksaddr{Fqdn: "www.example.org", Port: 443},
	}
	err := router.actionResolve(context.Background(), &metadata, &R.RuleActionResolve{RouteOnly: true})
	require.NoError(t, err)
	require.Equal(t, "www.example.org", metadata.Destination.Fqdn)
	require.Equal(t, []netip.Addr{resolvedAddress}, metadata.DestinationAddresses)
	require.True(t, metadata.DestinationAddressesRouteOnly)

	ipRule, err := R.NewRule(context.Background(), log.NewNOPFactory().Logger(), option.Rule{
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{IPCIDR: []string{"203.0.113.0/24"}},
		},
	}, false)
	require.NoError(t, err)
	require.True(t, ipRule.Match(&metadata))

	clearRouteOnlyDestinationAddresses(&metadata)
	require.Equal(t, "www.example.org", metadata.Destination.Fqdn)
	require.Empty(t, metadata.DestinationAddresses)
	require.False(t, metadata.DestinationAddressesRouteOnly)
}

func TestResolveRouteOnlyAction(t *testing.T) {
	t.Parallel()

	action, err := R.NewRuleAction(context.Background(), log.NewNOPFactory().Logger(), option.RuleAction{
		Action: C.RuleActionTypeResolve,
		ResolveOptions: option.RouteActionResolve{
			RouteOnly: true,
		},
	})
	require.NoError(t, err)
	resolveAction := action.(*R.RuleActionResolve)
	require.True(t, resolveAction.RouteOnly)
	require.Equal(t, "resolve(route_only)", resolveAction.String())
}

func TestResolveAffectsDialByDefault(t *testing.T) {
	t.Parallel()

	resolvedAddress := netip.MustParseAddr("203.0.113.1")
	router := newOverrideAddressWithDomainTestRouter(&overrideAddressWithDomainTestDNSRouter{
		warmAddresses: []netip.Addr{resolvedAddress},
	})
	metadata := adapter.InboundContext{
		Destination: M.Socksaddr{Fqdn: "www.example.org", Port: 443},
	}
	err := router.actionResolve(context.Background(), &metadata, &R.RuleActionResolve{})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{resolvedAddress}, metadata.DestinationAddresses)
	require.False(t, metadata.DestinationAddressesRouteOnly)

	clearRouteOnlyDestinationAddresses(&metadata)
	require.Equal(t, []netip.Addr{resolvedAddress}, metadata.DestinationAddresses)
}

func TestResolveIPAddressIsNoOp(t *testing.T) {
	t.Parallel()

	router := newOverrideAddressWithDomainTestRouter(&overrideAddressWithDomainTestDNSRouter{
		warmAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.1")},
	})
	metadata := adapter.InboundContext{
		Destination: M.Socksaddr{Addr: netip.MustParseAddr("198.51.100.1"), Port: 443},
	}
	err := router.actionResolve(context.Background(), &metadata, &R.RuleActionResolve{RouteOnly: true})
	require.NoError(t, err)
	require.True(t, metadata.Destination.IsIP())
	require.Empty(t, metadata.DestinationAddresses)
	require.False(t, metadata.DestinationAddressesRouteOnly)
}

func TestResolveLastActionControlsDial(t *testing.T) {
	t.Parallel()

	router := newOverrideAddressWithDomainTestRouter(&overrideAddressWithDomainTestDNSRouter{
		warmAddresses: []netip.Addr{netip.MustParseAddr("203.0.113.1")},
	})
	metadata := adapter.InboundContext{
		Destination: M.Socksaddr{Fqdn: "www.example.org", Port: 443},
	}
	require.NoError(t, router.actionResolve(context.Background(), &metadata, &R.RuleActionResolve{RouteOnly: true}))
	require.True(t, metadata.DestinationAddressesRouteOnly)
	require.NoError(t, router.actionResolve(context.Background(), &metadata, &R.RuleActionResolve{}))
	require.False(t, metadata.DestinationAddressesRouteOnly)
	require.NoError(t, router.actionResolve(context.Background(), &metadata, &R.RuleActionResolve{RouteOnly: true}))
	require.True(t, metadata.DestinationAddressesRouteOnly)
}

func TestRouteOnlyAddressesRemainAvailableForFakeIPPreMatch(t *testing.T) {
	t.Parallel()

	resolvedAddress := netip.MustParseAddr("203.0.113.1")
	flowOutbound := &resolveRouteOnlyTestFlowOutbound{}
	router := &Router{
		ctx:      context.Background(),
		logger:   log.NewNOPFactory().Logger(),
		outbound: &resolveRouteOnlyTestOutboundManager{outbound: flowOutbound},
	}
	metadata := adapter.InboundContext{
		Network:                       N.NetworkTCP,
		Source:                        M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 12345},
		Destination:                   M.Socksaddr{Fqdn: "www.example.org", Port: 443},
		DestinationAddresses:          []netip.Addr{resolvedAddress},
		DestinationAddressesRouteOnly: true,
		FakeIP:                        true,
	}
	result := router.preMatchFlow(context.Background(), &metadata, M.Socksaddr{
		Addr: netip.MustParseAddr("198.18.0.1"),
		Port: 443,
	}, nil, flowOutbound.Tag())
	require.Equal(t, adapter.PreMatchFlow, result.Action)
	require.Equal(t, netip.AddrPortFrom(resolvedAddress, 443), result.Destination)
	require.Equal(t, []netip.Addr{resolvedAddress}, metadata.DestinationAddresses)
	require.True(t, metadata.DestinationAddressesRouteOnly)
}

func TestRouteOnlyAddressesAreClearedBeforeTCPTrackerAndOutbound(t *testing.T) {
	t.Parallel()

	outbound := &resolveRouteOnlyTestCaptureOutbound{}
	tracker := &resolveRouteOnlyTestTracker{}
	router := &Router{
		ctx:      context.Background(),
		logger:   log.NewNOPFactory().Logger(),
		outbound: &resolveRouteOnlyTestOutboundManager{outbound: outbound},
		trackers: []adapter.ConnectionTracker{tracker},
	}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	require.NoError(t, router.routeConnection(context.Background(), serverConn, resolveRouteOnlyTestMetadata(), nil))
	require.Empty(t, tracker.tcpMetadata.DestinationAddresses)
	require.False(t, tracker.tcpMetadata.DestinationAddressesRouteOnly)
	require.Empty(t, outbound.tcpMetadata.DestinationAddresses)
	require.False(t, outbound.tcpMetadata.DestinationAddressesRouteOnly)
}

func TestRouteOnlyAddressesAreClearedBeforeUDPTrackerAndOutbound(t *testing.T) {
	t.Parallel()

	outbound := &resolveRouteOnlyTestCaptureOutbound{}
	tracker := &resolveRouteOnlyTestTracker{}
	router := &Router{
		ctx:      context.Background(),
		logger:   log.NewNOPFactory().Logger(),
		outbound: &resolveRouteOnlyTestOutboundManager{outbound: outbound},
		trackers: []adapter.ConnectionTracker{tracker},
	}
	require.NoError(t, router.routePacketConnection(context.Background(), &resolveRouteOnlyTestPacketConn{}, resolveRouteOnlyTestMetadata(), nil))
	require.Empty(t, tracker.udpMetadata.DestinationAddresses)
	require.False(t, tracker.udpMetadata.DestinationAddressesRouteOnly)
	require.Empty(t, outbound.udpMetadata.DestinationAddresses)
	require.False(t, outbound.udpMetadata.DestinationAddressesRouteOnly)
}

func resolveRouteOnlyTestMetadata() adapter.InboundContext {
	return adapter.InboundContext{
		Domain:                        "www.example.org",
		Destination:                   M.Socksaddr{Fqdn: "www.example.org", Port: 443},
		DestinationAddresses:          []netip.Addr{netip.MustParseAddr("203.0.113.1")},
		DestinationAddressesRouteOnly: true,
	}
}

type resolveRouteOnlyTestOutboundManager struct {
	outbound adapter.Outbound
}

func (m *resolveRouteOnlyTestOutboundManager) Start(adapter.StartStage) error { return nil }
func (m *resolveRouteOnlyTestOutboundManager) Close() error                   { return nil }
func (m *resolveRouteOnlyTestOutboundManager) Outbounds() []adapter.Outbound {
	return []adapter.Outbound{m.outbound}
}
func (m *resolveRouteOnlyTestOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	return m.outbound, tag == m.outbound.Tag()
}
func (m *resolveRouteOnlyTestOutboundManager) Default() adapter.Outbound { return m.outbound }
func (m *resolveRouteOnlyTestOutboundManager) Remove(string) error       { return nil }
func (m *resolveRouteOnlyTestOutboundManager) Create(context.Context, adapter.Router, log.ContextLogger, string, string, any) error {
	return nil
}

type resolveRouteOnlyTestFlowOutbound struct{}

func (o *resolveRouteOnlyTestFlowOutbound) Type() string           { return "test" }
func (o *resolveRouteOnlyTestFlowOutbound) Tag() string            { return "test" }
func (o *resolveRouteOnlyTestFlowOutbound) Network() []string      { return []string{N.NetworkTCP} }
func (o *resolveRouteOnlyTestFlowOutbound) Dependencies() []string { return nil }
func (o *resolveRouteOnlyTestFlowOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (o *resolveRouteOnlyTestFlowOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}
func (o *resolveRouteOnlyTestFlowOutbound) PreMatchFlow(string, netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}
func (o *resolveRouteOnlyTestFlowOutbound) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.Addr{}, netip.Addr{}
}
func (o *resolveRouteOnlyTestFlowOutbound) PortMTU() uint32               { return 0 }
func (o *resolveRouteOnlyTestFlowOutbound) AttachReturn(tun.Return) error { return nil }
func (o *resolveRouteOnlyTestFlowOutbound) DetachReturn(tun.Return) error { return nil }
func (o *resolveRouteOnlyTestFlowOutbound) WritePackets([][]byte) error   { return nil }

type resolveRouteOnlyTestCaptureOutbound struct {
	resolveRouteOnlyTestFlowOutbound
	tcpMetadata adapter.InboundContext
	udpMetadata adapter.InboundContext
}

func (o *resolveRouteOnlyTestCaptureOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (o *resolveRouteOnlyTestCaptureOutbound) NewConnection(_ context.Context, _ net.Conn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	o.tcpMetadata = metadata
}

func (o *resolveRouteOnlyTestCaptureOutbound) NewPacketConnection(_ context.Context, _ N.PacketConn, metadata adapter.InboundContext, _ N.CloseHandlerFunc) {
	o.udpMetadata = metadata
}

type resolveRouteOnlyTestTracker struct {
	tcpMetadata adapter.InboundContext
	udpMetadata adapter.InboundContext
}

func (t *resolveRouteOnlyTestTracker) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	t.tcpMetadata = metadata
	return conn
}

func (t *resolveRouteOnlyTestTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	t.udpMetadata = metadata
	return conn
}

func (t *resolveRouteOnlyTestTracker) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}

type resolveRouteOnlyTestPacketConn struct{}

func (c *resolveRouteOnlyTestPacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, net.ErrClosed
}

func (c *resolveRouteOnlyTestPacketConn) WritePacket(*buf.Buffer, M.Socksaddr) error {
	return net.ErrClosed
}

func (c *resolveRouteOnlyTestPacketConn) Close() error                     { return nil }
func (c *resolveRouteOnlyTestPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *resolveRouteOnlyTestPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *resolveRouteOnlyTestPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *resolveRouteOnlyTestPacketConn) SetWriteDeadline(time.Time) error { return nil }
