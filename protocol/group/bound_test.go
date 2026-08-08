package group

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	A "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type bindingTestOutbound struct {
	A.Adapter
}

type bindingTestParallelCall struct {
	network               string
	destination           M.Socksaddr
	destinationAddresses  []netip.Addr
	strategy              *C.NetworkStrategy
	interfaceType         []C.InterfaceType
	fallbackInterfaceType []C.InterfaceType
	fallbackDelay         time.Duration
}

type bindingTestParallelOutbound struct {
	*bindingTestOutbound
	dialCall          bindingTestParallelCall
	listenCall        bindingTestParallelCall
	dialError         error
	listenError       error
	packetDestination netip.Addr
}

type bindingTestPacketConn struct{}

func (*bindingTestPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}

func (*bindingTestPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("not implemented")
}

func (*bindingTestPacketConn) Close() error                     { return nil }
func (*bindingTestPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*bindingTestPacketConn) SetDeadline(time.Time) error      { return nil }
func (*bindingTestPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*bindingTestPacketConn) SetWriteDeadline(time.Time) error { return nil }

func newBindingTestOutbound(tag string) *bindingTestOutbound {
	return &bindingTestOutbound{
		Adapter: A.NewAdapter("test", tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
	}
}

type bindingTestOutboundManager struct {
	adapter.OutboundManager
	strategies map[adapter.Outbound]option.DestinationStrategy
}

func (m *bindingTestOutboundManager) ConnectionDialer(outbound adapter.Outbound) adapter.ConnectionDialer {
	strategy, loaded := m.strategies[outbound]
	if !loaded {
		strategy = option.DefaultDestinationStrategy()
	}
	return adapter.ConnectionDialer{Dialer: outbound, DestinationStrategy: strategy}
}

func (o *bindingTestOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (o *bindingTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func (o *bindingTestParallelOutbound) DialParallelNetwork(
	_ context.Context,
	network string,
	destination M.Socksaddr,
	destinationAddresses []netip.Addr,
	strategy *C.NetworkStrategy,
	interfaceType []C.InterfaceType,
	fallbackInterfaceType []C.InterfaceType,
	fallbackDelay time.Duration,
) (net.Conn, error) {
	o.dialCall = bindingTestParallelCall{
		network:               network,
		destination:           destination,
		destinationAddresses:  append([]netip.Addr(nil), destinationAddresses...),
		strategy:              strategy,
		interfaceType:         append([]C.InterfaceType(nil), interfaceType...),
		fallbackInterfaceType: append([]C.InterfaceType(nil), fallbackInterfaceType...),
		fallbackDelay:         fallbackDelay,
	}
	if o.dialError != nil {
		return nil, o.dialError
	}
	conn, peer := net.Pipe()
	peer.Close()
	return conn, nil
}

func (o *bindingTestParallelOutbound) ListenSerialNetworkPacket(
	_ context.Context,
	destination M.Socksaddr,
	destinationAddresses []netip.Addr,
	strategy *C.NetworkStrategy,
	interfaceType []C.InterfaceType,
	fallbackInterfaceType []C.InterfaceType,
	fallbackDelay time.Duration,
) (net.PacketConn, netip.Addr, error) {
	o.listenCall = bindingTestParallelCall{
		destination:           destination,
		destinationAddresses:  append([]netip.Addr(nil), destinationAddresses...),
		strategy:              strategy,
		interfaceType:         append([]C.InterfaceType(nil), interfaceType...),
		fallbackInterfaceType: append([]C.InterfaceType(nil), fallbackInterfaceType...),
		fallbackDelay:         fallbackDelay,
	}
	if o.listenError != nil {
		return nil, netip.Addr{}, o.listenError
	}
	return new(bindingTestPacketConn), o.packetDestination, nil
}

func TestSelectorBindsLeafAndDestinationStrategy(t *testing.T) {
	t.Parallel()

	leafA := newBindingTestOutbound("a")
	leafB := newBindingTestOutbound("b")
	outboundManager := &bindingTestOutboundManager{strategies: map[adapter.Outbound]option.DestinationStrategy{
		leafA: {Strategy: C.DestinationStrategyPreferDestination},
		leafB: option.DefaultDestinationStrategy(),
	}}
	selector := &Selector{
		Adapter:        A.NewAdapter(C.TypeSelector, "selector", nil, nil),
		outbound:       outboundManager,
		logger:         log.NewNOPFactory().Logger(),
		interruptGroup: interrupt.NewGroup(),
	}
	selector.selected.Store(leafA)

	boundA, err := selector.bindConnection(N.NetworkTCP)
	require.NoError(t, err)
	selector.selected.Store(leafB)

	boundSelectorA := boundA.Dialer.(*boundSelectorOutbound)
	require.Same(t, leafA, boundSelectorA.Outbound)
	require.Equal(t, C.DestinationStrategyPreferDestination, boundA.DestinationStrategy.EffectiveStrategy())

	boundB, err := selector.bindConnection(N.NetworkTCP)
	require.NoError(t, err)
	boundSelectorB := boundB.Dialer.(*boundSelectorOutbound)
	require.Same(t, leafB, boundSelectorB.Outbound)
	require.Equal(t, C.DestinationStrategyPreferDestinationAddresses, boundB.DestinationStrategy.EffectiveStrategy())
}

func TestNestedSelectorBindsFinalLeaf(t *testing.T) {
	t.Parallel()

	leafA := newBindingTestOutbound("a")
	leafB := newBindingTestOutbound("b")
	outboundManager := &bindingTestOutboundManager{strategies: map[adapter.Outbound]option.DestinationStrategy{
		leafA: {Strategy: C.DestinationStrategyPreferDestination},
		leafB: option.DefaultDestinationStrategy(),
	}}
	inner := &Selector{
		Adapter:        A.NewAdapter(C.TypeSelector, "inner", nil, nil),
		outbound:       outboundManager,
		logger:         log.NewNOPFactory().Logger(),
		interruptGroup: interrupt.NewGroup(),
	}
	inner.selected.Store(leafA)
	outer := &Selector{
		Adapter:        A.NewAdapter(C.TypeSelector, "outer", nil, nil),
		outbound:       outboundManager,
		logger:         log.NewNOPFactory().Logger(),
		interruptGroup: interrupt.NewGroup(),
	}
	outer.selected.Store(inner)

	bound, err := outer.bindConnection(N.NetworkUDP)
	require.NoError(t, err)
	inner.selected.Store(leafB)

	outerBound := bound.Dialer.(*boundSelectorOutbound)
	innerBound := outerBound.Outbound.(*boundSelectorOutbound)
	require.Same(t, leafA, innerBound.Outbound)
	require.Equal(t, C.DestinationStrategyPreferDestination, bound.DestinationStrategy.EffectiveStrategy())
}

func TestURLTestBindsProtocolLeafAndDestinationStrategy(t *testing.T) {
	t.Parallel()

	leafA := newBindingTestOutbound("a")
	leafB := newBindingTestOutbound("b")
	outboundManager := &bindingTestOutboundManager{strategies: map[adapter.Outbound]option.DestinationStrategy{
		leafA: {Strategy: C.DestinationStrategyPreferDestination},
		leafB: option.DefaultDestinationStrategy(),
	}}
	urlTestGroup := &URLTestGroup{interruptGroup: interrupt.NewGroup()}
	urlTestGroup.selectedOutboundTCP.Store(adapter.Outbound(leafA))
	urlTestGroup.selectedOutboundUDP.Store(adapter.Outbound(leafB))
	urlTest := &URLTest{
		Adapter:  A.NewAdapter(C.TypeURLTest, "urltest", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		outbound: outboundManager,
		logger:   log.NewNOPFactory().Logger(),
		group:    urlTestGroup,
	}

	boundTCP, err := urlTest.bindConnection(N.NetworkTCP)
	require.NoError(t, err)
	urlTestGroup.selectedOutboundTCP.Store(adapter.Outbound(leafB))

	boundURLTestTCP := boundTCP.Dialer.(*boundURLTestOutbound)
	require.Same(t, leafA, boundURLTestTCP.Outbound)
	require.Equal(t, C.DestinationStrategyPreferDestination, boundTCP.DestinationStrategy.EffectiveStrategy())

	boundUDP, err := urlTest.bindConnection(N.NetworkUDP)
	require.NoError(t, err)
	boundURLTestUDP := boundUDP.Dialer.(*boundURLTestOutbound)
	require.Same(t, leafB, boundURLTestUDP.Outbound)
}

func TestBoundOutboundsPreserveParallelNetworkDialer(t *testing.T) {
	t.Parallel()

	t.Run("selector", func(t *testing.T) {
		leaf := &bindingTestParallelOutbound{
			bindingTestOutbound: newBindingTestOutbound("leaf"),
			packetDestination:   netip.MustParseAddr("192.0.2.10"),
		}
		outboundManager := &bindingTestOutboundManager{strategies: map[adapter.Outbound]option.DestinationStrategy{
			leaf: option.DefaultDestinationStrategy(),
		}}
		selector := &Selector{
			Adapter:        A.NewAdapter(C.TypeSelector, "selector", nil, nil),
			outbound:       outboundManager,
			logger:         log.NewNOPFactory().Logger(),
			interruptGroup: interrupt.NewGroup(),
		}
		selector.selected.Store(adapter.Outbound(leaf))
		bound, err := selector.bindConnection(N.NetworkTCP)
		require.NoError(t, err)
		testBoundParallelNetworkDialer(t, bound, leaf, 0)
	})

	t.Run("urltest", func(t *testing.T) {
		leaf := &bindingTestParallelOutbound{
			bindingTestOutbound: newBindingTestOutbound("leaf"),
			packetDestination:   netip.MustParseAddr("192.0.2.10"),
		}
		outboundManager := &bindingTestOutboundManager{strategies: map[adapter.Outbound]option.DestinationStrategy{
			leaf: option.DefaultDestinationStrategy(),
		}}
		group := &URLTestGroup{
			history:        urltest.NewHistoryStorage(),
			interruptGroup: interrupt.NewGroup(),
		}
		group.selectedOutboundTCP.Store(adapter.Outbound(leaf))
		group.selectedOutboundUDP.Store(adapter.Outbound(leaf))
		urlTest := &URLTest{
			Adapter:  A.NewAdapter(C.TypeURLTest, "urltest", []string{N.NetworkTCP, N.NetworkUDP}, nil),
			outbound: outboundManager,
			logger:   log.NewNOPFactory().Logger(),
			group:    group,
		}
		bound, err := urlTest.bindConnection(N.NetworkTCP)
		require.NoError(t, err)
		testBoundParallelNetworkDialer(t, bound, leaf, 1)
	})

	t.Run("nested selector", func(t *testing.T) {
		leaf := &bindingTestParallelOutbound{
			bindingTestOutbound: newBindingTestOutbound("leaf"),
			packetDestination:   netip.MustParseAddr("192.0.2.10"),
		}
		outboundManager := &bindingTestOutboundManager{strategies: map[adapter.Outbound]option.DestinationStrategy{
			leaf: option.DefaultDestinationStrategy(),
		}}
		inner := &Selector{
			Adapter:        A.NewAdapter(C.TypeSelector, "inner", nil, nil),
			outbound:       outboundManager,
			logger:         log.NewNOPFactory().Logger(),
			interruptGroup: interrupt.NewGroup(),
		}
		inner.selected.Store(adapter.Outbound(leaf))
		outer := &Selector{
			Adapter:        A.NewAdapter(C.TypeSelector, "outer", nil, nil),
			outbound:       outboundManager,
			logger:         log.NewNOPFactory().Logger(),
			interruptGroup: interrupt.NewGroup(),
		}
		outer.selected.Store(adapter.Outbound(inner))
		bound, err := outer.bindConnection(N.NetworkTCP)
		require.NoError(t, err)
		testBoundParallelNetworkDialer(t, bound, leaf, 0)
	})

	t.Run("urltest nested selector", func(t *testing.T) {
		leaf := &bindingTestParallelOutbound{
			bindingTestOutbound: newBindingTestOutbound("leaf"),
			packetDestination:   netip.MustParseAddr("192.0.2.10"),
		}
		outboundManager := &bindingTestOutboundManager{strategies: map[adapter.Outbound]option.DestinationStrategy{
			leaf: option.DefaultDestinationStrategy(),
		}}
		selector := &Selector{
			Adapter:        A.NewAdapter(C.TypeSelector, "selector", nil, nil),
			outbound:       outboundManager,
			logger:         log.NewNOPFactory().Logger(),
			interruptGroup: interrupt.NewGroup(),
		}
		selector.selected.Store(adapter.Outbound(leaf))
		group := &URLTestGroup{
			history:        urltest.NewHistoryStorage(),
			interruptGroup: interrupt.NewGroup(),
		}
		group.selectedOutboundTCP.Store(adapter.Outbound(selector))
		urlTest := &URLTest{
			Adapter:  A.NewAdapter(C.TypeURLTest, "urltest", []string{N.NetworkTCP, N.NetworkUDP}, nil),
			outbound: outboundManager,
			logger:   log.NewNOPFactory().Logger(),
			group:    group,
		}
		bound, err := urlTest.bindConnection(N.NetworkTCP)
		require.NoError(t, err)
		testBoundParallelNetworkDialer(t, bound, leaf, 2)
	})
}

func testBoundParallelNetworkDialer(t *testing.T, bound adapter.ConnectionDialer, leaf *bindingTestParallelOutbound, expectedInterruptLayers int) {
	t.Helper()

	parallelDialer, loaded := bound.Dialer.(dialer.ParallelNetworkDialer)
	require.True(t, loaded)
	destination := M.Socksaddr{Fqdn: "example.com", Port: 443}
	destinationAddresses := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("192.0.2.1"),
	}
	networkStrategy := C.NetworkStrategyHybrid
	interfaceType := []C.InterfaceType{C.InterfaceTypeWIFI, C.InterfaceTypeEthernet}
	fallbackInterfaceType := []C.InterfaceType{C.InterfaceTypeCellular}
	fallbackDelay := 250 * time.Millisecond

	conn, err := parallelDialer.DialParallelNetwork(
		context.Background(),
		N.NetworkTCP,
		destination,
		destinationAddresses,
		&networkStrategy,
		interfaceType,
		fallbackInterfaceType,
		fallbackDelay,
	)
	require.NoError(t, err)
	require.Equal(t, expectedInterruptLayers, countInterruptConnLayers(conn))
	require.NoError(t, conn.Close())
	require.Equal(t, N.NetworkTCP, leaf.dialCall.network)
	require.Equal(t, destination, leaf.dialCall.destination)
	require.Equal(t, destinationAddresses, leaf.dialCall.destinationAddresses)
	require.Same(t, &networkStrategy, leaf.dialCall.strategy)
	require.Equal(t, interfaceType, leaf.dialCall.interfaceType)
	require.Equal(t, fallbackInterfaceType, leaf.dialCall.fallbackInterfaceType)
	require.Equal(t, fallbackDelay, leaf.dialCall.fallbackDelay)

	packetConn, packetDestination, err := parallelDialer.ListenSerialNetworkPacket(
		context.Background(),
		destination,
		destinationAddresses,
		&networkStrategy,
		interfaceType,
		fallbackInterfaceType,
		fallbackDelay,
	)
	require.NoError(t, err)
	require.Equal(t, expectedInterruptLayers, countInterruptPacketConnLayers(packetConn))
	require.Equal(t, leaf.packetDestination, packetDestination)
	require.NoError(t, packetConn.Close())
	require.Equal(t, destination, leaf.listenCall.destination)
	require.Equal(t, destinationAddresses, leaf.listenCall.destinationAddresses)
	require.Same(t, &networkStrategy, leaf.listenCall.strategy)
	require.Equal(t, interfaceType, leaf.listenCall.interfaceType)
	require.Equal(t, fallbackInterfaceType, leaf.listenCall.fallbackInterfaceType)
	require.Equal(t, fallbackDelay, leaf.listenCall.fallbackDelay)
}

func countInterruptConnLayers(conn net.Conn) int {
	var count int
	for {
		interruptConn, loaded := conn.(*interrupt.Conn)
		if !loaded {
			return count
		}
		count++
		conn = interruptConn.Conn
	}
}

func countInterruptPacketConnLayers(conn net.PacketConn) int {
	var count int
	for {
		interruptConn, loaded := conn.(*interrupt.PacketConn)
		if !loaded {
			return count
		}
		count++
		conn = interruptConn.PacketConn
	}
}

func TestBoundURLTestParallelNetworkFailureDeletesHistory(t *testing.T) {
	t.Parallel()

	dialError := errors.New("parallel dial failed")
	listenError := errors.New("parallel listen failed")
	leaf := &bindingTestParallelOutbound{
		bindingTestOutbound: newBindingTestOutbound("leaf"),
		dialError:           dialError,
		listenError:         listenError,
	}
	outboundManager := &bindingTestOutboundManager{strategies: map[adapter.Outbound]option.DestinationStrategy{
		leaf: option.DefaultDestinationStrategy(),
	}}
	history := urltest.NewHistoryStorage()
	group := &URLTestGroup{
		history:        history,
		interruptGroup: interrupt.NewGroup(),
	}
	group.selectedOutboundTCP.Store(adapter.Outbound(leaf))
	urlTest := &URLTest{
		Adapter:  A.NewAdapter(C.TypeURLTest, "urltest", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		outbound: outboundManager,
		logger:   log.NewNOPFactory().Logger(),
		group:    group,
	}
	bound, err := urlTest.bindConnection(N.NetworkTCP)
	require.NoError(t, err)
	parallelDialer := bound.Dialer.(dialer.ParallelNetworkDialer)
	destination := M.Socksaddr{Fqdn: "example.com", Port: 443}
	destinationAddresses := []netip.Addr{netip.MustParseAddr("192.0.2.1")}

	history.StoreURLTestHistory(leaf.Tag(), &adapter.URLTestHistory{Delay: 10})
	_, err = parallelDialer.DialParallelNetwork(context.Background(), N.NetworkTCP, destination, destinationAddresses, nil, nil, nil, 0)
	require.ErrorIs(t, err, dialError)
	require.Nil(t, history.LoadURLTestHistory(leaf.Tag()))

	history.StoreURLTestHistory(leaf.Tag(), &adapter.URLTestHistory{Delay: 10})
	_, _, err = parallelDialer.ListenSerialNetworkPacket(context.Background(), destination, destinationAddresses, nil, nil, nil, 0)
	require.ErrorIs(t, err, listenError)
	require.Nil(t, history.LoadURLTestHistory(leaf.Tag()))
}
