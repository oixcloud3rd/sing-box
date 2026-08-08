package group

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type connectionBindMode bool

const (
	// Handler mode preserves the interrupt behavior of group NewConnection paths,
	// while dial mode preserves the behavior of traversing a group via DialContext.
	connectionBindModeHandler connectionBindMode = false
	connectionBindModeDial    connectionBindMode = true
)

type connectionBindable interface {
	bindConnectionWithMode(network string, mode connectionBindMode) (adapter.ConnectionDialer, error)
}

var errSelectionChanged = errors.New("selected outbound changed during connection setup")

func bindConnectionOutbound(outboundManager adapter.OutboundManager, outbound adapter.Outbound, network string, mode connectionBindMode) (adapter.ConnectionDialer, error) {
	if bindable, loaded := outbound.(connectionBindable); loaded {
		return bindable.bindConnectionWithMode(network, mode)
	}
	return outboundManager.ConnectionDialer(outbound), nil
}

type boundSelectorOutbound struct {
	adapter.Outbound
	selector   *Selector
	generation uint64
	interrupt  bool
}

func (b *boundSelectorOutbound) wrapConn(conn net.Conn) (net.Conn, error) {
	if !b.interrupt && !b.selector.interruptExternalConnections {
		return conn, nil
	}
	if b.selector.interruptExternalConnections {
		wrappedConn, loaded := b.selector.interruptGroup.NewConnAtGeneration(conn, true, b.generation)
		if !loaded {
			conn.Close()
			return nil, errSelectionChanged
		}
		return wrappedConn, nil
	}
	return b.selector.interruptGroup.NewConn(conn, true), nil
}

func (b *boundSelectorOutbound) wrapPacketConn(conn net.PacketConn) (net.PacketConn, error) {
	if !b.interrupt && !b.selector.interruptExternalConnections {
		return conn, nil
	}
	if b.selector.interruptExternalConnections {
		wrappedConn, loaded := b.selector.interruptGroup.NewPacketConnAtGeneration(conn, true, b.generation)
		if !loaded {
			conn.Close()
			return nil, errSelectionChanged
		}
		return wrappedConn, nil
	}
	return b.selector.interruptGroup.NewPacketConn(conn, true), nil
}

func (b *boundSelectorOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := b.Outbound.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return b.wrapConn(conn)
}

func (b *boundSelectorOutbound) DialParallelInterface(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
	strategy *C.NetworkStrategy,
	interfaceType []C.InterfaceType,
	fallbackInterfaceType []C.InterfaceType,
	fallbackDelay time.Duration,
) (net.Conn, error) {
	parallelDialer, loaded := b.Outbound.(dialer.ParallelInterfaceDialer)
	if !loaded {
		return b.DialContext(ctx, network, destination)
	}
	conn, err := parallelDialer.DialParallelInterface(ctx, network, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	if err != nil {
		return nil, err
	}
	return b.wrapConn(conn)
}

func (b *boundSelectorOutbound) DialParallelNetwork(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
	destinationAddresses []netip.Addr,
	strategy *C.NetworkStrategy,
	interfaceType []C.InterfaceType,
	fallbackInterfaceType []C.InterfaceType,
	fallbackDelay time.Duration,
) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	parallelDialer, loaded := b.Outbound.(dialer.ParallelNetworkDialer)
	if loaded {
		conn, err = parallelDialer.DialParallelNetwork(ctx, network, destination, destinationAddresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	} else {
		conn, err = dialer.DialSerialNetwork(ctx, b.Outbound, network, destination, destinationAddresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	}
	if err != nil {
		return nil, err
	}
	return b.wrapConn(conn)
}

func (b *boundSelectorOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := b.Outbound.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return b.wrapPacketConn(conn)
}

func (b *boundSelectorOutbound) ListenSerialInterfacePacket(
	ctx context.Context,
	destination M.Socksaddr,
	strategy *C.NetworkStrategy,
	interfaceType []C.InterfaceType,
	fallbackInterfaceType []C.InterfaceType,
	fallbackDelay time.Duration,
) (net.PacketConn, error) {
	parallelDialer, loaded := b.Outbound.(dialer.ParallelInterfaceDialer)
	if !loaded {
		return b.ListenPacket(ctx, destination)
	}
	conn, err := parallelDialer.ListenSerialInterfacePacket(ctx, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	if err != nil {
		return nil, err
	}
	return b.wrapPacketConn(conn)
}

func (b *boundSelectorOutbound) ListenSerialNetworkPacket(
	ctx context.Context,
	destination M.Socksaddr,
	destinationAddresses []netip.Addr,
	strategy *C.NetworkStrategy,
	interfaceType []C.InterfaceType,
	fallbackInterfaceType []C.InterfaceType,
	fallbackDelay time.Duration,
) (net.PacketConn, netip.Addr, error) {
	var (
		conn               net.PacketConn
		destinationAddress netip.Addr
		err                error
	)
	parallelDialer, loaded := b.Outbound.(dialer.ParallelNetworkDialer)
	if loaded {
		conn, destinationAddress, err = parallelDialer.ListenSerialNetworkPacket(ctx, destination, destinationAddresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	} else {
		conn, destinationAddress, err = dialer.ListenSerialNetworkPacket(ctx, b.Outbound, destination, destinationAddresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	}
	if err != nil {
		return nil, netip.Addr{}, err
	}
	wrappedConn, wrapErr := b.wrapPacketConn(conn)
	if wrapErr != nil {
		return nil, netip.Addr{}, wrapErr
	}
	return wrappedConn, destinationAddress, nil
}

func (b *boundSelectorOutbound) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	packetDialer, loaded := b.Outbound.(dialer.PacketDialerWithDestination)
	if !loaded {
		conn, err := b.ListenPacket(ctx, destination)
		return conn, netip.Addr{}, err
	}
	conn, destinationAddress, err := packetDialer.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	wrappedConn, wrapErr := b.wrapPacketConn(conn)
	if wrapErr != nil {
		return nil, netip.Addr{}, wrapErr
	}
	return wrappedConn, destinationAddress, nil
}

type boundURLTestOutbound struct {
	adapter.Outbound
	urlTest          *URLTest
	selectedOutbound adapter.Outbound
	generation       uint64
}

func (b *boundURLTestOutbound) onError(ctx context.Context, err error) {
	if errors.Is(err, errSelectionChanged) {
		return
	}
	b.urlTest.logger.ErrorContext(ctx, err)
	b.urlTest.group.history.DeleteURLTestHistory(b.selectedOutbound.Tag())
}

func (b *boundURLTestOutbound) wrapConn(conn net.Conn) (net.Conn, error) {
	if b.urlTest.group.interruptExternalConnections {
		wrappedConn, loaded := b.urlTest.group.interruptGroup.NewConnAtGeneration(conn, true, b.generation)
		if !loaded {
			conn.Close()
			return nil, errSelectionChanged
		}
		return wrappedConn, nil
	}
	return b.urlTest.group.interruptGroup.NewConn(conn, true), nil
}

func (b *boundURLTestOutbound) wrapPacketConn(conn net.PacketConn) (net.PacketConn, error) {
	if b.urlTest.group.interruptExternalConnections {
		wrappedConn, loaded := b.urlTest.group.interruptGroup.NewPacketConnAtGeneration(conn, true, b.generation)
		if !loaded {
			conn.Close()
			return nil, errSelectionChanged
		}
		return wrappedConn, nil
	}
	return b.urlTest.group.interruptGroup.NewPacketConn(conn, true), nil
}

func (b *boundURLTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := b.Outbound.DialContext(ctx, network, destination)
	if err != nil {
		b.onError(ctx, err)
		return nil, err
	}
	return b.wrapConn(conn)
}

func (b *boundURLTestOutbound) DialParallelInterface(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
	strategy *C.NetworkStrategy,
	interfaceType []C.InterfaceType,
	fallbackInterfaceType []C.InterfaceType,
	fallbackDelay time.Duration,
) (net.Conn, error) {
	parallelDialer, loaded := b.Outbound.(dialer.ParallelInterfaceDialer)
	if !loaded {
		return b.DialContext(ctx, network, destination)
	}
	conn, err := parallelDialer.DialParallelInterface(ctx, network, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	if err != nil {
		b.onError(ctx, err)
		return nil, err
	}
	return b.wrapConn(conn)
}

func (b *boundURLTestOutbound) DialParallelNetwork(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
	destinationAddresses []netip.Addr,
	strategy *C.NetworkStrategy,
	interfaceType []C.InterfaceType,
	fallbackInterfaceType []C.InterfaceType,
	fallbackDelay time.Duration,
) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	parallelDialer, loaded := b.Outbound.(dialer.ParallelNetworkDialer)
	if loaded {
		conn, err = parallelDialer.DialParallelNetwork(ctx, network, destination, destinationAddresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	} else {
		conn, err = dialer.DialSerialNetwork(ctx, b.Outbound, network, destination, destinationAddresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	}
	if err != nil {
		b.onError(ctx, err)
		return nil, err
	}
	return b.wrapConn(conn)
}

func (b *boundURLTestOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := b.Outbound.ListenPacket(ctx, destination)
	if err != nil {
		b.onError(ctx, err)
		return nil, err
	}
	return b.wrapPacketConn(conn)
}

func (b *boundURLTestOutbound) ListenSerialInterfacePacket(
	ctx context.Context,
	destination M.Socksaddr,
	strategy *C.NetworkStrategy,
	interfaceType []C.InterfaceType,
	fallbackInterfaceType []C.InterfaceType,
	fallbackDelay time.Duration,
) (net.PacketConn, error) {
	parallelDialer, loaded := b.Outbound.(dialer.ParallelInterfaceDialer)
	if !loaded {
		return b.ListenPacket(ctx, destination)
	}
	conn, err := parallelDialer.ListenSerialInterfacePacket(ctx, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	if err != nil {
		b.onError(ctx, err)
		return nil, err
	}
	return b.wrapPacketConn(conn)
}

func (b *boundURLTestOutbound) ListenSerialNetworkPacket(
	ctx context.Context,
	destination M.Socksaddr,
	destinationAddresses []netip.Addr,
	strategy *C.NetworkStrategy,
	interfaceType []C.InterfaceType,
	fallbackInterfaceType []C.InterfaceType,
	fallbackDelay time.Duration,
) (net.PacketConn, netip.Addr, error) {
	var (
		conn               net.PacketConn
		destinationAddress netip.Addr
		err                error
	)
	parallelDialer, loaded := b.Outbound.(dialer.ParallelNetworkDialer)
	if loaded {
		conn, destinationAddress, err = parallelDialer.ListenSerialNetworkPacket(ctx, destination, destinationAddresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	} else {
		conn, destinationAddress, err = dialer.ListenSerialNetworkPacket(ctx, b.Outbound, destination, destinationAddresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	}
	if err != nil {
		b.onError(ctx, err)
		return nil, netip.Addr{}, err
	}
	wrappedConn, wrapErr := b.wrapPacketConn(conn)
	if wrapErr != nil {
		return nil, netip.Addr{}, wrapErr
	}
	return wrappedConn, destinationAddress, nil
}

func (b *boundURLTestOutbound) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	packetDialer, loaded := b.Outbound.(dialer.PacketDialerWithDestination)
	if !loaded {
		conn, err := b.ListenPacket(ctx, destination)
		return conn, netip.Addr{}, err
	}
	conn, destinationAddress, err := packetDialer.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		b.onError(ctx, err)
		return nil, netip.Addr{}, err
	}
	wrappedConn, wrapErr := b.wrapPacketConn(conn)
	if wrapErr != nil {
		return nil, netip.Addr{}, wrapErr
	}
	return wrappedConn, destinationAddress, nil
}

var (
	_ dialer.ParallelNetworkDialer       = (*boundSelectorOutbound)(nil)
	_ dialer.ParallelNetworkDialer       = (*boundURLTestOutbound)(nil)
	_ dialer.ParallelInterfaceDialer     = (*boundSelectorOutbound)(nil)
	_ dialer.ParallelInterfaceDialer     = (*boundURLTestOutbound)(nil)
	_ dialer.PacketDialerWithDestination = (*boundSelectorOutbound)(nil)
	_ dialer.PacketDialerWithDestination = (*boundURLTestOutbound)(nil)
	_ N.Dialer                           = (*boundSelectorOutbound)(nil)
	_ N.Dialer                           = (*boundURLTestOutbound)(nil)
)
