package adapter

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

type ConnectionDialer struct {
	Dialer              N.Dialer
	DestinationStrategy option.DestinationStrategy
}

type ConnectionManager interface {
	Lifecycle
	Count() int
	CloseAll()
	TrackConn(conn net.Conn) net.Conn
	TrackPacketConn(conn net.PacketConn) net.PacketConn
	NewConnection(ctx context.Context, dialer ConnectionDialer, conn net.Conn, metadata InboundContext, onClose N.CloseHandlerFunc)
	NewPacketConnection(ctx context.Context, dialer ConnectionDialer, conn N.PacketConn, metadata InboundContext, onClose N.CloseHandlerFunc)
}
