package outbound

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type destinationManagerTestOptions struct {
	option.DialerOptions
	option.DestinationStrategyOptions
}

type destinationManagerTestOutbound struct {
	Adapter
}

func (o *destinationManagerTestOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (o *destinationManagerTestOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func TestManagerCreatesDialAndDestinationStrategyOptionsTogether(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	var receivedDialOptions option.DialerOptions
	Register[destinationManagerTestOptions](registry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options destinationManagerTestOptions) (adapter.Outbound, error) {
		receivedDialOptions = options.DialerOptions
		return &destinationManagerTestOutbound{
			Adapter: NewAdapter("test", tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		}, nil
	})
	manager := NewManager(log.NewNOPFactory().Logger(), registry, nil, "")
	strategy := option.DestinationStrategy{Strategy: C.DestinationStrategyPreferDestination}
	options := &destinationManagerTestOptions{
		DialerOptions: option.DialerOptions{
			Detour: "upstream",
			AbstractDialerOptions: option.AbstractDialerOptions{
				BindInterface: "en0",
			},
		},
		DestinationStrategyOptions: option.DestinationStrategyOptions{
			DestinationStrategy: &strategy,
		},
	}

	err := manager.Create(context.Background(), nil, log.NewNOPFactory().Logger(), "test-out", "test", options)
	require.NoError(t, err)
	require.Equal(t, "upstream", receivedDialOptions.Detour)
	require.Equal(t, "en0", receivedDialOptions.BindInterface)
	created, loaded := manager.Outbound("test-out")
	require.True(t, loaded)
	connectionDialer := manager.ConnectionDialer(created)
	require.Same(t, created, connectionDialer.Dialer)
	require.Equal(t, C.DestinationStrategyPreferDestination, connectionDialer.DestinationStrategy.EffectiveStrategy())
}
