package endpoint

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

type destinationManagerTestEndpoint struct {
	Adapter
}

func (e *destinationManagerTestEndpoint) Start(adapter.StartStage) error { return nil }
func (e *destinationManagerTestEndpoint) Close() error                   { return nil }

func (e *destinationManagerTestEndpoint) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (e *destinationManagerTestEndpoint) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func TestManagerStoresDestinationStrategyOutsideEndpointAdapter(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	Register[destinationManagerTestOptions](registry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ destinationManagerTestOptions) (adapter.Endpoint, error) {
		return &destinationManagerTestEndpoint{
			Adapter: NewAdapter("test", tag, []string{N.NetworkTCP, N.NetworkUDP}, nil),
		}, nil
	})
	manager := NewManager(log.NewNOPFactory().Logger(), registry)
	strategy := option.DestinationStrategy{Strategy: C.DestinationStrategyPreferDestination}
	err := manager.Create(context.Background(), nil, log.NewNOPFactory().Logger(), "test-endpoint", "test", &destinationManagerTestOptions{
		DestinationStrategyOptions: option.DestinationStrategyOptions{DestinationStrategy: &strategy},
	})
	require.NoError(t, err)
	created, loaded := manager.Get("test-endpoint")
	require.True(t, loaded)
	connectionDialer := manager.ConnectionDialer(created)
	require.Same(t, created, connectionDialer.Dialer)
	require.Equal(t, C.DestinationStrategyPreferDestination, connectionDialer.DestinationStrategy.EffectiveStrategy())
}
