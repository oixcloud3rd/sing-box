package libbox

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestPlatformTransportPreferredDomain(t *testing.T) {
	t.Parallel()

	transport, err := newPlatformTransport(
		context.Background(),
		log.NewNOPFactory().Logger(),
		nil,
		"local",
		option.LocalDNSServerOptions{},
	)
	require.NoError(t, err)
	require.Implements(t, (*adapter.DNSTransportWithPreferredDomain)(nil), transport)
	require.True(t, transport.PreferredDomain("printer.local"))
	require.False(t, transport.PreferredDomain("example.org"))
}
