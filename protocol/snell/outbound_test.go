package snell

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func newECHTLSOptions() option.SnellOutboundOptions {
	return option.SnellOutboundOptions{
		Version: 4,
		PSK:     "password",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled: true,
				ECH:     &option.OutboundECHOptions{Enabled: true},
			},
		},
		Transport: &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path: "/snell",
			},
		},
	}
}

func TestValidateECHTLSOptions(t *testing.T) {
	t.Parallel()

	legacyOptions := option.SnellOutboundOptions{Version: 4, PSK: "password"}
	enabled, err := validateECHTLSOptions(legacyOptions)
	require.NoError(t, err)
	require.False(t, enabled)

	validOptions := newECHTLSOptions()
	enabled, err = validateECHTLSOptions(validOptions)
	require.NoError(t, err)
	require.True(t, enabled)

	testCases := []struct {
		name        string
		modify      func(*option.SnellOutboundOptions)
		errorString string
	}{
		{
			name: "version 6",
			modify: func(options *option.SnellOutboundOptions) {
				options.Version = 6
			},
			errorString: "requires version 4",
		},
		{
			name: "missing transport",
			modify: func(options *option.SnellOutboundOptions) {
				options.Transport = nil
			},
			errorString: "requires WebSocket transport",
		},
		{
			name: "wrong transport",
			modify: func(options *option.SnellOutboundOptions) {
				options.Transport.Type = C.V2RayTransportTypeHTTP
			},
			errorString: "requires WebSocket transport",
		},
		{
			name: "missing path",
			modify: func(options *option.SnellOutboundOptions) {
				options.Transport.WebsocketOptions.Path = ""
			},
			errorString: "requires a non-empty WebSocket path",
		},
		{
			name: "missing TLS",
			modify: func(options *option.SnellOutboundOptions) {
				options.TLS = nil
			},
			errorString: "requires TLS",
		},
		{
			name: "TLS disabled",
			modify: func(options *option.SnellOutboundOptions) {
				options.TLS.Enabled = false
			},
			errorString: "requires TLS",
		},
		{
			name: "missing ECH",
			modify: func(options *option.SnellOutboundOptions) {
				options.TLS.ECH = nil
			},
			errorString: "requires ECH",
		},
		{
			name: "ECH disabled",
			modify: func(options *option.SnellOutboundOptions) {
				options.TLS.ECH.Enabled = false
			},
			errorString: "requires ECH",
		},
		{
			name: "obfs conflict",
			modify: func(options *option.SnellOutboundOptions) {
				options.ObfsOptions.ObfsMode = "http"
			},
			errorString: "cannot be combined with obfs",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			options := newECHTLSOptions()
			testCase.modify(&options)
			enabled, err := validateECHTLSOptions(options)
			require.False(t, enabled)
			require.ErrorContains(t, err, testCase.errorString)
		})
	}
}

func TestValidateIdentityOptions(t *testing.T) {
	t.Parallel()

	require.NoError(t, validateIdentityOptions(option.SnellOutboundOptions{Version: 4, Identity: true}))
	require.NoError(t, validateIdentityOptions(option.SnellOutboundOptions{Version: 6}))
	require.ErrorContains(t, validateIdentityOptions(option.SnellOutboundOptions{Version: 6, Identity: true}), "requires version 4")
}

type stubClientTransport struct {
	conn   net.Conn
	dialed bool
	closed bool
}

func (t *stubClientTransport) DialContext(ctx context.Context) (net.Conn, error) {
	t.dialed = true
	return t.conn, nil
}

func (t *stubClientTransport) Close() error {
	t.closed = true
	return nil
}

func TestTransportDialer(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})
	transport := &stubClientTransport{conn: clientConn}
	dialer := &transportDialer{transport: transport}

	conn, err := dialer.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("ignored.example:443"))
	require.NoError(t, err)
	require.Same(t, clientConn, conn)
	require.True(t, transport.dialed)

	_, err = dialer.DialContext(context.Background(), N.NetworkUDP, M.Socksaddr{})
	require.Error(t, err)
	_, err = dialer.ListenPacket(context.Background(), M.Socksaddr{})
	require.Error(t, err)
}

var (
	_ adapter.V2RayClientTransport = (*stubClientTransport)(nil)
	_ N.Dialer                     = (*transportDialer)(nil)
)
