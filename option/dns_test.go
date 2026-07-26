package option

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type stubDNSTransportOptionsRegistry struct{}

func (stubDNSTransportOptionsRegistry) OptionTypes() []string {
	return []string{C.DNSTypeUDP, C.DNSTypeFakeIP}
}

func (stubDNSTransportOptionsRegistry) CreateOptions(transportType string) (any, bool) {
	switch transportType {
	case C.DNSTypeUDP, C.DNSTypeTCP:
		return new(RemoteDNSServerOptions), true
	case C.DNSTypeTLS, C.DNSTypeQUIC:
		return new(RemoteTLSDNSServerOptions), true
	case C.DNSTypeHTTPS, C.DNSTypeHTTP3:
		return new(RemoteHTTPSDNSServerOptions), true
	case C.DNSTypeFakeIP:
		return new(FakeIPDNSServerOptions), true
	default:
		return nil, false
	}
}

func TestRemoteDNSServerOIXCloudOptions(t *testing.T) {
	t.Parallel()

	ctx := service.ContextWith[DNSTransportOptionsRegistry](context.Background(), stubDNSTransportOptionsRegistry{})
	for _, transportType := range []string{
		C.DNSTypeUDP,
		C.DNSTypeTCP,
		C.DNSTypeTLS,
		C.DNSTypeHTTPS,
		C.DNSTypeQUIC,
		C.DNSTypeHTTP3,
	} {
		t.Run(transportType, func(t *testing.T) {
			var options DNSServerOptions
			err := json.UnmarshalContext(ctx, []byte(`{"type":"`+transportType+`","server":"127.0.0.1","oixcloud":true}`), &options)
			require.NoError(t, err)
			oixCloudOptions, loaded := options.Options.(interface{ IsOIXCloudEnabled() bool })
			require.True(t, loaded)
			require.True(t, oixCloudOptions.IsOIXCloudEnabled())

			encoded, err := json.MarshalContext(ctx, &options)
			require.NoError(t, err)
			require.JSONEq(t, `{"type":"`+transportType+`","server":"127.0.0.1","oixcloud":true}`, string(encoded))
		})
	}
}

func TestNonRemoteDNSServerRejectsOIXCloudOptions(t *testing.T) {
	t.Parallel()

	ctx := service.ContextWith[DNSTransportOptionsRegistry](context.Background(), stubDNSTransportOptionsRegistry{})
	var options DNSServerOptions
	err := json.UnmarshalContext(ctx, []byte(`{"type":"fakeip","oixcloud":true}`), &options)
	require.ErrorContains(t, err, "unknown field")
}

func TestDNSOptionsRejectsLegacyFakeIPOptions(t *testing.T) {
	t.Parallel()

	ctx := service.ContextWith[DNSTransportOptionsRegistry](context.Background(), stubDNSTransportOptionsRegistry{})
	var options DNSOptions
	err := json.UnmarshalContext(ctx, []byte(`{
		"fakeip": {
			"enabled": true,
			"inet4_range": "198.18.0.0/15"
		}
	}`), &options)
	require.EqualError(t, err, legacyDNSFakeIPRemovedMessage)
}

func TestDNSServerOptionsRejectsLegacyFormats(t *testing.T) {
	t.Parallel()

	ctx := service.ContextWith[DNSTransportOptionsRegistry](context.Background(), stubDNSTransportOptionsRegistry{})
	testCases := []string{
		`{"address":"1.1.1.1"}`,
		`{"type":"legacy","address":"1.1.1.1"}`,
	}
	for _, content := range testCases {
		var options DNSServerOptions
		err := json.UnmarshalContext(ctx, []byte(content), &options)
		require.EqualError(t, err, legacyDNSServerRemovedMessage)
	}
}
