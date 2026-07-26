package option

import (
	"testing"

	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestSnellOutboundECHTLSOptionsJSON(t *testing.T) {
	t.Parallel()

	content := []byte(`{
		"server": "server.example.com",
		"server_port": 443,
		"version": 4,
		"psk": "password",
		"identity": true,
		"reuse": true,
		"tls": {
			"enabled": true,
			"server_name": "public.example.com",
			"alpn": "h2",
			"ech": {
				"enabled": true,
				"config": [
					"-----BEGIN ECH CONFIGS-----",
					"AA==",
					"-----END ECH CONFIGS-----"
				]
			},
			"utls": {
				"enabled": true,
				"fingerprint": "chrome"
			}
		}
	}`)
	var options SnellOutboundOptions
	require.NoError(t, json.Unmarshal(content, &options))
	require.True(t, options.Identity)
	require.NotNil(t, options.TLS)
	require.True(t, options.TLS.Enabled)
	require.Equal(t, []string{"h2"}, []string(options.TLS.ALPN))
	require.NotNil(t, options.TLS.ECH)
	require.True(t, options.TLS.ECH.Enabled)

	encoded, err := json.Marshal(options)
	require.NoError(t, err)
	require.JSONEq(t, string(content), string(encoded))
}

func TestSnellOutboundLegacyOptionsJSON(t *testing.T) {
	t.Parallel()

	content := []byte(`{
		"server": "127.0.0.1",
		"server_port": 1080,
		"version": 4,
		"psk": "password",
		"obfs_mode": "http",
		"obfs_host": "example.com"
	}`)
	var options SnellOutboundOptions
	require.NoError(t, json.Unmarshal(content, &options))
	require.Nil(t, options.TLS)
	require.False(t, options.Identity)

	encoded, err := json.Marshal(options)
	require.NoError(t, err)
	require.JSONEq(t, string(content), string(encoded))
}

func TestSnellOutboundV2RayTransportRejected(t *testing.T) {
	t.Parallel()

	content := []byte(`{
		"server": "server.example.com",
		"server_port": 443,
		"version": 4,
		"psk": "password",
		"transport": {
			"type": "ws",
			"path": "/snell"
		}
	}`)
	var options SnellOutboundOptions
	require.ErrorContains(t, json.Unmarshal(content, &options), `unknown field "transport"`)
}
