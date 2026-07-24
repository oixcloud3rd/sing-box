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
		},
		"transport": {
			"type": "ws",
			"path": "/snell",
			"headers": {
				"Host": "tunnel.example.com"
			}
		}
	}`)
	var options SnellOutboundOptions
	require.NoError(t, json.Unmarshal(content, &options))
	require.True(t, options.Identity)
	require.NotNil(t, options.TLS)
	require.True(t, options.TLS.Enabled)
	require.NotNil(t, options.TLS.ECH)
	require.True(t, options.TLS.ECH.Enabled)
	require.NotNil(t, options.Transport)
	require.Equal(t, "ws", options.Transport.Type)
	require.Equal(t, "/snell", options.Transport.WebsocketOptions.Path)

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
	require.Nil(t, options.Transport)
	require.False(t, options.Identity)

	encoded, err := json.Marshal(options)
	require.NoError(t, err)
	require.JSONEq(t, string(content), string(encoded))
}
