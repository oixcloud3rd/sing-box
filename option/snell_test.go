package option

import (
	"os"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/schema"
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
		"identity": 2,
		"reuse": true,
		"preconnect": 2,
		"tls": {
			"enabled": true,
			"server_name": "public.example.com",
			"alpn": "snell-ech/1",
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
	require.NotNil(t, options.Identity)
	require.Equal(t, 2, *options.Identity)
	require.Equal(t, 2, options.Preconnect)
	require.NotNil(t, options.TLS)
	require.True(t, options.TLS.Enabled)
	require.Equal(t, []string{"snell-ech/1"}, []string(options.TLS.ALPN))
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
	require.Nil(t, options.Identity)

	encoded, err := json.Marshal(options)
	require.NoError(t, err)
	require.JSONEq(t, string(content), string(encoded))
}

func TestSnellIdentityRejectsBooleanJSON(t *testing.T) {
	t.Parallel()
	var options SnellOutboundOptions
	require.Error(t, json.Unmarshal([]byte(`{"version":4,"psk":"password","identity":true}`), &options))
}

func TestSnellInboundIdentityJSON(t *testing.T) {
	t.Parallel()
	content := []byte(`{
		"listen": "::",
		"listen_port": 443,
		"version": 5,
		"psk": "password",
		"identity": true,
		"tls": {
			"enabled": true,
			"alpn": "snell-ech/1",
			"ech": {"enabled": true}
		}
	}`)
	var options SnellInboundOptions
	require.NoError(t, json.Unmarshal(content, &options))
	require.True(t, options.Identity)
	require.NotNil(t, options.TLS)
	encoded, err := json.Marshal(options)
	require.NoError(t, err)
	require.JSONEq(t, string(content), string(encoded))
}

func TestSnellInboundIdentityRejectsNumberJSON(t *testing.T) {
	t.Parallel()
	var options SnellInboundOptions
	require.Error(t, json.Unmarshal([]byte(`{"version":5,"psk":"password","identity":2}`), &options))
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
	require.Error(t, json.Unmarshal(content, &options))
}

func TestSnellHTTP3Options(t *testing.T) {
	content := `{"server":"server.example","server_port":443,"version":4,"psk":"password","identity":2,"transport":{"type":"http3"}}`
	var options SnellOutboundOptions
	require.NoError(t, json.Unmarshal([]byte(content), &options))
	require.False(t, options.Transport.HappyEyeballs)
	require.Empty(t, options.Transport.QUICCongestionControl)
	require.Nil(t, options.Transport.BBRProfile)
	encoded, err := json.Marshal(options)
	require.NoError(t, err)
	require.JSONEq(t, content, string(encoded))

	for _, transport := range []string{
		`{"type":"http3","quic_congestion_control":"reno"}`,
		`{"type":"http3","quic_congestion_control":"cubic","happy_eyeballs":true}`,
		`{"type":"http3","quic_congestion_control":"bbr","bbr_profile":"standard"}`,
		`{"type":"http3","quic_congestion_control":"bbr","bbr_profile":"conservative"}`,
		`{"type":"http3","quic_congestion_control":"bbr","bbr_profile":"aggressive"}`,
	} {
		var options SnellTransportOptions
		require.NoError(t, json.Unmarshal([]byte(transport), &options))
		encoded, err := json.Marshal(options)
		require.NoError(t, err)
		require.JSONEq(t, transport, string(encoded))
	}
	for _, transport := range []string{
		`{"type":"http3","quic_congestion_control":"unknown"}`,
		`{"type":"http3","bbr_profile":"standard"}`,
		`{"type":"http3","quic_congestion_control":"bbr","bbr_profile":"unknown"}`,
		`{"type":"http3","path":"/custom"}`,
		`{"type":"http3","fallback":true}`,
		`{"type":"http3","fallback":false}`,
		`{"type":"http3","happy_eyeballs":true,"fallback":true}`,
		`{"type":"http3","happy_eyeballs":"true"}`,
	} {
		var options SnellTransportOptions
		require.Error(t, json.Unmarshal([]byte(transport), &options))
	}
}

func TestSnellHTTP3Schema(t *testing.T) {
	generated, err := schema.Generate(t.Context(), reflect.TypeFor[SnellTransportOptions]())
	require.NoError(t, err)
	published, err := os.ReadFile("../docs/schema.json")
	require.NoError(t, err)
	var generatedSchema, publishedSchema struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(generated, &generatedSchema))
	require.NoError(t, json.Unmarshal(published, &publishedSchema))
	require.JSONEq(t, string(generatedSchema.Defs["SnellTransport"]), string(publishedSchema.Defs["SnellTransport"]))
	var transport struct {
		Properties           map[string]json.RawMessage `json:"properties"`
		AdditionalProperties bool                       `json:"additionalProperties"`
	}
	require.NoError(t, json.Unmarshal(generatedSchema.Defs["SnellTransport"], &transport))
	require.Contains(t, transport.Properties, "happy_eyeballs")
	require.NotContains(t, transport.Properties, "fallback")
	require.False(t, transport.AdditionalProperties)
}
