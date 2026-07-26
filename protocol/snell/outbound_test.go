package snell

import (
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func newECHTLSOptions() option.SnellOutboundOptions {
	return option.SnellOutboundOptions{
		Version: 4,
		PSK:     "password",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled: true,
				ALPN:    []string{"h2"},
				ECH:     &option.OutboundECHOptions{Enabled: true},
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
