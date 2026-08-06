package snell

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"

	"github.com/stretchr/testify/require"
)

func newECHTLSOptions() option.SnellOutboundOptions {
	return option.SnellOutboundOptions{
		Version: 4,
		AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{
			PSK: "password",
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled: true,
					ALPN:    []string{"h2"},
					ECH:     &option.OutboundECHOptions{Enabled: true},
				},
			},
		},
	}
}

func TestValidateECHTLSOptions(t *testing.T) {
	t.Parallel()

	legacyOptions := option.SnellOutboundOptions{
		Version: 4,
		AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{
			PSK: "password",
		},
	}
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

	require.NoError(t, validateIdentityOptions(option.SnellOutboundOptions{
		Version: 4,
		AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{
			Identity: common.Ptr(1),
		},
	}))
	v2Options := newECHTLSOptions()
	v2Options.Identity = common.Ptr(2)
	require.NoError(t, validateIdentityOptions(v2Options))
	require.NoError(t, validateIdentityOptions(option.SnellOutboundOptions{Version: 6}))
	require.ErrorContains(t, validateIdentityOptions(option.SnellOutboundOptions{
		Version: 6,
		AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{
			Identity: common.Ptr(1),
		},
	}), "requires version 4")
	require.ErrorContains(t, validateIdentityOptions(option.SnellOutboundOptions{Version: 4, AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{Identity: common.Ptr(0)}}), "must be 1 or 2")
	require.ErrorContains(t, validateIdentityOptions(option.SnellOutboundOptions{Version: 4, AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{Identity: common.Ptr(3)}}), "must be 1 or 2")
	require.ErrorContains(t, validateIdentityOptions(option.SnellOutboundOptions{Version: 4, AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{Identity: common.Ptr(2)}}), "requires ECH-TLS")
}

func TestValidatePreconnectOptions(t *testing.T) {
	t.Parallel()
	options := newECHTLSOptions()
	options.Reuse = true
	options.Preconnect = 4
	require.NoError(t, validatePreconnectOptions(options, true))
	options.Preconnect = 5
	require.ErrorContains(t, validatePreconnectOptions(options, true), "between 0 and 4")
	options.Preconnect = 1
	options.Reuse = false
	require.ErrorContains(t, validatePreconnectOptions(options, true), "requires version 4, ECH-TLS, and reuse")
	options.Reuse = true
	require.ErrorContains(t, validatePreconnectOptions(options, false), "requires version 4, ECH-TLS, and reuse")
}
