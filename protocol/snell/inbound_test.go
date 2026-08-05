package snell

import (
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func newInboundECHTLSOptions() option.SnellInboundOptions {
	return option.SnellInboundOptions{
		Version: 5,
		AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{
			PSK:      "password",
			Identity: true,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &option.InboundTLSOptions{
					Enabled: true,
					ECH:     &option.InboundECHOptions{Enabled: true},
				},
			},
		},
	}
}

func TestValidateInboundOptions(t *testing.T) {
	t.Parallel()
	options := newInboundECHTLSOptions()
	enabled, err := validateInboundOptions(options)
	require.NoError(t, err)
	require.True(t, enabled)

	options = newInboundECHTLSOptions()
	options.TLS = nil
	enabled, err = validateInboundOptions(options)
	require.NoError(t, err)
	require.False(t, enabled)
	options = newInboundECHTLSOptions()
	options.Version = 6
	_, err = validateInboundOptions(options)
	require.ErrorContains(t, err, "inbound identity requires version 5")
	options = newInboundECHTLSOptions()
	options.ObfsOptions.ObfsMode = "http"
	_, err = validateInboundOptions(options)
	require.ErrorContains(t, err, "cannot be combined with obfs")
}
