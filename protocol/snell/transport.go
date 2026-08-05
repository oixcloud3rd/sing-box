package snell

import (
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type transportDialer interface {
	N.Dialer
	Reset()
	Close() error
}

func validateTransportOptions(options option.SnellOutboundOptions) error {
	transport := options.Transport
	if transport == nil {
		return nil
	}
	if err := transport.Validate(); err != nil {
		return err
	}
	if options.Version != 4 || options.Identity == nil || *options.Identity != 2 {
		return E.New("snell: HTTP/3 requires version 4 and identity 2")
	}
	enabled, err := validateECHTLSOptions(options)
	if err != nil {
		return err
	}
	if !enabled {
		return E.New("snell: HTTP/3 requires ECH-TLS")
	}
	tlsOptions := options.TLS
	if tlsOptions.Insecure {
		return E.New("snell: HTTP/3 requires certificate verification")
	}
	if tlsOptions.Engine != "" && tlsOptions.Engine != "go" {
		return E.New("snell: HTTP/3 requires the Go TLS engine")
	}
	if tlsOptions.Reality != nil && tlsOptions.Reality.Enabled {
		return E.New("snell: HTTP/3 cannot be combined with Reality")
	}
	if (tlsOptions.MinVersion != "" && tlsOptions.MinVersion != "1.3") ||
		(tlsOptions.MaxVersion != "" && tlsOptions.MaxVersion != "1.3") {
		return E.New("snell: HTTP/3 requires TLS 1.3")
	}
	return nil
}
