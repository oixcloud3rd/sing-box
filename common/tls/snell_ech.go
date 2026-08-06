package tls

import E "github.com/sagernet/sing/common/exceptions"

const SnellECHSessionCacheCapacity = 32

type snellECHClientConfig interface {
	configureSnellECH()
}

func ConfigureSnellECHClient(config Config) error {
	configurator, loaded := config.(snellECHClientConfig)
	if !loaded {
		return E.New("TLS configuration does not support Snell ECH-TLS")
	}
	configurator.configureSnellECH()
	return nil
}
