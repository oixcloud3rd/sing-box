package tls

import (
	stdtls "crypto/tls"
	"testing"
)

func TestSnellECHStandardSessionCacheSharedByClone(t *testing.T) {
	config := &STDClientConfig{config: &stdtls.Config{}}
	config.configureSnellECH()
	if config.config.ClientSessionCache == nil {
		t.Fatal("session cache was not configured")
	}
	cloned := config.Clone().(*STDClientConfig)
	if cloned.config.ClientSessionCache != config.config.ClientSessionCache {
		t.Fatal("cloned configuration does not share session cache")
	}
}
