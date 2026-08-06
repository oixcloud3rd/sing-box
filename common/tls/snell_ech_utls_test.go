//go:build with_utls

package tls

import (
	"testing"

	utls "github.com/metacubex/utls"
)

func TestSnellECHUTLSSessionCacheSharedByClone(t *testing.T) {
	config := &UTLSClientConfig{config: &utls.Config{}}
	config.configureSnellECH()
	if config.config.ClientSessionCache == nil {
		t.Fatal("session cache was not configured")
	}
	cloned := config.Clone().(*UTLSClientConfig)
	if cloned.config.ClientSessionCache != config.config.ClientSessionCache {
		t.Fatal("cloned configuration does not share session cache")
	}
}
