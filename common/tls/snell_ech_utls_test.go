//go:build with_utls

package tls

import (
	"net"
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
	if !config.disableRenegotiation || !cloned.disableRenegotiation {
		t.Fatal("disable renegotiation setting was not preserved")
	}
}

func TestSnellECHUTLSClientUsesConfiguredSessionCache(t *testing.T) {
	cache := &recordingUTLSSessionCache{}
	config := &UTLSClientConfig{
		config: &utls.Config{ServerName: "example.com", ClientSessionCache: cache},
		id:     utls.HelloChrome_Auto,
	}
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	client, err := config.Client(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.(*utlsALPNWrapper).BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	if len(cache.getKeys) != 1 || cache.getKeys[0] != "example.com" {
		t.Fatalf("configured uTLS session cache was not used: keys=%v", cache.getKeys)
	}
}

func TestSnellECHUTLSDisablesFingerprintRenegotiation(t *testing.T) {
	config := &UTLSClientConfig{
		config:               &utls.Config{ServerName: "example.com"},
		id:                   utls.HelloChrome_Auto,
		disableRenegotiation: true,
	}
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	client, err := config.Client(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	wrapper := client.(*utlsALPNWrapper)
	if err = wrapper.prepareHandshakeState(); err != nil {
		t.Fatal(err)
	}
	foundRenegotiation := false
	for _, extension := range wrapper.Extensions {
		if renegotiation, loaded := extension.(*utls.RenegotiationInfoExtension); loaded {
			foundRenegotiation = true
			if renegotiation.Renegotiation != utls.RenegotiateNever {
				t.Fatalf("renegotiation = %v, want RenegotiateNever", renegotiation.Renegotiation)
			}
		}
	}
	if !foundRenegotiation {
		t.Fatal("fingerprint did not contain a renegotiation extension")
	}
}

type recordingUTLSSessionCache struct {
	getKeys []string
}

func (c *recordingUTLSSessionCache) Get(sessionKey string) (*utls.ClientSessionState, bool) {
	c.getKeys = append(c.getKeys, sessionKey)
	return nil, false
}

func (*recordingUTLSSessionCache) Put(string, *utls.ClientSessionState) {
}
