package build_shared

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOIXCloudDNSAuthLinkerFlag(t *testing.T) {
	seed := make([]byte, 32)
	encoded := base64.StdEncoding.EncodeToString(seed)
	t.Setenv(OIXCloudDNSAuthPrivateKeyEnvironment, encoded)
	flag, err := OIXCloudDNSAuthLinkerFlag(true)
	require.NoError(t, err)
	require.Equal(t, "-X "+oixCloudDNSAuthPrivateKeyLinkerName+"="+encoded, flag)
	require.Contains(t, LinkerFlags("test", false), flag)
}

func TestOIXCloudDNSAuthLinkerFlagValidation(t *testing.T) {
	t.Setenv(OIXCloudDNSAuthPrivateKeyEnvironment, "")
	flag, err := OIXCloudDNSAuthLinkerFlag(false)
	require.NoError(t, err)
	require.Empty(t, flag)
	_, err = OIXCloudDNSAuthLinkerFlag(true)
	require.EqualError(t, err, "missing "+OIXCloudDNSAuthPrivateKeyEnvironment)

	t.Setenv(OIXCloudDNSAuthPrivateKeyEnvironment, "invalid!")
	_, err = OIXCloudDNSAuthLinkerFlag(false)
	require.ErrorContains(t, err, "decode "+OIXCloudDNSAuthPrivateKeyEnvironment)

	t.Setenv(OIXCloudDNSAuthPrivateKeyEnvironment, base64.StdEncoding.EncodeToString([]byte("short")))
	_, err = OIXCloudDNSAuthLinkerFlag(false)
	require.EqualError(t, err, "invalid "+OIXCloudDNSAuthPrivateKeyEnvironment+" seed length: got 5, want 32")

	t.Setenv(OIXCloudDNSAuthPrivateKeyEnvironment, strings.TrimRight(base64.StdEncoding.EncodeToString(make([]byte, 32)), "="))
	_, err = OIXCloudDNSAuthLinkerFlag(true)
	require.NoError(t, err)
}
