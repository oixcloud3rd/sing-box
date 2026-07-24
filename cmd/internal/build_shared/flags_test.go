package build_shared

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOIXCloudLinkerFlag(t *testing.T) {
	seed := make([]byte, 32)
	encoded := base64.StdEncoding.EncodeToString(seed)
	t.Setenv(OIXCloudPrivateKeyEnvironment, encoded)
	flag, err := OIXCloudLinkerFlag(true)
	require.NoError(t, err)
	require.Equal(t, "-X "+oixCloudPrivateKeyLinkerName+"="+encoded, flag)
	require.Contains(t, LinkerFlags("test", false), flag)
}

func TestOIXCloudLinkerFlagValidation(t *testing.T) {
	t.Setenv(OIXCloudPrivateKeyEnvironment, "")
	flag, err := OIXCloudLinkerFlag(false)
	require.NoError(t, err)
	require.Empty(t, flag)
	_, err = OIXCloudLinkerFlag(true)
	require.EqualError(t, err, "missing "+OIXCloudPrivateKeyEnvironment)

	t.Setenv(OIXCloudPrivateKeyEnvironment, "invalid!")
	_, err = OIXCloudLinkerFlag(false)
	require.ErrorContains(t, err, "decode "+OIXCloudPrivateKeyEnvironment)

	t.Setenv(OIXCloudPrivateKeyEnvironment, base64.StdEncoding.EncodeToString([]byte("short")))
	_, err = OIXCloudLinkerFlag(false)
	require.EqualError(t, err, "invalid "+OIXCloudPrivateKeyEnvironment+" seed length: got 5, want 32")

	t.Setenv(OIXCloudPrivateKeyEnvironment, strings.TrimRight(base64.StdEncoding.EncodeToString(make([]byte, 32)), "="))
	_, err = OIXCloudLinkerFlag(true)
	require.NoError(t, err)
}
