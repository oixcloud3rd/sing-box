package local

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractNeighborHost(t *testing.T) {
	t.Parallel()

	require.Equal(t, "router", extractNeighborHost("router.lan.", []string{".lan."}))
	require.Empty(t, extractNeighborHost("nested.router.lan.", []string{".lan."}))
	require.Empty(t, extractNeighborHost("example.org.", []string{".lan."}))
}

func TestBuildNeighborMatchersRejectsInvalidDomain(t *testing.T) {
	t.Parallel()

	_, err := buildNeighborMatchers([]string{"lan"})
	require.EqualError(t, err, "neighbor_domain entry must start with '.': lan")
}
