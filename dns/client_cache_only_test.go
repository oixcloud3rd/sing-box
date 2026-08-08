package dns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestClientLookupCacheOnly(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{
		Context: context.Background(),
		Logger:  log.NewNOPFactory().Logger(),
	})
	client.Start()
	transport := &fakeDNSTransport{
		tag:     "cache-only",
		address: netip.MustParseAddr("192.0.2.1"),
	}
	queryOptions := adapter.DNSQueryOptions{
		Strategy:  C.DomainStrategyIPv4Only,
		CacheOnly: true,
	}
	addresses, err := client.Lookup(context.Background(), transport, "example.org", queryOptions, nil)
	require.ErrorIs(t, err, ErrNotCached)
	require.Empty(t, addresses)
	require.Zero(t, transport.queryCount.Load())

	queryOptions.CacheOnly = false
	addresses, err = client.Lookup(context.Background(), transport, "example.org", queryOptions, nil)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, addresses)
	require.Equal(t, int32(1), transport.queryCount.Load())

	queryOptions.CacheOnly = true
	addresses, err = client.Lookup(context.Background(), transport, "example.org", queryOptions, nil)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, addresses)
	require.Equal(t, int32(1), transport.queryCount.Load())
}

func TestClientExchangeCacheOnly(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{
		Context: context.Background(),
		Logger:  log.NewNOPFactory().Logger(),
	})
	client.Start()
	transport := &fakeDNSTransport{
		tag:     "exchange-cache-only",
		address: netip.MustParseAddr("192.0.2.2"),
	}
	message := &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{RecursionDesired: true},
		Question: []mDNS.Question{{
			Name:   "example.net.",
			Qtype:  mDNS.TypeA,
			Qclass: mDNS.ClassINET,
		}},
	}
	response, err := client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{CacheOnly: true}, nil)
	require.ErrorIs(t, err, ErrNotCached)
	require.Nil(t, response)
	require.Zero(t, transport.queryCount.Load())

	response, err = client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, int32(1), transport.queryCount.Load())

	response, err = client.Exchange(context.Background(), transport, message, adapter.DNSQueryOptions{CacheOnly: true}, nil)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, int32(1), transport.queryCount.Load())
}

func TestClientLookupCacheOnlyDoesNotRefreshStaleCache(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{
		Context:           context.Background(),
		OptimisticTimeout: time.Minute,
		Logger:            log.NewNOPFactory().Logger(),
	})
	client.Start()
	transport := &fakeDNSTransport{
		tag:     "cache-only-stale",
		address: netip.MustParseAddr("192.0.2.3"),
	}
	question := mDNS.Question{
		Name:   "example.com.",
		Qtype:  mDNS.TypeA,
		Qclass: mDNS.ClassINET,
	}
	client.cache.AddWithLifetime(
		dnsCacheKey{Question: question, transportTag: transport.tag},
		FixedResponse(0, question, []netip.Addr{transport.address}, 300),
		-time.Second,
	)
	addresses, err := client.Lookup(context.Background(), transport, "example.com", adapter.DNSQueryOptions{
		Strategy:  C.DomainStrategyIPv4Only,
		CacheOnly: true,
	}, nil)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{transport.address}, addresses)
	require.Never(t, func() bool {
		return transport.queryCount.Load() > 0
	}, 100*time.Millisecond, time.Millisecond)
}
