package libbox

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type platformLocalDNSTransportStub struct {
	lookupCalls   int
	exchangeCalls int
}

func (s *platformLocalDNSTransportStub) Raw() bool {
	return false
}

func (s *platformLocalDNSTransportStub) Lookup(ctx *ExchangeContext, network string, domain string) error {
	s.lookupCalls++
	ctx.Success("192.0.2.10")
	return nil
}

func (s *platformLocalDNSTransportStub) Exchange(ctx *ExchangeContext, message []byte) error {
	s.exchangeCalls++
	return nil
}

type platformPreferredDomainResolverStub struct {
	response *mDNS.Msg
	resolved bool
}

func (s *platformPreferredDomainResolverStub) Start(stage adapter.StartStage) error {
	return nil
}

func (s *platformPreferredDomainResolverStub) PreferredDomain(domain string) bool {
	return s.resolved
}

func (s *platformPreferredDomainResolverStub) TryResolve(message *mDNS.Msg) (*mDNS.Msg, bool) {
	return s.response, s.resolved
}

func TestPlatformTransportPreferredDomain(t *testing.T) {
	t.Parallel()

	platformTransport := new(platformLocalDNSTransportStub)
	transport, err := newPlatformTransport(
		context.Background(),
		log.NewNOPFactory().Logger(),
		platformTransport,
		"local",
		option.LocalDNSServerOptions{},
	)
	require.NoError(t, err)
	require.Implements(t, (*adapter.DNSTransportWithPreferredDomain)(nil), transport)
	require.True(t, transport.PreferredDomain("printer.local"))
	require.False(t, transport.PreferredDomain("example.org"))
}

func TestPlatformTransportResolvesLocalOverridesFirst(t *testing.T) {
	t.Parallel()

	platformResolver := new(platformLocalDNSTransportStub)
	transport, err := newPlatformTransport(
		context.Background(),
		log.NewNOPFactory().Logger(),
		platformResolver,
		"local",
		option.LocalDNSServerOptions{},
	)
	require.NoError(t, err)
	expectedResponse := new(mDNS.Msg)
	transport.preferredDomainResolver = &platformPreferredDomainResolverStub{
		response: expectedResponse,
		resolved: true,
	}
	request := new(mDNS.Msg)
	request.SetQuestion("router.lan.", mDNS.TypeA)

	response, err := transport.Exchange(context.Background(), request)
	require.NoError(t, err)
	require.Same(t, expectedResponse, response)
	require.Zero(t, platformResolver.lookupCalls)
	require.Zero(t, platformResolver.exchangeCalls)
}

func TestPlatformTransportFallsBackToPlatformResolver(t *testing.T) {
	t.Parallel()

	platformResolver := new(platformLocalDNSTransportStub)
	transport, err := newPlatformTransport(
		context.Background(),
		log.NewNOPFactory().Logger(),
		platformResolver,
		"local",
		option.LocalDNSServerOptions{},
	)
	require.NoError(t, err)
	transport.preferredDomainResolver = new(platformPreferredDomainResolverStub)
	request := new(mDNS.Msg)
	request.SetQuestion("example.org.", mDNS.TypeA)

	response, err := transport.Exchange(context.Background(), request)
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
	require.IsType(t, new(mDNS.A), response.Answer[0])
	require.Equal(t, "192.0.2.10", response.Answer[0].(*mDNS.A).A.String())
	require.Equal(t, 1, platformResolver.lookupCalls)
	require.Zero(t, platformResolver.exchangeCalls)
}
