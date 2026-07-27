package local

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/mdns"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// PreferredDomainResolver matches names owned by the local DNS transport and
// resolves hosts and neighbor overrides before the transport queries upstream.
type PreferredDomainResolver interface {
	Start(stage adapter.StartStage) error
	PreferredDomain(domain string) bool
	TryResolve(message *mDNS.Msg) (*mDNS.Msg, bool)
}

type preferredDomainResolver struct {
	ctx              context.Context
	logger           logger.ContextLogger
	hosts            *hosts.File
	neighborResolver adapter.NeighborResolver
	neighborSuffixes []string
}

var _ PreferredDomainResolver = (*preferredDomainResolver)(nil)

// NewPreferredDomainResolver creates the shared preferred-domain resolver used
// by both the regular and platform local DNS transports.
func NewPreferredDomainResolver(ctx context.Context, logger logger.ContextLogger, neighborDomains []string) (PreferredDomainResolver, error) {
	suffixes, err := buildNeighborMatchers(neighborDomains)
	if err != nil {
		return nil, err
	}
	return &preferredDomainResolver{
		ctx:              ctx,
		logger:           logger,
		neighborSuffixes: suffixes,
	}, nil
}

func (r *preferredDomainResolver) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateInitialize:
		defaultHosts, err := hosts.NewDefault()
		if err != nil {
			r.logger.Warn(err)
		} else {
			r.hosts = defaultHosts
		}
	case adapter.StartStateStart:
		router := service.FromContext[adapter.Router](r.ctx)
		if router != nil {
			r.neighborResolver = router.NeighborResolver()
		}
	}
	return nil
}

func (r *preferredDomainResolver) PreferredDomain(domain string) bool {
	canonical := mDNS.CanonicalName(domain)
	return len(r.lookupHosts(canonical)) > 0 || r.hasNeighborHost(canonical) || mdns.IsLocalDomain(canonical)
}

func (r *preferredDomainResolver) TryResolve(message *mDNS.Msg) (*mDNS.Msg, bool) {
	question := message.Question[0]
	if question.Qtype == mDNS.TypeA || question.Qtype == mDNS.TypeAAAA {
		addresses := r.lookupHosts(question.Name)
		if len(addresses) > 0 {
			return dns.FixedResponse(message.Id, question, addresses, C.DefaultDNSTTL), true
		}
	}
	response := r.lookupNeighbor(message)
	return response, response != nil
}

func (r *preferredDomainResolver) lookupHosts(domain string) []netip.Addr {
	if r.hosts == nil {
		return nil
	}
	return r.hosts.Lookup(dns.FqdnToDomain(domain))
}
